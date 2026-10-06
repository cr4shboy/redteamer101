"""Unit tests for the offline archive validator (TOOLING-001 hardening).

These tests are offline: they create local fixtures in a temporary directory and
never invoke WSL, the network, or an installed recon binary.
"""

import importlib.util
import io
import json
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "utils" / "validate_tool_archive.py"

# Do not leave a "__pycache__" beside the standalone helper script.
sys.dont_write_bytecode = True

_spec = importlib.util.spec_from_file_location("validate_tool_archive", MODULE_PATH)
validator = importlib.util.module_from_spec(_spec)
assert _spec is not None and _spec.loader is not None
_spec.loader.exec_module(validator)


def _make_zip(path: Path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            if mode:
                info.external_attr = mode << 16
            archive.writestr(info, data)


def _make_targz(path: Path, members):
    with tarfile.open(path, "w:gz") as archive:
        for info, data in members:
            if data is None:
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


class MemberNameTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = str(Path(self._tmp.name) / "root")
        Path(self.root).mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_safe_names_are_accepted(self):
        for name in ("file", "dir/file", "dir/file.txt", "a/b/c/", "./x"):
            with self.subTest(name=name):
                resolved = validator.check_member_name(name, self.root)
                self.assertTrue(
                    resolved.startswith(validator.os.path.normpath(self.root))
                    or resolved == validator.os.path.normpath(self.root)
                )

    def test_traversal_rejected(self):
        for name in ("../evil", "a/../../evil", "a\\..\\..\\evil", "..", "./.."):
            with self.subTest(name=name):
                with self.assertRaises(validator.ArchiveViolation):
                    validator.check_member_name(name, self.root)

    def test_absolute_rejected(self):
        for name in ("/etc/passwd", "\\windows\\evil", "//server/share"):
            with self.subTest(name=name):
                with self.assertRaises(validator.ArchiveViolation):
                    validator.check_member_name(name, self.root)

    def test_windows_drive_and_unc_rejected(self):
        for name in ("C:/Windows/evil", "C:evil", "\\\\server\\share\\evil"):
            with self.subTest(name=name):
                with self.assertRaises(validator.ArchiveViolation):
                    validator.check_member_name(name, self.root)

    def test_nul_and_control_chars_rejected(self):
        for name in ("bad\x00name", "bad\nname", "bad\tname"):
            with self.subTest(name=name):
                with self.assertRaises(validator.ArchiveViolation):
                    validator.check_member_name(name, self.root)

    def test_empty_name_rejected(self):
        with self.assertRaises(validator.ArchiveViolation):
            validator.check_member_name("", self.root)

    def test_destination_escape_rejected(self):
        with self.assertRaises(validator.ArchiveViolation):
            validator.check_member_name("sub/../../outside", self.root)


class ZipTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = str(Path(self._tmp.name) / "root")
        Path(self.root).mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_safe_zip_accepted(self):
        path = Path(self._tmp.name) / "safe.zip"
        _make_zip(path, [("dir/file.txt", "data", 0)])
        self.assertEqual(validator.validate_zip(str(path), self.root), 1)

    def test_traversal_zip_rejected(self):
        path = Path(self._tmp.name) / "traversal.zip"
        _make_zip(path, [("../escape.txt", "data", 0)])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_zip(str(path), self.root)

    def test_absolute_zip_rejected(self):
        path = Path(self._tmp.name) / "abs.zip"
        _make_zip(path, [("/etc/passwd", "data", 0)])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_zip(str(path), self.root)

    def test_symlink_zip_rejected(self):
        path = Path(self._tmp.name) / "link.zip"
        _make_zip(path, [("link", "/etc/passwd", stat.S_IFLNK | 0o777)])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_zip(str(path), self.root)

    def test_special_zip_rejected(self):
        path = Path(self._tmp.name) / "fifo.zip"
        _make_zip(path, [("pipe", "", stat.S_IFIFO | 0o644)])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_zip(str(path), self.root)

    def test_read_error_raises(self):
        with self.assertRaises((OSError, zipfile.BadZipFile)):
            validator.validate_zip(str(Path(self._tmp.name) / "missing.zip"), self.root)


class TarGzTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = str(Path(self._tmp.name) / "root")
        Path(self.root).mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_safe_targz_accepted(self):
        path = Path(self._tmp.name) / "safe.tar.gz"
        info = tarfile.TarInfo("dir/file.txt")
        _make_targz(path, [(info, b"data")])
        self.assertEqual(validator.validate_targz(str(path), self.root), 1)

    def test_traversal_targz_rejected(self):
        path = Path(self._tmp.name) / "traversal.tar.gz"
        info = tarfile.TarInfo("../escape.txt")
        _make_targz(path, [(info, b"data")])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_targz(str(path), self.root)

    def test_symlink_targz_rejected(self):
        path = Path(self._tmp.name) / "symlink.tar.gz"
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        _make_targz(path, [(info, None)])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_targz(str(path), self.root)

    def test_hardlink_targz_rejected(self):
        path = Path(self._tmp.name) / "hardlink.tar.gz"
        info = tarfile.TarInfo("hardlink")
        info.type = tarfile.LNKTYPE
        info.linkname = "dir/file.txt"
        _make_targz(path, [(info, None)])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_targz(str(path), self.root)

    def test_device_targz_rejected(self):
        path = Path(self._tmp.name) / "device.tar.gz"
        info = tarfile.TarInfo("dev")
        info.type = tarfile.CHRTYPE
        info.devmajor = 1
        info.devminor = 3
        _make_targz(path, [(info, None)])
        with self.assertRaises(validator.ArchiveViolation):
            validator.validate_targz(str(path), self.root)


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "root"
        self.root.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_self_test_exits_zero(self):
        result = self.run_cli("--self-test")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_success_prints_json(self):
        archive = Path(self._tmp.name) / "safe.zip"
        _make_zip(archive, [("sub/file.txt", "data", 0)])
        result = self.run_cli(
            "--archive", str(archive), "--type", "zip", "--root", str(self.root)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["members"], 1)

    def test_violation_exits_two(self):
        archive = Path(self._tmp.name) / "bad.zip"
        _make_zip(archive, [("../escape", "data", 0)])
        result = self.run_cli(
            "--archive", str(archive), "--type", "zip", "--root", str(self.root)
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("error:", result.stderr)

    def test_unreadable_exits_three(self):
        result = self.run_cli(
            "--archive",
            str(Path(self._tmp.name) / "missing.zip"),
            "--type",
            "zip",
            "--root",
            str(self.root),
        )
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
