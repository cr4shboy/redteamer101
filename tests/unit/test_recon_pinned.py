"""Offline tests for the pinned-tool/runtime preflight (pure/local)."""

import json
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.pinned import (
    CANONICAL_LAYOUT,
    PINNED_TOOLS,
    check_runtime,
    install_dir_for,
    parse_checksum_file,
    parse_os_release,
    verify_all_installs,
    verify_install,
)

SPEC = PINNED_TOOLS["subfinder"]


def make_workspace(tmp: str) -> Path:
    root = Path(tmp)
    (root / ".tools" / "wsl").mkdir(parents=True)
    return root


def valid_manifest(install_dir: Path, spec=SPEC) -> dict:
    return {
        "package": "TOOLING-001",
        "tool": spec.tool,
        "version": spec.version,
        "platform": "linux_amd64",
        "distro": "Ubuntu-24.04",
        "artifact": spec.artifact,
        "artifact_url": f"https://example.invalid/{spec.artifact}",
        "checksums_url": f"https://example.invalid/{spec.checksum_file}",
        "sha256": spec.sha256,
        "sha256_expected": spec.sha256,
        "sha256_verified": True,
        "install_layout": list(CANONICAL_LAYOUT),
        "redirect_evidence": [{"status": "302", "host": "release-assets.example.invalid"}],
        "redirect_urls_persisted": False,
        "install_dir": str(install_dir),
    }


def official_checksum_text(spec=SPEC) -> str:
    return f"{spec.sha256}  {spec.artifact}\n"


def make_install(
    root: Path,
    spec=SPEC,
    *,
    manifest_overrides=None,
    remove=None,
    extra=None,
    checksum_text=None,
):
    install_dir = install_dir_for(root, spec)
    install_dir.mkdir(parents=True, exist_ok=True)
    binary = install_dir / spec.binary_name
    checksum = install_dir / spec.checksum_file
    # The binary bytes are arbitrary: the release archive SHA is checked against
    # the official checksum file, never against the extracted binary's hash.
    binary.write_bytes(b"binary-bytes")
    # A pinned install binary is executable; on POSIX the execute bit is checked.
    binary.chmod(binary.stat().st_mode | 0o111)
    text = official_checksum_text(spec) if checksum_text is None else checksum_text
    checksum.write_text(text, encoding="utf-8")
    manifest = valid_manifest(install_dir, spec)
    manifest.update(manifest_overrides or {})
    (install_dir / "install-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    if remove:
        (install_dir / remove).unlink()
    if extra:
        (install_dir / extra).write_text("x", encoding="utf-8")
    return install_dir


class RuntimeTests(unittest.TestCase):
    GOOD_RELEASE = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'
    GOOD_KERNEL = "6.6.87.2-microsoft-standard-WSL2"

    def check(self, **overrides):
        values = dict(
            platform="linux",
            os_release_text=self.GOOD_RELEASE,
            sysname="Linux",
            machine="x86_64",
            kernel_release=self.GOOD_KERNEL,
        )
        values.update(overrides)
        return check_runtime(**values)

    def test_accepts_exact_runtime(self):
        report = self.check()
        self.assertTrue(report.ok, report.detail)
        self.assertEqual(report.os_id, "ubuntu")
        self.assertEqual(report.version_id, "24.04")

    def test_rejects_platform(self):
        self.assertFalse(self.check(platform="win32").ok)
        self.assertFalse(self.check(platform="darwin").ok)

    def test_rejects_distro_and_version(self):
        self.assertFalse(self.check(os_release_text="ID=debian\nVERSION_ID=24.04\n").ok)
        self.assertFalse(self.check(os_release_text='ID=ubuntu\nVERSION_ID="22.04"\n').ok)

    def test_rejects_uname(self):
        self.assertFalse(self.check(sysname="Darwin").ok)
        self.assertFalse(self.check(machine="aarch64").ok)

    def test_rejects_non_wsl_and_wsl1(self):
        self.assertFalse(self.check(kernel_release="6.8.0-generic").ok)
        self.assertFalse(self.check(kernel_release="4.4.0-microsoft-standard").ok)

    def test_accepts_amd64_and_uppercase_kernel(self):
        self.assertTrue(self.check(machine="amd64", kernel_release="5.15.90.1-Microsoft-WSL2").ok)

    def test_parse_os_release_handles_quotes_and_comments(self):
        text = '# comment\nID=ubuntu\nVERSION_ID="24.04"\nEMPTY=\nBADLINE\n'
        parsed = parse_os_release(text)
        self.assertEqual(parsed["ID"], "ubuntu")
        self.assertEqual(parsed["VERSION_ID"], "24.04")
        self.assertEqual(parsed["EMPTY"], "")
        self.assertNotIn("BADLINE", parsed)
        self.assertEqual(parse_os_release(None), {})


class InstallTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_workspace(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def verify(self, spec=SPEC, **kwargs):
        return verify_install(self.root, spec, **kwargs)

    def test_valid_install(self):
        make_install(self.root)
        report = self.verify()
        self.assertTrue(report.ok, report.reason)
        self.assertTrue(report.binary_path.endswith(SPEC.binary_name))
        self.assertEqual(report.detail["artifact"], SPEC.artifact)
        self.assertEqual(report.detail["archive_sha256"], SPEC.sha256)
        self.assertEqual(
            report.detail["checksum_entry"],
            {"filename": SPEC.artifact, "sha256": SPEC.sha256},
        )
        self.assertFalse(report.detail["binary_sha256_verified"])
        self.assertEqual(report.detail["binary_sha256_source"], "observational")

    def test_binary_hash_is_observational_not_archive_sha(self):
        make_install(self.root)
        report = verify_install(self.root, SPEC, digest=lambda path: "f" * 64)
        self.assertTrue(report.ok, report.reason)
        self.assertEqual(report.detail["binary_sha256"], "f" * 64)
        self.assertNotEqual(report.detail["binary_sha256"], SPEC.sha256)

    def test_missing_checksum_entry_rejected(self):
        make_install(self.root, checksum_text=f"{'0' * 64}  other.zip\n")
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertIn("entry", report.reason)

    def test_mismatched_checksum_entry_rejected(self):
        make_install(self.root, checksum_text=f"{'0' * 64}  {SPEC.artifact}\n")
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertIn("match", report.reason)

    def test_duplicate_checksum_entry_rejected(self):
        make_install(self.root, checksum_text=official_checksum_text() * 2)
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertIn("duplicate", report.reason)

    def test_malformed_checksum_entry_rejected(self):
        make_install(self.root, checksum_text="not-a-digest  x.zip\n")
        report = self.verify()
        self.assertFalse(report.ok)

    def test_non_executable_binary_rejected(self):
        make_install(self.root)
        report = verify_install(self.root, SPEC, executable_check=lambda path: False)
        self.assertFalse(report.ok)
        self.assertIn("executable", report.reason)

    def test_missing_directory(self):
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertIn("missing", report.reason)

    def test_extra_entry_rejected(self):
        make_install(self.root, extra="junk.txt")
        report = self.verify()
        self.assertFalse(report.ok)
        self.assertIn("canonical", report.reason)

    def test_missing_file_rejected(self):
        make_install(self.root, remove=SPEC.checksum_file)
        report = self.verify()
        self.assertFalse(report.ok)

    def test_manifest_field_rejections(self):
        cases = {
            "package": "TOOLING-999",
            "tool": "other",
            "version": "9.9.9",
            "platform": "darwin_amd64",
            "distro": "Ubuntu-22.04",
            "artifact": "other.zip",
            "sha256": "0" * 64,
            "sha256_expected": "0" * 64,
            "sha256_verified": False,
        }
        for key, value in cases.items():
            with self.subTest(field=key):
                fresh = make_workspace(tempfile.mkdtemp())
                try:
                    make_install(fresh, manifest_overrides={key: value})
                    report = verify_install(fresh, SPEC)
                    self.assertFalse(report.ok, key)
                finally:
                    import shutil

                    shutil.rmtree(fresh, ignore_errors=True)

    def test_layout_and_redirect_rejections(self):
        make_install(self.root, manifest_overrides={"install_layout": ["binary"]})
        self.assertFalse(self.verify().ok)

    def test_redirect_url_persistence_rejected(self):
        make_install(self.root, manifest_overrides={"redirect_urls_persisted": True})
        self.assertFalse(self.verify().ok)

    def test_redirect_url_key_rejected(self):
        make_install(self.root, manifest_overrides={"redirect_url": "https://x/"})
        self.assertFalse(self.verify().ok)

    def test_query_string_rejected(self):
        make_install(
            self.root,
            manifest_overrides={"checksums_url": "https://x/checksums.txt?token=abc"},
        )
        self.assertFalse(self.verify().ok)

    def test_redirect_evidence_extra_field_rejected(self):
        make_install(
            self.root,
            manifest_overrides={
                "redirect_evidence": [{"status": "302", "host": "h", "url": "https://x/"}]
            },
        )
        self.assertFalse(self.verify().ok)

    def test_install_dir_must_be_canonical(self):
        make_install(self.root, manifest_overrides={"install_dir": "/tmp/wrong"})
        self.assertFalse(self.verify().ok)

    def test_sha256_digest_is_checked(self):
        # Replaced by archive-checksum semantics: see the checksum tests above.
        make_install(self.root, checksum_text=f"{'0' * 64}  other.zip\n")
        bad = verify_install(self.root, SPEC, digest=lambda path: SPEC.sha256)
        self.assertFalse(bad.ok)
        self.assertIn("checksum", bad.reason)

    def test_symlink_rejected(self):
        install_dir = make_install(self.root)
        binary = install_dir / SPEC.binary_name
        binary.unlink()
        try:
            binary.symlink_to(install_dir / "install-manifest.json")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        report = self.verify()
        self.assertFalse(report.ok)

    def test_verify_all_reports_every_tool(self):
        for spec in PINNED_TOOLS.values():
            make_install(self.root, spec)
        reports = verify_all_installs(self.root)
        self.assertEqual([r.tool for r in reports], ["subfinder", "dnsx", "amass"])
        self.assertTrue(all(r.ok for r in reports))


class ChecksumFileTests(unittest.TestCase):
    def test_parses_binary_marker_and_ignores_blank_lines(self):
        text = (
            "\n"
            f"{'a' * 64}  first.zip\n"
            f"{'b' * 64} *second.zip\n"
        )
        entries = parse_checksum_file(text)
        self.assertEqual(entries["first.zip"], "a" * 64)
        self.assertEqual(entries["second.zip"], "b" * 64)

    def test_rejects_malformed_lines(self):
        for text in ("only-one-field\n", f"{'z' * 64}  bad.zip\n", "abc  x.zip\n"):
            with self.assertRaises(Exception):
                parse_checksum_file(text)

    def test_rejects_duplicates_and_unsafe_names(self):
        with self.assertRaises(Exception):
            parse_checksum_file(f"{'a' * 64}  dup.zip\n{'b' * 64}  dup.zip\n")
        with self.assertRaises(Exception):
            parse_checksum_file(f"{'a' * 64}  ../evil.zip\n")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
