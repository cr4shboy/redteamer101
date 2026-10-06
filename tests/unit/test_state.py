"""Unit tests for atomic scan-state persistence."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from red_teaming.orchestration import state as state_mod
from red_teaming.projects.models import ProjectDomain, Target
from red_teaming.projects.paths import ScanPath


class StateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.domain = ProjectDomain.parse("example.com")
        self.target = Target.parse("https://app.example.com/", self.domain)
        self.scan = ScanPath.build(
            self.root,
            self.domain,
            self.target,
            now=datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
            suffix="abc123",
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_write_then_read_roundtrip(self):
        payload = {"scan_id": self.scan.scan_id, "status": "created", "notes": ["a", "b"]}
        path = state_mod.write_state(self.scan, payload)
        self.assertEqual(path, self.scan.scan_dir / state_mod.STATE_FILENAME)
        self.assertTrue(path.is_file())
        self.assertEqual(state_mod.read_state(self.scan), payload)

    def test_write_creates_scan_directory(self):
        self.assertFalse(self.scan.scan_dir.exists())
        state_mod.write_state(self.scan, {"status": "created"})
        self.assertTrue(self.scan.scan_dir.is_dir())

    def test_formatting_is_stable_and_readable(self):
        state_mod.write_state(self.scan, {"b": 1, "a": {"z": 2}})
        raw = (self.scan.scan_dir / state_mod.STATE_FILENAME).read_text(encoding="utf-8")
        self.assertEqual(raw, '{\n  "a": {\n    "z": 2\n  },\n  "b": 1\n}\n')

    def test_no_temporary_files_remain(self):
        state_mod.write_state(self.scan, {"status": "created"})
        leftovers = [
            entry.name
            for entry in self.scan.scan_dir.iterdir()
            if entry.name != state_mod.STATE_FILENAME
        ]
        self.assertEqual(leftovers, [])

    def test_unicode_roundtrip(self):
        payload = {"label": "žmogus", "path": "/aplinka"}
        state_mod.write_state(self.scan, payload)
        self.assertEqual(state_mod.read_state(self.scan), payload)

    def test_read_rejects_non_object_root(self):
        self.scan.create()
        (self.scan.scan_dir / state_mod.STATE_FILENAME).write_text(
            "[1, 2, 3]\n", encoding="utf-8"
        )
        with self.assertRaises(state_mod.ScanStateError):
            state_mod.read_state(self.scan)

    def test_read_rejects_scalar_root(self):
        self.scan.create()
        (self.scan.scan_dir / state_mod.STATE_FILENAME).write_text(
            '"just a string"\n', encoding="utf-8"
        )
        with self.assertRaises(state_mod.ScanStateError):
            state_mod.read_state(self.scan)

    def test_read_missing_file_raises(self):
        self.scan.create()
        with self.assertRaises(FileNotFoundError):
            state_mod.read_state(self.scan)

    def test_write_rejects_non_dict(self):
        with self.assertRaises(state_mod.ScanStateError):
            state_mod.write_state(self.scan, ["not", "an", "object"])  # type: ignore[arg-type]
        self.assertFalse(self.scan.scan_dir.exists())

    def test_atomic_write_rejects_outside_scan_directory(self):
        self.scan.create()
        escape = self.scan.scan_dir / ".." / "evil.json"
        with self.assertRaises(state_mod.ScanStateError):
            state_mod.atomic_write_json(escape, {"x": 1}, scan_dir=self.scan.scan_dir)
        self.assertFalse((self.scan.scan_dir.parent / "evil.json").exists())

    def test_atomic_write_rejects_sibling_directory(self):
        self.scan.create()
        sibling = self.scan.scan_dir.parent / "other" / "state.json"
        with self.assertRaises(state_mod.ScanStateError):
            state_mod.atomic_write_json(sibling, {"x": 1}, scan_dir=self.scan.scan_dir)

    def test_atomic_write_to_explicit_valid_path(self):
        self.scan.create()
        target = self.scan.scan_dir / "custom.json"
        written = state_mod.atomic_write_json(target, {"x": 1}, scan_dir=self.scan.scan_dir)
        self.assertEqual(written, target)
        self.assertEqual(state_mod.read_json_object(target), {"x": 1})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
