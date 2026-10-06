"""Unit tests for deterministic scan path resolution and scan IDs."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from red_teaming.projects import paths as pathlib
from red_teaming.projects.models import ProjectDomain, Target, ValidationError


class ScanIdTests(unittest.TestCase):
    def test_deterministic_with_injected_values(self):
        now = datetime(2026, 10, 2, 12, 34, 56, tzinfo=timezone.utc)
        self.assertEqual(
            pathlib.generate_scan_id(now=now, suffix="abc123"),
            "20261002T123456Z-abc123",
        )

    def test_ids_are_sortable_by_time(self):
        first = pathlib.generate_scan_id(
            now=datetime(2026, 1, 1, tzinfo=timezone.utc), suffix="aaaaaa"
        )
        second = pathlib.generate_scan_id(
            now=datetime(2026, 1, 2, tzinfo=timezone.utc), suffix="aaaaaa"
        )
        self.assertLess(first, second)

    def test_random_suffix_format(self):
        scan_id = pathlib.generate_scan_id(now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertRegex(scan_id, r"^\d{8}T\d{6}Z-[0-9a-f]+$")

    def test_rejects_bad_suffix(self):
        with self.assertRaises(ValidationError):
            pathlib.generate_scan_id(suffix="XYZ")

    def test_rejects_naive_timestamp(self):
        with self.assertRaises(ValidationError):
            pathlib.generate_scan_id(now=datetime(2026, 1, 1), suffix="aaaaaa")


class ScanPathTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.domain = ProjectDomain.parse("example.com")
        self.target = Target.parse("https://app.example.com/App", self.domain)
        self.now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
        self.scan_id = "20261002T120000Z-abc123"

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, **overrides):
        overrides.setdefault("now", self.now)
        overrides.setdefault("suffix", "abc123")
        return pathlib.ScanPath.build(
            self.root, self.domain, self.target, **overrides
        )

    def test_layout_is_deterministic(self):
        scan = self.build()
        expected = (
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "app.example.com"
            / "scans"
            / "zap"
            / self.scan_id
        )
        self.assertEqual(scan.scan_id, self.scan_id)
        self.assertEqual(scan.scan_dir, expected)
        self.assertEqual(scan.project_dir, self.root / "projects" / "example.com")
        self.assertEqual(scan.target_dir, scan.targets_dir / "app.example.com")
        self.assertEqual(scan.zap_dir, scan.scans_dir / "zap")

    def test_containment_chain(self):
        scan = self.build()
        self.assertTrue(pathlib.is_within(scan.project_dir, self.root))
        self.assertTrue(pathlib.is_within(scan.targets_dir, scan.project_dir))
        self.assertTrue(pathlib.is_within(scan.target_dir, scan.targets_dir))
        self.assertTrue(pathlib.is_within(scan.scans_dir, scan.target_dir))
        self.assertTrue(pathlib.is_within(scan.zap_dir, scan.scans_dir))
        self.assertTrue(pathlib.is_within(scan.scan_dir, scan.zap_dir))
        self.assertTrue(
            pathlib.is_within(scan.scan_dir, self.root / "projects" / "example.com")
        )

    def test_build_does_not_create_directories(self):
        scan = self.build()
        self.assertFalse(scan.project_dir.exists())
        self.assertFalse(scan.zap_dir.exists())
        self.assertFalse(scan.scan_dir.exists())

    def test_create_is_explicit_and_idempotent(self):
        scan = self.build()
        self.assertFalse(scan.scan_dir.exists())
        created = scan.create()
        self.assertEqual(created, scan.scan_dir)
        self.assertTrue(scan.scan_dir.is_dir())
        self.assertEqual(scan.create(), scan.scan_dir)

    def test_requires_absolute_root(self):
        with self.assertRaises(ValidationError):
            pathlib.ScanPath.build(
                "relative/root",
                self.domain,
                self.target,
                now=self.now,
                suffix="abc123",
            )

    def test_rejects_target_outside_domain(self):
        with self.assertRaises(ValidationError):
            pathlib.ScanPath.build(
                self.root, self.domain, "other.example", now=self.now, suffix="abc123"
            )

    def test_accepts_root_domain_target(self):
        scan = pathlib.ScanPath.build(
            self.root, self.domain, "example.com", now=self.now, suffix="abc123"
        )
        self.assertEqual(scan.target, "example.com")
        self.assertEqual(
            scan.scan_dir,
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "example.com"
            / "scans"
            / "zap"
            / self.scan_id,
        )

    def test_is_within_rejects_siblings_and_parents(self):
        base = self.root / "projects" / "example.com"
        self.assertTrue(pathlib.is_within(base, base))
        self.assertFalse(pathlib.is_within(self.root / "projects" / "example.org", base))
        self.assertFalse(pathlib.is_within(self.root, base))

    def test_state_file_path_is_bounded(self):
        scan = self.build()
        self.assertEqual(scan.state_file_path(), scan.scan_dir / "scan.json")
        for bad in ["../evil.json", "..\\evil.json", "/abs/evil.json", "sub/state.json", "..", "."]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    scan.state_file_path(bad)

    def test_deterministic_scan_id_injection(self):
        scan = self.build()
        self.assertEqual(scan.scan_id, self.scan_id)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
