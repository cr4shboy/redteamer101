"""Unit tests for immutable per-domain recon run path resolution."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from red_teaming.projects import paths as project_paths
from red_teaming.projects.models import ProjectDomain, ValidationError
from red_teaming.recon.paths import (
    RECON_DIRNAME,
    ReconPath,
    ReconPathError,
    recon_dir,
    recon_run_dir,
    validate_run_id,
)


class ReconPathTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.now = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
        self.run_id = "20261003T120000Z-abc123"

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, root="example.com", **overrides):
        overrides.setdefault("now", self.now)
        overrides.setdefault("suffix", "abc123")
        return ReconPath.build(self.root, root, **overrides)

    def test_deterministic_layout(self):
        recon = self.build()
        expected = self.root / "projects" / "example.com" / "recon" / self.run_id
        self.assertEqual(recon.run_id, self.run_id)
        self.assertEqual(recon.run_dir, expected)
        self.assertEqual(recon.project_dir, self.root / "projects" / "example.com")
        self.assertEqual(recon.recon_dir, recon.project_dir / RECON_DIRNAME)

    def test_build_has_no_side_effects(self):
        recon = self.build()
        self.assertFalse(recon.project_dir.exists())
        self.assertFalse(recon.recon_dir.exists())
        self.assertFalse(recon.run_dir.exists())

    def test_explicit_create_then_immutable(self):
        recon = self.build()
        created = recon.create()
        self.assertEqual(created, recon.run_dir)
        self.assertTrue(recon.run_dir.is_dir())
        with self.assertRaises(ReconPathError):
            recon.create()

    def test_create_rejects_preexisting_directory(self):
        recon = self.build()
        recon.run_dir.mkdir(parents=True)
        with self.assertRaises(ReconPathError):
            recon.create()

    def test_requires_absolute_root(self):
        with self.assertRaises(ValidationError):
            ReconPath.build("relative/root", "example.com", self.run_id)

    def test_invalid_run_id_rejected(self):
        for bad in [
            "",
            "not-a-run-id",
            "2026-10-03",
            "../evil",
            "20261003T120000Z-ABC",
            "20261003-120000Z-abc123",
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    ReconPath.build(self.root, "example.com", bad)

    def test_generated_run_id_matches_format(self):
        recon = ReconPath.build(self.root, "example.com", now=self.now, suffix="abc123")
        self.assertEqual(recon.run_id, self.run_id)

    def test_contains_and_containment_chain(self):
        recon = self.build()
        self.assertTrue(project_paths.is_within(recon.project_dir, self.root))
        self.assertTrue(project_paths.is_within(recon.recon_dir, recon.project_dir))
        self.assertTrue(project_paths.is_within(recon.run_dir, recon.recon_dir))
        self.assertTrue(recon.contains(recon.run_dir / "scope.json"))
        self.assertFalse(recon.contains(self.root / "outside.json"))

    def test_file_path_rejects_unsafe_names(self):
        recon = self.build()
        for bad in [
            "../evil.json",
            "..\\evil.json",
            "/abs/evil.json",
            "sub/state.json",
            "..",
            ".",
            "x:y.json",
            "",
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(ReconPathError):
                    recon.file_path(bad)

    def test_file_path_default_and_alias(self):
        recon = self.build()
        self.assertEqual(recon.file_path(), recon.run_dir / "recon.json")
        self.assertEqual(
            recon.state_file_path("state.json"), recon.run_dir / "state.json"
        )

    def test_module_helpers_match(self):
        recon = self.build()
        self.assertEqual(recon_dir(self.root, "example.com"), recon.recon_dir)
        self.assertEqual(
            recon_run_dir(self.root, "example.com", self.run_id), recon.run_dir
        )

    def test_validate_run_id_accepts_generated(self):
        self.assertEqual(validate_run_id(self.run_id), self.run_id)

    def test_root_normalized_via_canonical(self):
        recon = ReconPath.build(
            self.root, ProjectDomain.parse("Example.COM."), self.run_id
        )
        self.assertEqual(recon.root, "example.com")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
