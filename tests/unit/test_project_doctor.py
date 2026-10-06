"""Focused tests for the offline, read-only project doctor."""

from __future__ import annotations

import ast
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from red_teaming.cli import project_doctor


class ProjectDoctorTests(unittest.TestCase):
    def setUp(self):
        project_root = Path(__file__).resolve().parents[2]
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".project-doctor-test-", dir=project_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in project_doctor.REQUIRED_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        for relative in project_doctor.REQUIRED_DIRECTORIES:
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        for relative in project_doctor.CLI_WRAPPERS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        self.write_registry("""sample:\n  type: skill\n  status: available\n  path: skills/sample\n  description: Sample.\n""")
        skill = self.root / "skills" / "sample"
        skill.mkdir(parents=True)
        (skill / "run.py").touch()

    def write_registry(self, text: str) -> None:
        (self.root / "capabilities" / "registry.yaml").write_text(
            text, encoding="utf-8"
        )

    def blockers(self):
        return project_doctor.readiness_blockers(self.root, (3, 10))

    def test_success(self):
        self.assertEqual(self.blockers(), [])
        output = io.StringIO()
        with mock.patch.object(project_doctor, "readiness_blockers", return_value=[]):
            code = project_doctor.main([], stdout=output)
        self.assertEqual(code, 0)
        self.assertEqual(
            output.getvalue(),
            "code readiness: ready\n"
            "live execution authorization: not evaluated\n",
        )

    def test_missing_available_capability_path(self):
        (self.root / "skills" / "sample" / "run.py").unlink()
        (self.root / "skills" / "sample").rmdir()
        self.assertIn("available capability 'sample' directory is missing", self.blockers())

    def test_malformed_registry_and_entry(self):
        self.write_registry("not-a-mapping\n")
        self.assertTrue(self.blockers()[-1].startswith("invalid capability registry:"))
        self.write_registry("sample:\n  type: skill\n  status: broken\n")
        blockers = self.blockers()
        self.assertIn("registry entry 'sample' missing fields: path, description", blockers)
        self.write_registry("""sample:\n  type: skill\n  status: broken\n  path: skills/sample\n  description: Sample.\n""")
        self.assertIn("registry entry 'sample' has invalid status: broken", self.blockers())

    def test_available_path_escape(self):
        self.write_registry("""sample:\n  type: skill\n  status: available\n  path: ../outside\n  description: Sample.\n""")
        self.assertIn("available capability 'sample' path escapes project root", self.blockers())

    def test_missing_marker_and_wrapper(self):
        (self.root / "PROJECT.md").unlink()
        (self.root / "scripts" / "scan_target.py").unlink()
        blockers = self.blockers()
        self.assertIn("missing required file: PROJECT.md", blockers)
        self.assertIn("missing CLI wrapper: scripts/scan_target.py", blockers)

    def test_module_has_no_write_network_or_subprocess_imports(self):
        source = Path(project_doctor.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertTrue(imports.isdisjoint({"socket", "subprocess", "urllib", "http"}))
        self.assertNotIn("write_text", source)
        self.assertNotIn("write_bytes", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
