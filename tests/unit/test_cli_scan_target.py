"""Offline tests for the thin scan-target CLI composition.

No process is started, no socket is opened, and no target is called: the
client/manager/scanner factories are faked for every actual-run test.
"""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from red_teaming.tools.zap.models import ZapError
from red_teaming.cli.scan_target import (
    EXIT_OK,
    EXIT_RUNTIME,
    EXIT_VALIDATION,
    build_parser,
    main,
)

SCAN_ID = "20261002T120000Z-abc123"
PROJECT_MARKERS = ("AGENTS.md", "PROJECT.md", "CURRENT_TASK.md")

_INJECT = object()


def make_checkout_root(root):
    """Populate *root* with the markers required of a valid workspace checkout."""

    for marker in PROJECT_MARKERS:
        (root / marker).write_text("marker\n", encoding="utf-8")
    (root / "projects").mkdir()
    return root


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_checkout_root(Path(self._tmp.name))
        self.scan_id = SCAN_ID
        self.output_dir = (
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "app.example.com"
            / "scans"
            / "zap"
            / self.scan_id
        )
        # A harmless, empty regular file standing in for the ZAP executable.
        self.exe = self.root / "zap.exe"
        self.exe.write_bytes(b"")

    def tearDown(self):
        self._tmp.cleanup()

    def args(self, output_dir=None, *, mode="spider", validate_only=False, confirm=False,
             workspace_root=None, zap_executable=None, extra=()):
        argv = [
            "--workspace-root", str(workspace_root if workspace_root is not None else self.root),
            "--output-dir", str(output_dir if output_dir is not None else self.output_dir),
            "--zap-executable", str(zap_executable if zap_executable is not None else self.exe),
            "--project", "example.com",
            "--target", "https://app.example.com/App",
            "--mode", mode,
        ]
        if validate_only:
            argv.append("--validate-only")
        if confirm:
            argv.append("--confirm-authorized")
        argv.extend(extra)
        return argv

    def run_main(self, argv, *, expected_root=_INJECT, **kwargs):
        if expected_root is _INJECT:
            expected_root = self.root
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(
                argv,
                stdout=out,
                stderr=err,
                expected_root=expected_root,
                **kwargs,
            )
        return code, out.getvalue(), err.getvalue()


class ParserTests(CliTestCase):
    def test_required_options_and_defaults(self):
        parser = build_parser()
        args = parser.parse_args(self.args())
        self.assertEqual(args.mode, "spider")
        self.assertEqual(args.zap_host, "127.0.0.1")
        self.assertEqual(args.zap_port, 8080)
        self.assertEqual(args.request_timeout, 10.0)
        self.assertEqual(args.poll_interval, 0.25)
        self.assertFalse(args.validate_only)
        self.assertFalse(args.confirm_authorized)

    def test_bad_mode_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(self.args(mode="active"))
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_required_option_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args([])
        self.assertEqual(ctx.exception.code, 2)


class ValidateOnlyTests(CliTestCase):
    def test_validate_only_is_side_effect_free(self):
        calls = []

        def explode(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("factory must not be called during validate-only")

        code, out, err = self.run_main(
            self.args(validate_only=True),
            client_factory=explode,
            manager_factory=explode,
            scanner_factory=explode,
            key_factory=explode,
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("scan-id: " + self.scan_id, out)
        self.assertIn("authorization: not run (validate-only)", out)
        self.assertIn("API key: not generated", out)
        self.assertEqual(calls, [])
        self.assertFalse(self.output_dir.exists())
        self.assertFalse((self.root / "projects" / "example.com").exists())

    def test_validate_only_accepts_existing_empty_executable(self):
        code, out, _ = self.run_main(self.args(validate_only=True))
        self.assertEqual(code, EXIT_OK)
        self.assertIn(str(self.exe), out)

    def test_validate_only_rejects_missing_executable(self):
        missing = self.root / "no-zap.exe"
        code, out, err = self.run_main(
            self.args(validate_only=True, zap_executable=missing)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--zap-executable", err)
        self.assertIn("regular file", err)
        self.assertEqual(out, "")

    def test_validate_only_rejects_directory_executable(self):
        directory = self.root / "zap-dir"
        directory.mkdir()
        code, _, err = self.run_main(
            self.args(validate_only=True, zap_executable=directory)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("regular file", err)


class AuthorizationTests(CliTestCase):
    def test_actual_run_without_confirm_is_refused(self):
        calls = []

        def record(*args, **kwargs):
            calls.append((args, kwargs))
            return object()

        code, out, err = self.run_main(
            self.args(confirm=False),
            client_factory=record,
            manager_factory=record,
            scanner_factory=record,
            key_factory=lambda: "unused",
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--confirm-authorized", err)
        self.assertIn("does not itself confer legal authorization", err)
        self.assertEqual(calls, [])
        self.assertFalse(self.output_dir.exists())


class WorkspaceRootTests(CliTestCase):
    def _other_checkout(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def test_workspace_root_must_match_expected_checkout(self):
        other = make_checkout_root(self._other_checkout())
        code, _, err = self.run_main(
            self.args(workspace_root=other, validate_only=True)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("must resolve to this project checkout", err)

    def test_default_expected_root_is_the_source_checkout(self):
        # No injection: the production default must reject an unrelated root.
        code, _, err = self.run_main(
            self.args(validate_only=True), expected_root=None
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("must resolve to this project checkout", err)

    def test_missing_root_marker_is_rejected(self):
        other = self._other_checkout()
        for marker in ("PROJECT.md", "CURRENT_TASK.md"):
            (other / marker).write_text("marker\n", encoding="utf-8")
        (other / "projects").mkdir()
        code, _, err = self.run_main(
            self.args(workspace_root=other, validate_only=True),
            expected_root=other,
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("missing required AGENTS.md", err)

    def test_missing_projects_directory_is_rejected(self):
        other = self._other_checkout()
        for marker in PROJECT_MARKERS:
            (other / marker).write_text("marker\n", encoding="utf-8")
        code, _, err = self.run_main(
            self.args(workspace_root=other, validate_only=True),
            expected_root=other,
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("projects/", err)

    def test_symlinked_parent_escape_is_rejected_when_supported(self):
        outside = self._other_checkout()
        zap_parent = (
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "app.example.com"
            / "scans"
        )
        zap_parent.mkdir(parents=True)
        link = zap_parent / "zap"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"platform cannot create directory symlinks: {exc}")
        code, _, err = self.run_main(self.args(validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("symlink/junction escape", err)


class LayoutValidationTests(CliTestCase):
    def test_mismatched_host_layout_is_rejected(self):
        bad = (
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "other.example.com"
            / "scans"
            / "zap"
            / self.scan_id
        )
        code, _, err = self.run_main(self.args(bad, validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("canonical", err)
        self.assertFalse(bad.exists())

    def test_mismatched_tool_layout_is_rejected(self):
        bad = (
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "app.example.com"
            / "scans"
            / "othertool"
            / self.scan_id
        )
        code, _, err = self.run_main(self.args(bad, validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("canonical", err)

    def test_output_dir_outside_workspace_is_rejected(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        outside = (
            Path(other.name)
            / "projects"
            / "example.com"
            / "targets"
            / "app.example.com"
            / "scans"
            / "zap"
            / self.scan_id
        )
        code, _, err = self.run_main(self.args(outside, validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("canonical", err)
        self.assertFalse(outside.exists())

    def test_invalid_scan_id_is_rejected(self):
        bad = (
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "app.example.com"
            / "scans"
            / "zap"
            / "not-a-scan-id"
        )
        code, _, err = self.run_main(self.args(bad, validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)

    def test_existing_output_dir_is_refused(self):
        self.output_dir.mkdir(parents=True)
        code, _, err = self.run_main(self.args(validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("already exists", err)

    def test_relative_output_dir_is_rejected(self):
        code, _, err = self.run_main(
            self.args(Path("relative") / self.scan_id, validate_only=True)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("absolute", err)

    def test_relative_workspace_root_is_rejected(self):
        code, _, err = self.run_main(
            self.args(workspace_root="relative/root", validate_only=True)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("absolute", err)

    def test_relative_executable_is_rejected(self):
        code, _, err = self.run_main(
            self.args(zap_executable="zap.exe", validate_only=True)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--zap-executable", err)

    def test_invalid_timeout_is_rejected(self):
        code, _, err = self.run_main(
            self.args(validate_only=True, extra=("--spider-timeout", "0"))
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--spider-timeout", err)


class CompositionTests(CliTestCase):
    def _fakes(self, records, *, scanner_error=None):
        def client_factory(endpoint, api_key, *, timeout):
            client = {"kind": "client"}
            records["client"] = {
                "endpoint": endpoint,
                "api_key": api_key,
                "timeout": timeout,
                "obj": client,
            }
            return client

        def manager_factory(**kwargs):
            manager = {"kind": "manager"}
            records["manager"] = {"kwargs": kwargs, "obj": manager}
            return manager

        def scanner_factory(**kwargs):
            records["scanner"] = kwargs

            class FakeScanner:
                def run(self):
                    if scanner_error is not None:
                        raise scanner_error
                    records["ran"] = True

            return FakeScanner()

        return client_factory, manager_factory, scanner_factory

    def test_actual_run_composes_one_shared_client(self):
        records = {}
        factories = self._fakes(records)
        code, out, err = self.run_main(
            self.args(confirm=True),
            client_factory=factories[0],
            manager_factory=factories[1],
            scanner_factory=factories[2],
            key_factory=lambda: "ephemeralkey123",
        )
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(records.get("ran"))
        self.assertEqual(records["client"]["api_key"], "ephemeralkey123")
        client_obj = records["client"]["obj"]
        self.assertIs(records["manager"]["kwargs"]["client"], client_obj)
        self.assertIs(records["scanner"]["client"], client_obj)
        self.assertIs(records["scanner"]["manager"], records["manager"]["obj"])
        self.assertEqual(records["manager"]["kwargs"]["api_key"], "ephemeralkey123")
        self.assertNotIn("ephemeralkey123", out)
        self.assertNotIn("ephemeralkey123", err)

    def test_runtime_failure_is_sanitized(self):
        records = {}
        key = "leakykey123"
        factories = self._fakes(records, scanner_error=ZapError(f"boom {key}"))
        code, out, err = self.run_main(
            self.args(confirm=True),
            client_factory=factories[0],
            manager_factory=factories[1],
            scanner_factory=factories[2],
            key_factory=lambda: key,
        )
        self.assertEqual(code, EXIT_RUNTIME)
        self.assertNotIn(key, err)
        self.assertIn("***", err)
        self.assertNotIn(key, out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
