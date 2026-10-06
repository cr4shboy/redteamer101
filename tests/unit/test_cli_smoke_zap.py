"""Offline tests for the local-only ZAP daemon smoke CLI.

No process is started, no socket is opened, and no target is contacted: the
runner is faked for every actual-run test.
"""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from red_teaming.cli.smoke_zap import (
    EXIT_OK,
    EXIT_RUNTIME,
    EXIT_VALIDATION,
    build_parser,
    main,
)

SCAN_ID = "20261003T120000Z-abc123"
PROJECT_MARKERS = ("AGENTS.md", "PROJECT.md", "CURRENT_TASK.md")

_INJECT = object()


def make_checkout_root(root):
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
            / "acme.example"
            / "targets"
            / "acme.example"
            / "scans"
            / "zap"
            / self.scan_id
        )
        self.exe = self.root / "ZAP.exe"
        self.exe.write_bytes(b"MZ fake")

    def tearDown(self):
        self._tmp.cleanup()

    def args(self, output_dir=None, *, validate_only=False, confirm=False,
             workspace_root=None, zap_executable=None, extra=()):
        argv = [
            "--workspace-root",
            str(workspace_root if workspace_root is not None else self.root),
            "--output-dir",
            str(output_dir if output_dir is not None else self.output_dir),
            "--zap-executable",
            str(zap_executable if zap_executable is not None else self.exe),
            "--project",
            "acme.example",
        ]
        if validate_only:
            argv.append("--validate-only")
        if confirm:
            argv.append("--confirm-local-smoke")
        argv.extend(extra)
        return argv

    def run_main(self, argv, *, expected_root=_INJECT, **kwargs):
        if expected_root is _INJECT:
            expected_root = self.root
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(
                argv, stdout=out, stderr=err, expected_root=expected_root, **kwargs
            )
        return code, out.getvalue(), err.getvalue()


class ParserTests(CliTestCase):
    def test_defaults(self):
        args = build_parser().parse_args(self.args())
        self.assertEqual(args.zap_host, "127.0.0.1")
        self.assertEqual(args.zap_port, 18080)
        self.assertEqual(args.guard_host, "127.0.0.1")
        self.assertEqual(args.guard_port, 1)
        self.assertEqual(args.expected_version, "2.17.0")
        self.assertFalse(args.validate_only)
        self.assertFalse(args.confirm_local_smoke)

    def test_no_target_or_scan_options_exist(self):
        parser = build_parser()
        option_strings = set()
        for action in parser._actions:
            option_strings.update(action.option_strings)
        self.assertNotIn("--target", option_strings)
        self.assertNotIn("--url", option_strings)
        self.assertNotIn("--mode", option_strings)

    def test_target_option_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(self.args(extra=("--target", "https://x/")))
        self.assertEqual(ctx.exception.code, 2)


class ValidateOnlyTests(CliTestCase):
    def test_validate_only_is_side_effect_free(self):
        calls = []

        def explode(plan):
            calls.append(plan)
            raise AssertionError("runner must not be constructed")

        code, out, err = self.run_main(
            self.args(validate_only=True), runner_factory=explode
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("scan-id: " + self.scan_id, out)
        self.assertIn("target: none (local tool-health smoke)", out)
        self.assertIn("authorization: not run (validate-only)", out)
        self.assertEqual(calls, [])
        self.assertFalse(self.output_dir.exists())

    def test_validate_only_rejects_missing_executable(self):
        missing = self.root / "nope.exe"
        code, _, err = self.run_main(
            self.args(validate_only=True, zap_executable=missing)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--zap-executable", err)


class AuthorizationTests(CliTestCase):
    def test_actual_run_without_confirm_is_refused(self):
        calls = []

        def record(plan):
            calls.append(plan)
            return object()

        code, _, err = self.run_main(
            self.args(confirm=False), runner_factory=record
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--confirm-local-smoke", err)
        self.assertEqual(calls, [])
        self.assertFalse(self.output_dir.exists())


class LayoutValidationTests(CliTestCase):
    def test_non_127_host_is_rejected(self):
        code, _, err = self.run_main(
            self.args(validate_only=True, extra=("--zap-host", "localhost"))
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("127.0.0.1", err)

    def test_mismatched_domain_layout_is_rejected(self):
        bad = (
            self.root
            / "projects"
            / "other.lt"
            / "targets"
            / "other.lt"
            / "scans"
            / "zap"
            / self.scan_id
        )
        code, _, err = self.run_main(self.args(bad, validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("canonical", err)
        self.assertFalse(bad.exists())

    def test_relative_output_dir_is_rejected(self):
        code, _, err = self.run_main(
            self.args(Path("relative") / self.scan_id, validate_only=True)
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("absolute", err)

    def test_existing_output_dir_is_refused(self):
        self.output_dir.mkdir(parents=True)
        code, _, err = self.run_main(self.args(validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("already exists", err)

    def test_invalid_scan_id_is_rejected(self):
        bad = (
            self.root
            / "projects"
            / "acme.example"
            / "targets"
            / "acme.example"
            / "scans"
            / "zap"
            / "not-a-scan-id"
        )
        code, _, err = self.run_main(self.args(bad, validate_only=True))
        self.assertEqual(code, EXIT_VALIDATION)

    def test_invalid_timeout_is_rejected(self):
        code, _, err = self.run_main(
            self.args(validate_only=True, extra=("--startup-timeout", "0"))
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--startup-timeout", err)


class CompositionTests(CliTestCase):
    def test_actual_run_returns_ok_on_success(self):
        captured = {}

        class FakeRunner:
            def __init__(self, plan):
                captured["plan"] = plan

            def run(self):
                return {"status": "succeeded", "observed_version": "2.17.0"}

        code, out, err = self.run_main(
            self.args(confirm=True), runner_factory=FakeRunner
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("status: succeeded", out)
        self.assertEqual(captured["plan"].bind_host, "127.0.0.1")
        self.assertEqual(captured["plan"].bind_port, 18080)

    def test_actual_run_returns_runtime_on_failure(self):
        class FakeRunner:
            def run(self):
                return {"status": "failed", "observed_version": None}

        code, _, err = self.run_main(
            self.args(confirm=True), runner_factory=lambda plan: FakeRunner()
        )
        self.assertEqual(code, EXIT_RUNTIME)
        self.assertIn("acceptance", err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
