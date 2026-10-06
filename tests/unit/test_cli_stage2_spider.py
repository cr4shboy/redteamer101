"""Offline tests for the dedicated bounded Stage 2 Spider CLI.

No runner, process, socket, DNS, or target call occurs: the runner factory is
injected. The production path is keyless and guarded, so there is no key
generation, no key factory, and no capability override anywhere in the CLI.
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from red_teaming.cli.stage2_spider import (
    EXIT_OK,
    EXIT_RUNTIME,
    EXIT_VALIDATION,
    build_parser,
    main,
)
from red_teaming.tools.zap.bounded import STAGE2_DOMAIN, STAGE2_HOST
from red_teaming.tools.zap.models import ZapError

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
        self.addCleanup(self._tmp.cleanup)
        self.root = make_checkout_root(Path(self._tmp.name))
        self.output_dir = (
            self.root
            / "projects"
            / STAGE2_DOMAIN
            / "targets"
            / STAGE2_HOST
            / "scans"
            / "zap"
            / SCAN_ID
        )
        self.exe = self.root / "zap.exe"
        self.exe.write_bytes(b"")

    def args(self, *, validate_only=False, confirm=False, output_dir=None, extra=()):
        argv = [
            "--workspace-root", str(self.root),
            "--output-dir", str(output_dir if output_dir is not None else self.output_dir),
            "--zap-executable", str(self.exe),
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
        code = main(
            argv,
            stdout=out,
            stderr=err,
            expected_root=expected_root,
            **kwargs,
        )
        return code, out.getvalue(), err.getvalue()


class ParserTests(CliTestCase):
    def test_target_project_and_mode_are_not_options(self):
        parser = build_parser()
        for bad in (["--target", "https://x/"], ["--project", "x"], ["--mode", "ajax"]):
            with self.subTest(bad=bad):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        parser.parse_args(self.args() + bad)
                self.assertEqual(ctx.exception.code, 2)

    def test_no_option_can_bypass_guard_or_control_checks(self):
        parser = build_parser()
        for bad in (
            ["--capabilities", "proven"],
            ["--key-non-persistence-proven"],
            ["--redirect-egress-prevention-proven"],
            ["--api-key", "x"],
            ["--guard-host", "evil.test"],
            ["--skip-guard"],
            ["--access-url"],
        ):
            with self.subTest(bad=bad):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        parser.parse_args(self.args() + bad)
                self.assertEqual(ctx.exception.code, 2)

    def test_defaults(self):
        args = build_parser().parse_args(self.args())
        self.assertEqual(args.zap_host, "127.0.0.1")
        self.assertEqual(args.zap_port, 18080)
        self.assertEqual(args.spider_timeout, 300.0)
        self.assertFalse(args.validate_only)
        self.assertFalse(args.confirm_authorized)

    def test_main_accepts_no_key_factory(self):
        with self.assertRaises(TypeError):
            main(self.args(validate_only=True), key_factory=lambda: "x")


class ValidateOnlyTests(CliTestCase):
    def test_validate_only_is_side_effect_free(self):
        calls = []

        def explode(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("runner factory must not run in validate-only")

        code, out, err = self.run_main(
            self.args(validate_only=True), runner_factory=explode
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("acme.example", out)
        self.assertIn("https://acme.example/", out)
        self.assertIn("authorization: not run (validate-only)", out)
        self.assertIn("API authentication: keyless (no key generated)", out)
        self.assertEqual(calls, [])
        self.assertFalse(self.output_dir.exists())

    def test_non_loopback_endpoint_is_validation_error(self):
        code, out, err = self.run_main(
            self.args(validate_only=True, extra=("--zap-host", "10.0.0.9"))
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertEqual(out, "")

    def test_wrong_output_route_is_validation_error(self):
        bad = self.root / "projects" / "example.com" / SCAN_ID
        code, _, err = self.run_main(self.args(validate_only=True, output_dir=bad))
        self.assertEqual(code, EXIT_VALIDATION)


class AuthorizationTests(CliTestCase):
    def test_actual_run_without_confirm_is_refused(self):
        calls = []

        def record(*args, **kwargs):
            calls.append((args, kwargs))
            return object()

        code, out, err = self.run_main(
            self.args(confirm=False), runner_factory=record
        )
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertIn("--confirm-authorized", err)
        self.assertEqual(calls, [])
        self.assertFalse(self.output_dir.exists())


class CompositionTests(CliTestCase):
    class FakeRunner:
        def __init__(self, state=None, error=None):
            self.state = state or {"status": "succeeded", "preflight": {"blockers": []}}
            self.error = error

        def run(self):
            if self.error is not None:
                raise self.error
            return self.state

    def test_injected_runner_receives_profile_only(self):
        records = {}

        def runner_factory(**kwargs):
            records.update(kwargs)
            return self.FakeRunner()

        code, out, err = self.run_main(self.args(confirm=True), runner_factory=runner_factory)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(set(records), {"profile"})
        self.assertEqual(records["profile"].target.url, "https://acme.example/")
        self.assertIn("API authentication: keyless (no key generated)", out)
        self.assertIn("status: succeeded", out)

    def test_failed_state_returns_runtime_error_with_blockers(self):
        runner = self.FakeRunner(
            state={"status": "failed", "preflight": {"blockers": ["proxy_config_exact"]}}
        )
        code, out, _ = self.run_main(
            self.args(confirm=True), runner_factory=lambda **kwargs: runner
        )
        self.assertEqual(code, EXIT_RUNTIME)
        self.assertIn("proxy_config_exact", out)

    def test_runner_error_is_propagated(self):
        runner = self.FakeRunner(error=ZapError("guard preparation failed"))
        code, out, err = self.run_main(
            self.args(confirm=True), runner_factory=lambda **kwargs: runner
        )
        self.assertEqual(code, EXIT_RUNTIME)
        self.assertIn("guard preparation failed", err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
