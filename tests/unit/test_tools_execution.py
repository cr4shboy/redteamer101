"""Unit tests for shared bounded subprocess execution.

All execution is faked: no real process is launched and no network is touched.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.models import MAX_TOOL_OUTPUT_CHARS, ToolRunStatus
from red_teaming.tools import execution
from tests.unit.tool_fakes import FakeRunner, completed


class WorkDirTests(unittest.TestCase):
    def test_requires_absolute_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(execution.require_work_dir(tmp), Path(tmp))
        with self.assertRaises(execution.ExecutionError):
            execution.require_work_dir("relative/dir")
        with self.assertRaises(execution.ExecutionError):
            execution.require_work_dir(str(Path(tempfile.gettempdir()) / "does-not-exist-xyz"))


class SanitizedEnvTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_keeps_allowlisted_and_drops_secrets_and_proxies(self):
        base = {
            "PATH": "/usr/bin",
            "HTTPS_PROXY": "http://proxy.example",
            "HTTP_PROXY": "http://proxy.example",
            "API_TOKEN": "tok",
            "SECRET_KEY": "sek",
            "AWS_ACCESS_KEY_ID": "aws",
            "RANDOM_VAR": "nope",
        }
        env = execution.build_sanitized_env(self.work, base_env=base)
        self.assertEqual(env["PATH"], "/usr/bin")
        for forbidden in [
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "API_TOKEN",
            "SECRET_KEY",
            "AWS_ACCESS_KEY_ID",
            "RANDOM_VAR",
        ]:
            self.assertNotIn(forbidden, env)
        self.assertFalse(any("proxy" in name.lower() for name in env))

    def test_redirects_home_and_config_roots(self):
        base = {"HOME": "/home/user", "USERPROFILE": "C:\\Users\\user", "XDG_CONFIG_HOME": "/x"}
        env = execution.build_sanitized_env(self.work, base_env=base)
        self.assertEqual(env["HOME"], str(self.work))
        self.assertEqual(env["USERPROFILE"], str(self.work))
        self.assertEqual(env["XDG_CONFIG_HOME"], str(self.work / "config"))

    def test_requires_absolute_existing_work_dir(self):
        with self.assertRaises(execution.ExecutionError):
            execution.build_sanitized_env("relative")


class ResolveExecutableTests(unittest.TestCase):
    def test_uses_injected_which(self):
        target = str(Path(tempfile.gettempdir()) / "subfinder")
        self.assertEqual(
            execution.resolve_executable("subfinder", which=lambda name: target),
            target,
        )

    def test_missing_returns_none(self):
        self.assertIsNone(execution.resolve_executable("subfinder", which=lambda name: None))

    def test_rejects_relative_path_input(self):
        with self.assertRaises(execution.ExecutionError):
            execution.resolve_executable("bin/subfinder", which=lambda name: None)

    def test_absolute_missing_path_returns_none(self):
        path = str(Path(tempfile.gettempdir()) / "nope-xyz.exe")
        self.assertIsNone(execution.resolve_executable(path, which=lambda name: None))


class BoundTextTests(unittest.TestCase):
    def test_truncates_and_flags(self):
        text, truncated = execution.bound_text("x" * (MAX_TOOL_OUTPUT_CHARS + 5))
        self.assertEqual(len(text), MAX_TOOL_OUTPUT_CHARS)
        self.assertTrue(truncated)

    def test_short_text_not_truncated(self):
        self.assertEqual(execution.bound_text("hello"), ("hello", False))
        self.assertEqual(execution.bound_text(None), ("", False))


class ParseVersionTests(unittest.TestCase):
    def test_extracts_first_version_like_token(self):
        self.assertEqual(execution.parse_version_text("subfinder version v2.6.3"), "2.6.3")
        self.assertEqual(execution.parse_version_text(None, "amass 4.2.0"), "4.2.0")

    def test_none_when_absent(self):
        self.assertIsNone(execution.parse_version_text("no version here"))


class RunProcessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.env = execution.build_sanitized_env(self.work)

    def tearDown(self):
        self._tmp.cleanup()

    def test_success_records_argv_and_flags(self):
        runner = FakeRunner([(lambda a: True, lambda a: completed(a, stdout="out", stderr="err"))])
        outcome = execution.run_process(
            ("tool.exe", "-x"), env=self.env, cwd=self.work, runner=runner
        )
        self.assertEqual(outcome.argv, ("tool.exe", "-x"))
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(outcome.stdout, "out")
        self.assertTrue(outcome.ok)
        argv, kwargs = runner.calls[0]
        self.assertFalse(kwargs["shell"])
        self.assertFalse(kwargs["check"])
        self.assertEqual(argv, ("tool.exe", "-x"))

    def test_timeout_is_structured(self):
        runner = FakeRunner(
            [(lambda a: True, lambda a: subprocess.TimeoutExpired(a, 1.0))]
        )
        outcome = execution.run_process(("tool.exe",), env=self.env, runner=runner)
        self.assertTrue(outcome.timed_out)
        self.assertIsNone(outcome.returncode)
        self.assertEqual(execution.status_for_outcome(outcome), ToolRunStatus.TIMEOUT)

    def test_oserror_is_structured(self):
        runner = FakeRunner([(lambda a: True, lambda a: FileNotFoundError("boom"))])
        outcome = execution.run_process(("tool.exe",), env=self.env, runner=runner)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.error, "FileNotFoundError")
        self.assertEqual(execution.status_for_outcome(outcome), ToolRunStatus.TOOL_FAILED)

    def test_nonzero_exit_is_tool_failed(self):
        runner = FakeRunner([(lambda a: True, lambda a: completed(a, code=2, stderr="bad"))])
        outcome = execution.run_process(("tool.exe",), env=self.env, runner=runner)
        self.assertEqual(execution.status_for_outcome(outcome), ToolRunStatus.TOOL_FAILED)

    def test_bounded_output_and_truncation_marker(self):
        huge = "x" * (MAX_TOOL_OUTPUT_CHARS + 100)
        runner = FakeRunner([(lambda a: True, lambda a: completed(a, stdout=huge))])
        outcome = execution.run_process(("tool.exe",), env=self.env, runner=runner)
        self.assertEqual(len(outcome.stdout), MAX_TOOL_OUTPUT_CHARS)
        self.assertTrue(outcome.stdout_truncated)
        self.assertFalse(outcome.stderr_truncated)

    def test_stdin_text_is_passed_through(self):
        runner = FakeRunner([(lambda a: True, lambda a: completed(a))])
        execution.run_process(
            ("tool.exe",), env=self.env, runner=runner, stdin_text="a.example\n"
        )
        self.assertEqual(runner.calls[0][1]["input"], "a.example\n")

    def test_rejects_string_argv(self):
        with self.assertRaises(execution.ExecutionError):
            execution.run_process("tool.exe", env=self.env)

    def test_rejects_bad_timeout(self):
        with self.assertRaises(execution.ExecutionError):
            execution.run_process(("tool.exe",), env=self.env, timeout=0)

    def test_parser_capture_separate_from_retained_evidence(self):
        payload = "x" * 150
        runner = FakeRunner([(lambda a: True, lambda a: completed(a, stdout=payload))])
        outcome = execution.run_process(
            ("tool.exe",), env=self.env, runner=runner, parse_max=100
        )
        self.assertEqual(outcome.parse_stdout, "x" * 100)
        self.assertTrue(outcome.parse_truncated)
        self.assertEqual(outcome.parser_text, "x" * 100)
        # Retained evidence cap is independent (default 4096).
        self.assertEqual(outcome.stdout, payload)
        self.assertFalse(outcome.stdout_truncated)

    def test_small_output_is_not_parse_truncated(self):
        payload = "y" * 50
        runner = FakeRunner([(lambda a: True, lambda a: completed(a, stdout=payload))])
        outcome = execution.run_process(
            ("tool.exe",), env=self.env, runner=runner, parse_max=100
        )
        self.assertEqual(outcome.parse_stdout, payload)
        self.assertFalse(outcome.parse_truncated)

    def test_to_dict_excludes_parser_payload(self):
        runner = FakeRunner([(lambda a: True, lambda a: completed(a, stdout="hello"))])
        outcome = execution.run_process(("tool.exe",), env=self.env, runner=runner)
        dumped = outcome.to_dict()
        self.assertNotIn("parse_stdout", dumped)
        self.assertNotIn("parse_truncated", dumped)
        self.assertEqual(outcome.parse_stdout, "hello")

    def test_outcome_to_dict(self):
        outcome = execution.ProcessOutcome(
            argv=("tool.exe",), executable="tool.exe", returncode=0,
            stdout="o", stderr="e", stdout_truncated=False, stderr_truncated=False,
        )
        self.assertEqual(outcome.to_dict()["argv"], ["tool.exe"])
        self.assertEqual(outcome.to_dict()["returncode"], 0)
        self.assertEqual(
            execution.status_for_outcome(outcome), ToolRunStatus.SUCCEEDED
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
