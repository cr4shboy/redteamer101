"""Unit tests for the Amass parser and passive-only adapter (fully offline)."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.models import ObservationState, ToolRunStatus
from red_teaming.recon.scope import DomainScope
from red_teaming.tools.amass import (
    AmassAdapter,
    accepted_hosts,
    parse_output,
    supports_required_capabilities,
)
from red_teaming.tools.adapter_base import _failure_hint
from red_teaming.tools.execution import ExecutionError
from tests.unit.tool_fakes import FakeRunner, completed

HELP_OK = "Usage: amass enum -passive -d DOMAIN -oA PREFIX"
HELP_DOMAIN_ONLY = "Usage: amass enum -passive -domain DOMAIN -oA PREFIX"
HELP_NO_DOMAIN = "Usage: amass enum -passive -oA PREFIX"
HELP_NEAR_COLLISION = "Usage: amass enum -passive -debug DOMAIN -oA PREFIX"

FORBIDDEN_FLAGS = ("-active", "-brute", "-brute-force", "-rf", "-min-recursive", "-dns")


class AmassParserTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])

    def test_array_document(self):
        text = json.dumps(
            [
                {"name": "a.example.com", "sources": ["crtsh"]},
                {"name": "x.other.org"},
                {"name": "excluded.example.com"},
            ]
        )
        observations = parse_output(text, self.scope)
        by_host = {o.normalized: o for o in observations}
        self.assertEqual(by_host["a.example.com"].state, ObservationState.DISCOVERED)
        self.assertEqual(by_host["a.example.com"].source, "crtsh")
        self.assertEqual(by_host["x.other.org"].state, ObservationState.OUT_OF_SCOPE)
        self.assertEqual(
            by_host["excluded.example.com"].state, ObservationState.EXCLUDED
        )

    def test_single_object_document(self):
        observations = parse_output(json.dumps({"name": "www.example.com"}), self.scope)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].state, ObservationState.DISCOVERED)

    def test_json_lines_fallback(self):
        text = "\n".join(
            [json.dumps({"name": "a.example.com"}), json.dumps({"name": "b.example.com"})]
        )
        observations = parse_output(text, self.scope)
        self.assertEqual([o.normalized for o in observations], ["a.example.com", "b.example.com"])

    def test_duplicates_merge_sources(self):
        text = json.dumps(
            [
                {"name": "www.example.com", "sources": ["crtsh"]},
                {"name": "WWW.example.com", "sources": ["virustotal"]},
            ]
        )
        observations = parse_output(text, self.scope)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].source, "crtsh,virustotal")

    def test_malformed_records(self):
        observations = parse_output(
            json.dumps([{"other": 1}, {"name": 5}, "scalar", {"name": "bad host"}, 42]),
            self.scope,
        )
        reasons = {o.reason for o in observations}
        self.assertIn("missing_host", reasons)
        self.assertIn("invalid_host_type", reasons)
        self.assertIn("non_object", reasons)
        self.assertIn("malformed_host", reasons)

    def test_accepted_hosts_excludes_non_candidates(self):
        text = json.dumps([{"name": "a.example.com"}, {"name": "other.org"}])
        self.assertEqual(accepted_hosts(parse_output(text, self.scope)), ("a.example.com",))

    def test_capability_detection(self):
        self.assertTrue(supports_required_capabilities(HELP_OK))
        self.assertFalse(supports_required_capabilities("enum -d DOMAIN -oA PREFIX"))
        self.assertFalse(supports_required_capabilities("enum -passive -d DOMAIN"))
        self.assertFalse(supports_required_capabilities(None))


class AmassAdapterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])
        self.exe = self.work / "amass.exe"
        self.exe.write_text("fake\n", encoding="utf-8")
        self.payload = json.dumps([{"name": "a.example.com"}])

    def tearDown(self):
        self._tmp.cleanup()

    def runner(self, *, help_text=HELP_OK, main=None, version="amass v4.2.0"):
        main = main if main is not None else completed(["main"])
        return FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout=version)),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(a, stdout=help_text),
                ),
                (lambda a: True, lambda a: main),
            ]
        )

    def adapter(self, runner, **kwargs):
        return AmassAdapter(
            scope=self.scope,
            work_dir=self.work,
            executable=self.exe,
            runner=runner,
            output_reader=lambda path: self.payload,
            **kwargs,
        )

    def test_build_argv_is_passive_json_and_no_active_modes(self):
        adapter = self.adapter(self.runner())
        argv = adapter.build_argv(str(self.exe), domain_option="-d")
        self.assertEqual(
            argv,
            (
                str(self.exe),
                "enum",
                "-passive",
                "-d",
                "example.com",
                "-oA",
                str(self.work / "amass-enum"),
            ),
        )
        for flag in FORBIDDEN_FLAGS:
            self.assertNotIn(flag, argv)

    def test_build_argv_uses_selected_domain_option(self):
        adapter = self.adapter(self.runner())
        argv = adapter.build_argv(str(self.exe), domain_option="-domain")
        self.assertIn("-domain", argv)
        self.assertNotIn("-d", argv)
        self.assertEqual(argv[3], "-domain")

    def test_build_argv_rejects_unknown_domain_option(self):
        adapter = self.adapter(self.runner())
        with self.assertRaises(ExecutionError):
            adapter.build_argv(str(self.exe), domain_option="-nope")

    def test_success_end_to_end(self):
        runner = self.runner()
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.version, "4.2.0")
        self.assertEqual(
            [(o.state, o.normalized) for o in result.observations],
            [(ObservationState.DISCOVERED, "a.example.com")],
        )
        self.assertTrue(all(call[1]["shell"] is False for call in runner.calls))

    def test_missing_executable(self):
        runner = self.runner()
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, which=lambda name: None, runner=runner
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_NOT_AVAILABLE)
        self.assertEqual(runner.calls, [])

    def test_unsupported_capability_skips_enumeration(self):
        runner = self.runner(help_text="enum -d DOMAIN")
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.UNSUPPORTED)
        argv, _ = runner.calls[-1]
        self.assertIn("enum", argv)
        self.assertNotIn("-json", argv)

    def test_timeout_is_structured(self):
        runner = self.runner(main=subprocess.TimeoutExpired(["enum"], 1.0))
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.TIMEOUT)

    def main_call(self, runner):
        for argv, _ in runner.calls:
            if "-version" not in argv and "-help" not in argv:
                return argv
        raise AssertionError("no main invocation recorded")

    def test_run_uses_domain_option_advertised_by_help(self):
        runner = self.runner(help_text=HELP_DOMAIN_ONLY)
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        main_argv = self.main_call(runner)
        self.assertIn("-domain", main_argv)
        self.assertNotIn("-d", main_argv)

    def test_inspect_reports_selected_domain_option(self):
        inspection = self.adapter(self.runner()).inspect()
        self.assertTrue(inspection.supported)
        self.assertEqual(inspection.option("domain"), "-d")
        self.assertEqual(inspection.version, "4.2.0")
        self.assertIn("-passive", inspection.capabilities)

    def test_inspect_selects_domain_spelling(self):
        inspection = self.adapter(self.runner(help_text=HELP_DOMAIN_ONLY)).inspect()
        self.assertEqual(inspection.option("domain"), "-domain")

    def test_inspect_unsupported_when_domain_option_absent(self):
        inspection = self.adapter(self.runner(help_text=HELP_NO_DOMAIN)).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.UNSUPPORTED)

    def test_inspect_unsupported_on_near_collision(self):
        inspection = self.adapter(self.runner(help_text=HELP_NEAR_COLLISION)).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.UNSUPPORTED)

    def test_inspect_unsupported_reason_lists_only_missing_tokens(self):
        # -passive and -d are advertised, -oA is not.
        inspection = self.adapter(
            self.runner(help_text="enum -passive -d DOMAIN")
        ).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.UNSUPPORTED)
        self.assertEqual(
            inspection.reason, "amass enum help did not advertise: -oA"
        )

    def test_inspect_missing_executable(self):
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, which=lambda name: None,
            runner=self.runner(),
        )
        inspection = adapter.inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_NOT_AVAILABLE)
        self.assertFalse(inspection.available)

    def test_inspect_help_timeout_is_structured(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v4.2.0")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: subprocess.TimeoutExpired(a, 1.0),
                ),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TIMEOUT)

    def test_inspect_help_failure_is_structured(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v4.2.0")),
                (lambda a: "enum" in a and "-help" in a, lambda a: completed(a, code=3)),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_FAILED)

    def test_inspect_nonzero_help_includes_bounded_sanitized_hint(self):
        stderr = (
            "Failed to start https://engine.example/api?token=abc "
            "API_KEY=supersecret\x01\nsecond line"
        )
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(a, code=1, stderr=stderr),
                ),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_FAILED)
        self.assertIn("exit code 1", inspection.reason)
        self.assertIn("hint:", inspection.reason)
        self.assertNotIn("token=abc", inspection.reason)
        self.assertNotIn("supersecret", inspection.reason)
        self.assertNotIn("\x01", inspection.reason)
        self.assertNotIn("\n", inspection.reason)
        self.assertNotIn("second line", inspection.reason)
        self.assertLessEqual(len(inspection.reason), 256)

    def test_inspect_hint_uses_stdout_when_stderr_empty(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(a, code=1, stdout="engine unavailable\nmore"),
                ),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_FAILED)
        self.assertIn("hint: engine unavailable", inspection.reason)
        self.assertNotIn("more", inspection.reason)
        self.assertLessEqual(len(inspection.reason), 256)

    def test_inspect_hint_prefers_child_engine_error_over_parent_timeout(self):
        stderr = (
            "The Amass engine did not respond: the Amass engine did not "
            "respond within the timeout period\n"
            "Failed to start the engine: unable to open database file\n"
        )
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(a, code=1, stderr=stderr),
                ),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_FAILED)
        self.assertIn("Failed to start the engine", inspection.reason)
        self.assertNotIn("did not respond", inspection.reason)
        self.assertNotIn("\n", inspection.reason)
        self.assertLessEqual(len(inspection.reason), 256)

    def test_inspect_never_runs_discovery(self):
        runner = self.runner()
        self.adapter(runner).inspect()
        for argv, _ in runner.calls:
            self.assertTrue("-version" in argv or "-help" in argv)


class FailureHintTests(unittest.TestCase):
    def test_redacts_url_query_secret_and_control_chars(self):
        text = (
            "Failed to start https://engine.example/api?token=abc&x=1 "
            "API_KEY=supersecret\x01\r\nsecond line"
        )
        hint = _failure_hint(text)
        self.assertNotIn("token=abc", hint)
        self.assertNotIn("supersecret", hint)
        self.assertNotIn("\x01", hint)
        self.assertNotIn("\n", hint)
        self.assertNotIn("second line", hint)
        self.assertIn("https://engine.example/api?<redacted>", hint)
        self.assertLessEqual(len(hint), 120)

    def test_returns_empty_for_no_safe_text(self):
        self.assertEqual(_failure_hint(None), "")
        self.assertEqual(_failure_hint(""), "")
        self.assertEqual(_failure_hint("\x01\x02\n"), "")

    def test_prefers_later_actionable_child_error_over_generic_timeout(self):
        text = (
            "The Amass engine did not respond: the Amass engine did not respond "
            "within the timeout period\n"
            "Failed to start the engine: unable to open database file: "
            "permission denied\n"
        )
        hint = _failure_hint(text)
        self.assertIn("Failed to start the engine", hint)
        self.assertIn("permission denied", hint)
        self.assertNotIn("did not respond", hint)
        self.assertNotIn("\n", hint)
        self.assertLessEqual(len(hint), 120)

    def test_selects_first_concrete_line_and_skips_intervening_noise(self):
        text = (
            "The Amass engine did not respond within the timeout period\n"
            "starting up\n"
            "listen tcp 127.0.0.1:4000: bind: address already in use\n"
            "Failed to start the engine: panic: boom\n"
        )
        hint = _failure_hint(text)
        self.assertEqual(
            hint, "listen tcp 127.0.0.1:4000: bind: address already in use"
        )

    def test_falls_back_to_first_line_without_concrete_signal(self):
        text = "engine unavailable\nmore output"
        self.assertEqual(_failure_hint(text), "engine unavailable")
        # Generic timeout only -> first-line fallback, still sanitized/bounded.
        self.assertEqual(
            _failure_hint(
                "The Amass engine did not respond within the timeout period"
            ),
            "The Amass engine did not respond within the timeout period",
        )

    def test_caps_length(self):
        self.assertEqual(len(_failure_hint("x" * 500)), 120)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
