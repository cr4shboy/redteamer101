"""Unit tests for the ffuf parser and active subdomain-fuzzing adapter (offline)."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.models import ObservationState, ToolRunStatus
from red_teaming.recon.scope import DomainScope
from red_teaming.tools.execution import ExecutionError
from red_teaming.tools.ffuf import (
    DEFAULT_MAXTIME,
    DEFAULT_RATE,
    FfufAdapter,
    parse_ffuf_output,
    supports_required_capabilities,
)
from tests.unit.tool_fakes import FakeRunner, completed, make_fake_executable

HELP_OK = "Usage: ffuf -w WORDLIST -u URL -o FILE -of FORMAT -mc CODES"
HELP_NO_OF = "Usage: ffuf -w WORDLIST -u URL -o FILE"


def _ffuf_document(hosts):
    return json.dumps(
        {
            "commandline": "ffuf ...",
            "time": "2026-10-05T00:00:00Z",
            "results": [
                {"input": {"FUZZ": host.split(".")[0]}, "status": 200, "url": f"https://{host}/", "host": host}
                for host in hosts
            ],
            "config": {},
        }
    )


class FfufParserTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])

    def test_results_object_document(self):
        text = _ffuf_document(["www.example.com", "api.example.com"])
        observations = parse_ffuf_output(text, self.scope)
        by_host = {o.normalized: o for o in observations}
        self.assertEqual(by_host["www.example.com"].state, ObservationState.DISCOVERED)
        self.assertEqual(by_host["api.example.com"].state, ObservationState.DISCOVERED)
        self.assertEqual(by_host["www.example.com"].source, "ffuf")

    def test_host_falls_back_to_url_then_fuzz_keyword(self):
        text = json.dumps(
            {
                "results": [
                    {"url": "https://only-url.example.com/"},
                    {"input": {"FUZZ": "only-fuzz"}, "status": 200},
                ]
            }
        )
        observations = parse_ffuf_output(text, self.scope)
        normalized = {o.normalized for o in observations}
        self.assertIn("only-url.example.com", normalized)
        self.assertIn("only-fuzz.example.com", normalized)

    def test_out_of_scope_and_excluded_retained_not_promoted(self):
        text = _ffuf_document(["x.other.org", "excluded.example.com"])
        observations = parse_ffuf_output(text, self.scope)
        by_host = {o.normalized: o for o in observations}
        self.assertEqual(by_host["x.other.org"].state, ObservationState.OUT_OF_SCOPE)
        self.assertEqual(
            by_host["excluded.example.com"].state, ObservationState.EXCLUDED
        )

    def test_json_lines_fallback(self):
        text = "\n".join(
            [
                json.dumps({"host": "a.example.com"}),
                json.dumps({"host": "b.example.com"}),
            ]
        )
        observations = parse_ffuf_output(text, self.scope)
        self.assertEqual(
            [o.normalized for o in observations], ["a.example.com", "b.example.com"]
        )

    def test_duplicates_merge(self):
        text = _ffuf_document(["www.example.com", "WWW.example.com"])
        observations = parse_ffuf_output(text, self.scope)
        self.assertEqual(len(observations), 1)

    def test_malformed_records(self):
        text = json.dumps({"results": [{"status": 200}, "scalar", 42]})
        observations = parse_ffuf_output(text, self.scope)
        reasons = {o.reason for o in observations}
        self.assertIn("missing_host", reasons)
        self.assertIn("non_object", reasons)

    def test_invalid_json_lines_rejected(self):
        observations = parse_ffuf_output("not-json\n{bad", self.scope)
        self.assertTrue(all(o.reason == "invalid_json" for o in observations))

    def test_capability_detection(self):
        self.assertTrue(supports_required_capabilities(HELP_OK))
        self.assertFalse(supports_required_capabilities(HELP_NO_OF))
        self.assertFalse(supports_required_capabilities(None))


class FfufAdapterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])
        self.exe = make_fake_executable(self.work, "ffuf.exe")
        self.wordlist = self.work / "subdomains.txt"
        self.wordlist.write_text("www\napi\n", encoding="utf-8")
        self.payload = _ffuf_document(["www.example.com"])

    def tearDown(self):
        self._tmp.cleanup()

    def runner(self, *, help_text=HELP_OK, main=None, version="ffuf version v2.1.0"):
        main = main if main is not None else completed(["main"])
        return FakeRunner(
            [
                (lambda a: "-V" in a, lambda a: completed(a, stdout=version)),
                (lambda a: "-h" in a, lambda a: completed(a, stdout=help_text)),
                (lambda a: True, lambda a: main),
            ]
        )

    def adapter(self, runner, **kwargs):
        return FfufAdapter(
            scope=self.scope,
            work_dir=self.work,
            executable=self.exe,
            wordlist=self.wordlist,
            runner=runner,
            output_reader=lambda path: self.payload,
            **kwargs,
        )

    def main_call(self, runner):
        for argv, kwargs in runner.calls:
            if "-V" not in argv and "-h" not in argv:
                return argv, kwargs
        raise AssertionError("no main invocation recorded")

    def test_build_argv_is_bounded_and_scoped(self):
        argv = self.adapter(self.runner()).build_argv(str(self.exe))
        self.assertEqual(argv[0], str(self.exe))
        self.assertIn("-w", argv)
        self.assertIn(str(self.wordlist), argv)
        self.assertIn("https://FUZZ.example.com/", argv)
        self.assertIn("-of", argv)
        self.assertIn("json", argv)
        # Bounded by construction: a request-rate cap and a wall-clock cap.
        self.assertIn("-rate", argv)
        self.assertIn(str(DEFAULT_RATE), argv)
        self.assertIn("-maxtime", argv)
        self.assertIn(str(DEFAULT_MAXTIME), argv)
        # No arbitrary host and no plain-HTTP downgrade.
        self.assertTrue(all("http://" not in token for token in argv))

    def test_success_end_to_end(self):
        runner = self.runner()
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.version, "2.1.0")
        self.assertEqual(
            [(o.state, o.normalized) for o in result.observations],
            [(ObservationState.DISCOVERED, "www.example.com")],
        )
        self.assertTrue(all(call[1]["shell"] is False for call in runner.calls))

    def test_missing_executable(self):
        adapter = FfufAdapter(
            scope=self.scope,
            work_dir=self.work,
            wordlist=self.wordlist,
            which=lambda name: None,
            runner=self.runner(),
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_NOT_AVAILABLE)

    def test_unsupported_capability_skips_run(self):
        runner = self.runner(help_text=HELP_NO_OF)
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.UNSUPPORTED)
        argv, _ = runner.calls[-1]
        self.assertIn("-h", argv)

    def test_timeout_is_structured(self):
        runner = self.runner(main=subprocess.TimeoutExpired(["main"], 1.0))
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.TIMEOUT)

    def test_missing_output_fails_closed(self):
        # No output_reader and no file on disk => fail closed.
        adapter = FfufAdapter(
            scope=self.scope,
            work_dir=self.work,
            executable=self.exe,
            wordlist=self.wordlist,
            runner=self.runner(),
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)
        self.assertTrue(
            any("was not created/readable" in error for error in result.errors)
        )

    def test_parser_truncation_fails_closed(self):
        runner = self.runner()
        adapter = self.adapter(runner, parse_max=len(self.payload) - 1)
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)
        self.assertTrue(any("truncated" in error for error in result.errors))

    def test_environment_is_sanitized(self):
        runner = self.runner()
        self.adapter(runner).run()
        env = runner.calls[0][1]["env"]
        self.assertEqual(env["HOME"], str(self.work))
        self.assertFalse(any("proxy" in name.lower() for name in env))

    def test_absolute_wordlist_required(self):
        with self.assertRaises(ExecutionError):
            FfufAdapter(
                scope=self.scope,
                work_dir=self.work,
                executable=self.exe,
                wordlist="relative.txt",
                runner=self.runner(),
            )

    def test_run_requires_wordlist(self):
        adapter = FfufAdapter(
            scope=self.scope,
            work_dir=self.work,
            executable=self.exe,
            runner=self.runner(),
            output_reader=lambda path: self.payload,
        )
        with self.assertRaises(ExecutionError):
            adapter.run()

    def test_inspect_confirms_capabilities_without_fuzzing(self):
        runner = self.runner()
        inspection = self.adapter(runner).inspect()
        self.assertTrue(inspection.supported)
        self.assertEqual(inspection.version, "2.1.0")
        for argv, _ in runner.calls:
            self.assertTrue("-V" in argv or "-h" in argv)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
