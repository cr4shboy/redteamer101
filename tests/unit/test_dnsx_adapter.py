"""Unit tests for the dnsx parser and adapter (fully offline)."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.models import ObservationState, ResolutionStatus, ToolRunStatus
from red_teaming.recon.scope import DomainScope
from red_teaming.tools.acceptance import accepted_resolutions_from_result
from red_teaming.tools.dnsx import (
    DnsxAdapter,
    parse_json_lines,
    prepare_candidates,
    supports_required_capabilities,
)
from red_teaming.tools.execution import ExecutionError
from tests.unit.tool_fakes import FakeRunner, completed, make_fake_executable

HELP_OK = "Usage: dnsx -json -a -aaaa -cname"
HELP_NO_SHORT_A = "Usage: dnsx -json -aaaa -cname"
HELP_JSONL = "Usage: dnsx -jsonl -a -aaaa -cname"


class DnsxParserTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])

    def parse(self, records):
        text = "\n".join(
            record if isinstance(record, str) else json.dumps(record)
            for record in records
        )
        return parse_json_lines(text, self.scope)

    def test_a_aaaa_cname_arrays(self):
        observations, resolutions = self.parse(
            [
                {
                    "host": "www.example.com",
                    "a": ["192.0.2.1", "192.0.2.1"],
                    "aaaa": ["2001:db8::1"],
                    "cname": ["cdn.third.example"],
                    "status_code": "NOERROR",
                }
            ]
        )
        self.assertEqual(observations, ())
        self.assertEqual(len(resolutions), 1)
        resolution = resolutions[0]
        self.assertEqual(resolution.status, ResolutionStatus.RESOLVED)
        self.assertEqual(resolution.dns.a, ("192.0.2.1",))
        self.assertEqual(resolution.dns.aaaa, ("2001:db8::1",))
        self.assertEqual(resolution.dns.cname, ("cdn.third.example",))

    def test_multiple_records_are_ordered(self):
        observations, resolutions = self.parse(
            [
                {"host": "z.example.com", "a": ["192.0.2.3"]},
                {"host": "a.example.com", "a": ["192.0.2.1"]},
                {"host": "m.example.com", "a": ["192.0.2.2"]},
            ]
        )
        self.assertEqual(
            [r.hostname for r in resolutions],
            ["a.example.com", "m.example.com", "z.example.com"],
        )

    def test_duplicate_hosts_merge_records(self):
        observations, resolutions = self.parse(
            [
                {"host": "www.example.com", "a": ["192.0.2.1"]},
                {"host": "www.example.com", "a": ["192.0.2.2"]},
            ]
        )
        self.assertEqual(len(resolutions), 1)
        self.assertEqual(resolutions[0].dns.a, ("192.0.2.1", "192.0.2.2"))

    def test_nxdomain(self):
        observations, resolutions = self.parse(
            [{"host": "none.example.com", "status_code": "NXDOMAIN"}]
        )
        self.assertEqual(resolutions[0].status, ResolutionStatus.NXDOMAIN)

    def test_unresolved(self):
        observations, resolutions = self.parse([{"host": "none.example.com"}])
        self.assertEqual(resolutions[0].status, ResolutionStatus.UNRESOLVED)

    def test_malformed_records_are_rejected(self):
        observations, resolutions = self.parse(
            [
                "not-json",
                [1, 2],
                {"foo": 1},
                {"host": 5},
                {"host": "bad host"},
                {"host": "www.example.com", "a": ["999.999.999.999"]},
                {"host": "www.example.com", "cname": "not-an-array"},
            ]
        )
        self.assertEqual(resolutions, ())
        reasons = {o.reason for o in observations}
        self.assertIn("invalid_json", reasons)
        self.assertIn("non_object", reasons)
        self.assertIn("missing_host", reasons)
        self.assertIn("invalid_host_type", reasons)
        self.assertIn("malformed_host", reasons)
        self.assertIn("invalid_dns_records", reasons)

    def test_out_of_scope_retained_without_resolution(self):
        observations, resolutions = self.parse(
            [{"host": "other.org", "a": ["192.0.2.1"]}]
        )
        self.assertEqual(resolutions, ())
        self.assertEqual(observations[0].state, ObservationState.OUT_OF_SCOPE)

    def test_external_cname_is_evidence_only(self):
        observations, resolutions = self.parse(
            [{"host": "www.example.com", "cname": ["cdn.third.example"]}]
        )
        self.assertEqual(resolutions[0].dns.cname, ("cdn.third.example",))
        # The external target never becomes a candidate or observation.
        self.assertTrue(all(o.normalized != "cdn.third.example" for o in observations))
        self.assertTrue(all(r.hostname != "cdn.third.example" for r in resolutions))

    def test_capability_detection(self):
        self.assertTrue(supports_required_capabilities(HELP_OK))
        self.assertFalse(supports_required_capabilities("-json -a -aaaa"))
        self.assertFalse(supports_required_capabilities(None))

    def test_short_a_not_satisfied_by_aaaa(self):
        self.assertFalse(supports_required_capabilities(HELP_NO_SHORT_A))

    def test_json_not_satisfied_by_jsonl(self):
        self.assertFalse(supports_required_capabilities(HELP_JSONL))


class PrepareCandidatesTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])

    def test_filters_sorts_and_dedups(self):
        hosts, observations = prepare_candidates(
            [
                "b.example.com",
                "A.example.com",
                "a.example.com",
                "excluded.example.com",
                "other.org",
                "bad host",
            ],
            self.scope,
        )
        self.assertEqual(hosts, ("a.example.com", "b.example.com"))
        states = {o.normalized: o.state for o in observations}
        self.assertEqual(states["excluded.example.com"], ObservationState.EXCLUDED)
        self.assertEqual(states["other.org"], ObservationState.OUT_OF_SCOPE)
        self.assertTrue(any(o.reason == "malformed_host" for o in observations))

    def test_rejects_bare_string(self):
        with self.assertRaises(ExecutionError):
            prepare_candidates("example.com", self.scope)


class DnsxAdapterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])
        self.exe = make_fake_executable(self.work, "dnsx.exe")

    def tearDown(self):
        self._tmp.cleanup()

    def runner(self, *, help_text=HELP_OK, main=None, version="dnsx v1.2.0"):
        main = main if main is not None else completed(
            ["main"],
            stdout=json.dumps(
                {
                    "host": "www.example.com",
                    "a": ["192.0.2.1"],
                    "cname": ["cdn.third.example"],
                    "status_code": "NOERROR",
                }
            )
            + "\n",
        )
        return FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout=version)),
                (lambda a: "-h" in a, lambda a: completed(a, stdout=help_text)),
                (lambda a: True, lambda a: main),
            ]
        )

    def adapter(self, runner, **kwargs):
        return DnsxAdapter(
            scope=self.scope, work_dir=self.work, executable=self.exe, runner=runner, **kwargs
        )

    def main_call(self, runner):
        for argv, kwargs in runner.calls:
            if "-version" not in argv and "-h" not in argv:
                return argv, kwargs
        raise AssertionError("no main invocation recorded")

    def test_build_argv_is_exact(self):
        adapter = self.adapter(self.runner())
        self.assertEqual(
            adapter.build_argv(str(self.exe)),
            (str(self.exe), "-json", "-a", "-aaaa", "-cname", "-silent"),
        )

    def test_success_feeds_stdin_sorted_and_parses(self):
        runner = self.runner()
        result = self.adapter(runner).run(
            ["b.example.com", "A.example.com", "a.example.com"]
        )
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.version, "1.2.0")
        argv, kwargs = self.main_call(runner)
        self.assertEqual(kwargs["input"], "a.example.com\nb.example.com\n")
        self.assertFalse(kwargs["shell"])
        self.assertEqual(result.resolutions[0].hostname, "www.example.com")
        self.assertEqual(result.resolutions[0].dns.cname, ("cdn.third.example",))

    def test_no_candidates_skips_discovery(self):
        runner = self.runner()
        result = self.adapter(runner).run(["other.org"])
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.argv, ())
        self.assertEqual(result.observations[0].state, ObservationState.OUT_OF_SCOPE)
        for argv, _ in runner.calls:
            self.assertTrue("-version" in argv or "-h" in argv)

    def test_missing_executable(self):
        runner = self.runner()
        adapter = DnsxAdapter(
            scope=self.scope, work_dir=self.work, which=lambda name: None, runner=runner
        )
        result = adapter.run(["a.example.com"])
        self.assertEqual(result.status, ToolRunStatus.TOOL_NOT_AVAILABLE)
        self.assertEqual(runner.calls, [])

    def test_unsupported_capability_skips_resolution(self):
        runner = self.runner(help_text="-json -a")
        result = self.adapter(runner).run(["a.example.com"])
        self.assertEqual(result.status, ToolRunStatus.UNSUPPORTED)
        argv, _ = runner.calls[-1]
        self.assertIn("-h", argv)

    def test_timeout_is_structured(self):
        runner = self.runner(main=subprocess.TimeoutExpired(["main"], 1.0))
        result = self.adapter(runner).run(["a.example.com"])
        self.assertEqual(result.status, ToolRunStatus.TIMEOUT)

    def test_environment_is_sanitized(self):
        runner = self.runner()
        self.adapter(runner).run(["a.example.com"])
        env = runner.calls[0][1]["env"]
        self.assertEqual(env["HOME"], str(self.work))
        self.assertFalse(any("proxy" in name.lower() for name in env))

    def test_inspect_confirms_capabilities_without_discovery(self):
        runner = self.runner()
        inspection = self.adapter(runner).inspect()
        self.assertTrue(inspection.supported)
        self.assertEqual(inspection.version, "1.2.0")
        self.assertIn("-a", inspection.capabilities)
        for argv, _ in runner.calls:
            self.assertTrue("-version" in argv or "-h" in argv)

    def test_inspect_unsupported_on_near_collision(self):
        inspection = self.adapter(self.runner(help_text=HELP_NO_SHORT_A)).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.UNSUPPORTED)

    def test_inspect_missing_executable(self):
        adapter = DnsxAdapter(
            scope=self.scope, work_dir=self.work, which=lambda name: None,
            runner=self.runner(),
        )
        inspection = adapter.inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_NOT_AVAILABLE)

    def test_inspect_help_timeout_is_structured(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="dnsx v1.2.0")),
                (lambda a: "-h" in a, lambda a: subprocess.TimeoutExpired(a, 1.0)),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TIMEOUT)

    def test_parser_truncation_fails_closed(self):
        line1 = json.dumps({"host": "www.example.com", "a": ["192.0.2.1"]})
        line2 = json.dumps({"host": "api.example.com", "a": ["192.0.2.2"]})
        runner = self.runner(main=completed(["main"], stdout=line1 + "\n" + line2 + "\n"))
        result = self.adapter(runner, parse_max=len(line1) + 1).run(["www.example.com"])
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)
        self.assertTrue(any("truncated" in error for error in result.errors))
        self.assertEqual(accepted_resolutions_from_result(result), ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
