"""Unit tests for the Subfinder parser and adapter (fully offline)."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.models import MAX_TOOL_OUTPUT_CHARS, ObservationState, ToolRunStatus
from red_teaming.recon.scope import DomainScope
from red_teaming.tools.acceptance import accepted_hosts_from_result
from red_teaming.tools.subfinder import (
    SubfinderAdapter,
    accepted_hosts,
    parse_json_lines,
    supports_required_capabilities,
)
from tests.unit.tool_fakes import FakeRunner, completed, make_fake_executable

HELP_OK = "Usage: subfinder -d DOMAIN -json -silent"
HELP_NO_SHORT_D = "Usage: subfinder -domain DOMAIN -json -silent"
HELP_DEBUG = "Usage: subfinder -debug DOMAIN -json -silent"
HELP_JSONL = "Usage: subfinder -d DOMAIN -jsonl -silent"


class SubfinderParserTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])

    def parse(self, records):
        text = "\n".join(
            record if isinstance(record, str) else json.dumps(record)
            for record in records
        )
        return parse_json_lines(text, self.scope)

    def test_discovered_root_and_subdomain(self):
        observations = self.parse([{"host": "example.com"}, {"host": "www.example.com"}])
        self.assertEqual(
            [(o.state, o.normalized) for o in observations],
            [
                (ObservationState.DISCOVERED, "example.com"),
                (ObservationState.DISCOVERED, "www.example.com"),
            ],
        )

    def test_duplicates_merge_and_sort_deterministically(self):
        observations = self.parse(
            [
                {"host": "WWW.example.com", "source": "virustotal"},
                {"host": "www.example.com", "source": "crtsh"},
                {"host": "a.example.com"},
            ]
        )
        by_host = {o.normalized: o for o in observations}
        self.assertEqual(by_host["www.example.com"].source, "crtsh,virustotal")
        self.assertEqual(observations[0].normalized, "a.example.com")
        self.assertEqual(observations[-1].normalized, "www.example.com")

    def test_excluded_and_out_of_scope_retained(self):
        observations = self.parse([{"host": "excluded.example.com"}, {"host": "other.org"}])
        states = {o.normalized: o.state for o in observations}
        self.assertEqual(states["excluded.example.com"], ObservationState.EXCLUDED)
        self.assertEqual(states["other.org"], ObservationState.OUT_OF_SCOPE)

    def test_accepted_hosts_excludes_non_candidates(self):
        observations = self.parse(
            [
                {"host": "www.example.com"},
                {"host": "excluded.example.com"},
                {"host": "other.org"},
                "not-json",
            ]
        )
        self.assertEqual(accepted_hosts(observations), ("www.example.com",))

    def test_malformed_records_are_rejected(self):
        observations = self.parse(
            ["not-json", [1, 2], {"foo": 1}, {"host": 123}, {"host": "bad host"}]
        )
        reasons = {o.reason for o in observations}
        self.assertEqual(
            reasons,
            {"invalid_json", "non_object", "missing_host", "invalid_host_type", "malformed_host"},
        )
        self.assertTrue(all(o.state is ObservationState.REJECTED for o in observations))

    def test_output_is_sorted_by_host(self):
        observations = self.parse(
            [{"host": "z.example.com"}, {"host": "a.example.com"}, {"host": "m.example.com"}]
        )
        self.assertEqual(
            [o.normalized for o in observations],
            ["a.example.com", "m.example.com", "z.example.com"],
        )

    def test_capability_detection(self):
        self.assertTrue(supports_required_capabilities(HELP_OK))
        self.assertFalse(supports_required_capabilities("Usage: -d DOMAIN -json"))
        self.assertFalse(supports_required_capabilities(None))

    def test_short_d_not_satisfied_by_domain(self):
        self.assertFalse(supports_required_capabilities(HELP_NO_SHORT_D))

    def test_short_d_not_satisfied_by_debug(self):
        self.assertFalse(supports_required_capabilities(HELP_DEBUG))

    def test_json_not_satisfied_by_jsonl(self):
        self.assertFalse(supports_required_capabilities(HELP_JSONL))


class SubfinderAdapterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])
        self.exe = make_fake_executable(self.work, "subfinder.exe")

    def tearDown(self):
        self._tmp.cleanup()

    def runner(self, *, help_text=HELP_OK, main=None, version="subfinder version v2.6.3"):
        main = main if main is not None else completed(
            ["main"], stdout=json.dumps({"host": "www.example.com"}) + "\n"
        )
        return FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout=version)),
                (lambda a: "-h" in a, lambda a: completed(a, stdout=help_text)),
                (lambda a: True, lambda a: main),
            ]
        )

    def adapter(self, runner, **kwargs):
        return SubfinderAdapter(
            scope=self.scope, work_dir=self.work, executable=self.exe, runner=runner, **kwargs
        )

    def test_build_argv_is_exact_and_passive(self):
        adapter = self.adapter(self.runner())
        argv = adapter.build_argv(str(self.exe))
        self.assertEqual(
            argv, (str(self.exe), "-d", "example.com", "-json", "-silent")
        )

    def test_success_end_to_end(self):
        runner = self.runner()
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.version, "2.6.3")
        self.assertEqual(
            result.argv, (str(self.exe), "-d", "example.com", "-json", "-silent")
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.timeout, 120.0)
        self.assertEqual(
            [(o.state, o.normalized) for o in result.observations],
            [(ObservationState.DISCOVERED, "www.example.com")],
        )
        # shell=False is enforced for every invocation.
        self.assertTrue(all(call[1]["shell"] is False for call in runner.calls))

    def test_missing_executable_is_normal_result(self):
        runner = self.runner()
        adapter = SubfinderAdapter(
            scope=self.scope, work_dir=self.work, which=lambda name: None, runner=runner
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_NOT_AVAILABLE)
        self.assertEqual(runner.calls, [])

    def test_unsupported_capability_skips_enumeration(self):
        runner = self.runner(help_text="Usage: no flags here")
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.UNSUPPORTED)
        argv, _ = runner.calls[-1]
        self.assertIn("-h", argv)
        self.assertNotIn("-json", argv)

    def test_timeout_is_structured(self):
        runner = self.runner(
            main=subprocess.TimeoutExpired(["main"], 1.0)
        )
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.TIMEOUT)

    def test_nonzero_exit_is_tool_failed(self):
        runner = self.runner(main=completed(["main"], code=2, stderr="boom"))
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)

    def test_output_is_bounded_and_flagged(self):
        huge = "x" * (MAX_TOOL_OUTPUT_CHARS + 50)
        runner = self.runner(main=completed(["main"], stdout=huge))
        result = self.adapter(runner).run()
        self.assertEqual(len(result.stdout), MAX_TOOL_OUTPUT_CHARS)
        self.assertTrue(result.stdout_truncated)

    def test_environment_is_sanitized(self):
        runner = self.runner()
        self.adapter(runner).run()
        env = runner.calls[0][1]["env"]
        self.assertEqual(env["HOME"], str(self.work))
        self.assertFalse(any("proxy" in name.lower() for name in env))

    def test_inspect_confirms_capabilities_without_discovery(self):
        runner = self.runner()
        inspection = self.adapter(runner).inspect()
        self.assertTrue(inspection.supported)
        self.assertEqual(inspection.version, "2.6.3")
        self.assertIn("-json", inspection.capabilities)
        for argv, _ in runner.calls:
            self.assertTrue("-version" in argv or "-h" in argv)

    def test_inspect_unsupported_on_near_collision(self):
        inspection = self.adapter(self.runner(help_text=HELP_NO_SHORT_D)).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.UNSUPPORTED)

    def test_inspect_missing_executable(self):
        adapter = SubfinderAdapter(
            scope=self.scope, work_dir=self.work, which=lambda name: None,
            runner=self.runner(),
        )
        inspection = adapter.inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_NOT_AVAILABLE)

    def test_inspect_help_timeout_is_structured(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="subfinder v2.6.3")),
                (lambda a: "-h" in a, lambda a: subprocess.TimeoutExpired(a, 1.0)),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TIMEOUT)

    def test_inspect_version_timeout(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: subprocess.TimeoutExpired(a, 1.0)),
                (lambda a: True, lambda a: completed(a, stdout=HELP_OK)),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TIMEOUT)
        self.assertIn("version", inspection.reason)
        # Help must not be consulted after a version timeout.
        self.assertEqual(len(runner.calls), 1)

    def test_inspect_version_oserror(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: FileNotFoundError("gone")),
                (lambda a: True, lambda a: completed(a, stdout=HELP_OK)),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_FAILED)
        self.assertIn("version inspection failed", inspection.reason)
        self.assertIsNone(inspection.version)
        self.assertEqual(len(runner.calls), 1)

    def test_inspect_version_nonzero_continues_with_warning(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, code=1, stdout="v2.6.3")),
                (lambda a: "-h" in a, lambda a: completed(a, stdout=HELP_OK)),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.SUCCEEDED)
        self.assertIsNone(inspection.version)
        self.assertTrue(any("exited with code 1" in w for w in inspection.warnings))
        self.assertTrue(all(len(w) <= 256 for w in inspection.warnings))
        self.assertEqual(inspection.to_dict()["warnings"], list(inspection.warnings))

    def test_inspect_version_unparsable_continues_with_warning(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="no version here")),
                (lambda a: "-h" in a, lambda a: completed(a, stdout=HELP_OK)),
            ]
        )
        inspection = self.adapter(runner).inspect()
        self.assertEqual(inspection.status, ToolRunStatus.SUCCEEDED)
        self.assertIsNone(inspection.version)
        self.assertTrue(
            any("parseable version token" in w for w in inspection.warnings)
        )

    def test_inspect_version_warning_reaches_run_result(self):
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, code=1)),
                (lambda a: "-h" in a, lambda a: completed(a, stdout=HELP_OK)),
                (
                    lambda a: True,
                    lambda a: completed(
                        a, stdout=json.dumps({"host": "www.example.com"}) + "\n"
                    ),
                ),
            ]
        )
        result = self.adapter(runner).run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertTrue(any("exited with code" in error for error in result.errors))

    def test_parser_truncation_fails_closed(self):
        line1 = json.dumps({"host": "www.example.com"})
        line2 = json.dumps({"host": "api.example.com"})
        runner = self.runner(main=completed(["main"], stdout=line1 + "\n" + line2 + "\n"))
        result = self.adapter(runner, parse_max=len(line1) + 1).run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)
        self.assertTrue(any("truncated" in error for error in result.errors))
        self.assertEqual(accepted_hosts_from_result(result), ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
