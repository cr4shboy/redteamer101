"""Offline tests for production-configured adapters (exact argv/version)."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.models import ToolRunStatus
from red_teaming.recon.scope import DomainScope
from red_teaming.recon.tool_argv import (
    ToolCommandSpec,
    expected_live_argv,
    required_markers_for,
)
from red_teaming.tools.adapter_base import Inspection
from red_teaming.tools.amass import AmassAdapter
from red_teaming.tools.dnsx import DnsxAdapter
from red_teaming.tools.subfinder import SubfinderAdapter
from tests.unit.tool_fakes import FakeRunner, completed, make_fake_executable


class ProductionAdapterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.scope = DomainScope.parse(["acme.example"])

    def tearDown(self):
        self._tmp.cleanup()

    def test_subfinder_exact_argv_and_version(self):
        exe = make_fake_executable(self.work, "subfinder")
        spec = ToolCommandSpec("subfinder", "2.16.0", str(exe), root="acme.example")
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="subfinder v2.16.0")),
                (
                    lambda a: "-h" in a,
                    lambda a: completed(
                        a, stdout="Usage: subfinder -d DOMAIN -s crtsh -json -silent -rl 1 -duc"
                    ),
                ),
                (
                    lambda a: True,
                    lambda a: completed(a, stdout=json.dumps({"host": "www.acme.example"}) + "\n"),
                ),
            ]
        )
        adapter = SubfinderAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        self.assertEqual(adapter.build_argv(str(exe)), expected_live_argv(spec))
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.version, "2.16.0")
        self.assertEqual(result.argv, expected_live_argv(spec))

    def test_subfinder_wrong_version_is_unsupported(self):
        exe = make_fake_executable(self.work, "subfinder")
        spec = ToolCommandSpec("subfinder", "2.16.0", str(exe), root="acme.example")
        runner = FakeRunner(
            [(lambda a: True, lambda a: completed(a, stdout="subfinder v2.5.0"))]
        )
        adapter = SubfinderAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        inspection = adapter.inspect()
        self.assertEqual(inspection.status, ToolRunStatus.UNSUPPORTED)
        self.assertIn("2.16.0", inspection.reason)

    def test_subfinder_missing_marker_is_unsupported(self):
        exe = make_fake_executable(self.work, "subfinder")
        spec = ToolCommandSpec("subfinder", "2.16.0", str(exe), root="acme.example")
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="subfinder v2.16.0")),
                (lambda a: True, lambda a: completed(a, stdout="-d DOMAIN -json -silent")),
            ]
        )
        adapter = SubfinderAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        self.assertEqual(adapter.inspect().status, ToolRunStatus.UNSUPPORTED)

    def test_dnsx_exact_argv_and_result(self):
        exe = make_fake_executable(self.work, "dnsx")
        spec = ToolCommandSpec("dnsx", "1.3.1", str(exe), root="acme.example")
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="dnsx v1.3.1")),
                (
                    lambda a: "-h" in a,
                    lambda a: completed(
                        a, stdout="-json -a -aaaa -cname -silent -r RES -rl 5 -t 2 -duc"
                    ),
                ),
                (
                    lambda a: True,
                    lambda a: completed(
                        a,
                        stdout=json.dumps(
                            {"host": "www.acme.example", "a": ["192.0.2.1"]}
                        )
                        + "\n",
                    ),
                ),
            ]
        )
        adapter = DnsxAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        self.assertEqual(adapter.build_argv(str(exe)), expected_live_argv(spec))
        result = adapter.run(["www.acme.example"])
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.argv, expected_live_argv(spec))
        self.assertEqual(result.resolutions[0].hostname, "www.acme.example")

    def test_amass_exact_argv_and_result(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(a, stdout="enum -passive -d DOMAIN -oA PREFIX -include SOURCE"),
                ),
                (lambda a: True, lambda a: completed(a)),
            ]
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
            output_reader=lambda path: json.dumps([{"name": "www.acme.example"}]),
        )
        self.assertEqual(
            adapter.build_argv(str(exe), domain_option="-d"), expected_live_argv(spec)
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.version, "5.1.1")
        self.assertEqual(result.argv, expected_live_argv(spec))

    def test_amass_output_path_is_prefix_plus_json(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "custom-prefix")
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            command_spec=spec,
        )
        self.assertEqual(adapter.output_prefix(), Path(prefix))
        self.assertEqual(adapter.output_path(), Path(prefix + ".json"))
        argv = adapter.build_argv(str(exe), domain_option="-d")
        self.assertEqual(argv[5:7], ("-oA", prefix))

    def test_amass_removes_stale_output_before_run(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        stale = Path(prefix + ".json")
        stale.write_text(
            json.dumps([{"name": "stale.acme.example"}]), encoding="utf-8"
        )
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(
                        a, stdout="enum -passive -d DOMAIN -oA PREFIX -include crtsh"
                    ),
                ),
                (lambda a: True, lambda a: completed(a)),
            ]
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        result = adapter.run()
        # The stale generated file is removed and never parsed as this run's output.
        self.assertFalse(stale.exists())
        self.assertEqual(result.observations, ())

    def _amass_production_runner(self, main=None):
        help_ok = "enum -passive -d DOMAIN -oA PREFIX -include crtsh"
        if main is None:
            main = lambda argv: completed(argv)
        return FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(a, stdout=help_ok),
                ),
                (lambda a: True, main),
            ]
        )

    def test_amass_success_without_generated_json_is_empty_success(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=self._amass_production_runner(
                lambda argv: completed(
                    argv,
                    stdout=json.dumps({"name": "stdout.acme.example"}),
                )
            ),
            command_spec=spec,
        )
        # Pinned Amass emits no JSON file for zero findings. Stdout is never parsed.
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.observations, ())
        self.assertTrue(
            any("interpreted as zero findings" in e for e in result.errors),
            result.errors,
        )

    def test_amass_absent_json_preserves_failed_process_status_without_stdout(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        stdout = json.dumps({"name": "stdout.acme.example"})
        cases = (
            ("nonzero", lambda argv: completed(argv, code=2, stdout=stdout), ToolRunStatus.TOOL_FAILED),
            ("timeout", subprocess.TimeoutExpired(["amass"], 1.0, output=stdout), ToolRunStatus.TIMEOUT),
            ("error", OSError("offline synthetic failure"), ToolRunStatus.TOOL_FAILED),
        )
        for name, main, expected_status in cases:
            with self.subTest(name=name):
                adapter = AmassAdapter(
                    scope=self.scope,
                    work_dir=self.work,
                    executable=str(exe),
                    runner=self._amass_production_runner(main),
                    command_spec=spec,
                )
                result = adapter.run()
                self.assertEqual(result.status, expected_status)
                self.assertEqual(result.observations, ())
                self.assertFalse(
                    any("zero findings" in error for error in result.errors),
                    result.errors,
                )

    def test_amass_unreadable_generated_json_fails_closed(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        Path(prefix + ".json").mkdir()
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=self._amass_production_runner(), command_spec=spec,
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)
        self.assertEqual(result.observations, ())
        self.assertTrue(
            any("exists but is unreadable" in e for e in result.errors), result.errors
        )

    def test_amass_valid_generated_json_succeeds(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")

        def main(argv):
            Path(prefix + ".json").write_text(
                json.dumps([{"name": "www.acme.example"}]), encoding="utf-8"
            )
            return completed(argv)

        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(
                        a, stdout="enum -passive -d DOMAIN -oA PREFIX -include crtsh"
                    ),
                ),
                (lambda a: True, main),
            ]
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(
            [o.normalized for o in result.observations], ["www.acme.example"]
        )

    def test_amass_truncated_generated_json_fails_closed(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")

        def main(argv):
            Path(prefix + ".json").write_text(
                json.dumps([{"name": "www.acme.example"}]), encoding="utf-8"
            )
            return completed(argv)

        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=self._amass_production_runner(main), command_spec=spec,
            parse_max=16,
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)
        self.assertTrue(any("truncated" in error for error in result.errors))

    def test_amass_malformed_generated_json_preserves_parser_behavior(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")

        def main(argv):
            Path(prefix + ".json").write_text("not-json", encoding="utf-8")
            return completed(argv)

        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=self._amass_production_runner(main), command_spec=spec,
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].reason, "invalid_json")

    def test_amass_inspection_uses_exact_enum_help_argv(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(
                        a,
                        code=2,
                        stdout="enum -passive -d DOMAIN -oA PREFIX -include crtsh",
                    ),
                ),
            ]
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        self.assertEqual(adapter.help_argv(str(exe)), (str(exe), "enum", "-help"))
        inspection = adapter.inspect()
        # A nonzero help exit that still advertises every required option is
        # accepted, with the exact inspection argv preserved and a warning.
        self.assertEqual(inspection.status, ToolRunStatus.SUCCEEDED)
        help_calls = [call[0] for call in runner.calls if "enum" in call[0]]
        self.assertEqual(help_calls, [(str(exe), "enum", "-help")])
        self.assertTrue(any("exited with code 2" in w for w in inspection.warnings))

    def test_amass_nonzero_help_without_evidence_is_failed_with_reason(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (lambda a: "enum" in a and "-help" in a, lambda a: completed(a, code=2)),
            ]
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        inspection = adapter.inspect()
        self.assertEqual(inspection.status, ToolRunStatus.TOOL_FAILED)
        self.assertIn("exit code 2", inspection.reason)
        self.assertNotIn("\n", inspection.reason)
        self.assertLessEqual(len(inspection.reason), 256)

    def test_amass_unsupported_reason_lists_only_missing_tokens(self):
        exe = make_fake_executable(self.work, "amass")
        prefix = str(self.work / "amass-enum")
        spec = ToolCommandSpec(
            "amass", "5.1.1", str(exe), root="acme.example",
            domain_option="-d", output_prefix=prefix,
        )
        # Pinned Amass 5.1.1 advertises -passive/-d/-include but not -oA.
        help_text = "Usage: amass enum [options] -d DOMAIN; -passive -include crtsh"
        runner = FakeRunner(
            [
                (lambda a: "-version" in a, lambda a: completed(a, stdout="amass v5.1.1")),
                (
                    lambda a: "enum" in a and "-help" in a,
                    lambda a: completed(a, stdout=help_text),
                ),
            ]
        )
        adapter = AmassAdapter(
            scope=self.scope, work_dir=self.work, executable=str(exe),
            runner=runner, command_spec=spec,
        )
        inspection = adapter.inspect()
        self.assertEqual(inspection.status, ToolRunStatus.UNSUPPORTED)
        self.assertEqual(
            inspection.reason, "amass enum help did not advertise: -oA"
        )

    def test_cached_inspection_skips_reinspection(self):
        exe = make_fake_executable(self.work, "subfinder")
        spec = ToolCommandSpec("subfinder", "2.16.0", str(exe), root="acme.example")
        cached = Inspection(
            tool="subfinder",
            status=ToolRunStatus.SUCCEEDED,
            executable=str(exe),
            version="2.16.0",
            capabilities=required_markers_for(spec),
        )
        runner = FakeRunner(
            [
                (
                    lambda a: True,
                    lambda a: completed(
                        a, stdout=json.dumps({"host": "www.acme.example"}) + "\n"
                    ),
                )
            ]
        )
        adapter = SubfinderAdapter(
            scope=self.scope,
            work_dir=self.work,
            executable=str(exe),
            runner=runner,
            command_spec=spec,
            prevalidated_inspection=cached,
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        # Exactly one live invocation; no version/help inspection was repeated.
        self.assertEqual([call[0] for call in runner.calls], [expected_live_argv(spec)])

    def test_cached_inspection_mismatch_fails_closed(self):
        exe = make_fake_executable(self.work, "subfinder")
        spec = ToolCommandSpec("subfinder", "2.16.0", str(exe), root="acme.example")
        wrong = Inspection(
            tool="subfinder",
            status=ToolRunStatus.SUCCEEDED,
            executable=str(exe),
            version="2.5.0",  # does not match the pinned version
            capabilities=required_markers_for(spec),
        )
        runner = FakeRunner([(lambda a: True, lambda a: completed(a))])
        adapter = SubfinderAdapter(
            scope=self.scope,
            work_dir=self.work,
            executable=str(exe),
            runner=runner,
            command_spec=spec,
            prevalidated_inspection=wrong,
        )
        result = adapter.run()
        self.assertEqual(result.status, ToolRunStatus.TOOL_FAILED)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
