"""Offline tests for the fail-closed production CLI path (fakes only)."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from red_teaming.cli import recon_assets as cli
from red_teaming.recon.evidence import PACKAGE_NAME
from red_teaming.recon.models import ToolRunStatus
from red_teaming.recon.pinned import PINNED_TOOLS, InstallReport, RuntimeReport
from red_teaming.recon.runner import HelperOutcome
from red_teaming.recon.scope import DomainScope
from tests.unit import recon_fakes
from tests.unit.recon_fakes import (
    DnsAdapter,
    ResultAdapter,
    amass_result,
    dnsx_result,
    factories,
    subfinder_result,
)

RUN_ID = "20260101T000000Z-abc123"
ROOT = "acme.example"


def make_workspace(tmp: str) -> Path:
    root = Path(tmp)
    (root / "projects").mkdir()
    for marker in ("AGENTS.md", "PROJECT.md", "CURRENT_TASK.md"):
        (root / marker).write_text("marker\n", encoding="utf-8")
    return root


def good_runtime() -> RuntimeReport:
    return RuntimeReport(
        ok=True,
        detail="ok",
        os_id="ubuntu",
        version_id="24.04",
        sysname="Linux",
        machine="x86_64",
        kernel_release="6.6.0-microsoft-standard-WSL2",
    )


def good_installs():
    return tuple(
        InstallReport(
            tool=spec.tool,
            version=spec.version,
            ok=True,
            install_dir=f"/ws/.tools/wsl/{spec.tool}/{spec.version}",
            binary_path=f"/ws/.tools/wsl/{spec.tool}/{spec.version}/{spec.tool}",
        )
        for spec in PINNED_TOOLS.values()
    )


class FakeSelftest:
    passed = True
    reason = None


class FakeProvider:
    def __init__(self):
        self.documents = 0

    def document(self, *, run_id, root, status="completed"):
        self.documents += 1
        return {
            "schema_version": 1,
            "package": PACKAGE_NAME,
            "root_domain": root,
            "run_id": run_id,
            "status": status,
        }


class FakeRuntime:
    def __init__(self, fac, provider):
        self._fac = fac
        self._provider = provider

    def factories(self):
        return self._fac

    def evidence_provider(self):
        return self._provider


def fake_factories():
    scope = DomainScope.parse([ROOT])

    def sf(s, w):
        return ResultAdapter(subfinder_result(s, [{"host": f"www.{ROOT}"}]))

    def am(s, w):
        return ResultAdapter(amass_result(s, [{"name": f"api.{ROOT}"}]))

    def dx(s, w):
        return DnsAdapter(
            lambda candidates: dnsx_result(
                s, [{"host": h, "a": ["192.0.2.1"]} for h in candidates]
            )
        )

    return factories(sf, am, dx), scope


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_rejects_other_root(self):
        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse(["example.com"]),
            src_path="/src",
            runtime_probe=good_runtime,
            install_verifier=lambda ws: good_installs(),
            selftest_runner=lambda **kw: FakeSelftest(),
            inspect_tools=False,
        )
        self.assertFalse(report.ok)
        self.assertIn(ROOT, report.blocked_reason)

    def test_runtime_failure_blocks(self):
        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse([ROOT]),
            src_path="/src",
            runtime_probe=lambda: RuntimeReport(ok=False, detail="runtime_not_wsl"),
            install_verifier=lambda ws: good_installs(),
            selftest_runner=lambda **kw: FakeSelftest(),
            inspect_tools=False,
        )
        self.assertFalse(report.ok)
        self.assertIn("runtime", report.blocked_reason)

    def test_install_failure_blocks(self):
        bad = list(good_installs())
        bad[0] = InstallReport(tool="subfinder", version="2.16.0", ok=False, install_dir="/x", reason="bad")
        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse([ROOT]),
            src_path="/src",
            runtime_probe=good_runtime,
            install_verifier=lambda ws: tuple(bad),
            selftest_runner=lambda **kw: FakeSelftest(),
            inspect_tools=False,
        )
        self.assertFalse(report.ok)
        self.assertIn("pinned-installs", report.blocked_reason)

    def test_selftest_failure_blocks(self):
        class Bad:
            passed = False
            reason = "route_leak"

        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse([ROOT]),
            src_path="/src",
            runtime_probe=good_runtime,
            install_verifier=lambda ws: good_installs(),
            selftest_runner=lambda **kw: Bad(),
            inspect_tools=False,
        )
        self.assertFalse(report.ok)
        self.assertIn("namespace-selftest", report.blocked_reason)

    def test_success_builds_runtime(self):
        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse([ROOT]),
            src_path="/src",
            runtime_probe=good_runtime,
            install_verifier=lambda ws: good_installs(),
            selftest_runner=lambda **kw: FakeSelftest(),
            inspect_tools=False,
        )
        self.assertTrue(report.ok, report.blocked_reason)
        self.assertIsNotNone(report.runtime_obj)


class ProductionPreflightInspectionTests(unittest.TestCase):
    VERSION_OUTPUT = {
        "subfinder": "subfinder v2.16.0",
        "dnsx": "dnsx v1.3.1",
        "amass": "amass v5.1.1",
    }
    HELP_OUTPUT = {
        "subfinder": "-d -s -json -silent -rl -duc",
        "dnsx": "-json -a -aaaa -cname -silent -r -rl -t -duc",
        "amass": "enum -passive -d -oA -include",
    }

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_workspace(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _real_installs(self):
        installs = []
        paths = {}
        for spec in PINNED_TOOLS.values():
            directory = self.root / ".tools" / "wsl" / spec.tool / spec.version
            directory.mkdir(parents=True, exist_ok=True)
            exe = directory / spec.binary_name
            exe.write_text("fake", encoding="utf-8")
            paths[spec.tool] = str(exe)
            installs.append(
                InstallReport(
                    tool=spec.tool,
                    version=spec.version,
                    ok=True,
                    install_dir=str(directory),
                    binary_path=str(exe),
                )
            )
        return tuple(installs), paths

    def _helper(self, paths, *, amass_help_exit=0):
        by_path = {path: tool for tool, path in paths.items()}

        class FakeHelper:
            def __init__(self):
                self.payloads = []

            def __call__(self, config, status_parent, deadline):
                payload = json.loads(config.exec_payload)
                self.payloads.append(payload)
                argv = payload["argv"]
                tool = by_path.get(argv[0]) if argv else None
                if tool is None:
                    raise AssertionError(f"unexpected binary: {argv[:1]}")
                exit_code = 0
                if "-version" in argv:
                    stdout = ProductionPreflightInspectionTests.VERSION_OUTPUT[tool]
                else:
                    stdout = ProductionPreflightInspectionTests.HELP_OUTPUT[tool]
                    if tool == "amass":
                        exit_code = amass_help_exit
                        if amass_help_exit != 0:
                            stdout = ""
                Path(payload["stdout_path"]).write_bytes(stdout.encode("utf-8"))
                Path(payload["stderr_path"]).write_bytes(b"")
                Path(payload["status_path"]).write_text(
                    json.dumps(
                        {
                            "exit_code": exit_code,
                            "timed_out": False,
                            "error": None,
                            "stdout_bytes": len(stdout),
                            "stderr_bytes": 0,
                            "stdout_truncated": False,
                            "stderr_truncated": False,
                        }
                    ),
                    encoding="utf-8",
                )
                events = (
                    {"event": "ready", "uid": 0, "route4": "", "route6": ""},
                    {"event": "tool_exit", "exit_code": exit_code},
                    {"event": "stopped"},
                )
                return HelperOutcome(
                    returncode=0, events=events, timed_out=False
                )

        return FakeHelper()

    def test_caches_inspections_and_cleans_transient_work_dir(self):
        installs, paths = self._real_installs()
        helper = self._helper(paths)
        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse([ROOT]),
            src_path="/src",
            runtime_probe=good_runtime,
            install_verifier=lambda ws: installs,
            selftest_runner=lambda **kw: FakeSelftest(),
            inspect_tools=True,
            amass_launcher_check=lambda path: True,
            helper_runner=helper,
            port_factory=lambda: 18099,
        )
        self.assertTrue(report.ok, report.blocked_reason)
        self.assertEqual(
            set(report.runtime_obj.inspections), {"subfinder", "dnsx", "amass"}
        )
        for inspection in report.runtime_obj.inspections.values():
            self.assertEqual(inspection.status, ToolRunStatus.SUCCEEDED)
        # No preflight sandbox at the project root and no residual transient dir.
        self.assertFalse((self.root / "_sandbox").exists())
        self.assertEqual(
            list((self.root / "projects" / ROOT).glob(".preflight-*")), []
        )
        # Every inspection ran in the transient dir under projects/<root>/.
        self.assertTrue(helper.payloads)
        for payload in helper.payloads:
            self.assertIn(".preflight-", payload["cwd"])
            self.assertIn(ROOT, payload["cwd"])

    def test_cached_inspection_is_injected_into_live_adapters(self):
        installs, paths = self._real_installs()
        helper = self._helper(paths)
        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse([ROOT]),
            src_path="/src",
            runtime_probe=good_runtime,
            install_verifier=lambda ws: installs,
            selftest_runner=lambda **kw: FakeSelftest(),
            inspect_tools=True,
            amass_launcher_check=lambda path: True,
            helper_runner=helper,
            port_factory=lambda: 18099,
        )
        self.assertTrue(report.ok, report.blocked_reason)
        root_scope = DomainScope.parse([ROOT]).for_root(ROOT)
        work = self.root / "projects" / ROOT
        factories = report.runtime_obj.factories()
        for tool in ("subfinder", "amass", "dnsx"):
            adapter = getattr(factories, tool)(root_scope, work)
            cached = adapter.prevalidated_inspection
            self.assertIsNotNone(cached, tool)
            self.assertEqual(cached.tool, tool)
            self.assertEqual(cached.status, ToolRunStatus.SUCCEEDED)

    def test_failed_inspection_reports_bounded_reason(self):
        installs, paths = self._real_installs()
        helper = self._helper(paths, amass_help_exit=2)
        report = cli.production_preflight(
            workspace_root=self.root,
            scope=DomainScope.parse([ROOT]),
            src_path="/src",
            runtime_probe=good_runtime,
            install_verifier=lambda ws: installs,
            selftest_runner=lambda **kw: FakeSelftest(),
            inspect_tools=True,
            amass_launcher_check=lambda path: True,
            helper_runner=helper,
            port_factory=lambda: 18099,
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.blocked_reason, "capability-inspection:amass")
        reasons = dict(report.inspection_reasons)
        self.assertIn("exit code 2", reasons["amass"])
        self.assertNotIn("\n", reasons["amass"])
        self.assertLessEqual(len(reasons["amass"]), 256)
        lines = report.to_lines()
        self.assertTrue(
            any(
                line.startswith("tool[amass]: tool_failed reason=")
                and "exit code 2" in line
                for line in lines
            )
        )
        # No raw help output is emitted.
        self.assertFalse(any("enum -passive" in line for line in lines))

    def test_inspection_reason_is_collapsed_and_capped(self):
        report = cli.ProductionPreflightReport(
            ok=False,
            inspections=(("amass", "tool_failed"),),
            inspection_reasons=(("amass", "line one\nline two " + "x" * 500),),
        )
        line = next(
            line for line in report.to_lines() if line.startswith("tool[amass]")
        )
        self.assertNotIn("\n", line)
        self.assertIn("line one line two", line)
        reason = line.split("reason=", 1)[1]
        self.assertLessEqual(len(reason), 256)


class ProductionCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_workspace(self._tmp.name)
        self.domains = self.root / "domains.txt"
        self.domains.write_text(f"{ROOT}\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, argv, *, preflight_fn):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(
            argv,
            stdout=out,
            stderr=err,
            expected_root=self.root,
            production_preflight_fn=preflight_fn,
        )
        return code, out.getvalue(), err.getvalue()

    def base_argv(self, *extra):
        return [
            "--workspace-root",
            str(self.root),
            "--domains",
            str(self.domains),
            "--run-id",
            RUN_ID,
            *extra,
        ]

    def ok_preflight(self, provider=None, fac=None):
        fac = fac if fac is not None else fake_factories()[0]
        provider = provider if provider is not None else FakeProvider()
        runtime = FakeRuntime(fac, provider)
        report = cli.ProductionPreflightReport(ok=True, runtime_obj=runtime)

        def fn(**kwargs):
            self.assertEqual(kwargs["scope"].authorized_domains, (ROOT,))
            return report

        return fn, provider

    def failing_preflight(self):
        def fn(**kwargs):
            return cli.ProductionPreflightReport(ok=False, blocked_reason="runtime:x")

        return fn

    def test_validate_only_ok_creates_nothing(self):
        fn, _ = self.ok_preflight()
        code, out, _ = self.run_cli(self.base_argv("--validate-only"), preflight_fn=fn)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("mode: validate-only", out)
        self.assertEqual(list((self.root / "projects").iterdir()), [])

    def test_validate_only_failure_nonzero(self):
        code, out, _ = self.run_cli(
            self.base_argv("--validate-only"), preflight_fn=self.failing_preflight()
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("blocked", out)

    def test_actual_requires_confirm(self):
        fn, _ = self.ok_preflight()
        code, _, err = self.run_cli(self.base_argv(), preflight_fn=fn)
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("--confirm-authorized", err)
        self.assertFalse((self.root / "projects" / ROOT / "recon").exists())

    def test_actual_requires_explicit_run_id(self):
        fn, _ = self.ok_preflight()
        argv = [
            "--workspace-root",
            str(self.root),
            "--domains",
            str(self.domains),
            "--confirm-authorized",
        ]
        code, _, err = self.run_cli(argv, preflight_fn=fn)
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("--run-id", err)

    def test_actual_blocks_when_preflight_fails(self):
        code, _, err = self.run_cli(
            self.base_argv("--confirm-authorized"),
            preflight_fn=self.failing_preflight(),
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertFalse((self.root / "projects" / ROOT).exists())

    def test_actual_blocks_on_prior_run(self):
        run_dir = self.root / "projects" / ROOT / "recon" / "20250101T000000Z-000000"
        run_dir.mkdir(parents=True)
        fn, _ = self.ok_preflight()
        code, _, err = self.run_cli(
            self.base_argv("--confirm-authorized"), preflight_fn=fn
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("one-run", err)

    def test_actual_allows_valid_historical_recon_002_run(self):
        historical_id = "20261004T110717Z-94fa0e"
        run_dir = self.root / "projects" / ROOT / "recon" / historical_id
        run_dir.mkdir(parents=True)
        document = {
            "package": "RECON-002",
            "root_domain": ROOT,
            "run_id": historical_id,
            "launch_budget_consumed": True,
        }
        for filename in ("run.json", "launch-marker.json"):
            (run_dir / filename).write_text(json.dumps(document), encoding="utf-8")
        fn, _ = self.ok_preflight()
        code, _, err = self.run_cli(
            self.base_argv("--confirm-authorized"), preflight_fn=fn
        )
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertTrue(run_dir.is_dir())

    def test_recon_003_package_labels_are_current(self):
        fn, _ = self.ok_preflight()
        code, out, err = self.run_cli(
            self.base_argv("--validate-only"), preflight_fn=fn
        )
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn("RECON-003 recon plan", out)
        self.assertIn("RECON-003 production preflight", out)

    def test_actual_run_writes_evidence_and_marker(self):
        fn, provider = self.ok_preflight()
        code, out, err = self.run_cli(
            self.base_argv("--confirm-authorized"), preflight_fn=fn
        )
        self.assertEqual(code, cli.EXIT_OK, err)
        run_dir = self.root / "projects" / ROOT / "recon" / RUN_ID
        self.assertTrue((run_dir / "launch-marker.json").is_file())
        self.assertTrue((run_dir / "evidence" / "network-policy.json").is_file())
        marker = json.loads((run_dir / "launch-marker.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["package"], PACKAGE_NAME)
        policy = json.loads(
            (run_dir / "evidence" / "network-policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(policy["package"], PACKAGE_NAME)
        self.assertEqual(policy["root_domain"], ROOT)
        doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["package"], PACKAGE_NAME)
        self.assertTrue(doc["launch_budget_consumed"])

    def test_actual_failure_retains_run_dir_and_failure_evidence(self):
        class ExplodingProvider(FakeProvider):
            def document(self, *, run_id, root, status="completed"):
                raise RuntimeError("evidence boom")

        fn, _ = self.ok_preflight(provider=ExplodingProvider())
        code, _, err = self.run_cli(
            self.base_argv("--confirm-authorized"), preflight_fn=fn
        )
        self.assertEqual(code, cli.EXIT_RUNTIME)
        run_dir = self.root / "projects" / ROOT / "recon" / RUN_ID
        self.assertTrue(run_dir.is_dir())
        failure = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(failure["status"], "failed")
        self.assertIn("evidence boom", failure["error"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
