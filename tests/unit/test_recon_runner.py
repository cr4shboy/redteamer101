"""Offline tests for the production sandbox runner (fake helper only)."""

import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.runner import (
    DenyBroker,
    HelperOutcome,
    SandboxRunnerError,
    SandboxToolRunner,
    ToolScopedBroker,
    _kill_process_group,
)
from red_teaming.recon.tool_argv import LIVE, ToolCommandSpec, expected_live_argv


class FakeHelper:
    """A helper stand-in that records payloads and writes bounded outputs."""

    def __init__(self, *, exit_code=0, stdout="", stderr="", timed_out=False, error=None):
        self.payloads = []
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.error = error

    def __call__(self, config, status_parent, deadline):
        payload = json.loads(config.exec_payload)
        self.payloads.append(payload)
        Path(payload["stdout_path"]).write_bytes(self.stdout.encode("utf-8"))
        Path(payload["stderr_path"]).write_bytes(self.stderr.encode("utf-8"))
        Path(payload["status_path"]).write_text(
            json.dumps(
                {
                    "exit_code": None if self.timed_out else self.exit_code,
                    "timed_out": self.timed_out,
                    "error": self.error,
                    "stdout_bytes": len(self.stdout),
                    "stderr_bytes": len(self.stderr),
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
            ),
            encoding="utf-8",
        )
        events = (
            {"event": "ready", "uid": 0, "route4": "", "route6": ""},
            {"event": "tool_exit", "exit_code": self.exit_code},
            {"event": "stopped"},
        )
        return HelperOutcome(returncode=self.exit_code, events=events, timed_out=self.timed_out)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.exe = self.work / "subfinder"
        self.exe.write_text("fake\n", encoding="utf-8")
        self.spec = ToolCommandSpec(
            "subfinder", "2.16.0", str(self.exe), root="acme.example"
        )
        self.helper = FakeHelper(stdout=json.dumps({"host": "www.acme.example"}) + "\n")

    def tearDown(self):
        self._tmp.cleanup()

    def runner(self, **kwargs):
        kwargs.setdefault("helper_runner", self.helper)
        kwargs.setdefault("http_port", 18080)
        return SandboxToolRunner(spec=self.spec, work_dir=self.work, **kwargs)

    def test_refuses_arbitrary_argv(self):
        runner = self.runner()
        with self.assertRaises(OSError):
            runner(["/bin/sh", "-c", "id"])
        with self.assertRaises(OSError):
            runner((str(self.exe), "-d", "example.com"))

    def test_live_invocation_runs_exact_argv_with_loopback_proxy(self):
        runner = self.runner()
        completed = runner(expected_live_argv(self.spec))
        self.assertEqual(completed.returncode, 0)
        self.assertIn("www.acme.example", completed.stdout)
        payload = self.helper.payloads[0]
        self.assertEqual(tuple(payload["argv"]), expected_live_argv(self.spec))
        self.assertEqual(payload["cwd"], str(self.work))
        self.assertEqual(payload["env"]["HTTP_PROXY"], "http://127.0.0.1:18080")
        self.assertEqual(payload["env"]["HTTPS_PROXY"], "http://127.0.0.1:18080")
        self.assertEqual(payload["env"]["NO_PROXY"], "")
        # No other proxy-like names leaked.
        self.assertFalse(
            any("proxy" in name.lower() for name in payload["env"] if name not in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"))
        )

    def test_live_env_drops_secrets_and_inherited_proxies(self):
        runner = self.runner()
        runner(
            expected_live_argv(self.spec),
            env={
                "HOME": str(self.work),
                "HTTP_PROXY": "http://evil.example:1",
                "API_TOKEN": "secret",
                "AWS_SECRET_ACCESS_KEY": "secret",
            },
        )
        env = self.helper.payloads[0]["env"]
        self.assertNotIn("API_TOKEN", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:18080")

    def test_inspection_uses_no_proxy_and_deny_broker(self):
        self.helper.stdout = "subfinder v2.16.0"
        runner = self.runner()
        runner((str(self.exe), "-version"))
        payload = self.helper.payloads[0]
        self.assertEqual(payload["argv"], [str(self.exe), "-version"])
        self.assertFalse(any("proxy" in name.lower() for name in payload["env"]))
        self.assertIsInstance(runner._broker_for("inspection"), DenyBroker)
        self.assertEqual(runner.evidence[0]["invocation"], "inspection")

    def _amass_spec(self):
        exe = self.work / "amass"
        exe.write_text("fake\n", encoding="utf-8")
        return exe, ToolCommandSpec(
            "amass",
            "5.1.1",
            str(exe),
            root="acme.example",
            domain_option="-d",
            output_prefix=str(self.work / "amass-enum"),
        )

    def _amass_runner(self, *, spec, helper):
        # Off-platform tests inject the launcher predicate; production uses the
        # real exact ``/usr/bin/nohup`` existence/executable check.
        return SandboxToolRunner(
            spec=spec,
            work_dir=self.work,
            helper_runner=helper,
            http_port=18080,
            amass_launcher_check=lambda path: True,
        )

    def test_amass_inspection_argv_is_exactly_allowlisted(self):
        exe, spec = self._amass_spec()
        helper = FakeHelper(stdout="enum -passive -d DOMAIN -oA PREFIX -include SOURCES")
        runner = self._amass_runner(spec=spec, helper=helper)
        runner((str(exe), "enum", "-help"))
        self.assertEqual(helper.payloads[0]["argv"], [str(exe), "enum", "-help"])
        self.assertEqual(runner.evidence[0]["invocation"], "inspection")
        # The short/reserved form is refused before any process is launched.
        with self.assertRaises(SandboxRunnerError):
            runner((str(exe), "enum", "-h"))

    def test_amass_child_path_is_exact_system_dir(self):
        exe, spec = self._amass_spec()
        helper = FakeHelper(stdout="enum -passive -d DOMAIN -oA PREFIX -include SOURCES")
        runner = self._amass_runner(spec=spec, helper=helper)
        # Inspection payload.
        runner((str(exe), "enum", "-help"))
        env = helper.payloads[0]["env"]
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(helper.payloads[0]["argv"][0], str(exe))
        # Live payload.
        runner(expected_live_argv(spec))
        env = helper.payloads[1]["env"]
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(helper.payloads[1]["argv"][0], str(exe))
        # Live still carries the exact loopback proxy wiring.
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:18080")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:18080")
        self.assertEqual(env["NO_PROXY"], "")

    def test_amass_path_does_not_inherit_host_or_pinned_entries(self):
        exe, spec = self._amass_spec()
        helper = FakeHelper(stdout="enum -passive -d -oA -include")
        runner = self._amass_runner(spec=spec, helper=helper)
        runner(
            (str(exe), "enum", "-help"),
            env={
                "PATH": "/evil/bin:/mnt/c/Windows/System32:"
                + str(exe.parent)
            },
        )
        env = helper.payloads[0]["env"]
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertNotIn("/evil/bin", env["PATH"])
        self.assertNotIn("Windows", env["PATH"])
        self.assertNotIn(str(exe.parent), env["PATH"])

    def test_amass_launcher_directory_requires_executable_launcher(self):
        from red_teaming.recon.runner import (
            AMASS_LAUNCHER_DIR,
            AMASS_LAUNCHER_PATH,
            _amass_launcher_directory,
        )

        self.assertEqual(AMASS_LAUNCHER_PATH, "/usr/bin/nohup")
        self.assertEqual(AMASS_LAUNCHER_DIR, "/usr/bin")
        self.assertEqual(
            _amass_launcher_directory(is_executable=lambda path: True), "/usr/bin"
        )
        with self.assertRaises(SandboxRunnerError):
            _amass_launcher_directory(is_executable=lambda path: False)

    def test_amass_launcher_failure_fails_closed_at_construction(self):
        _exe, spec = self._amass_spec()
        with self.assertRaises(SandboxRunnerError):
            SandboxToolRunner(
                spec=spec,
                work_dir=self.work,
                helper_runner=FakeHelper(),
                http_port=18080,
                amass_launcher_check=lambda path: False,
            )

    def test_subfinder_path_is_unchanged(self):
        helper = FakeHelper(stdout="subfinder v2.16.0")
        runner = self.runner(helper_runner=helper)
        runner((str(self.exe), "-version"), env={"PATH": "/usr/bin:/bin"})
        env = helper.payloads[0]["env"]
        # Subfinder inherits (does not override) PATH; no Amass wiring leaks.
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        # With no base PATH, no PATH is injected for subfinder.
        helper2 = FakeHelper(stdout="subfinder v2.16.0")
        runner2 = self.runner(helper_runner=helper2)
        runner2((str(self.exe), "-version"))
        self.assertNotIn("PATH", helper2.payloads[0]["env"])

    def test_dnsx_path_is_unchanged(self):
        dns_spec = ToolCommandSpec(
            "dnsx", "1.3.1", str(self.exe), root="acme.example"
        )
        helper = FakeHelper(stdout="")
        runner = SandboxToolRunner(
            spec=dns_spec, work_dir=self.work, helper_runner=helper, http_port=18080
        )
        runner(expected_live_argv(dns_spec), env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(helper.payloads[0]["env"]["PATH"], "/usr/bin:/bin")

    def test_live_broker_is_scoped_by_tool_identity(self):
        subfinder_broker = self.runner()._broker_for(LIVE)
        self.assertIsInstance(subfinder_broker, ToolScopedBroker)
        self.assertEqual(subfinder_broker.allowed_channels, frozenset({"connect"}))

        dns_spec = ToolCommandSpec(
            "dnsx", "1.3.1", str(self.exe), root="acme.example"
        )
        dnsx_runner = SandboxToolRunner(
            spec=dns_spec, work_dir=self.work, helper_runner=self.helper, http_port=18080
        )
        dnsx_broker = dnsx_runner._broker_for(LIVE)
        self.assertIsInstance(dnsx_broker, ToolScopedBroker)
        self.assertEqual(dnsx_broker.allowed_channels, frozenset({"dns"}))

    def test_stdin_is_written_and_referenced(self):
        self.helper.stdout = ""
        runner = self.runner()
        dns_spec = ToolCommandSpec(
            "dnsx", "1.3.1", str(self.exe), root="acme.example"
        )
        runner = SandboxToolRunner(spec=dns_spec, work_dir=self.work, helper_runner=self.helper, http_port=18080)
        runner(expected_live_argv(dns_spec), input="a.acme.example\n")
        payload = self.helper.payloads[0]
        self.assertIsNotNone(payload["stdin_path"])
        self.assertEqual(
            Path(payload["stdin_path"]).read_text(encoding="utf-8"),
            "a.acme.example\n",
        )

    def test_timeout_raises_timeout_expired(self):
        self.helper.timed_out = True
        runner = self.runner()
        with self.assertRaises(subprocess.TimeoutExpired):
            runner(expected_live_argv(self.spec))

    def test_tool_launch_error_maps_to_oserror(self):
        self.helper.error = "PermissionError"
        runner = self.runner()
        with self.assertRaises(OSError):
            runner(expected_live_argv(self.spec))

    def test_evidence_records_invocation_and_events(self):
        runner = self.runner()
        runner(expected_live_argv(self.spec))
        entry = runner.evidence[0]
        self.assertEqual(entry["tool"], "subfinder")
        self.assertEqual(entry["invocation"], "live")
        self.assertEqual(entry["sandbox"]["event"], "ready")
        self.assertEqual(len(entry["helper_events"]), 3)


class ProcessGroupTests(unittest.TestCase):
    def test_kill_falls_back_to_kill_when_no_killpg(self):
        class Proc:
            pid = 1234
            killed = False
            def poll(self):
                return None
            def kill(self):
                self.killed = True
        proc = Proc()
        _kill_process_group(proc)
        self.assertTrue(proc.killed)

    def test_kill_is_noop_when_exited(self):
        class Proc:
            killed = False
            def poll(self):
                return 0
            def kill(self):
                self.killed = True
        proc = Proc()
        _kill_process_group(proc)
        self.assertFalse(proc.killed)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
