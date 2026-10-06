"""Offline unit tests for the ZAP daemon process manager.

All tests use a fake ``Popen`` factory, a fake process object, a fake clock,
and a fake API client. No real process is launched and no socket is opened.
"""

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from red_teaming.projects.models import ProjectDomain, Target
from red_teaming.projects.paths import ScanPath, is_within
from red_teaming.tools.zap.client import ZapApiClient
from red_teaming.tools.zap.lifecycle import (
    ConnectionRecord,
    DaemonIdentity,
    ProcessRecord,
    SystemSnapshot,
    command_line_has_dir,
    relevant_pids,
    reverify_daemon_identity,
    scope_snapshot,
    split_command_line,
    verify_daemon_identity,
)
from red_teaming.tools.zap.models import ZapApiError, ZapConfigError, ZapVersionError
from red_teaming.tools.zap.process import (
    DEFAULT_OAST_CALLBACK_PORT,
    DEFAULT_OFFLINE_GUARD_PORT,
    LOG_DIRNAME,
    OFFLINE_CONFIG_CALLHOME_TEL_ENABLED,
    OFFLINE_CONFIG_CHECK_ADDON_UPDATES,
    OFFLINE_CONFIG_CHECK_ON_START,
    OFFLINE_CONFIG_DOWNLOAD_NEW_RELEASE,
    OFFLINE_CONFIG_HTTP_PROXY_ENABLED,
    OFFLINE_CONFIG_HTTP_PROXY_HOST,
    OFFLINE_CONFIG_HTTP_PROXY_PORT,
    OFFLINE_CONFIG_INSTALL_ADDON_UPDATES,
    OFFLINE_CONFIG_INSTALL_SCANNER_RULES,
    OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR,
    OFFLINE_CONFIG_OAST_CALLBACK_PORT,
    OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR,
    SILENT_FLAG,
    STDERR_FILENAME,
    STDOUT_FILENAME,
    ZAP_HOME_DIRNAME,
    ZapDaemonIdentityError,
    ZapExecutableError,
    ZapProcessExitedError,
    ZapProcessManager,
    ZapProcessStateError,
    ZapReadyTimeoutError,
    ZapStopError,
)

API_KEY = "ephemeralkey123"


class FakeClock:
    def __init__(self, start=0.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += float(seconds)


class FakeProcess:
    def __init__(self, returncode=None, pid=4242):
        self.returncode = returncode
        self.pid = pid
        self.terminate_calls = 0
        self.kill_calls = 0
        self.on_terminate = None
        self.on_kill = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminate_calls += 1
        if self.on_terminate is not None:
            self.on_terminate(self)

    def kill(self):
        self.kill_calls += 1
        if self.on_kill is not None:
            self.on_kill(self)


class FakePopenFactory:
    def __init__(self, process):
        self.process = process
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), dict(kwargs)))
        return self.process


class FakeClient:
    """Minimal stand-in exposing only the methods the manager calls."""

    def __init__(self, versions=(), *, on_shutdown=None):
        self.versions = list(versions)
        self.shutdown_calls = 0
        self.on_shutdown = on_shutdown

    def get_version(self):
        if not self.versions:
            raise ZapApiError("not ready")
        item = self.versions.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def shutdown(self):
        self.shutdown_calls += 1
        if self.on_shutdown is not None:
            self.on_shutdown()


class FakeLifecycleSystem:
    """Injectable read-only lifecycle system for offline manager tests."""

    def __init__(self, snapshots):
        self.snapshots = list(snapshots)
        self.snapshot_calls = 0
        self.terminated = []
        self.killed = []

    def snapshot(self):
        index = min(self.snapshot_calls, len(self.snapshots) - 1)
        self.snapshot_calls += 1
        return self.snapshots[index]

    def terminate(self, pid):
        self.terminated.append(pid)

    def kill(self, pid):
        self.killed.append(pid)


def make_snapshot(
    *,
    zap_home,
    daemon_pid=555,
    launcher_pid=4242,
    command_line=None,
    creation_time=1000.0,
    api_port=18080,
    callback_port=18081,
    daemon=True,
    api_listener=True,
    callback_wildcard=False,
    method="Get-NetTCPConnection",
    processes=None,
    connections=None,
    error=None,
):
    if processes is None:
        processes = []
        if daemon:
            processes.append(
                ProcessRecord(
                    pid=daemon_pid,
                    parent_pid=launcher_pid,
                    name="javaw.exe",
                    command_line=(
                        command_line
                        if command_line is not None
                        else f'"C:\\j\\javaw.exe" -dir "{zap_home}"'
                    ),
                    executable_path="C:\\j\\javaw.exe",
                    creation_time=creation_time,
                )
            )
    if connections is None:
        connections = []
        if daemon and api_listener:
            connections.append(
                ConnectionRecord(
                    local_address="127.0.0.1",
                    local_port=api_port,
                    remote_address="0.0.0.0",
                    remote_port=0,
                    state="Listen",
                    pid=daemon_pid,
                )
            )
        if daemon and callback_port is not None:
            connections.append(
                ConnectionRecord(
                    local_address="0.0.0.0" if callback_wildcard else "127.0.0.1",
                    local_port=callback_port,
                    remote_address="0.0.0.0",
                    remote_port=0,
                    state="Listen",
                    pid=daemon_pid,
                )
            )
    return SystemSnapshot(
        method=method,
        processes=tuple(processes),
        connections=tuple(connections),
        error=error,
    )


class ProcessTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        domain = ProjectDomain.parse("example.com")
        target = Target.parse("https://app.example.com/", domain)
        self.scan = ScanPath.build(
            self.root,
            domain,
            target,
            now=datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
            suffix="abc123",
        )
        self.exe = self.root / "zap.exe"
        self.exe.write_bytes(b"")
        self.clock = FakeClock()
        self.process = FakeProcess()
        self.managers = []

    def tearDown(self):
        for manager in self.managers:
            try:
                manager.stop()
            except ZapStopError:
                # Fake processes that never exit intentionally surface a stop
                # failure; these tests do not assert on shutdown.
                pass
        self._tmp.cleanup()

    def make_manager(self, *, client=None, executable=None, process=None, **overrides):
        process = process if process is not None else self.process
        factory = FakePopenFactory(process)
        if client is None:
            client = FakeClient(["2.17.0"])
        options = dict(
            executable=executable if executable is not None else self.exe,
            scan_path=self.scan,
            api_key=API_KEY,
            client=client,
            popen_factory=factory,
            clock=self.clock,
            sleep=self.clock.sleep,
            startup_timeout=1.0,
            graceful_timeout=0.5,
            terminate_timeout=0.5,
            kill_timeout=0.5,
            poll_interval=0.25,
        )
        options.update(overrides)
        manager = ZapProcessManager(**options)
        self.managers.append(manager)
        return manager, factory, process


class CommandConstructionTests(ProcessTestCase):
    def test_command_is_deterministic_and_loopback_bound(self):
        manager, _, _ = self.make_manager()
        command = manager._build_command()
        self.assertEqual(command[0], str(self.exe))
        self.assertIn("-daemon", command)
        self.assertEqual(command[command.index("-host") + 1], "127.0.0.1")
        self.assertEqual(command[command.index("-port") + 1], "8080")
        self.assertEqual(command[command.index("-dir") + 1], str(manager.zap_home))
        self.assertIn("api.disablekey=false", command)
        self.assertIn(f"api.key={API_KEY}", command)

    def test_command_never_contains_a_target_url(self):
        manager, _, _ = self.make_manager()
        command = manager._build_command()
        joined = " ".join(command)
        # No URL-form target anywhere in the argv vector.
        self.assertNotIn("://", joined)
        # The only argument allowed to mention the domain is the local -dir path.
        dir_path = str(manager.zap_home)
        for arg in command:
            if arg == dir_path:
                continue
            self.assertNotIn("example.com", arg)

    def test_safe_command_redacts_key(self):
        manager, _, _ = self.make_manager()
        safe = manager.safe_command()
        self.assertNotIn(API_KEY, " ".join(safe))
        self.assertIn("api.key=***", safe)

    def test_silent_flag_is_off_by_default(self):
        # The default (key-holding) manager makes no unsolicited request anyway,
        # so ``-silent`` is not added unless explicitly requested.
        manager, _, _ = self.make_manager()
        self.assertFalse(manager.silent)
        self.assertNotIn(SILENT_FLAG, manager._build_command())

    def test_silent_flag_is_added_when_requested(self):
        manager, _, _ = self.make_manager(silent=True)
        self.assertTrue(manager.silent)
        command = manager._build_command()
        self.assertIn(SILENT_FLAG, command)
        # The flag is a bare switch, never a ``-config`` pair, and introduces no
        # target or external hostname.
        self.assertNotIn(f"config={SILENT_FLAG}", " ".join(command))
        self.assertNotIn("://", " ".join(command))
        self.assertEqual(SILENT_FLAG, "-silent")

    def test_repr_redacts_key(self):
        manager, _, _ = self.make_manager()
        self.assertNotIn(API_KEY, repr(manager))


class KeylessProcessTests(ProcessTestCase):
    """Explicit keyless daemon mode for the local health smoke."""

    def test_default_mode_still_requires_and_redacts_a_key(self):
        with self.assertRaises(ZapConfigError):
            self.make_manager(api_key=None)
        manager, _, _ = self.make_manager()
        self.assertFalse(manager.keyless)
        self.assertIn("api.disablekey=false", manager._build_command())
        self.assertIn(f"api.key={API_KEY}", manager._build_command())
        self.assertIn("api.key=***", manager.safe_command())

    def test_keyless_command_disables_key_and_omits_api_key(self):
        keyless_client = ZapApiClient(
            "http://127.0.0.1:8080", None, keyless=True
        )
        manager, _, _ = self.make_manager(
            api_key=None, keyless=True, client=keyless_client
        )
        command = manager._build_command()
        self.assertTrue(manager.keyless)
        self.assertIn("api.disablekey=true", command)
        self.assertNotIn("api.disablekey=false", command)
        self.assertFalse(any(arg.startswith("api.key=") for arg in command))
        self.assertFalse(any(arg.startswith("api.key=") for arg in manager.safe_command()))

    def test_keyless_rejects_a_supplied_api_key(self):
        with self.assertRaises(ZapConfigError):
            self.make_manager(api_key=API_KEY, keyless=True)

    def test_keyless_flag_must_be_a_boolean(self):
        with self.assertRaises(ZapConfigError):
            self.make_manager(api_key=None, keyless="yes")

    def test_injected_client_keyless_mode_must_match(self):
        # A protected manager cannot silently pair with a keyless client.
        with self.assertRaises(ZapConfigError):
            self.make_manager(
                client=ZapApiClient("http://127.0.0.1:8080", None, keyless=True)
            )
        # A keyless manager cannot silently pair with a protected client.
        with self.assertRaises(ZapConfigError):
            self.make_manager(
                api_key=None,
                keyless=True,
                client=ZapApiClient("http://127.0.0.1:8080", API_KEY),
            )
        # Matching keyless modes are accepted.
        manager, _, _ = self.make_manager(
            api_key=None,
            keyless=True,
            client=ZapApiClient("http://127.0.0.1:8080", None, keyless=True),
        )
        self.assertTrue(manager.keyless)

    def test_repr_shows_keyless_without_implying_a_secret(self):
        keyless_client = ZapApiClient("http://127.0.0.1:8080", None, keyless=True)
        manager, _, _ = self.make_manager(
            api_key=None, keyless=True, client=keyless_client
        )
        text = repr(manager)
        self.assertIn("keyless=True", text)
        self.assertNotIn("api.key=", text)
        self.assertNotIn("***", text)


class OfflineSmokeTests(ProcessTestCase):
    """Offline-smoke hardening flags and loopback guard validation."""

    @staticmethod
    def _config_pairs(command):
        pairs = []
        index = 0
        while index < len(command):
            if command[index] == "-config":
                pairs.append(command[index + 1])
                index += 2
            else:
                index += 1
        return pairs

    def test_offline_smoke_defaults_off(self):
        manager, _, _ = self.make_manager()
        self.assertFalse(manager.offline_smoke)
        pairs = self._config_pairs(manager._build_command())
        self.assertNotIn(f"{OFFLINE_CONFIG_CHECK_ON_START}=false", pairs)
        self.assertNotIn(f"{OFFLINE_CONFIG_CALLHOME_TEL_ENABLED}=false", pairs)
        self.assertFalse(
            any(pair.startswith(f"{OFFLINE_CONFIG_HTTP_PROXY_ENABLED}=") for pair in pairs)
        )
        # OAST containment is absent in normal (non-offline) mode.
        self.assertFalse(
            any(pair.startswith(f"{OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR}=") for pair in pairs)
        )
        self.assertFalse(
            any(pair.startswith(f"{OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR}=") for pair in pairs)
        )
        self.assertFalse(
            any(pair.startswith(f"{OFFLINE_CONFIG_OAST_CALLBACK_PORT}=") for pair in pairs)
        )

    def test_offline_smoke_adds_all_hardening_flags(self):
        manager, _, _ = self.make_manager(offline_smoke=True)
        pairs = self._config_pairs(manager._build_command())
        for expected in (
            f"{OFFLINE_CONFIG_CHECK_ON_START}=false",
            f"{OFFLINE_CONFIG_DOWNLOAD_NEW_RELEASE}=false",
            f"{OFFLINE_CONFIG_CHECK_ADDON_UPDATES}=false",
            f"{OFFLINE_CONFIG_INSTALL_ADDON_UPDATES}=false",
            f"{OFFLINE_CONFIG_INSTALL_SCANNER_RULES}=false",
            f"{OFFLINE_CONFIG_CALLHOME_TEL_ENABLED}=false",
            f"{OFFLINE_CONFIG_HTTP_PROXY_ENABLED}=true",
            f"{OFFLINE_CONFIG_HTTP_PROXY_HOST}=127.0.0.1",
            f"{OFFLINE_CONFIG_HTTP_PROXY_PORT}={DEFAULT_OFFLINE_GUARD_PORT}",
            f"{OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR}=127.0.0.1",
            f"{OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR}=127.0.0.1",
            f"{OFFLINE_CONFIG_OAST_CALLBACK_PORT}={DEFAULT_OAST_CALLBACK_PORT}",
        ):
            self.assertIn(expected, pairs)

    def test_offline_smoke_oast_containment_is_exact_and_fixed(self):
        manager, _, _ = self.make_manager(offline_smoke=True)
        pairs = self._config_pairs(manager._build_command())
        oast = {
            OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR: "127.0.0.1",
            OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR: "127.0.0.1",
            OFFLINE_CONFIG_OAST_CALLBACK_PORT: str(DEFAULT_OAST_CALLBACK_PORT),
        }
        for key, value in oast.items():
            self.assertIn(f"{key}={value}", pairs)
        self.assertEqual(DEFAULT_OAST_CALLBACK_PORT, 18081)
        # The OAST port is deterministic and not derived from the configurable
        # guard port.
        self.assertEqual(
            pairs.count(
                f"{OFFLINE_CONFIG_OAST_CALLBACK_PORT}={DEFAULT_OAST_CALLBACK_PORT}"
            ),
            1,
        )

    def test_offline_smoke_guard_port_is_configurable(self):
        manager, _, _ = self.make_manager(offline_smoke=True, guard_port=9)
        pairs = self._config_pairs(manager._build_command())
        self.assertIn(f"{OFFLINE_CONFIG_HTTP_PROXY_PORT}=9", pairs)
        self.assertEqual(manager.guard_endpoint.port, 9)
        self.assertEqual(manager.guard_endpoint.host, "127.0.0.1")

    def test_guard_endpoint_validation(self):
        for port in [0, 65536, True, "1"]:
            with self.subTest(port=port):
                with self.assertRaises(ZapConfigError):
                    self.make_manager(offline_smoke=True, guard_port=port)
        with self.assertRaises(ZapConfigError):
            self.make_manager(offline_smoke=True, guard_host="example.com")
        with self.assertRaises(ZapConfigError):
            self.make_manager(offline_smoke=True, guard_host="10.0.0.1")

    def test_offline_command_never_adds_a_target_or_external_host(self):
        manager, _, _ = self.make_manager(offline_smoke=True, api_key=None, keyless=True)
        command = manager._build_command()
        joined = " ".join(command)
        self.assertNotIn("://", joined)
        for arg in command:
            if arg == str(manager.zap_home):
                continue
            self.assertNotIn("example.com", arg)
        # The only host-like values are the loopback bind and guard endpoints.
        self.assertNotIn("0.0.0.0", joined)
        self.assertNotIn("localhost", joined)

    def test_offline_command_keeps_configuration_scan_local(self):
        manager, _, _ = self.make_manager(offline_smoke=True)
        command = manager._build_command()
        self.assertEqual(command[command.index("-dir") + 1], str(manager.zap_home))
        self.assertTrue(is_within(manager.zap_home, manager.scan_dir))

    def test_keyless_and_offline_smoke_combine(self):
        manager, _, _ = self.make_manager(
            api_key=None, keyless=True, offline_smoke=True
        )
        command = manager._build_command()
        self.assertIn("api.disablekey=true", command)
        self.assertFalse(any(arg.startswith("api.key=") for arg in command))
        pairs = self._config_pairs(command)
        self.assertIn(f"{OFFLINE_CONFIG_HTTP_PROXY_PORT}=1", pairs)

    def test_offline_smoke_enables_silent_unsolicited_request_suppression(self):
        # Offline smoke must suppress ZAP-initiated unsolicited requests (the
        # auto-update/news fetch) so no off-host egress is ever attempted, even
        # with a closed guard port.
        manager, _, _ = self.make_manager(offline_smoke=True)
        self.assertTrue(manager.silent)
        self.assertIn(SILENT_FLAG, manager._build_command())
        # Disabling the offline smoke removes it again.
        manager_plain, _, _ = self.make_manager(offline_smoke=False)
        self.assertFalse(manager_plain.silent)
        self.assertNotIn(SILENT_FLAG, manager_plain._build_command())


class ScanLayoutTests(ProcessTestCase):
    def test_start_creates_only_process_directories_under_scan(self):
        manager, _, _ = self.make_manager()
        manager.start()
        self.assertTrue(manager.zap_home.is_dir())
        self.assertTrue(manager.logs_dir.is_dir())
        self.assertEqual(manager.zap_home, manager.scan_dir / ZAP_HOME_DIRNAME)
        self.assertEqual(manager.logs_dir, manager.scan_dir / LOG_DIRNAME)
        self.assertTrue(is_within(manager.zap_home, manager.scan_dir))
        self.assertTrue(is_within(manager.logs_dir, manager.scan_dir))

    def test_logs_are_captured_under_the_scan_directory(self):
        manager, factory, _ = self.make_manager()
        manager.start()
        _, kwargs = factory.calls[0]
        self.assertEqual(Path(kwargs["stdout"].name), manager.stdout_path)
        self.assertEqual(Path(kwargs["stderr"].name), manager.stderr_path)
        self.assertEqual(manager.stdout_path.name, STDOUT_FILENAME)
        self.assertEqual(manager.stderr_path.name, STDERR_FILENAME)
        self.assertTrue(manager.stdout_path.is_file())
        self.assertTrue(manager.stderr_path.is_file())
        self.assertTrue(is_within(manager.stdout_path, manager.logs_dir))

    def test_start_uses_shell_false_and_executable_parent_cwd(self):
        manager, factory, _ = self.make_manager()
        manager.start()
        _, kwargs = factory.calls[0]
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["cwd"], str(manager._executable.parent))
        self.assertNotEqual(kwargs["cwd"], str(manager.scan_dir))
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_start_cwd_supports_executable_path_with_spaces(self):
        install_dir = self.root / "Program Files" / "Zed Attack Proxy"
        install_dir.mkdir(parents=True)
        exe = install_dir / "ZAP.exe"
        exe.write_bytes(b"MZ fake")

        manager, factory, _ = self.make_manager(executable=exe)
        manager.start()
        command, kwargs = factory.calls[0]
        self.assertEqual(kwargs["cwd"], str(install_dir))
        self.assertIn(" ", str(kwargs["cwd"]))
        self.assertEqual(command[0], str(exe))
        # The project-local ZAP home stays routed through -dir under the scan
        # directory even though the process cwd is the install directory.
        self.assertEqual(command[command.index("-dir") + 1], str(manager.zap_home))
        self.assertTrue(is_within(manager.zap_home, manager.scan_dir))


class StartGuardTests(ProcessTestCase):
    def test_relative_executable_is_rejected(self):
        with self.assertRaises(ZapConfigError):
            ZapProcessManager(
                executable="zap.exe",
                scan_path=self.scan,
                api_key=API_KEY,
            )

    def test_non_loopback_host_is_rejected(self):
        with self.assertRaises(ZapConfigError):
            self.make_manager(host="example.com")

    def test_double_start_is_rejected(self):
        manager, _, _ = self.make_manager()
        manager.start()
        with self.assertRaises(ZapProcessStateError):
            manager.start()

    def test_missing_executable_is_rejected_before_side_effects(self):
        missing = self.root / "does-not-exist.exe"
        manager, factory, _ = self.make_manager(executable=missing)
        with self.assertRaises(ZapExecutableError):
            manager.start()
        self.assertEqual(factory.calls, [])
        self.assertFalse(manager.scan_dir.exists())

    def test_directory_executable_is_rejected(self):
        self.scan.create()
        manager, factory, _ = self.make_manager(executable=self.scan.scan_dir)
        with self.assertRaises(ZapExecutableError):
            manager.start()
        self.assertEqual(factory.calls, [])

    def test_blank_api_key_is_rejected(self):
        with self.assertRaises(ZapConfigError):
            self.make_manager(api_key="   ")

    def test_invalid_timeout_is_rejected(self):
        with self.assertRaises(ZapConfigError):
            self.make_manager(startup_timeout=0)

    def test_client_factory_is_resolved_lazily(self):
        calls = []

        def factory_client():
            calls.append(1)
            return FakeClient(["2.17.0"])

        manager, _, _ = self.make_manager(client=factory_client)
        self.assertEqual(calls, [])
        manager.start()
        manager.wait_until_ready()
        self.assertEqual(len(calls), 1)


class ReadinessTests(ProcessTestCase):
    def test_readiness_success(self):
        manager, _, _ = self.make_manager(client=FakeClient(["2.17.0"]))
        manager.start()
        self.assertEqual(manager.wait_until_ready(), "2.17.0")
        self.assertTrue(manager.ready)

    def test_readiness_timeout(self):
        manager, _, _ = self.make_manager(client=FakeClient([ZapApiError("down")]))
        manager.start()
        with self.assertRaises(ZapReadyTimeoutError):
            manager.wait_until_ready()
        self.assertFalse(manager.ready)

    def test_readiness_detects_premature_exit(self):
        manager, _, process = self.make_manager(client=FakeClient(["2.17.0"]))
        manager.start()
        process.returncode = 1
        with self.assertRaises(ZapProcessExitedError):
            manager.wait_until_ready()

    def test_readiness_rejects_old_version(self):
        manager, _, _ = self.make_manager(client=FakeClient(["2.16.1"]))
        manager.start()
        with self.assertRaises(ZapVersionError):
            manager.wait_until_ready()
        self.assertFalse(manager.ready)

    def test_wait_before_start_is_rejected(self):
        manager, _, _ = self.make_manager()
        with self.assertRaises(ZapProcessStateError):
            manager.wait_until_ready()


class ShutdownTests(ProcessTestCase):
    def test_graceful_shutdown_via_api(self):
        process = FakeProcess()

        def exit_on_shutdown():
            process.returncode = 0

        client = FakeClient(["2.17.0"], on_shutdown=exit_on_shutdown)
        manager, _, _ = self.make_manager(client=client, process=process)
        manager.start()
        manager.wait_until_ready()
        manager.stop()
        self.assertEqual(client.shutdown_calls, 1)
        self.assertEqual(process.terminate_calls, 0)
        self.assertEqual(process.kill_calls, 0)
        self.assertIsNone(manager._process)

    def test_terminate_fallback(self):
        process = FakeProcess()
        process.on_terminate = lambda p: setattr(p, "returncode", 0)
        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"]), process=process
        )
        manager.start()
        manager.wait_until_ready()
        manager.stop()
        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 0)
        self.assertIsNone(manager._process)

    def test_kill_fallback(self):
        process = FakeProcess()
        process.on_kill = lambda p: setattr(p, "returncode", -9)
        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"]), process=process
        )
        manager.start()
        manager.wait_until_ready()
        manager.stop()
        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 1)
        self.assertIsNone(manager._process)

    def test_stop_is_idempotent_and_closes_logs(self):
        process = FakeProcess()

        def exit_on_shutdown():
            process.returncode = 0

        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"], on_shutdown=exit_on_shutdown),
            process=process,
        )
        manager.start()
        stdout_handle = manager._stdout_handle
        manager.stop()
        manager.stop()
        self.assertIsNone(manager._process)
        self.assertIsNone(manager._stdout_handle)
        self.assertIsNone(manager._stderr_handle)
        self.assertTrue(stdout_handle.closed)

    def test_stop_before_start_is_safe(self):
        manager, _, _ = self.make_manager()
        manager.stop()
        self.assertIsNone(manager._process)

    def test_stop_when_process_already_exited(self):
        process = FakeProcess(returncode=0)
        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"]), process=process
        )
        manager.start()
        manager.stop()
        self.assertEqual(process.terminate_calls, 0)
        self.assertEqual(process.kill_calls, 0)
        self.assertIsNone(manager._process)


class StopFailureTests(ProcessTestCase):
    def test_process_survives_kill_raises_and_retains_handle(self):
        process = FakeProcess()
        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"]), process=process
        )
        manager.start()
        manager.wait_until_ready()
        stdout_handle = manager._stdout_handle

        with self.assertRaises(ZapStopError):
            manager.stop()

        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 1)
        # A still-live process handle must not be silently discarded.
        self.assertIs(manager._process, process)
        self.assertFalse(manager.ready)
        self.assertIsNone(manager._stdout_handle)
        self.assertIsNone(manager._stderr_handle)
        self.assertTrue(stdout_handle.closed)

        # Let the process exit so tearDown's idempotent stop can succeed.
        process.returncode = -9

    def test_stop_retry_after_failed_stop_succeeds(self):
        process = FakeProcess()
        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"]), process=process
        )
        manager.start()
        manager.wait_until_ready()

        with self.assertRaises(ZapStopError):
            manager.stop()
        self.assertIs(manager._process, process)

        # The process dies later; a retried stop clears the retained handle.
        process.returncode = 0
        manager.stop()
        self.assertIsNone(manager._process)

        # Once cleared, further stops remain safe no-ops.
        manager.stop()
        self.assertIsNone(manager._process)


class CommandLineMarkerTests(unittest.TestCase):
    """Windows-quoting-tolerant, argument-bounded ``-dir`` matching."""

    def test_split_tolerates_quoted_path_with_spaces(self):
        args = split_command_line(
            '"C:\\Program Files\\Zed Attack Proxy\\ZAP.exe" -daemon '
            '-dir "C:\\work\\my zap home"'
        )
        self.assertEqual(
            args,
            [
                "C:\\Program Files\\Zed Attack Proxy\\ZAP.exe",
                "-daemon",
                "-dir",
                "C:\\work\\my zap home",
            ],
        )

    def test_exact_dir_argument_matches(self):
        self.assertTrue(
            command_line_has_dir(
                'javaw -dir "C:\\work\\my zap home"', "C:\\work\\my zap home"
            )
        )
        self.assertTrue(
            command_line_has_dir(
                'javaw -dir="C:\\work\\my zap home"', "C:\\work\\my zap home"
            )
        )

    def test_prefix_and_substring_collisions_do_not_match(self):
        home = "C:\\work\\my zap home"
        self.assertFalse(
            command_line_has_dir(f'javaw -dir "{home}-sibling"', home)
        )
        self.assertFalse(
            command_line_has_dir(f'javaw -c other="{home}"', home)
        )
        self.assertFalse(
            command_line_has_dir('javaw -dir "C:\\work\\my zap"', home)
        )

    def test_missing_command_line_never_matches(self):
        self.assertFalse(command_line_has_dir("", "C:\\work\\home"))

    def test_partial_quote_is_tolerated(self):
        self.assertTrue(
            command_line_has_dir(
                'javaw -dir "C:\\work\\my zap home', "C:\\work\\my zap home"
            )
        )


class DaemonIdentityVerificationTests(unittest.TestCase):
    """Pure, fail-closed identity verification."""

    HOME = "C:\\work\\my zap home"

    def _snapshot(self, *, owners, processes, method="Get-NetTCPConnection"):
        connections = tuple(
            ConnectionRecord(
                local_address="127.0.0.1",
                local_port=18080,
                remote_address="0.0.0.0",
                remote_port=0,
                state="Listen",
                pid=pid,
            )
            for pid in owners
        )
        return SystemSnapshot(
            method=method,
            processes=tuple(processes),
            connections=connections,
        )

    def test_verified_single_candidate(self):
        record = ProcessRecord(
            pid=10,
            parent_pid=9,
            name="javaw.exe",
            command_line=f'-dir "{self.HOME}"',
            creation_time=1000.0,
        )
        result = verify_daemon_identity(
            self._snapshot(owners=[10], processes=[record]),
            zap_home=self.HOME,
            api_port=18080,
            launcher_pid=9,
            launched_after=999.0,
        )
        self.assertTrue(result.verified)
        self.assertEqual(result.identity.pid, 10)
        self.assertTrue(result.identity.parent_matched)

    def test_absent_when_no_port_owner(self):
        result = verify_daemon_identity(
            self._snapshot(owners=[], processes=[]),
            zap_home=self.HOME,
            api_port=18080,
            launched_after=999.0,
        )
        self.assertEqual(result.status, "absent")

    def test_ambiguous_multiple_candidates(self):
        records = [
            ProcessRecord(
                pid=pid,
                command_line=f'-dir "{self.HOME}"',
                creation_time=1000.0,
            )
            for pid in (10, 11)
        ]
        result = verify_daemon_identity(
            self._snapshot(owners=[10, 11], processes=records),
            zap_home=self.HOME,
            api_port=18080,
            launched_after=999.0,
        )
        self.assertEqual(result.status, "ambiguous")

    def test_mismatched_prefix_collision(self):
        record = ProcessRecord(
            pid=10,
            command_line=f'-dir "{self.HOME}-sibling"',
            creation_time=1000.0,
        )
        result = verify_daemon_identity(
            self._snapshot(owners=[10], processes=[record]),
            zap_home=self.HOME,
            api_port=18080,
            launched_after=999.0,
        )
        self.assertEqual(result.status, "mismatched")

    def test_stale_creation_time_is_rejected(self):
        record = ProcessRecord(
            pid=10,
            command_line=f'-dir "{self.HOME}"',
            creation_time=100.0,
        )
        result = verify_daemon_identity(
            self._snapshot(owners=[10], processes=[record]),
            zap_home=self.HOME,
            api_port=18080,
            launched_after=1000.0,
        )
        self.assertEqual(result.status, "mismatched")
        self.assertIn("stale", result.reason)

    def test_missing_creation_time_fails_closed(self):
        record = ProcessRecord(
            pid=10,
            command_line=f'-dir "{self.HOME}"',
            creation_time=None,
        )
        result = verify_daemon_identity(
            self._snapshot(owners=[10], processes=[record]),
            zap_home=self.HOME,
            api_port=18080,
            launched_after=1000.0,
        )
        self.assertEqual(result.status, "mismatched")

    def test_unavailable_observation_fails_closed(self):
        result = verify_daemon_identity(
            self._snapshot(
                owners=[10],
                processes=[],
                method="Get-NetTCPConnection-unavailable",
            ),
            zap_home=self.HOME,
            api_port=18080,
            launched_after=1000.0,
        )
        self.assertEqual(result.status, "unavailable")


class DaemonIdentityContinuityTests(unittest.TestCase):
    """Pure reconfirmation of an already-verified identity (no API ownership)."""

    HOME = "C:\\work\\my zap home"

    def _identity(self, **overrides):
        values = dict(
            pid=555,
            api_port=18080,
            parent_pid=4242,
            name="javaw.exe",
            command_line=f'-dir "{self.HOME}"',
            executable_path="C:\\j\\javaw.exe",
            creation_time=1000.0,
        )
        values.update(overrides)
        return DaemonIdentity(**values)

    def _snapshot(self, record, *, method="Get-NetTCPConnection"):
        return SystemSnapshot(
            method=method,
            processes=() if record is None else (record,),
            connections=(),
        )

    def _record(self, **overrides):
        values = dict(
            pid=555,
            parent_pid=4242,
            name="javaw.exe",
            command_line=f'-dir "{self.HOME}"',
            executable_path="C:\\j\\javaw.exe",
            creation_time=1000.0,
        )
        values.update(overrides)
        return ProcessRecord(**values)

    def test_reconfirms_identity_without_api_listener(self):
        result = reverify_daemon_identity(
            self._snapshot(self._record()),
            self._identity(),
            zap_home=self.HOME,
        )
        self.assertTrue(result.verified)
        self.assertEqual(result.identity.pid, 555)

    def test_rejects_changed_creation_time(self):
        result = reverify_daemon_identity(
            self._snapshot(self._record(creation_time=9999.0)),
            self._identity(),
            zap_home=self.HOME,
        )
        self.assertEqual(result.status, "mismatched")
        self.assertIn("creation time", result.reason)

    def test_rejects_changed_command_line_marker(self):
        record = self._record(command_line=f'-dir "{self.HOME}-sibling"')
        result = reverify_daemon_identity(
            self._snapshot(record),
            self._identity(),
            zap_home=self.HOME,
        )
        self.assertEqual(result.status, "mismatched")

    def test_rejects_changed_executable(self):
        record = self._record(executable_path="C:\\other\\javaw.exe")
        result = reverify_daemon_identity(
            self._snapshot(record),
            self._identity(),
            zap_home=self.HOME,
        )
        self.assertEqual(result.status, "mismatched")

    def test_rejects_absent_process(self):
        result = reverify_daemon_identity(
            self._snapshot(None),
            self._identity(),
            zap_home=self.HOME,
        )
        self.assertEqual(result.status, "absent")

    def test_rejects_unavailable_process_observation(self):
        snapshot = SystemSnapshot(
            method="netstat",
            processes=(),
            connections=(),
        )
        result = reverify_daemon_identity(
            snapshot,
            self._identity(),
            zap_home=self.HOME,
        )
        self.assertEqual(result.status, "unavailable")


class SnapshotScopingTests(unittest.TestCase):
    """Bounded PID/connection scoping for persisted evidence."""

    def test_relevant_pids_excludes_non_positive_pid_owners(self):
        snapshot = SystemSnapshot(
            method="Get-NetTCPConnection",
            processes=(),
            connections=(
                # Kernel/system placeholder: fixed-port TIME_WAIT with PID 0.
                ConnectionRecord("127.0.0.1", 18080, "93.184.216.34", 443, "TimeWait", 0),
                # Invalid/non-positive ownership on the callback port.
                ConnectionRecord("127.0.0.1", 18081, "0.0.0.0", 0, "Listen", -1),
                # The genuine daemon owner must still be admitted.
                ConnectionRecord("127.0.0.1", 18081, "0.0.0.0", 0, "Listen", 555),
            ),
        )
        pids = relevant_pids(snapshot, api_port=18080, callback_port=18081)
        self.assertEqual(pids, {555})

    def test_relevant_pids_excludes_non_positive_extra_pids(self):
        snapshot = SystemSnapshot(
            method="Get-NetTCPConnection", processes=(), connections=()
        )
        pids = relevant_pids(
            snapshot, api_port=18080, callback_port=18081, extra_pids=(0, -5, None, 42)
        )
        self.assertEqual(pids, {42})

    def test_scope_snapshot_excludes_unrelated_pid_zero_records(self):
        snapshot = SystemSnapshot(
            method="Get-NetTCPConnection",
            processes=(
                ProcessRecord(pid=0, name="System Idle Process"),
                ProcessRecord(pid=555, name="javaw.exe"),
            ),
            connections=(
                # A fixed-port PID-0 TIME_WAIT record is port-bounded and kept.
                ConnectionRecord("127.0.0.1", 18080, "93.184.216.34", 443, "TimeWait", 0),
                # Unrelated PID-0 endpoints are not on a fixed port and drop out.
                ConnectionRecord("127.0.0.1", 51000, "8.8.8.8", 53, "TimeWait", 0),
                ConnectionRecord("127.0.0.1", 52000, "8.8.4.4", 53, "Established", 0),
                # The daemon's own listener is retained.
                ConnectionRecord("127.0.0.1", 18080, "0.0.0.0", 0, "Listen", 555),
            ),
        )
        scoped = scope_snapshot(
            snapshot, api_port=18080, callback_port=18081, extra_pids=(555,)
        )
        scoped_pids = {record.pid for record in scoped.processes}
        self.assertEqual(scoped_pids, {555})
        self.assertNotIn(0, relevant_pids(
            snapshot, api_port=18080, callback_port=18081, extra_pids=(555,)
        ))
        addresses = {
            (record.local_port, record.remote_address)
            for record in scoped.connections
        }
        self.assertIn((18080, "93.184.216.34"), addresses)
        self.assertNotIn((51000, "8.8.8.8"), addresses)
        self.assertNotIn((52000, "8.8.4.4"), addresses)
        self.assertIn((18080, "0.0.0.0"), addresses)


class SystemReadinessTests(ProcessTestCase):
    """Launcher/daemon separation during readiness with an injected system."""

    def make_system_manager(self, *, process, snapshots, client=None, **overrides):
        system = FakeLifecycleSystem(snapshots)
        options = dict(
            system=system,
            wall_clock=lambda: 1000.0,
            offline_smoke=True,
            api_key=None,
            keyless=True,
            host="127.0.0.1",
            port=18080,
        )
        options.update(overrides)
        manager, factory, proc = self.make_manager(
            process=process, client=client, **options
        )
        return manager, system, proc

    def _ready(self):
        return make_snapshot(zap_home=self.scan.scan_dir / "zap-home")

    def test_clean_launcher_exit_zero_then_verified_daemon(self):
        process = FakeProcess(returncode=0)
        manager, system, _ = self.make_system_manager(
            process=process, snapshots=[self._ready(), self._ready()]
        )
        manager.start()
        version = manager.wait_until_ready()
        self.assertEqual(version, "2.17.0")
        self.assertTrue(manager.ready)
        # Public pid/running describe the verified daemon, not the launcher.
        self.assertEqual(manager.pid, 555)
        self.assertEqual(manager.launcher_pid, 4242)
        self.assertEqual(manager.launcher_exit_code, 0)
        self.assertTrue(manager.running)

    def test_nonzero_launcher_exit_is_startup_failure(self):
        process = FakeProcess(returncode=3)
        manager, _, _ = self.make_system_manager(
            process=process, snapshots=[make_snapshot(zap_home=self.scan.scan_dir / "zap-home", daemon=False)]
        )
        manager.start()
        with self.assertRaises(ZapProcessExitedError):
            manager.wait_until_ready()

    def test_zero_candidates_times_out_without_readiness(self):
        process = FakeProcess(returncode=0)
        manager, _, _ = self.make_system_manager(
            process=process,
            snapshots=[
                make_snapshot(
                    zap_home=self.scan.scan_dir / "zap-home",
                    daemon=False,
                )
            ],
            startup_timeout=0.5,
        )
        manager.start()
        with self.assertRaises(ZapReadyTimeoutError):
            manager.wait_until_ready()
        self.assertFalse(manager.ready)
        self.assertIsNone(manager.identity)

    def test_multiple_candidates_are_ambiguous(self):
        ready = make_snapshot(
            zap_home=self.scan.scan_dir / "zap-home",
            processes=[
                ProcessRecord(
                    pid=pid,
                    command_line=f'-dir "{self.scan.scan_dir / "zap-home"}"',
                    creation_time=1000.0,
                )
                for pid in (555, 556)
            ],
            connections=[
                ConnectionRecord("127.0.0.1", 18080, "0.0.0.0", 0, "Listen", pid)
                for pid in (555, 556)
            ],
        )
        process = FakeProcess(returncode=0)
        manager, _, _ = self.make_system_manager(
            process=process, snapshots=[ready, ready]
        )
        manager.start()
        with self.assertRaises(ZapDaemonIdentityError):
            manager.wait_until_ready()

    def test_mismatched_candidate_is_rejected(self):
        ready = make_snapshot(
            zap_home=self.scan.scan_dir / "zap-home",
            command_line=f'-dir "{self.scan.scan_dir / "zap-home"}-sibling"',
        )
        process = FakeProcess(returncode=0)
        manager, _, _ = self.make_system_manager(
            process=process, snapshots=[ready, ready]
        )
        manager.start()
        with self.assertRaises(ZapDaemonIdentityError):
            manager.wait_until_ready()

    def test_stale_pid_reuse_is_rejected(self):
        ready = make_snapshot(
            zap_home=self.scan.scan_dir / "zap-home", creation_time=1.0
        )
        process = FakeProcess(returncode=0)
        manager, _, _ = self.make_system_manager(
            process=process, snapshots=[ready, ready]
        )
        manager.start()
        with self.assertRaises(ZapDaemonIdentityError):
            manager.wait_until_ready()

    def test_lifecycle_evidence_records_launcher_and_daemon(self):
        ready = self._ready()
        process = FakeProcess(returncode=0)
        manager, _, _ = self.make_system_manager(
            process=process, snapshots=[ready, ready]
        )
        manager.start()
        manager.wait_until_ready()
        lifecycle = manager.lifecycle_evidence()
        self.assertEqual(lifecycle["launcher"]["pid"], 4242)
        self.assertEqual(lifecycle["launcher"]["exit_code"], 0)
        self.assertEqual(lifecycle["daemon"]["pid"], 555)
        self.assertTrue(lifecycle["identity"]["verified"])
        self.assertIsNotNone(lifecycle["detach"])


class SystemShutdownTests(ProcessTestCase):
    """Shutdown of a detached daemon with an injected lifecycle system."""

    def make_system_manager(self, *, process, snapshots, client, **overrides):
        system = FakeLifecycleSystem(snapshots)
        options = dict(
            system=system,
            wall_clock=lambda: 1000.0,
            offline_smoke=True,
            api_key=None,
            keyless=True,
            host="127.0.0.1",
            port=18080,
        )
        options.update(overrides)
        manager, _, proc = self.make_manager(
            process=process, client=client, **options
        )
        return manager, system, proc

    def _ready(self):
        return make_snapshot(zap_home=self.scan.scan_dir / "zap-home")

    def _gone(self):
        return SystemSnapshot(
            method="Get-NetTCPConnection", processes=(), connections=()
        )

    def test_api_shutdown_with_dead_launcher_is_graceful(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        manager, system, proc = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=[ready, ready, ready, self._gone()],
        )
        manager.start()
        manager.wait_until_ready()
        manager.stop()
        self.assertEqual(manager._get_client().shutdown_calls, 1)
        self.assertEqual(system.terminated, [])
        self.assertEqual(system.killed, [])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertTrue(stop["api_attempted"])
        self.assertEqual(stop["result"], "graceful")
        self.assertTrue(stop["process_exited"])
        self.assertTrue(stop["both_ports_closed"])

    def test_fail_closed_when_identity_cannot_be_reverified(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        ambiguous = make_snapshot(
            zap_home=self.scan.scan_dir / "zap-home",
            processes=[
                ProcessRecord(
                    pid=pid,
                    command_line=f'-dir "{self.scan.scan_dir / "zap-home"}"',
                    creation_time=1000.0,
                )
                for pid in (555, 556)
            ],
            connections=[
                ConnectionRecord("127.0.0.1", 18080, "0.0.0.0", 0, "Listen", pid)
                for pid in (555, 556)
            ],
        )
        # detach, verify, pre-stop, two graceful-wait polls, revertify
        snapshots = [ready, ready, ready, ready, ready, ambiguous]
        manager, system, proc = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=snapshots,
        )
        manager.start()
        manager.wait_until_ready()
        with self.assertRaises(ZapStopError):
            manager.stop()
        self.assertEqual(system.terminated, [])
        self.assertEqual(system.killed, [])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertEqual(stop["result"], "fail_closed_identity")
        self.assertFalse(stop["identity_reverified"])

    def test_fallback_terminate_only_after_reverification(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        snapshots = [
            ready, ready,  # detach, verify
            ready,  # pre-shutdown
            ready, ready,  # graceful wait: not gone
            ready,  # reverify before terminate
            self._gone(),  # terminate wait
        ]
        manager, system, proc = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=snapshots,
        )
        manager.start()
        manager.wait_until_ready()
        manager.stop()
        self.assertEqual(system.terminated, [555])
        self.assertEqual(system.killed, [])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertTrue(stop["identity_reverified"])
        self.assertIn("terminate", stop["fallbacks"])

    def test_kill_only_after_second_reverification(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        snapshots = [
            ready, ready,  # detach, verify
            ready,  # pre-shutdown
            ready, ready,  # graceful wait
            ready,  # reverify before terminate
            ready, ready,  # terminate wait
            ready,  # reverify before kill
            self._gone(),  # kill wait
        ]
        manager, system, proc = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=snapshots,
        )
        manager.start()
        manager.wait_until_ready()
        manager.stop()
        self.assertEqual(system.terminated, [555])
        self.assertEqual(system.killed, [555])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertIn("kill", stop["fallbacks"])

    def test_pid_reuse_before_terminate_fails_closed(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        reused = make_snapshot(
            zap_home=self.scan.scan_dir / "zap-home",
            daemon_pid=999,
        )
        snapshots = [ready, ready, ready, ready, ready, reused]
        manager, system, proc = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=snapshots,
        )
        manager.start()
        manager.wait_until_ready()
        with self.assertRaises(ZapStopError):
            manager.stop()
        self.assertEqual(system.terminated, [])
        self.assertEqual(system.killed, [])

    def _jvm_only(
        self,
        *,
        command_line=None,
        executable_path="C:\\j\\javaw.exe",
        creation_time=1000.0,
        daemon_pid=555,
    ):
        """A snapshot where the JVM survives but both listeners are closed."""

        home = self.scan.scan_dir / "zap-home"
        return SystemSnapshot(
            method="Get-NetTCPConnection",
            processes=(
                ProcessRecord(
                    pid=daemon_pid,
                    parent_pid=4242,
                    name="javaw.exe",
                    command_line=(
                        command_line
                        if command_line is not None
                        else f'"C:\\j\\javaw.exe" -dir "{home}"'
                    ),
                    executable_path=executable_path,
                    creation_time=creation_time,
                ),
            ),
            connections=(),
        )

    def test_ports_closed_but_process_present_is_not_exited_and_fallback_runs(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        jvm = self._jvm_only()
        # detach, verify, pre-shutdown all see the ready daemon; every later
        # poll sees the ports closed but the JVM still alive.
        manager, system, _ = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=[ready, ready, ready, jvm],
        )
        manager.start()
        manager.wait_until_ready()
        with self.assertRaises(ZapStopError):
            manager.stop()

        # A port-closed JVM is not "exited"; the same identity was safely
        # reconfirmed and terminate/kill were attempted.
        self.assertEqual(system.terminated, [555])
        self.assertEqual(system.killed, [555])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertFalse(stop["process_exited"])
        self.assertEqual(stop["result"], "failed")
        self.assertTrue(stop["api_port_closed"])
        self.assertTrue(stop["callback_port_closed"])

    def test_process_observation_unavailable_never_claims_exit(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        # Connections are observed (netstat) and show both ports closed, but no
        # process enumeration is available, so absence cannot be asserted.
        unobservable = SystemSnapshot(
            method="netstat", processes=(), connections=()
        )
        manager, system, _ = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=[ready, ready, ready, unobservable],
        )
        manager.start()
        manager.wait_until_ready()
        with self.assertRaises(ZapStopError):
            manager.stop()
        self.assertEqual(system.terminated, [])
        self.assertEqual(system.killed, [])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertFalse(stop["process_exited"])
        self.assertEqual(stop["result"], "fail_closed_identity")

    def test_process_absent_and_ports_closed_is_graceful(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        manager, system, _ = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=[ready, ready, ready, gone],
        )
        manager.start()
        manager.wait_until_ready()
        manager.stop()
        self.assertEqual(system.terminated, [])
        self.assertEqual(system.killed, [])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertTrue(stop["process_exited"])
        self.assertTrue(stop["both_ports_closed"])
        self.assertEqual(stop["result"], "graceful")

    def test_same_pid_changed_metadata_rejected_before_terminate(self):
        variants = {
            "creation_time": {"creation_time": 9999.0},
            "command_line": {
                "command_line": f'-dir "{self.scan.scan_dir / "zap-home"}-x"'
            },
            "executable": {"executable_path": "C:\\other\\javaw.exe"},
        }
        for name, overrides in variants.items():
            with self.subTest(name=name):
                process = FakeProcess(returncode=0)
                ready = self._ready()
                changed = self._jvm_only(**overrides)
                manager, system, _ = self.make_system_manager(
                    process=process,
                    client=FakeClient(["2.17.0"]),
                    snapshots=[ready, ready, ready, changed],
                )
                manager.start()
                manager.wait_until_ready()
                with self.assertRaises(ZapStopError):
                    manager.stop()
                self.assertEqual(system.terminated, [])
                self.assertEqual(system.killed, [])
                stop = manager.lifecycle_evidence()["shutdown"]
                self.assertEqual(stop["result"], "fail_closed_identity")

    def test_different_freshly_verified_pid_is_rejected(self):
        process = FakeProcess(returncode=0)
        ready = self._ready()
        # A different PID owns the API port with a valid marker and metadata:
        # the strict verifier would call it "verified", but it must never
        # replace this run's already-verified daemon.
        freshly_verified = make_snapshot(
            zap_home=self.scan.scan_dir / "zap-home",
            daemon_pid=999,
            launcher_pid=4242,
        )
        manager, system, _ = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=[ready, ready, ready, ready, ready, freshly_verified],
        )
        manager.start()
        manager.wait_until_ready()
        with self.assertRaises(ZapStopError):
            manager.stop()
        self.assertEqual(system.terminated, [])
        self.assertEqual(system.killed, [])
        stop = manager.lifecycle_evidence()["shutdown"]
        self.assertEqual(stop["result"], "fail_closed_identity")

    def test_lifecycle_evidence_excludes_unrelated_process_data(self):
        token = "SYNTHETIC-TOKEN-DEADBEEF"
        home = self.scan.scan_dir / "zap-home"
        ready = make_snapshot(
            zap_home=home,
            processes=[
                ProcessRecord(
                    pid=555,
                    parent_pid=4242,
                    name="javaw.exe",
                    command_line=f'-dir "{home}"',
                    executable_path="C:\\j\\javaw.exe",
                    creation_time=1000.0,
                ),
                ProcessRecord(
                    pid=7777,
                    parent_pid=1,
                    name="unrelated.exe",
                    command_line=f"unrelated.exe --token {token}",
                    executable_path="C:\\unrelated.exe",
                    creation_time=1.0,
                ),
            ],
            connections=[
                ConnectionRecord("127.0.0.1", 18080, "0.0.0.0", 0, "Listen", 555),
                ConnectionRecord("127.0.0.1", 18081, "0.0.0.0", 0, "Listen", 555),
                ConnectionRecord(
                    "127.0.0.1", 54321, "203.0.113.5", 443, "Established", 7777
                ),
            ],
        )
        process = FakeProcess(returncode=0)
        manager, _, _ = self.make_system_manager(
            process=process,
            client=FakeClient(["2.17.0"]),
            snapshots=[ready],
        )
        manager.start()
        manager.wait_until_ready()
        serialized = json.dumps(manager.lifecycle_evidence())
        self.assertNotIn(token, serialized)
        self.assertNotIn("7777", serialized)
        self.assertNotIn("203.0.113.5", serialized)
        # The daemon's own relevant records remain.
        self.assertIn("555", serialized)
        self.assertIn("18080", serialized)


class ContextManagerTests(ProcessTestCase):
    def test_context_manager_starts_and_cleans_up(self):
        process = FakeProcess()

        def exit_on_shutdown():
            process.returncode = 0

        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"], on_shutdown=exit_on_shutdown),
            process=process,
        )
        with manager as active:
            self.assertTrue(active.running)
            active.wait_until_ready()
            handle = active._stdout_handle
            self.assertFalse(handle.closed)
        self.assertIsNone(manager._process)
        self.assertFalse(manager.running)
        self.assertTrue(handle.closed)

    def test_context_manager_cleans_up_on_exception(self):
        process = FakeProcess()

        def exit_on_shutdown():
            process.returncode = 0

        manager, _, _ = self.make_manager(
            client=FakeClient(["2.17.0"], on_shutdown=exit_on_shutdown),
            process=process,
        )
        with self.assertRaises(RuntimeError):
            with manager as active:
                active.wait_until_ready()
                handle = active._stdout_handle
                raise RuntimeError("boom")
        self.assertIsNone(manager._process)
        self.assertTrue(handle.closed)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
