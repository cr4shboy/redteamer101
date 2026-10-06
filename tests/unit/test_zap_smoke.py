"""Offline unit tests for the local-only ZAP daemon smoke component.

No process is started, no socket is opened, and no target or external host is
ever contacted: the transport, manager, client, inspector, and port checker are
all faked.
"""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from red_teaming.orchestration.state import read_json_object
from red_teaming.projects.models import ProjectDomain
from red_teaming.projects.paths import ScanPath
from red_teaming.tools.zap.client import ZapApiClient
from red_teaming.tools.zap.lifecycle import (
    ConnectionRecord,
    DaemonIdentity,
    ProcessRecord,
    SystemSnapshot,
)
from red_teaming.tools.zap.models import HttpResponse, ZapEndpoint, ZapTransportError
from red_teaming.tools.zap.process import (
    DEFAULT_OAST_CALLBACK_PORT,
    OFFLINE_CONFIG_CALLHOME_TEL_ENABLED,
    OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR,
    OFFLINE_CONFIG_OAST_CALLBACK_PORT,
    OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR,
)
from red_teaming.tools.zap.smoke import (
    SCHEMA_VERSION,
    SMOKE_JSON_FILENAME,
    SMOKE_MARKDOWN_FILENAME,
    SMOKE_STATE_FILENAME,
    ApiCallRecorder,
    AllowlistedTransport,
    PowerShellLocalInspector,
    SmokeAllowlistError,
    SmokeConfigurationError,
    SmokeProcessControlError,
    ZapSmokeRunner,
    _parse_netstat,
    _redact_key_material,
    analyze_inspection,
    check_port_free,
    inspect_artifacts,
    render_markdown,
)

SCAN_ID = "20261003T120000Z-abc123"
FIXED_NOW = "2026-10-03T12:00:00+00:00"
ENDPOINT = ZapEndpoint.from_host_port("127.0.0.1", 18080)


class FakeTransport:
    """Records requests and replays queued responses/exceptions."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, timeout):
        self.requests.append((method, url, timeout))
        if not self.responses:
            raise AssertionError("no queued response")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def make_recorder():
    return ApiCallRecorder(lambda: FIXED_NOW)


class AllowlistTests(unittest.TestCase):
    def make_allowlisted(self, *responses):
        inner = FakeTransport(*responses)
        recorder = make_recorder()
        transport = AllowlistedTransport(inner, endpoint=ENDPOINT, recorder=recorder)
        client = ZapApiClient(
            ENDPOINT, None, keyless=True, transport=transport, timeout=5.0
        )
        return client, inner, recorder

    def test_version_is_allowed_and_recorded(self):
        client, inner, recorder = self.make_allowlisted(
            HttpResponse(200, b'{"version": "2.17.0"}')
        )
        self.assertEqual(client.get_version(), "2.17.0")
        self.assertEqual(len(inner.requests), 1)
        call = recorder.calls[0]
        self.assertTrue(call["allowed"])
        self.assertEqual(call["component"], "core")
        self.assertEqual(call["operation"], "version")
        self.assertEqual(call["kind"], "view")
        self.assertEqual(call["path"], "/JSON/core/view/version/")
        self.assertEqual(call["status"], 200)
        self.assertEqual(call["timestamp"], FIXED_NOW)

    def test_shutdown_is_allowed_and_recorded(self):
        client, inner, recorder = self.make_allowlisted(
            HttpResponse(200, b'{"message": "bye"}')
        )
        client.shutdown()
        self.assertEqual(len(inner.requests), 1)
        call = recorder.calls[0]
        self.assertTrue(call["allowed"])
        self.assertEqual(call["path"], "/JSON/core/action/shutdown/")

    def test_no_query_or_secret_is_recorded(self):
        client, _, recorder = self.make_allowlisted(
            HttpResponse(200, b'{"version": "2.17.0"}')
        )
        client.get_version()
        serialized = json.dumps(recorder.calls)
        self.assertNotIn("apikey", serialized.lower())
        self.assertNotIn("?", serialized)

    def test_scan_operation_is_rejected_before_sending(self):
        client, inner, recorder = self.make_allowlisted(
            HttpResponse(200, b'{"version": "2.17.0"}')
        )
        with self.assertRaises(SmokeAllowlistError):
            client._call(
                "spider", "scan", {"url": "https://example.test/"}, action=True
            )
        self.assertEqual(inner.requests, [])
        self.assertEqual(len(recorder.calls), 1)
        self.assertFalse(recorder.calls[0]["allowed"])
        self.assertEqual(recorder.calls[0]["component"], "spider")

    def test_unknown_core_operation_is_rejected(self):
        client, inner, _ = self.make_allowlisted()
        with self.assertRaises(SmokeAllowlistError):
            client._call("core", "accessUrl", action=True)
        self.assertEqual(inner.requests, [])

    def test_non_127_endpoint_is_rejected_before_sending(self):
        inner = FakeTransport()
        recorder = make_recorder()
        transport = AllowlistedTransport(inner, endpoint=ENDPOINT, recorder=recorder)
        with self.assertRaises(SmokeAllowlistError):
            transport.request(
                "GET", "http://localhost:18080/JSON/core/view/version/?", 5.0
            )
        self.assertEqual(inner.requests, [])
        self.assertFalse(recorder.calls[0]["allowed"])

    def test_non_matching_port_is_rejected(self):
        inner = FakeTransport()
        recorder = make_recorder()
        transport = AllowlistedTransport(inner, endpoint=ENDPOINT, recorder=recorder)
        with self.assertRaises(SmokeAllowlistError):
            transport.request(
                "GET", "http://127.0.0.1:9999/JSON/core/view/version/?", 5.0
            )
        self.assertEqual(inner.requests, [])

    def test_query_string_is_rejected(self):
        inner = FakeTransport()
        recorder = make_recorder()
        transport = AllowlistedTransport(inner, endpoint=ENDPOINT, recorder=recorder)
        with self.assertRaises(SmokeAllowlistError):
            transport.request(
                "GET",
                "http://127.0.0.1:18080/JSON/core/view/version/?apikey=secret",
                5.0,
            )
        self.assertEqual(inner.requests, [])
        self.assertNotIn("secret", json.dumps(recorder.calls))

    def test_transport_error_is_recorded_and_raised(self):
        inner = FakeTransport(ZapTransportError("connection refused"))
        recorder = make_recorder()
        transport = AllowlistedTransport(inner, endpoint=ENDPOINT, recorder=recorder)
        with self.assertRaises(ZapTransportError):
            transport.request("GET", "http://127.0.0.1:18080/JSON/core/view/version/?", 5.0)
        call = recorder.calls[0]
        self.assertTrue(call["allowed"])
        self.assertIsNone(call["status"])
        self.assertIn("ZapTransportError", call["error"])

    def test_constructor_rejects_non_127_endpoint(self):
        rogue = ZapEndpoint(scheme="http", host="localhost", port=18080)
        with self.assertRaises(SmokeConfigurationError):
            AllowlistedTransport(
                FakeTransport(), endpoint=rogue, recorder=make_recorder()
            )


class InspectionAnalysisTests(unittest.TestCase):
    def test_loopback_listener_and_external_connection(self):
        raw = {
            "method": "Get-NetTCPConnection",
            "port": 18080,
            "pids": [10, 11],
            "processes": [],
            "connections": [
                {
                    "local_address": "127.0.0.1",
                    "local_port": 18080,
                    "remote_address": "0.0.0.0",
                    "remote_port": 0,
                    "state": "Listen",
                    "pid": 11,
                },
                {
                    "local_address": "127.0.0.1",
                    "local_port": 55555,
                    "remote_address": "93.184.216.34",
                    "remote_port": 443,
                    "state": "Established",
                    "pid": 11,
                },
            ],
        }
        result = analyze_inspection(raw)
        self.assertTrue(result["listener_loopback_only"])
        self.assertEqual(result["listener_local_addresses"], ["127.0.0.1"])
        self.assertEqual(result["non_loopback_connection_count"], 1)

    def test_wildcard_listener_is_not_loopback_only(self):
        raw = {
            "port": 18080,
            "pids": [1],
            "connections": [
                {
                    "local_address": "0.0.0.0",
                    "local_port": 18080,
                    "remote_address": "0.0.0.0",
                    "remote_port": 0,
                    "state": "Listen",
                    "pid": 1,
                }
            ],
        }
        result = analyze_inspection(raw)
        self.assertFalse(result["listener_loopback_only"])
        self.assertEqual(result["non_loopback_connection_count"], 0)

    def test_all_listener_wildcard_is_reported_separately_from_api(self):
        raw = {
            "method": "Get-NetTCPConnection",
            "port": 18080,
            "callback_port": 18081,
            "pids": [1],
            "connections": [
                {
                    "local_address": "127.0.0.1",
                    "local_port": 18080,
                    "remote_address": "0.0.0.0",
                    "remote_port": 0,
                    "state": "Listen",
                    "pid": 1,
                },
                {
                    "local_address": "0.0.0.0",
                    "local_port": 18081,
                    "remote_address": "0.0.0.0",
                    "remote_port": 0,
                    "state": "Listen",
                    "pid": 1,
                },
            ],
        }
        result = analyze_inspection(raw)
        # The API listener is loopback-only, but the broad daemon-owned
        # containment still fails because the callback listener is wildcard.
        self.assertTrue(result["listener_loopback_only"])
        self.assertFalse(result["all_listener_loopback_only"])
        self.assertFalse(result["callback_listener_loopback_only"])

    def test_time_wait_non_loopback_is_not_active_external(self):
        # A TIME_WAIT endpoint is a historical/closing state. Even bound to a
        # fixed port with PID 0 and a non-loopback peer, it must never be
        # classified as active external traffic.
        raw = {
            "method": "Get-NetTCPConnection",
            "port": 18080,
            "pids": [0],
            "connections": [
                {
                    "local_address": "127.0.0.1",
                    "local_port": 18080,
                    "remote_address": "93.184.216.34",
                    "remote_port": 443,
                    "state": "TimeWait",
                    "pid": 0,
                },
            ],
        }
        result = analyze_inspection(raw)
        self.assertEqual(result["non_loopback_connection_count"], 0)
        self.assertEqual(result["non_loopback_connections"], [])

    def test_closing_states_are_not_active_external(self):
        for state in ("CloseWait", "FinWait2", "SynSent", "Closing", "LastAck"):
            with self.subTest(state=state):
                raw = {
                    "method": "Get-NetTCPConnection",
                    "port": 18080,
                    "connections": [
                        {
                            "local_address": "127.0.0.1",
                            "local_port": 55555,
                            "remote_address": "93.184.216.34",
                            "remote_port": 443,
                            "state": state,
                            "pid": 555,
                        },
                    ],
                }
                result = analyze_inspection(raw)
                self.assertEqual(result["non_loopback_connection_count"], 0)

    def test_established_casing_variants_are_active_external(self):
        # Both supported Windows inspection paths must be recognized:
        # Get-NetTCPConnection emits ``Established`` and netstat emits
        # ``ESTABLISHED``.
        for state in ("Established", "ESTABLISHED", " established "):
            with self.subTest(state=state):
                raw = {
                    "method": "Get-NetTCPConnection",
                    "port": 18080,
                    "connections": [
                        {
                            "local_address": "127.0.0.1",
                            "local_port": 55555,
                            "remote_address": "93.184.216.34",
                            "remote_port": 443,
                            "state": state,
                            "pid": 555,
                        },
                    ],
                }
                result = analyze_inspection(raw)
                self.assertEqual(result["non_loopback_connection_count"], 1)

    def test_parse_netstat_filters_by_pid(self):
        text = (
            "  TCP    127.0.0.1:18080    0.0.0.0:0    LISTENING    1234\r\n"
            "  TCP    127.0.0.1:5000     93.184.216.34:443  ESTABLISHED    9999\r\n"
        )
        connections = _parse_netstat(text, {1234})
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0]["local_port"], 18080)
        self.assertEqual(connections[0]["state"], "LISTENING")


class ArtifactInspectionTests(unittest.TestCase):
    SECRET = "SYNTHETICAPIKEY0001"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "logs").mkdir(parents=True)
        (self.root / "zap-home").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_key_material_is_detected_without_mutating_source(self):
        log = self.root / "logs" / "zap-stderr.log"
        original = (
            "starting\n"
            f"api.key={self.SECRET}\n"
            "ERROR boom happened\n"
        )
        log.write_bytes(original.encode("utf-8"))
        before_hash = self._sha256(log)
        before_bytes = log.read_bytes()

        result = inspect_artifacts(self.root)

        self.assertTrue(result["key_material"]["detected"])
        # Read-only inspection: nothing is ever rewritten or "remediated".
        self.assertFalse(result["key_material"]["remediated"])
        self.assertFalse(result["key_material"]["source_mutated"])
        # The actual secret must never appear anywhere in returned evidence.
        self.assertNotIn(self.SECRET, json.dumps(result))
        self.assertIn("***", json.dumps(result))
        self.assertGreaterEqual(result["key_material"]["match_count"], 1)
        # The source file is byte-for-byte unchanged.
        self.assertEqual(before_bytes, log.read_bytes())
        self.assertEqual(before_hash, self._sha256(log))
        self.assertIn(self.SECRET, log.read_text(encoding="utf-8"))

    def test_runtime_error_is_detected_in_logs(self):
        log = self.root / "logs" / "zap-stderr.log"
        log.write_text(
            "2026-10-03 12:00:00,000 [main] INFO  start\n"
            "2026-10-03 12:00:01,000 [main] ERROR failed to bind\n"
            "java.lang.RuntimeException: nope\n",
            encoding="utf-8",
        )
        result = inspect_artifacts(self.root)
        excerpts = [item["excerpt"] for item in result["errors"]]
        self.assertTrue(any("ERROR" in excerpt for excerpt in excerpts))
        self.assertTrue(
            any("RuntimeException" in excerpt for excerpt in excerpts)
        )

    def test_error_incident_folds_stack_frames_into_one_record(self):
        secret = "SYNTHETICINCIDENTSECRET"
        log = self.root / "logs" / "zap-stderr.log"
        frames = "\n".join(
            f"    at com.example.Frame{index}.run(Frame{index}.java:{index})"
            for index in range(40)
        )
        log.write_text(
            "2026-10-03 12:00:00,000 [main] INFO  start\n"
            "2026-10-03 12:00:01,000 [main] ERROR failed to bind\n"
            f"java.lang.RuntimeException: api.key={secret}\n"
            f"{frames}\n",
            encoding="utf-8",
        )
        result = inspect_artifacts(self.root)

        # One anchor produces exactly one incident; the many ``at`` frames are
        # folded into it rather than yielding a record each.
        self.assertEqual(len(result["errors"]), 1)
        excerpt = result["errors"][0]["excerpt"]
        self.assertIn("ERROR", excerpt)
        self.assertIn("RuntimeException", excerpt)
        self.assertLessEqual(len(excerpt), 300)
        # Redaction still applies to the folded excerpt.
        self.assertNotIn(secret, json.dumps(result))
        self.assertIn("***", excerpt)

    def test_module_prefixed_stack_frame_is_folded(self):
        log = self.root / "logs" / "zap-stderr.log"
        log.write_text(
            "ERROR boom\n"
            "java.lang.RuntimeException: x\n"
            "    at java.base/java.lang.Thread.run(Thread.java:833)\n",
            encoding="utf-8",
        )
        result = inspect_artifacts(self.root)
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("Thread.run", result["errors"][0]["excerpt"])

    def test_two_error_anchors_yield_two_records(self):
        log = self.root / "logs" / "zap-stderr.log"
        log.write_text(
            "INFO start\n"
            "2026-10-03 12:00:01,000 [main] ERROR first failure\n"
            "java.lang.RuntimeException: one\n"
            "    at a.b.C.d(C.java:1)\n"
            "INFO between incidents\n"
            "2026-10-03 12:00:02,000 [main] FATAL second failure\n"
            "    at e.f.G.h(G.java:2)\n",
            encoding="utf-8",
        )
        result = inspect_artifacts(self.root)

        self.assertEqual(len(result["errors"]), 2)
        excerpts = [item["excerpt"] for item in result["errors"]]
        self.assertTrue(any("first failure" in excerpt for excerpt in excerpts))
        self.assertTrue(any("second failure" in excerpt for excerpt in excerpts))

    def test_standalone_stack_frames_without_anchor_are_ignored(self):
        log = self.root / "logs" / "zap-stderr.log"
        log.write_text(
            "Traceback (most recent call last):\n"
            '  File "app.py", line 5, in <module>\n'
            "java.lang.RuntimeException: orphaned\n"
            "    at a.b.C.d(C.java:1)\n"
            "INFO no error found\n",
            encoding="utf-8",
        )
        result = inspect_artifacts(self.root)
        self.assertEqual(result["errors"], [])

    def test_harmless_prose_with_error_substring_is_not_classified(self):
        config = self.root / "zap-home" / "config.xml"
        config.write_text(
            "<config><description>This text mentions error and errors "
            "but is harmless prose.</description></config>",
            encoding="utf-8",
        )
        log = self.root / "logs" / "zap-stdout.log"
        log.write_text(
            "2026-10-03 12:00:00,000 [main] INFO  no error found\n",
            encoding="utf-8",
        )
        result = inspect_artifacts(self.root)
        self.assertEqual(result["errors"], [])

    def test_bundled_assets_are_not_scanned_or_mutated(self):
        (self.root / "zap-home" / "scripts").mkdir()
        (self.root / "zap-home" / "wordlists").mkdir()
        js = self.root / "zap-home" / "scripts" / "bundle.js"
        wordlist = self.root / "zap-home" / "wordlists" / "list.txt"
        js.write_text(
            f"var apikey='{self.SECRET}';\nconsole.log('error');\n",
            encoding="utf-8",
        )
        wordlist.write_text(
            f"apikey={self.SECRET}\nERROR\n", encoding="utf-8"
        )
        js_bytes = js.read_bytes()
        wordlist_bytes = wordlist.read_bytes()

        result = inspect_artifacts(self.root)

        self.assertFalse(result["key_material"]["detected"])
        self.assertFalse(result["key_material"]["source_mutated"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["total_files"], 0)
        self.assertNotIn(self.SECRET, json.dumps(result))
        # Bundled assets are untouched.
        self.assertEqual(js_bytes, js.read_bytes())
        self.assertEqual(wordlist_bytes, wordlist.read_bytes())

    def test_clean_logs_remain_clean(self):
        log = self.root / "logs" / "zap-stderr.log"
        log.write_text("all good\n", encoding="utf-8")
        result = inspect_artifacts(self.root)
        self.assertFalse(result["key_material"]["detected"])
        self.assertFalse(result["key_material"]["remediated"])
        self.assertFalse(result["key_material"]["source_mutated"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["total_files"], 1)

    def test_bundled_extension_jars_are_not_inventoried(self):
        ext = self.root / "zap-home" / "plugin" / "oast-0.24.0.zap"
        ext.parent.mkdir()
        ext.write_bytes(b"PK\x03\x04 fake jar with api.key=whatever")
        result = inspect_artifacts(self.root)
        self.assertEqual(result["files"], [])
        self.assertEqual(result["total_files"], 0)

    def test_redact_helper_never_returns_the_secret(self):
        sanitized, found = _redact_key_material(
            "api.key=abc123\n?apikey=def456\napi.key=\n"
        )
        self.assertEqual(found, 2)
        self.assertNotIn("abc123", sanitized)
        self.assertNotIn("def456", sanitized)
        self.assertIn("***", sanitized)


class PortPreflightTests(unittest.TestCase):
    def test_bind_probe_on_ephemeral_port_is_free(self):
        import socket

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        self.assertTrue(check_port_free("127.0.0.1", port))

    def test_bind_probe_detects_occupied_port(self):
        import socket

        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        try:
            self.assertFalse(check_port_free("127.0.0.1", port))
        finally:
            holder.close()

    def test_non_loopback_host_is_rejected(self):
        with self.assertRaises(SmokeConfigurationError):
            check_port_free("example.com", 18080)


def make_snapshot(
    *,
    zap_home,
    daemon_pid=555,
    launcher_pid=4242,
    api_port=18080,
    callback_port=18081,
    daemon=True,
    api_listener=True,
    callback_wildcard=False,
    external=None,
    method="Get-NetTCPConnection",
    creation_time=1000.0,
    extra_processes=(),
    extra_connections=(),
):
    processes = list(extra_processes)
    connections = list(extra_connections)
    if daemon:
        processes.append(
            ProcessRecord(
                pid=daemon_pid,
                parent_pid=launcher_pid,
                name="javaw.exe",
                command_line=f'"C:\\j\\javaw.exe" -dir "{zap_home}"',
                executable_path="C:\\j\\javaw.exe",
                creation_time=creation_time,
            )
        )
        if api_listener:
            connections.append(
                ConnectionRecord("127.0.0.1", api_port, "0.0.0.0", 0, "Listen", daemon_pid)
            )
        if callback_port is not None:
            connections.append(
                ConnectionRecord(
                    "0.0.0.0" if callback_wildcard else "127.0.0.1",
                    callback_port,
                    "0.0.0.0",
                    0,
                    "Listen",
                    daemon_pid,
                )
            )
        for remote_address, remote_port in external or ():
            connections.append(
                ConnectionRecord(
                    "127.0.0.1",
                    55555,
                    remote_address,
                    remote_port,
                    "Established",
                    daemon_pid,
                )
            )
    return SystemSnapshot(
        method=method, processes=tuple(processes), connections=tuple(connections)
    )


class FakeSystem:
    """Injectable lifecycle system returning a queue of snapshots."""

    def __init__(self, snapshots):
        self.snapshots = list(snapshots)
        self.index = 0
        self.terminated = []
        self.killed = []

    def snapshot(self):
        index = min(self.index, len(self.snapshots) - 1)
        self.index += 1
        return self.snapshots[index]

    def terminate(self, pid):
        self.terminated.append(pid)

    def kill(self, pid):
        self.killed.append(pid)


class FakeManager:
    """Manager double exposing the verified-launcher/daemon interface."""

    def __init__(
        self,
        *,
        fail_start=False,
        fail_ready=False,
        version="2.17.0",
        daemon_pid=555,
        launcher_pid=4242,
        already_exited=False,
        has_identity=True,
        api_attempted=True,
        daemon_gone=True,
        fallbacks=(),
        identity_reverified=False,
    ):
        self.started = False
        self.stopped = False
        self.fail_start = fail_start
        self.fail_ready = fail_ready
        self.version = version
        self._launcher_pid = launcher_pid
        self._daemon_pid = None if already_exited else daemon_pid
        self._running = not already_exited
        self._daemon_running = not already_exited
        self._has_identity = has_identity and not already_exited
        self._api_attempted = api_attempted
        self._daemon_gone = daemon_gone
        self._fallbacks = list(fallbacks)
        self._identity_reverified = identity_reverified
        self.launcher_exit_code = 0 if already_exited else None
        self.exit_code = 0 if already_exited else 0

    def safe_command(self):
        return [
            "ZAP.exe",
            "-daemon",
            "-host",
            "127.0.0.1",
            "-port",
            "18080",
            "-config",
            "api.disablekey=true",
        ]

    @property
    def pid(self):
        return self._daemon_pid if self._daemon_pid else self._launcher_pid

    @property
    def launcher_pid(self):
        return self._launcher_pid

    @property
    def daemon_pid(self):
        return self._daemon_pid

    @property
    def identity(self):
        if not self._has_identity:
            return None
        return DaemonIdentity(
            pid=self._daemon_pid,
            api_port=18080,
            parent_pid=self._launcher_pid,
            name="javaw.exe",
            command_line='-dir "zap-home"',
            creation_time=1000.0,
        )

    @property
    def running(self):
        if self._has_identity:
            return self._daemon_running
        return self._running

    def start(self):
        if self.fail_start:
            raise RuntimeError("start failed")
        self.started = True

    def wait_until_ready(self):
        if self.fail_ready:
            raise RuntimeError("not ready")
        return self.version

    def stop(self):
        self.stopped = True
        self._running = False
        if self._daemon_gone:
            self._daemon_running = False
            self._daemon_pid = None
            self._has_identity = False

    def lifecycle_evidence(self):
        return {
            "launcher": {
                "pid": self._launcher_pid,
                "exit_code": self.launcher_exit_code,
                "running": self._running,
            },
            "daemon": None,
            "identity": None,
            "detach": None,
            "ready": None,
            "pre_shutdown": None,
            "final": None,
            "shutdown": {
                "mode": "fake",
                "api_attempted": self._api_attempted,
                "api_result": "sent" if self._api_attempted else None,
                "fallbacks": list(self._fallbacks),
                "identity_reverified": self._identity_reverified,
                "process_exited": self._daemon_gone,
                "result": "graceful" if self._daemon_gone else "failed",
            },
        }


class RunnerTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        domain = ProjectDomain.parse("acme.example")
        self.scan = ScanPath.build(
            self.root,
            domain,
            "acme.example",
            scan_id=SCAN_ID,
        )
        self.exe = self.root / "ZAP.exe"
        self.exe.write_bytes(b"MZ fake")
        self.manager_calls = []
        self.zap_home = self.scan.scan_dir / "zap-home"

    def tearDown(self):
        self._tmp.cleanup()

    def default_system(self):
        ready = make_snapshot(zap_home=self.zap_home)
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        # preflight inspection, ready inspection, pre-shutdown inspection,
        # final inspection
        return FakeSystem([ready, ready, ready, gone])

    def make_runner(
        self,
        *,
        port_free=True,
        port_free_map=None,
        manager=None,
        system=None,
    ):
        if manager is None:
            manager = FakeManager()
        if system is None:
            system = self.default_system()

        def manager_factory(**kwargs):
            self.manager_calls.append(kwargs)
            return manager

        def client_factory(endpoint, transport):
            return object()

        if port_free_map is None:
            def port_checker(host, port):
                return bool(port_free)
        else:
            def port_checker(host, port):
                return bool(port_free_map.get(port, True))

        return ZapSmokeRunner(
            scan_path=self.scan,
            executable=self.exe,
            bind_host="127.0.0.1",
            bind_port=18080,
            callback_port=18081,
            manager_factory=manager_factory,
            client_factory=client_factory,
            system=system,
            port_checker=port_checker,
            now=lambda: FIXED_NOW,
        )

    # -- success and evidence ---------------------------------------------

    def test_successful_run_writes_mirrored_evidence(self):
        manager = FakeManager()
        runner = self.make_runner(manager=manager)
        evidence = runner.run()

        self.assertEqual(evidence["schema_version"], SCHEMA_VERSION)
        self.assertEqual(evidence["status"], "succeeded")
        self.assertEqual(evidence["observed_version"], "2.17.0")
        self.assertTrue(manager.started)
        self.assertTrue(manager.stopped)
        self.assertFalse(manager.running)
        self.assertEqual(evidence["scan_api_call_count"], 0)
        self.assertTrue(evidence["acceptance"]["listener_loopback_only"])
        self.assertTrue(evidence["acceptance"]["api_listener_loopback_only"])
        self.assertTrue(evidence["acceptance"]["all_listener_loopback_only"])
        self.assertTrue(evidence["acceptance"]["no_external_connections"])
        self.assertTrue(evidence["acceptance"]["api_shutdown_attempted"])
        self.assertTrue(evidence["acceptance"]["daemon_identity_verified"])
        self.assertTrue(evidence["acceptance"]["daemon_gone"])
        self.assertTrue(evidence["acceptance"]["both_ports_closed"])

        scan_dir = self.scan.scan_dir
        json_path = scan_dir / SMOKE_JSON_FILENAME
        md_path = scan_dir / SMOKE_MARKDOWN_FILENAME
        state_path = scan_dir / SMOKE_STATE_FILENAME
        self.assertTrue(json_path.is_file())
        self.assertTrue(md_path.is_file())
        self.assertTrue(state_path.is_file())

        payload = read_json_object(json_path)
        self.assertEqual(payload["status"], "succeeded")
        self.assertEqual(payload["observed_version"], "2.17.0")
        self.assertEqual(payload["scan_api_call_count"], 0)
        self.assertEqual(payload["target_input_count"], 0)
        self.assertEqual(payload["external_host_input_count"], 0)
        self.assertEqual(payload["bind_endpoint"], "http://127.0.0.1:18080")
        self.assertEqual(payload["callback_endpoint"], "http://127.0.0.1:18081")
        self.assertEqual(payload["guard_endpoint"], "http://127.0.0.1:1")
        self.assertEqual(payload["daemon_identity"]["pid"], 555)
        self.assertTrue(payload["process_ids"]["launcher_pid"] == 4242)

        markdown = md_path.read_text(encoding="utf-8")
        self.assertIn("status: succeeded", markdown)
        self.assertIn("observed_version: 2.17.0", markdown)
        self.assertIn("scan_api_call_count: 0", markdown)
        self.assertIn("target_url: n/a", markdown)
        self.assertIn('"domain": "acme.example"', markdown)
        self.assertIn("## Lifecycle snapshots", markdown)
        self.assertIn("api_listener_loopback_only: true", markdown)
        self.assertIn("all_listener_loopback_only: true", markdown)

    def test_lifecycle_and_inspection_snapshots_are_recorded(self):
        manager = FakeManager()
        runner = self.make_runner(manager=manager)
        evidence = runner.run()
        self.assertIsNotNone(evidence["ready_inspection"])
        self.assertIsNotNone(evidence["pre_shutdown_inspection"])
        self.assertIsNotNone(evidence["final_inspection"])
        self.assertIsInstance(evidence["lifecycle"], dict)
        self.assertIn("shutdown", evidence["lifecycle"])
        self.assertEqual(evidence["process_ids"]["launcher_pid"], 4242)
        self.assertEqual(evidence["process_ids"]["daemon_pid"], 555)
        self.assertEqual(evidence["process_ids"]["observed_pids"], [555])
        self.assertTrue(evidence["process_exit_verification"]["exited"])
        self.assertEqual(
            evidence["daemon_identity"]["pid"], 555
        )

    def test_evidence_api_allowlist_is_flat_strings(self):
        runner = self.make_runner()
        evidence = runner.run()
        self.assertEqual(
            evidence["api_allowlist"],
            ["core/action/shutdown", "core/view/version"],
        )

    def test_offline_flags_mirror_oast_callback_containment(self):
        runner = self.make_runner()
        evidence = runner.run()
        flags = evidence["offline_flags"]
        self.assertEqual(
            flags[OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR], "127.0.0.1"
        )
        self.assertEqual(
            flags[OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR], "127.0.0.1"
        )
        self.assertEqual(
            flags[OFFLINE_CONFIG_OAST_CALLBACK_PORT],
            str(DEFAULT_OAST_CALLBACK_PORT),
        )
        self.assertEqual(DEFAULT_OAST_CALLBACK_PORT, 18081)
        # The mirrored values match the deterministic loopback runtime pairs.
        self.assertEqual(
            [
                f"{OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR}="
                f"{flags[OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR]}",
                f"{OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR}="
                f"{flags[OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR]}",
                f"{OFFLINE_CONFIG_OAST_CALLBACK_PORT}="
                f"{flags[OFFLINE_CONFIG_OAST_CALLBACK_PORT]}",
            ],
            [
                "oast.callback.localaddr=127.0.0.1",
                "oast.callback.remoteaddr=127.0.0.1",
                "oast.callback.port=18081",
            ],
        )

    def test_offline_flags_disable_callhome_telemetry(self):
        runner = self.make_runner()
        evidence = runner.run()
        flags = evidence["offline_flags"]
        self.assertEqual(flags[OFFLINE_CONFIG_CALLHOME_TEL_ENABLED], "false")
        self.assertEqual(
            OFFLINE_CONFIG_CALLHOME_TEL_ENABLED, "callhome.tel.enabled"
        )

    def test_oast_callback_config_verification_provenance(self):
        runner = self.make_runner()
        evidence = runner.run()
        provenance = evidence["oast_callback_config_verification"]

        self.assertTrue(provenance["verified"])
        self.assertEqual(provenance["addon"], "OAST")
        self.assertEqual(provenance["version"], "0.24.0")
        self.assertEqual(
            provenance["verification_mode"],
            "read-only offline inspection of installed add-on",
        )
        self.assertTrue(provenance["read_only"])
        self.assertTrue(provenance["offline"])
        self.assertEqual(
            list(provenance["sources"]),
            ["CallbackParam bytecode", "embedded help"],
        )
        self.assertEqual(
            list(provenance["verified_keys"]),
            [
                OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR,
                OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR,
                OFFLINE_CONFIG_OAST_CALLBACK_PORT,
            ],
        )
        self.assertEqual(
            set(provenance["verified_keys"]),
            {
                "oast.callback.localaddr",
                "oast.callback.remoteaddr",
                "oast.callback.port",
            },
        )
        self.assertFalse(provenance["installed_tool_modified"])
        self.assertFalse(provenance["installed_addon_modified"])

        # The same structured provenance is persisted in the JSON evidence.
        payload = read_json_object(self.scan.scan_dir / SMOKE_JSON_FILENAME)
        self.assertEqual(
            payload["oast_callback_config_verification"], provenance
        )

    def test_evidence_has_no_contacted_target(self):
        runner = self.make_runner()
        evidence = runner.run()
        self.assertIsNone(evidence["target_url"])
        self.assertEqual(evidence["target_input_count"], 0)
        self.assertEqual(evidence["external_host_input_count"], 0)
        # The routing/storage domain lives in its own field and is never
        # presented as a contacted target.
        self.assertNotIn("target", evidence)
        self.assertEqual(evidence["artifact_route"]["domain"], "acme.example")
        self.assertEqual(evidence["artifact_route"]["target"], "acme.example")
        for forbidden in ("mode", "scan_mode", "seed_url", "spider"):
            self.assertNotIn(forbidden, evidence)

    # -- preflight gates ---------------------------------------------------

    def test_port_in_use_writes_failure_evidence_without_launching(self):
        runner = self.make_runner(port_free=False)
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(self.manager_calls, [])
        self.assertTrue(
            any("SmokePortInUseError" in e["type"] for e in evidence["errors"])
        )
        self.assertTrue((self.scan.scan_dir / SMOKE_JSON_FILENAME).is_file())
        self.assertTrue((self.scan.scan_dir / SMOKE_MARKDOWN_FILENAME).is_file())

    def test_callback_port_gate_failure_blocks_launch(self):
        runner = self.make_runner(port_free_map={18081: False})
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(self.manager_calls, [])
        self.assertFalse(evidence["acceptance"]["callback_preflight_free"])

    def test_guard_port_gate_failure_blocks_launch(self):
        runner = self.make_runner(port_free_map={1: False})
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(self.manager_calls, [])
        self.assertFalse(evidence["acceptance"]["guard_port_closed"])
        self.assertFalse(evidence["port_preflight"]["guard"]["closed"])

    # -- inspection capability preflight ----------------------------------

    def test_inspection_capability_preflight_blocks_launch_when_unavailable(self):
        unavailable = SystemSnapshot(
            method="Get-NetTCPConnection-unavailable", processes=(), connections=()
        )
        system = FakeSystem([unavailable])
        runner = self.make_runner(system=system)
        evidence = runner.run()

        self.assertEqual(evidence["status"], "failed")
        # No manager is constructed or started when inspection is unavailable.
        self.assertEqual(self.manager_calls, [])
        self.assertFalse(evidence["acceptance"]["inspection_preflight_available"])
        self.assertTrue(
            any(
                "SmokeInspectionCapabilityError" in e["type"]
                for e in evidence["errors"]
            )
        )

    def test_inspection_capability_preflight_blocks_when_process_enum_unavailable(self):
        # Connections are observed via a netstat fallback, but no process
        # enumeration is available, so a launch must not be permitted.
        connection_only = SystemSnapshot(
            method="netstat",
            processes=(),
            connections=(
                ConnectionRecord("127.0.0.1", 18080, "0.0.0.0", 0, "Listen", 555),
            ),
        )
        system = FakeSystem([connection_only])
        runner = self.make_runner(system=system)
        evidence = runner.run()
        self.assertEqual(self.manager_calls, [])
        self.assertFalse(evidence["acceptance"]["inspection_preflight_available"])
        self.assertFalse(
            evidence["port_preflight"]["inspection"]["process_observation_available"]
        )
        self.assertTrue(
            evidence["port_preflight"]["inspection"]["connection_observation_available"]
        )

    def test_inspection_preflight_evidence_is_bounded_and_non_sensitive(self):
        token = "SYNTHETIC-PREFLIGHT-TOKEN"
        capable = make_snapshot(
            zap_home=self.zap_home,
            extra_processes=(
                ProcessRecord(
                    pid=7777,
                    parent_pid=1,
                    name="unrelated.exe",
                    command_line=f"unrelated.exe --token {token}",
                    executable_path="C:\\unrelated.exe",
                    creation_time=1.0,
                ),
            ),
        )
        # First snapshot is the preflight; ensure a second capable snapshot is
        # available for the ready inspection and reuse it for the rest.
        system = FakeSystem([capable, capable, capable, capable])
        runner = self.make_runner(system=system)
        evidence = runner.run()

        inspection = evidence["port_preflight"]["inspection"]
        self.assertIn("method", inspection)
        self.assertIn("process_observation_available", inspection)
        self.assertIn("connection_observation_available", inspection)
        self.assertTrue(inspection["available"])
        # The bounded preflight summary never carries the process list or any
        # unrelated command line.
        self.assertNotIn("processes", inspection)
        self.assertNotIn("connections", inspection)
        self.assertNotIn(token, json.dumps(inspection))
        self.assertNotIn("7777", json.dumps(inspection))
        self.assertTrue(evidence["acceptance"]["inspection_preflight_available"])

    # -- fixed endpoint enforcement ---------------------------------------

    def test_constructor_rejects_non_fixed_callback_port(self):
        for port in (18080, 18082, 0, True):
            with self.subTest(port=port):
                with self.assertRaises(SmokeConfigurationError):
                    ZapSmokeRunner(
                        scan_path=self.scan,
                        executable=self.exe,
                        bind_port=18080,
                        callback_port=port,
                    )

    def test_constructor_rejects_non_fixed_guard_host(self):
        for host in ("localhost", "0.0.0.0", "10.0.0.1", "::1"):
            with self.subTest(host=host):
                with self.assertRaises(SmokeConfigurationError):
                    ZapSmokeRunner(
                        scan_path=self.scan,
                        executable=self.exe,
                        bind_port=18080,
                        guard_host=host,
                    )

    def test_constructor_rejects_non_fixed_guard_port(self):
        for port in (2, 8080, 0, True):
            with self.subTest(port=port):
                with self.assertRaises(SmokeConfigurationError):
                    ZapSmokeRunner(
                        scan_path=self.scan,
                        executable=self.exe,
                        bind_port=18080,
                        guard_port=port,
                    )

    def test_constructor_accepts_exact_fixed_endpoints(self):
        runner = self.make_runner()
        self.assertEqual(runner.endpoint.host, "127.0.0.1")
        self.assertEqual(
            runner._callback_endpoint.port, DEFAULT_OAST_CALLBACK_PORT
        )
        self.assertEqual(runner._guard_endpoint.host, "127.0.0.1")
        self.assertEqual(runner._guard_endpoint.port, 1)

    # -- containment -------------------------------------------------------

    def test_wildcard_callback_listener_fails_broad_containment(self):
        ready = make_snapshot(zap_home=self.zap_home, callback_wildcard=True)
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        system = FakeSystem([ready, ready, ready, gone])
        runner = self.make_runner(system=system)
        evidence = runner.run()
        self.assertTrue(evidence["acceptance"]["api_listener_loopback_only"])
        self.assertFalse(evidence["acceptance"]["all_listener_loopback_only"])
        self.assertFalse(evidence["acceptance"]["callback_listener_loopback_only"])
        self.assertEqual(evidence["status"], "failed")

    def test_external_daemon_connection_fails_containment(self):
        ready = make_snapshot(
            zap_home=self.zap_home, external=[("93.184.216.34", 443)]
        )
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        system = FakeSystem([ready, ready, ready, gone])
        runner = self.make_runner(system=system)
        evidence = runner.run()
        self.assertTrue(evidence["acceptance"]["external_connection_observation_available"])
        self.assertFalse(evidence["acceptance"]["no_external_connections"])
        self.assertEqual(evidence["status"], "failed")

    def test_external_connection_only_in_pre_shutdown_fails_containment(self):
        clean = make_snapshot(zap_home=self.zap_home)
        dirty = make_snapshot(
            zap_home=self.zap_home, external=[("93.184.216.34", 443)]
        )
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        # preflight, ready, pre-shutdown, final
        system = FakeSystem([clean, clean, dirty, gone])
        runner = self.make_runner(system=system)
        evidence = runner.run()

        self.assertTrue(
            evidence["acceptance"]["external_connection_observation_available"]
        )
        self.assertFalse(evidence["acceptance"]["no_external_connections"])
        self.assertEqual(evidence["status"], "failed")

        aggregate = evidence["external_connection_observation"]
        self.assertEqual(aggregate["non_loopback_connection_count"], 1)
        stages = {stage["stage"]: stage for stage in aggregate["stages"]}
        self.assertTrue(stages["ready"]["observation_available"])
        self.assertEqual(stages["ready"]["non_loopback_connection_count"], 0)
        self.assertEqual(stages["pre_shutdown"]["non_loopback_connection_count"], 1)
        self.assertEqual(
            aggregate["non_loopback_connections"][0]["remote_address"],
            "93.184.216.34",
        )
        # Unrelated process data is never part of the aggregate.
        serialized = json.dumps(aggregate)
        self.assertNotIn("processes", serialized)
        self.assertNotIn("command_line", serialized)

    def test_no_external_connections_not_verified_when_inspection_unavailable(self):
        # The preflight capability snapshot is available so the launch proceeds,
        # but the ready/pre-shutdown inspections are connection-unavailable, so
        # no external-connection absence can be claimed.
        capable = SystemSnapshot("Get-NetTCPConnection", (), ())
        unavailable = SystemSnapshot(
            method="Get-NetTCPConnection-unavailable", processes=(), connections=()
        )
        system = FakeSystem([capable, unavailable, unavailable, unavailable])
        runner = self.make_runner(system=system)
        evidence = runner.run()
        self.assertFalse(evidence["external_connection_observation"]["available"])
        self.assertFalse(
            evidence["acceptance"]["external_connection_observation_available"]
        )
        self.assertFalse(evidence["acceptance"]["no_external_connections"])
        self.assertEqual(evidence["status"], "failed")

    def test_no_external_connections_false_when_no_inspection_captured(self):
        # Readiness fails before the inspecting phase, so listener_evidence is
        # never captured and no external-connection absence can be claimed.
        manager = FakeManager(fail_ready=True)
        runner = self.make_runner(manager=manager)
        evidence = runner.run()
        self.assertIsNone(evidence["listener_evidence"])
        self.assertFalse(evidence["acceptance"]["no_external_connections"])
        self.assertFalse(
            evidence["acceptance"]["external_connection_observation_available"]
        )

    def test_callback_listener_absent_fails_callback_containment(self):
        # API listener present and loopback-only, but no OAST callback listener.
        ready = make_snapshot(zap_home=self.zap_home, callback_port=None)
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        system = FakeSystem([ready, ready, ready, gone])
        runner = self.make_runner(system=system)
        evidence = runner.run()
        self.assertTrue(evidence["acceptance"]["api_listener_loopback_only"])
        self.assertFalse(evidence["acceptance"]["callback_listener_loopback_only"])
        self.assertEqual(evidence["listener_evidence"]["callback_listeners"], [])
        self.assertEqual(evidence["status"], "failed")

    def test_serialized_evidence_excludes_unrelated_process_data(self):
        token = "SYNTHETIC-TOKEN-CAFEBABE"
        ready = make_snapshot(
            zap_home=self.zap_home,
            extra_processes=(
                ProcessRecord(
                    pid=7777,
                    parent_pid=1,
                    name="unrelated.exe",
                    command_line=f"unrelated.exe --token {token}",
                    executable_path="C:\\unrelated.exe",
                    creation_time=1.0,
                ),
            ),
            extra_connections=(
                ConnectionRecord(
                    "127.0.0.1", 54321, "203.0.113.7", 443, "Established", 7777
                ),
            ),
        )
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        system = FakeSystem([ready, ready, ready, gone])
        runner = self.make_runner(system=system)
        evidence = runner.run()
        serialized = json.dumps(evidence)
        self.assertNotIn(token, serialized)
        self.assertNotIn("7777", serialized)
        self.assertNotIn("203.0.113.7", serialized)
        # The verified daemon's relevant records are still present.
        self.assertIn("555", serialized)
        self.assertIn("18080", serialized)

    def test_fixed_port_pid_zero_time_wait_does_not_admit_unrelated_pid_zero(self):
        # A stale/system TCP record bound to the fixed API port with PID 0 and a
        # TIME_WAIT state must not drag every unrelated PID-0 endpoint into the
        # scoped snapshot, and must not be counted as active external traffic.
        ready = make_snapshot(
            zap_home=self.zap_home,
            extra_connections=(
                ConnectionRecord(
                    "127.0.0.1", 18080, "93.184.216.34", 443, "TimeWait", 0
                ),
                ConnectionRecord(
                    "127.0.0.1", 51000, "8.8.8.8", 53, "TimeWait", 0
                ),
                ConnectionRecord(
                    "127.0.0.1", 52000, "8.8.4.4", 53, "Established", 0
                ),
            ),
        )
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        system = FakeSystem([ready, ready, ready, gone])
        runner = self.make_runner(system=system)
        evidence = runner.run()

        serialized = json.dumps(evidence)
        # Unrelated PID-0 endpoints (not bound to a fixed port) never enter the
        # scoped snapshot or persisted evidence.
        self.assertNotIn("8.8.8.8", serialized)
        self.assertNotIn("8.8.4.4", serialized)
        self.assertNotIn("51000", serialized)
        self.assertNotIn("52000", serialized)
        # The fixed-port PID-0 TIME_WAIT record is a port-bounded record, but it
        # is never classified as active external traffic.
        self.assertTrue(evidence["acceptance"]["no_external_connections"])
        self.assertEqual(
            evidence["external_connection_observation"][
                "non_loopback_connection_count"
            ],
            0,
        )

    def test_daemon_established_external_connection_is_counted(self):
        # A genuine daemon-owned non-loopback ESTABLISHED connection remains in
        # scope and is counted, failing acceptance.
        ready = make_snapshot(
            zap_home=self.zap_home,
            extra_connections=(
                ConnectionRecord(
                    "127.0.0.1", 50000, "93.184.216.34", 443, "ESTABLISHED", 555
                ),
            ),
        )
        gone = SystemSnapshot("Get-NetTCPConnection", (), ())
        system = FakeSystem([ready, ready, ready, gone])
        runner = self.make_runner(system=system)
        evidence = runner.run()

        self.assertFalse(evidence["acceptance"]["no_external_connections"])
        aggregate = evidence["external_connection_observation"]
        # The same established connection is observed at the ready and
        # pre-shutdown stages, so the aggregate counts it in both.
        self.assertEqual(aggregate["non_loopback_connection_count"], 2)
        stages = {stage["stage"]: stage for stage in aggregate["stages"]}
        self.assertEqual(
            stages["ready"]["non_loopback_connection_count"], 1
        )
        self.assertEqual(
            aggregate["non_loopback_connections"][0]["remote_address"],
            "93.184.216.34",
        )
        self.assertEqual(evidence["status"], "failed")

    # -- lifecycle / shutdown evidence ------------------------------------

    def test_start_failure_writes_failure_evidence(self):
        manager = FakeManager(fail_start=True)
        runner = self.make_runner(manager=manager)
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        self.assertTrue(manager.stopped)
        self.assertTrue((self.scan.scan_dir / SMOKE_JSON_FILENAME).is_file())

    def test_readiness_failure_still_shuts_down_and_records(self):
        manager = FakeManager(fail_ready=True)
        runner = self.make_runner(manager=manager)
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        self.assertTrue(manager.stopped)
        self.assertFalse(evidence["acceptance"]["process_exited"] is None)

    def test_root_launcher_pid_captured_immediately_after_start(self):
        class EarlyExitManager(FakeManager):
            def __init__(self):
                super().__init__(fail_ready=True)

            def wait_until_ready(self):
                # The detached daemon never appeared and the launcher handle is
                # no longer meaningful; the launcher pid must still be retained.
                self._daemon_pid = None
                raise RuntimeError("exited during startup")

        manager = EarlyExitManager()
        runner = self.make_runner(manager=manager)
        evidence = runner.run()

        self.assertEqual(evidence["process_ids"]["root_pid"], 4242)
        self.assertEqual(evidence["process_ids"]["launcher_pid"], 4242)
        self.assertEqual(
            evidence["process_exit_verification"]["launcher_pid"], 4242
        )

    def test_shutdown_not_sent_when_no_verified_daemon(self):
        manager = FakeManager(
            fail_ready=True,
            already_exited=True,
            has_identity=False,
            api_attempted=False,
            daemon_gone=True,
        )
        runner = self.make_runner(manager=manager)
        evidence = runner.run()

        shutdown = evidence["shutdown"]
        self.assertFalse(shutdown["api_attempted"])
        self.assertFalse(evidence["acceptance"]["api_shutdown_attempted"])
        self.assertEqual(shutdown["result"], "not_sent_process_already_exited")

    def test_shutdown_records_api_method_when_daemon_verified(self):
        manager = FakeManager()
        runner = self.make_runner(manager=manager)
        evidence = runner.run()
        self.assertEqual(evidence["shutdown"]["method"], "api_core_shutdown")
        self.assertEqual(evidence["shutdown"]["result"], "graceful")
        self.assertTrue(evidence["shutdown"]["api_attempted"])
        self.assertEqual(evidence["shutdown"]["daemon_pid_before"], 555)
        self.assertTrue(evidence["shutdown"]["both_ports_closed"])

    def test_shutdown_does_not_claim_graceful_when_ports_open(self):
        ready = make_snapshot(zap_home=self.zap_home)
        system = FakeSystem([ready, ready, ready, ready])
        manager = FakeManager(daemon_gone=False)
        runner = self.make_runner(manager=manager, system=system)
        evidence = runner.run()
        self.assertFalse(evidence["acceptance"]["both_ports_closed"])
        self.assertFalse(evidence["acceptance"]["daemon_gone"])
        self.assertEqual(evidence["status"], "failed")

    def test_failed_run_retains_factual_failure_phase(self):
        manager = FakeManager(fail_ready=True)
        runner = self.make_runner(manager=manager)
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        self.assertNotEqual(evidence["phase"], "done")
        self.assertEqual(evidence["phase"], "starting")

    def test_version_mismatch_fails_acceptance(self):
        class OldManager(FakeManager):
            def wait_until_ready(self):
                return "2.16.1"

        manager = OldManager()
        runner = self.make_runner(manager=manager)
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        self.assertFalse(evidence["acceptance"]["version_matches_expected"])

    def test_missing_executable_is_rejected_before_side_effects(self):
        # A capable, read-only inspection snapshot is injected so the preflight
        # capability gate is satisfied without touching the real system.
        capable = SystemSnapshot("Get-NetTCPConnection", (), ())
        runner = ZapSmokeRunner(
            scan_path=self.scan,
            executable=self.root / "nope.exe",
            bind_port=18080,
            system=FakeSystem([capable]),
            port_checker=lambda host, port: True,
        )
        evidence = runner.run()
        self.assertEqual(evidence["status"], "failed")
        json_path = self.scan.scan_dir / SMOKE_JSON_FILENAME
        self.assertTrue(json_path.is_file())

    # -- artifact acceptance ----------------------------------------------

    def _write_runtime_log(self, text):
        logs = self.scan.scan_dir / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        log = logs / "zap-stderr.log"
        log.write_text(text, encoding="utf-8")
        return log

    def test_detected_synthetic_key_fails_acceptance_redacted_and_unmutated(self):
        secret = "SYNTHETICAPIKEY0001"
        original = f"starting\napi.key={secret}\n"
        log = self._write_runtime_log(original)

        runner = self.make_runner()
        evidence = runner.run()

        self.assertFalse(
            evidence["acceptance"]["artifact_key_material_not_detected"]
        )
        self.assertTrue(evidence["acceptance"]["artifact_source_not_mutated"])
        self.assertEqual(evidence["status"], "failed")
        # The synthetic key is detected but never surfaced; the source is
        # byte-for-byte unchanged.
        self.assertTrue(evidence["artifact_inspection"]["key_material"]["detected"])
        self.assertNotIn(secret, json.dumps(evidence))
        self.assertIn("***", json.dumps(evidence["artifact_inspection"]))
        self.assertEqual(log.read_text(encoding="utf-8"), original)

    def test_runtime_error_log_lines_are_evidence_not_failure(self):
        self._write_runtime_log(
            "2026-10-03 12:00:01,000 [main] ERROR failed to bind\n"
        )
        runner = self.make_runner()
        evidence = runner.run()

        # Runtime ERROR lines are retained as artifact evidence, but they do not
        # by themselves fail an otherwise clean run.
        self.assertTrue(evidence["artifact_inspection"]["errors"])
        self.assertTrue(evidence["acceptance"]["artifact_key_material_not_detected"])
        self.assertTrue(evidence["acceptance"]["artifact_source_not_mutated"])
        self.assertEqual(evidence["status"], "succeeded")

    def test_clean_artifacts_pass_artifact_acceptance(self):
        self._write_runtime_log("all good\n")
        runner = self.make_runner()
        evidence = runner.run()
        self.assertTrue(evidence["acceptance"]["artifact_key_material_not_detected"])
        self.assertTrue(evidence["acceptance"]["artifact_source_not_mutated"])
        self.assertEqual(evidence["status"], "succeeded")


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeRunner:
    """Command runner returning a queued return code for every invocation."""

    def __init__(self, returncode, *, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append((list(cmd), timeout))
        return _FakeCompleted(self.returncode, self.stdout, self.stderr)


class PowerShellProcessControlTests(unittest.TestCase):
    """Nonzero Stop-Process results must fail truthfully, never silently pass."""

    def test_nonzero_stop_process_result_raises_for_terminate(self):
        runner = _FakeRunner(1)
        inspector = PowerShellLocalInspector(command_runner=runner)
        with self.assertRaises(SmokeProcessControlError) as ctx:
            inspector.terminate(4321)
        self.assertIn("terminate", str(ctx.exception))
        self.assertEqual(len(runner.calls), 1)

    def test_nonzero_stop_process_result_raises_for_kill(self):
        runner = _FakeRunner(5)
        inspector = PowerShellLocalInspector(command_runner=runner)
        with self.assertRaises(SmokeProcessControlError) as ctx:
            inspector.kill(4321)
        self.assertIn("kill", str(ctx.exception))
        self.assertIn("5", str(ctx.exception))

    def test_zero_stop_process_result_is_accepted(self):
        runner = _FakeRunner(0)
        inspector = PowerShellLocalInspector(command_runner=runner)
        inspector.terminate(4321)
        inspector.kill(4321)
        self.assertEqual(len(runner.calls), 2)

    def test_control_error_is_bounded_and_secret_free(self):
        secret = "SUPERSECRETVALUE"
        runner = _FakeRunner(3, stdout=f"leaked {secret}", stderr=secret)
        inspector = PowerShellLocalInspector(command_runner=runner)
        with self.assertRaises(SmokeProcessControlError) as ctx:
            inspector.kill(4321)
        # Only the action name and exit code are surfaced; captured command
        # output is never echoed into the bounded error.
        self.assertNotIn(secret, str(ctx.exception))
        self.assertLess(len(str(ctx.exception)), 200)


class MarkdownRenderTests(unittest.TestCase):
    def test_render_mirrors_key_fields(self):
        evidence = {
            "status": "succeeded",
            "phase": "done",
            "observed_version": "2.17.0",
            "scan_api_call_count": 0,
            "bind_endpoint": "http://127.0.0.1:18080",
        }
        markdown = render_markdown(evidence)
        self.assertIn("status: succeeded", markdown)
        self.assertIn("observed_version: 2.17.0", markdown)
        self.assertIn("scan_api_call_count: 0", markdown)
        self.assertIn("http://127.0.0.1:18080", markdown)

    def test_render_includes_preflight_aggregate_and_artifact_acceptance(self):
        evidence = {
            "status": "succeeded",
            "port_preflight": {
                "method": "local-bind-probe",
                "free": True,
                "inspection_available": True,
                "inspection": {
                    "method": "Get-NetTCPConnection",
                    "process_observation_available": True,
                    "connection_observation_available": True,
                    "available": True,
                },
            },
            "external_connection_observation": {
                "available": True,
                "required_stage_count": 2,
                "non_loopback_connection_count": 0,
                "stages": [
                    {"stage": "ready", "observation_available": True},
                    {"stage": "pre_shutdown", "observation_available": True},
                ],
                "non_loopback_connections": [],
            },
            "acceptance": {
                "inspection_preflight_available": True,
                "no_external_connections": True,
                "artifact_key_material_not_detected": True,
                "artifact_source_not_mutated": True,
            },
        }
        markdown = render_markdown(evidence)
        self.assertIn("## Preflight", markdown)
        self.assertIn("inspection_method: Get-NetTCPConnection", markdown)
        self.assertIn("process_observation_available: true", markdown)
        self.assertIn("external_connection_observation_stages", markdown)
        self.assertIn("aggregated_non_loopback_connection_count: 0", markdown)
        self.assertIn("inspection_preflight_available: true", markdown)
        self.assertIn("artifact_key_material_not_detected: true", markdown)
        self.assertIn("artifact_source_not_mutated: true", markdown)

    def test_render_includes_oast_callback_config_provenance(self):
        evidence = {
            "status": "succeeded",
            "oast_callback_config_verification": {
                "verified": True,
                "addon": "OAST",
                "version": "0.24.0",
                "verification_mode": (
                    "read-only offline inspection of installed add-on"
                ),
                "read_only": True,
                "offline": True,
                "sources": ["CallbackParam bytecode", "embedded help"],
                "verified_keys": [
                    "oast.callback.localaddr",
                    "oast.callback.remoteaddr",
                    "oast.callback.port",
                ],
                "installed_tool_modified": False,
                "installed_addon_modified": False,
            },
        }
        markdown = render_markdown(evidence)

        self.assertIn("## Endpoints and offline posture", markdown)
        self.assertIn("oast_callback_addon: OAST 0.24.0", markdown)
        self.assertIn("oast_callback_verified: true", markdown)
        self.assertIn("oast_callback_read_only: true", markdown)
        self.assertIn("oast_callback_offline: true", markdown)
        self.assertIn("CallbackParam bytecode", markdown)
        self.assertIn("embedded help", markdown)
        self.assertIn("oast.callback.localaddr", markdown)
        self.assertIn("oast.callback.remoteaddr", markdown)
        self.assertIn("oast.callback.port", markdown)
        self.assertIn("oast_callback_installed_tool_modified: false", markdown)
        self.assertIn("oast_callback_installed_addon_modified: false", markdown)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
