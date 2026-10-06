"""Offline unit tests for the in-namespace helper's pure logic.

The CONNECT parser and relay are exercised without any namespace or external
network. Namespace setup is only meaningful on Linux and is skipped elsewhere.
"""

import io
import json
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from red_teaming.recon import dns_wire, ipc, netpolicy, netns_helper
from red_teaming.recon.netns_helper import (
    DnsRelay,
    HelperError,
    ProxyDenied,
    _execute_tool,
    _kill_tool_process_group,
    _relay,
    parse_exec_payload,
    parse_proxy_connect_head,
    run_ip,
)


class ConnectHeadParserTests(unittest.TestCase):
    def test_accepts_exact_authority(self):
        self.assertEqual(
            parse_proxy_connect_head(b"CONNECT crt.sh:443 HTTP/1.1\r\n\r\n"),
            ("crt.sh", 443),
        )

    def test_normalizes_host_case_and_trailing_dot(self):
        self.assertEqual(
            parse_proxy_connect_head(b"CONNECT CRT.SH.:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            ("crt.sh", 443),
        )

    def test_denies_other_methods(self):
        with self.assertRaises(ProxyDenied) as ctx:
            parse_proxy_connect_head(b"GET http://crt.sh/ HTTP/1.1\r\n\r\n")
        self.assertEqual(ctx.exception.status, 405)

    def test_denies_other_ports_and_hosts(self):
        for head, status in (
            (b"CONNECT crt.sh:8443 HTTP/1.1\r\n\r\n", 403),
            (b"CONNECT crt.sh:80 HTTP/1.1\r\n\r\n", 403),
            (b"CONNECT acme.example:443 HTTP/1.1\r\n\r\n", 403),
            (b"CONNECT www.crt.sh:443 HTTP/1.1\r\n\r\n", 403),
            (b"CONNECT evilcrt.sh:443 HTTP/1.1\r\n\r\n", 403),
        ):
            with self.assertRaises(ProxyDenied) as ctx:
                parse_proxy_connect_head(head)
            self.assertEqual(ctx.exception.status, status, head)

    def test_denies_userinfo_and_ip_literals(self):
        with self.assertRaises(ProxyDenied) as ctx:
            parse_proxy_connect_head(b"CONNECT user@crt.sh:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(ctx.exception.reason, "userinfo_forbidden")
        with self.assertRaises(ProxyDenied) as ctx:
            parse_proxy_connect_head(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(ctx.exception.reason, "ip_literal_forbidden")
        with self.assertRaises(ProxyDenied):
            parse_proxy_connect_head(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n")

    def test_denies_malformed(self):
        for head in (
            b"CONNECT crt.sh HTTP/1.1\r\n\r\n",
            b"CONNECT :443 HTTP/1.1\r\n\r\n",
            b"CONNECT crt.sh: HTTP/1.1\r\n\r\n",
            b"CONNECT crt.sh:notaport HTTP/1.1\r\n\r\n",
            b"CONNECT crt.sh:443\r\n\r\n",
            b"",
        ):
            with self.assertRaises(ProxyDenied):
                parse_proxy_connect_head(head)


class RelayTests(unittest.TestCase):
    def test_relays_bytes_both_directions(self):
        client_a, client_b = socket.socketpair()
        upstream_a, upstream_b = socket.socketpair()
        stop = threading.Event()
        result = {}

        def run():
            result["counts"] = _relay(client_a, upstream_a, stop)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            client_b.settimeout(2.0)
            upstream_b.settimeout(2.0)
            client_b.sendall(b"to-upstream")
            self.assertEqual(upstream_b.recv(64), b"to-upstream")
            upstream_b.sendall(b"to-client")
            self.assertEqual(client_b.recv(64), b"to-client")
        finally:
            client_b.close()
            upstream_b.close()
            thread.join(timeout=3.0)
            stop.set()
            client_a.close()
            upstream_a.close()
        self.assertIn("counts", result)


class IpUtilityTests(unittest.TestCase):
    def test_run_ip_requires_absolute_path(self):
        with self.assertRaises(HelperError):
            run_ip("ip", ["link", "show"])


class ExecPayloadTests(unittest.TestCase):
    def valid(self, **overrides):
        payload = {
            "argv": ["/opt/tools/subfinder", "-version"],
            "cwd": "/work",
            "env": {"HOME": "/work", "HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""},
            "stdin_path": None,
            "stdout_path": "/work/out.bin",
            "stderr_path": "/work/err.bin",
            "status_path": "/work/status.json",
            "timeout": 120.0,
        }
        payload.update(overrides)
        return json.dumps(payload)

    def test_accepts_valid_payload(self):
        parsed = parse_exec_payload(self.valid())
        self.assertEqual(parsed["argv"], ("/opt/tools/subfinder", "-version"))
        self.assertEqual(parsed["cwd"], "/work")
        self.assertEqual(parsed["env"]["HTTPS_PROXY"], "http://127.0.0.1:1")

    def test_rejects_bad_json_and_shape(self):
        for text in ("not-json", "[]", "{}", json.dumps({"argv": []})):
            with self.assertRaises(HelperError):
                parse_exec_payload(text)

    def test_rejects_relative_argv0(self):
        with self.assertRaises(HelperError):
            parse_exec_payload(self.valid(argv=["subfinder", "-version"]))

    def test_rejects_paths_outside_cwd(self):
        with self.assertRaises(HelperError):
            parse_exec_payload(self.valid(stdout_path="/etc/passwd"))

    def test_rejects_secret_env_but_allows_proxies(self):
        with self.assertRaises(HelperError):
            parse_exec_payload(self.valid(env={"API_TOKEN": "x"}))
        parsed = parse_exec_payload(self.valid(env={"HTTP_PROXY": "http://127.0.0.1:1"}))
        self.assertIn("HTTP_PROXY", parsed["env"])

    def test_rejects_bad_timeout(self):
        with self.assertRaises(HelperError):
            parse_exec_payload(self.valid(timeout=0))
        with self.assertRaises(HelperError):
            parse_exec_payload(self.valid(timeout=9999))


class ToolProcessGroupTests(unittest.TestCase):
    def test_prefers_process_group_kill(self):
        class Proc:
            pid = 4321

            def kill(self):  # pragma: no cover - must not be called
                raise AssertionError("must not fall back to direct kill")

        with mock.patch.object(netns_helper.os, "killpg", create=True) as killpg:
            self.assertTrue(_kill_tool_process_group(Proc()))
        killpg.assert_called_once_with(4321, netns_helper._SIGKILL)

    def test_falls_back_to_direct_kill(self):
        killed = []

        class Proc:
            pid = 99

            def kill(self):
                killed.append(True)

        with mock.patch.object(
            netns_helper.os, "killpg", create=True, side_effect=OSError("nope")
        ):
            self.assertTrue(_kill_tool_process_group(Proc()))
        self.assertEqual(killed, [True])

    def test_rejects_missing_or_invalid_pid(self):
        self.assertFalse(_kill_tool_process_group(None))

        class Proc:
            pid = "not-an-int"

        self.assertFalse(_kill_tool_process_group(Proc()))


class _FakeProc:
    def __init__(self, *, timeout_raises=False, returncode=0):
        self.pid = 5555
        self.returncode = returncode
        self.stdout = io.BytesIO(b'{"host":"www.acme.example"}')
        self.stderr = io.BytesIO(b"")
        self._timeout_raises = timeout_raises
        self._waits = 0

    def wait(self, timeout=None):
        self._waits += 1
        if self._timeout_raises and self._waits == 1:
            raise subprocess.TimeoutExpired("tool", timeout)
        return self.returncode

    def kill(self):  # pragma: no cover - group kill is asserted separately
        pass


class ExecuteToolTests(unittest.TestCase):
    def _payload(self, work: Path, timeout=5.0):
        return {
            "argv": ["/opt/tools/subfinder", "-version"],
            "cwd": str(work),
            "env": {},
            "stdin_path": None,
            "stdout_path": str(work / "out.bin"),
            "stderr_path": str(work / "err.bin"),
            "status_path": str(work / "status.json"),
            "timeout": timeout,
        }

    def test_execute_tool_uses_new_session_and_kills_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            proc = _FakeProc()
            kills = []
            with mock.patch.object(
                netns_helper.subprocess, "Popen", return_value=proc
            ) as popen, mock.patch.object(
                netns_helper,
                "_kill_tool_process_group",
                side_effect=lambda p: kills.append(p),
            ):
                result = _execute_tool(self._payload(work))
            self.assertTrue(Path(work / "status.json").is_file())
        self.assertTrue(popen.call_args.kwargs.get("start_new_session"))
        self.assertEqual(kills, [proc])
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["timed_out"])

    def test_execute_tool_kills_group_on_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            proc = _FakeProc(timeout_raises=True, returncode=None)
            kills = []
            with mock.patch.object(
                netns_helper.subprocess, "Popen", return_value=proc
            ), mock.patch.object(
                netns_helper,
                "_kill_tool_process_group",
                side_effect=lambda p: kills.append(p),
            ):
                result = _execute_tool(self._payload(work))
        self.assertGreaterEqual(len(kills), 1)
        self.assertTrue(result["timed_out"])
        self.assertIsNone(result["exit_code"])


class DnsRelayTransportTests(unittest.TestCase):
    def _relay_pair(self):
        helper_end, broker_end = socket.socketpair()
        stop = threading.Event()
        relay = DnsRelay(
            listen_host=netpolicy.UPSTREAM_DNS_HOST,
            listen_port=53,
            dns_sock=helper_end,
            stop_event=stop,
        )
        return relay, broker_end, stop

    def test_mismatched_response_tag_fails_closed(self):
        relay, broker_end, stop = self._relay_pair()
        try:
            def peer():
                payload = ipc.recv_frame(broker_end)
                protocol, _query = ipc.decode_dns_request(payload)
                wrong = netpolicy.DNS_PROTO_TCP if protocol == netpolicy.DNS_PROTO_UDP else netpolicy.DNS_PROTO_UDP
                ipc.send_frame(broker_end, ipc.encode_dns_response(wrong, ipc.STATUS_OK, b"x"))

            thread = threading.Thread(target=peer, daemon=True)
            thread.start()
            with self.assertRaises(HelperError):
                relay._forward(netpolicy.DNS_PROTO_UDP, b"\x00\x00")
            thread.join(timeout=2.0)
        finally:
            stop.set()

    def test_matching_response_tag_is_accepted(self):
        relay, broker_end, stop = self._relay_pair()
        try:
            def peer():
                payload = ipc.recv_frame(broker_end)
                protocol, _query = ipc.decode_dns_request(payload)
                ipc.send_frame(broker_end, ipc.encode_dns_response(protocol, ipc.STATUS_OK, b"ok"))

            thread = threading.Thread(target=peer, daemon=True)
            thread.start()
            status, response = relay._forward(netpolicy.DNS_PROTO_UDP, b"\x00\x00")
            self.assertEqual(status, ipc.STATUS_OK)
            self.assertEqual(response, b"ok")
            thread.join(timeout=2.0)
        finally:
            stop.set()


class LocalBootstrapDnsTests(unittest.TestCase):
    """The pinned tool's own engine-bootstrap probe is answered locally only."""

    def _query(self, name, qtype):
        return dns_wire.build_query(name, qtype, 0x1234)

    def test_answers_engine_bootstrap_name_locally(self):
        query = self._query("bgp.tools", netpolicy.DNS_TYPE_A)
        response = netns_helper._local_bootstrap_response(query)
        self.assertIsNotNone(response)
        parsed = dns_wire.parse_response(
            response,
            expect_id=0x1234,
            expect_name="bgp.tools",
            expect_type=netpolicy.DNS_TYPE_A,
        )
        self.assertEqual(dns_wire.extract_addresses(parsed), ("127.0.0.1",))

    def test_other_names_and_types_are_not_answered_locally(self):
        self.assertIsNone(
            netns_helper._local_bootstrap_response(
                self._query("example.com", netpolicy.DNS_TYPE_A)
            )
        )
        self.assertIsNone(
            netns_helper._local_bootstrap_response(
                self._query("bgp.tools", netpolicy.DNS_TYPE_AAAA)
            )
        )
        self.assertIsNone(netns_helper._local_bootstrap_response(b"\x00\x00"))

    def test_relay_serves_bootstrap_without_broker(self):
        helper_end, broker_end = socket.socketpair()
        stop = threading.Event()
        relay = DnsRelay(
            listen_host=netpolicy.UPSTREAM_DNS_HOST,
            listen_port=53,
            dns_sock=helper_end,
            stop_event=stop,
        )
        try:
            broker_end.setblocking(False)
            status, response = relay._forward(
                netpolicy.DNS_PROTO_UDP,
                self._query("bgp.tools", netpolicy.DNS_TYPE_A),
            )
            self.assertEqual(status, ipc.STATUS_OK)
            parsed = dns_wire.parse_response(
                response,
                expect_id=0x1234,
                expect_name="bgp.tools",
                expect_type=netpolicy.DNS_TYPE_A,
            )
            self.assertEqual(dns_wire.extract_addresses(parsed), ("127.0.0.1",))
            # No broker frame was sent for the locally-answered bootstrap name.
            with self.assertRaises(BlockingIOError):
                broker_end.recv(1)
        finally:
            stop.set()
            helper_end.close()
            broker_end.close()


if __name__ == "__main__":
    unittest.main()
