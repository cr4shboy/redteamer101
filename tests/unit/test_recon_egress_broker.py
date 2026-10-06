"""Offline unit tests for the RECON-002 outer egress broker.

Every dependency (DNS client, connector, clock, sleep) is injected: no external
network, DNS, or real connection is ever attempted.
"""

import socket
import threading
import unittest
from pathlib import Path
from unittest import mock

from red_teaming.recon import (
    dns_wire,
    egress_broker,
    ipc,
    netpolicy,
    netns_helper,
    netns_sandbox,
    netns_selftest,
)
from red_teaming.recon.egress_broker import (
    BrokerDenied,
    BrokerUpstreamError,
    DnsWireClient,
    EgressBroker,
    TokenBucket,
    _connect_literal,
    _default_connector,
)
from red_teaming.recon.runner import ToolScopedBroker, allowed_channels_for
from red_teaming.recon.tool_argv import LIVE
from red_teaming.recon.netpolicy import (
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
)

CRT_A = "8.8.8.8"
CRT_AAAA = "2606:4700::1111"


def _query(name, qtype, txn=1):
    return dns_wire.build_query(name, qtype, txn)


def _raw_query(name, qtype, txn=1):
    """Build a query with an arbitrary record type (bypassing the builder)."""

    query = bytearray(dns_wire.build_query(name, DNS_TYPE_A, txn))
    query[-4:-2] = qtype.to_bytes(2, "big")
    return bytes(query)


class FakeDnsClient:
    """Returns canned responses and records calls."""

    def __init__(self, mapping=None, gate=None):
        self.mapping = dict(mapping or {})
        self.queries = []
        self.exchanges = []
        self.gate = gate
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def _answers(self, name, qtype):
        values = self.mapping.get((name, qtype))
        if values is None and qtype == DNS_TYPE_A:
            values = [CRT_A]
        if values is None and qtype == DNS_TYPE_AAAA:
            values = [CRT_AAAA]
        return [(name, qtype, value) for value in (values or [])]

    def _respond(self, name, qtype, txn=1):
        query = dns_wire.build_query(name, qtype, txn)
        return dns_wire.build_response_for_query(query, self._answers(name, qtype))

    def query(self, name, qtype):
        self.queries.append((name, qtype))
        return self._respond(name, qtype)

    def exchange(self, query, *, expected_name, expected_type):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            parsed = dns_wire.parse_query(query)
            self.exchanges.append((parsed.name, parsed.qtype))
            if self.gate is not None:
                self.gate.wait(timeout=5.0)
            return self._respond(parsed.name, parsed.qtype, parsed.transaction_id)
        finally:
            with self._lock:
                self.active -= 1


class FakeConnector:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result if result is not None else object()
        self.error = error

    def __call__(self, ip, port, timeout):
        self.calls.append((ip, port, timeout))
        if self.error is not None:
            raise self.error
        return self.result


class OpenApprovedSocketTests(unittest.TestCase):
    def test_denies_disallowed_authority_before_resolver_or_connector(self):
        dns = FakeDnsClient()
        connector = FakeConnector()
        broker = EgressBroker(dns_client=dns, connector=connector)
        for host, port in (("example.com", 443), ("crt.sh", 8443), ("acme.example", 443)):
            with self.assertRaises(BrokerDenied):
                broker.open_approved_socket(host, port)
        self.assertEqual(dns.queries, [])
        self.assertEqual(connector.calls, [])
        events = broker.get_events()
        self.assertTrue(all(e["decision"] == "denied" for e in events))

    def test_allows_exact_authority_with_literal_ip(self):
        dns = FakeDnsClient()
        connector = FakeConnector()
        broker = EgressBroker(dns_client=dns, connector=connector)
        opened, ip = broker.open_approved_socket("CRT.SH.", 443)
        self.assertIs(opened, connector.result)
        self.assertIn(ip, {CRT_A, CRT_AAAA})
        self.assertTrue(all(port == 443 for _ip, port, _t in connector.calls))
        self.assertTrue(all(isinstance(_ip, str) for _ip, _p, _t in connector.calls))

    def test_resolve_bootstrap_rejects_non_global_answers(self):
        dns = FakeDnsClient(
            mapping={
                ("crt.sh", DNS_TYPE_A): ["127.0.0.1", "10.0.0.1"],
                ("crt.sh", DNS_TYPE_AAAA): [],
            }
        )
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())
        with self.assertRaises(BrokerUpstreamError):
            broker.resolve_bootstrap("crt.sh")

    def test_resolve_bootstrap_denies_other_hosts(self):
        broker = EgressBroker(dns_client=FakeDnsClient(), connector=FakeConnector())
        with self.assertRaises(BrokerDenied):
            broker.resolve_bootstrap("acme.example")

    def test_connector_failure_fails_closed(self):
        dns = FakeDnsClient()
        connector = FakeConnector(error=OSError("boom"))
        broker = EgressBroker(dns_client=dns, connector=connector)
        with self.assertRaises(BrokerUpstreamError):
            broker.open_approved_socket("crt.sh", 443)


class ForwardDnsTests(unittest.TestCase):
    def test_denies_out_of_scope_before_upstream(self):
        dns = FakeDnsClient()
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())
        with self.assertRaises(BrokerDenied):
            broker.forward_dns(netpolicy.DNS_PROTO_UDP, _query("example.com", DNS_TYPE_A))
        self.assertEqual(dns.exchanges, [])

    def test_denies_bootstrap_on_target_relay(self):
        dns = FakeDnsClient()
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())
        with self.assertRaises(BrokerDenied):
            broker.forward_dns(netpolicy.DNS_PROTO_UDP, _query("crt.sh", DNS_TYPE_A))
        self.assertEqual(dns.exchanges, [])

    def test_denies_disallowed_types(self):
        dns = FakeDnsClient()
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())
        for qtype in (15, 16, 2):
            with self.assertRaises(BrokerDenied):
                broker.forward_dns(
                    netpolicy.DNS_PROTO_UDP, _raw_query("acme.example", qtype)
                )
        self.assertEqual(dns.exchanges, [])

    def test_denies_malformed_query(self):
        dns = FakeDnsClient()
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())
        with self.assertRaises(BrokerDenied):
            broker.forward_dns(netpolicy.DNS_PROTO_UDP, b"\x00" * 13)
        self.assertEqual(dns.exchanges, [])

    def test_allows_in_scope_questions(self):
        dns = FakeDnsClient(
            mapping={
                ("acme.example", DNS_TYPE_A): ["198.51.100.1"],
                ("www.acme.example", DNS_TYPE_CNAME): ["target.acme.example"],
            }
        )
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())
        response = broker.forward_dns(
            netpolicy.DNS_PROTO_UDP, _query("acme.example", DNS_TYPE_A, txn=9)
        )
        parsed = dns_wire.parse_response(
            response, expect_id=9, expect_name="acme.example", expect_type=DNS_TYPE_A
        )
        self.assertEqual(dns_wire.extract_addresses(parsed), ("198.51.100.1",))
        self.assertEqual(dns.exchanges, [("acme.example", DNS_TYPE_A)])

    def test_response_validation_failure_fails_closed(self):
        class BadDns:
            def exchange(self, query, *, expected_name, expected_type):
                return b"\x00" * 13

        broker = EgressBroker(dns_client=BadDns(), connector=FakeConnector())
        with self.assertRaises(BrokerUpstreamError):
            broker.forward_dns(
                netpolicy.DNS_PROTO_UDP, _query("acme.example", DNS_TYPE_A)
            )


class NoSystemResolverTests(unittest.TestCase):
    def test_no_resolver_apis_in_egress_layer_sources(self):
        modules = (
            netpolicy,
            dns_wire,
            egress_broker,
            netns_helper,
            netns_sandbox,
            netns_selftest,
        )
        for module in modules:
            source = Path(module.__file__).read_text(encoding="utf-8")
            for forbidden in ("getaddrinfo", "gethostbyname", "getnameinfo"):
                self.assertNotIn(forbidden, source, f"{module.__name__} uses {forbidden}")

    def test_default_connector_validates_before_creating_socket(self):
        with mock.patch.object(socket, "socket") as socket_mock:
            with self.assertRaises(netpolicy.PolicyError):
                _default_connector("127.0.0.1", 443, 1.0)
            socket_mock.assert_not_called()
        with self.assertRaises(netpolicy.PolicyError):
            _connect_literal("10.0.0.1", 53, socket.SOCK_DGRAM, 1.0)


class DnsWireClientTests(unittest.TestCase):
    def _client(self, udp, tcp=None):
        return DnsWireClient(
            udp_exchange=udp,
            tcp_exchange=tcp or (lambda q, t: b""),
            transaction_id=lambda: 0x4321,
        )

    def test_validates_and_returns_response(self):
        query = _query("crt.sh", DNS_TYPE_A, txn=0x4321)

        def udp(q, timeout):
            return dns_wire.build_response_for_query(
                q, [("crt.sh", DNS_TYPE_A, "8.8.8.8")]
            )

        client = self._client(udp)
        response = client.exchange(query, expected_name="crt.sh", expected_type=DNS_TYPE_A)
        self.assertTrue(response)

    def test_truncated_udp_uses_tcp(self):
        calls = {"tcp": 0}

        def udp(q, timeout):
            return dns_wire.build_response_for_query(q, [], truncated=True)

        def tcp(q, timeout):
            calls["tcp"] += 1
            return dns_wire.build_response_for_query(q, [("crt.sh", DNS_TYPE_A, "8.8.8.8")])

        client = self._client(udp, tcp)
        client.exchange(
            _query("crt.sh", DNS_TYPE_A, txn=0x4321),
            expected_name="crt.sh",
            expected_type=DNS_TYPE_A,
        )
        self.assertEqual(calls["tcp"], 1)

    def test_mismatched_response_fails_closed(self):
        def udp(q, timeout):
            return dns_wire.build_response_for_query(q, [("crt.sh", DNS_TYPE_A, "8.8.8.8")])

        client = self._client(udp)
        with self.assertRaises(BrokerUpstreamError):
            client.exchange(
                _query("crt.sh", DNS_TYPE_A, txn=0x4321),
                expected_name="other.crt.sh",
                expected_type=DNS_TYPE_A,
            )


class TokenBucketTests(unittest.TestCase):
    def test_rate_and_bounded_wait(self):
        now = {"t": 0.0}
        sleeps = []

        def clock():
            return now["t"]

        def sleep(seconds):
            sleeps.append(seconds)
            now["t"] += seconds

        bucket = TokenBucket(5, capacity=5, clock=clock, sleep=sleep, max_wait=10.0)
        for _ in range(5):
            bucket.acquire()
        self.assertEqual(sleeps, [])
        bucket.acquire()
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.2, places=6)

    def test_bounded_wait_exceeded(self):
        bucket = TokenBucket(1, capacity=1, clock=lambda: 0.0, sleep=lambda s: None, max_wait=0.5)
        bucket.acquire()
        with self.assertRaises(egress_broker.BrokerError):
            bucket.acquire()


class ConcurrencyBoundTests(unittest.TestCase):
    def test_at_most_two_concurrent_dns_paths(self):
        gate = threading.Event()
        dns = FakeDnsClient(gate=gate)
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())

        barrier = threading.Barrier(3)
        errors = []

        def worker():
            try:
                barrier.wait(timeout=5.0)
                broker.forward_dns(
                    netpolicy.DNS_PROTO_UDP, _query("acme.example", DNS_TYPE_A)
                )
            except Exception as exc:  # pragma: no cover - failure reporting
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for thread in threads:
            thread.start()
        # Let the first two enter the exchange; the third must be held by the
        # broker's semaphore, so it can never make three concurrent paths.
        for _ in range(200):
            if dns.active >= 2:
                break
            threading.Event().wait(0.005)
        observed_active = dns.active
        gate.set()
        for thread in threads:
            thread.join(timeout=5.0)
        self.assertEqual(errors, [])
        self.assertEqual(observed_active, 2)
        self.assertEqual(dns.max_active, 2)


class EvidenceRedactionTests(unittest.TestCase):
    def test_events_are_bounded_and_request_data_free(self):
        dns = FakeDnsClient()
        broker = EgressBroker(dns_client=dns, connector=FakeConnector())
        long_name = "a" * 60 + ".acme.example"
        with self.assertRaises(BrokerDenied):
            broker.forward_dns(
                netpolicy.DNS_PROTO_TCP, _query("evil.example.com", DNS_TYPE_A)
            )
        with self.assertRaises(BrokerDenied):
            broker.open_approved_socket("evil.example.com", 443)
        for event in broker.get_events():
            self.assertEqual(
                set(event),
                {
                    "timestamp",
                    "component",
                    "action",
                    "decision",
                    "reason",
                    "host",
                    "port",
                    "qname",
                    "qtype",
                    "protocol",
                    "upstream_ip",
                    "upstream_host",
                    "upstream_port",
                },
            )
            for key in (
                "reason",
                "host",
                "qname",
                "qtype",
                "protocol",
                "upstream_ip",
                "upstream_host",
            ):
                value = event[key]
                if value is not None:
                    self.assertLessEqual(len(str(value)), 256)
                    self.assertNotIn("\n", str(value))
        self.assertTrue(broker.get_events())
        _ = long_name  # names are bounded by policy, not stored unbounded


class ToolScopedBrokerTests(unittest.TestCase):
    def _spy_egress(self):
        class SpyEgress:
            def __init__(self):
                self.serve_connect_calls = 0
                self.serve_dns_calls = 0
                self.stopped = 0

            def serve_connect(self, sock, event):
                self.serve_connect_calls += 1

            def serve_dns(self, sock, event):
                self.serve_dns_calls += 1

            def get_events(self):
                return []

            def stop(self):
                self.stopped += 1

        return SpyEgress()

    def test_channel_scoping_by_tool(self):
        self.assertEqual(allowed_channels_for("subfinder", LIVE), frozenset({"connect"}))
        self.assertEqual(allowed_channels_for("amass", LIVE), frozenset({"connect"}))
        self.assertEqual(allowed_channels_for("dnsx", LIVE), frozenset({"dns"}))
        self.assertEqual(allowed_channels_for("subfinder", "inspection"), frozenset())
        self.assertEqual(allowed_channels_for("dnsx", "inspection"), frozenset())

    def test_subfinder_scopes_connect_to_egress_and_dns_to_deny(self):
        egress = self._spy_egress()
        broker = ToolScopedBroker(tool="subfinder", invocation=LIVE, egress=egress)
        self.assertEqual(broker.channel_owner("connect"), "egress")
        self.assertEqual(broker.channel_owner("dns"), "deny")
        sock, peer = socket.socketpair()
        try:
            broker._serve_connect(sock, threading.Event())
        finally:
            sock.close()
            peer.close()
        self.assertEqual(egress.serve_connect_calls, 1)
        self.assertEqual(egress.serve_dns_calls, 0)

    def test_dnsx_disallowed_connect_denied_before_connector(self):
        connector = FakeConnector()
        egress = EgressBroker(dns_client=FakeDnsClient(), connector=connector)
        broker = ToolScopedBroker(tool="dnsx", invocation=LIVE, egress=egress)
        self.assertEqual(broker.channel_owner("connect"), "deny")
        self.assertEqual(broker.channel_owner("dns"), "egress")
        sock, peer = socket.socketpair()
        sent: list = []
        try:
            with mock.patch.object(
                ipc,
                "recv_message_fd",
                side_effect=[
                    (ipc.encode_connect_request("crt.sh", 443), None),
                    ipc.IpcClosed("done"),
                ],
            ), mock.patch.object(
                ipc, "send_fd_message", side_effect=lambda s, p, *a: sent.append(p)
            ):
                broker._serve_connect(sock, threading.Event())
        finally:
            sock.close()
            peer.close()
        self.assertEqual(connector.calls, [])
        self.assertTrue(sent)
        ok, _reason = ipc.decode_connect_response(sent[0])
        self.assertFalse(ok)
        self.assertTrue(
            any(
                event["action"] == "connect" and event["decision"] == "denied"
                for event in broker.get_events()
            )
        )

    def test_subfinder_disallowed_dns_denied_before_upstream(self):
        dns = FakeDnsClient()
        egress = EgressBroker(dns_client=dns, connector=FakeConnector())
        broker = ToolScopedBroker(tool="subfinder", invocation=LIVE, egress=egress)
        sock, peer = socket.socketpair()
        sent: list = []
        frame = ipc.encode_dns_request(
            netpolicy.DNS_PROTO_UDP, _query("acme.example", DNS_TYPE_A)
        )
        try:
            with mock.patch.object(
                ipc, "recv_frame", side_effect=[frame, None]
            ), mock.patch.object(
                ipc, "send_frame", side_effect=lambda s, p: sent.append(p)
            ):
                broker._serve_dns(sock, threading.Event())
        finally:
            sock.close()
            peer.close()
        self.assertEqual(dns.exchanges, [])
        self.assertTrue(sent)
        _tag, status, _response = ipc.decode_dns_response(sent[0])
        self.assertEqual(status, ipc.STATUS_DENIED)


if __name__ == "__main__":
    unittest.main()
