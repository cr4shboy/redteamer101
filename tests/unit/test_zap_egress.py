"""Offline unit tests for the loopback exact-host CONNECT egress guard.

No external network, DNS, target, process, or ZAP launch occurs: the resolver,
connector, relay, clock, and ``now`` function are all injected fakes, and the
only real sockets are loopback sockets used to exercise lifecycle and relay
behavior. No target is contacted.
"""

import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

from red_teaming.tools.zap import egress
from red_teaming.tools.zap.egress import (
    DECISION_ALLOWED,
    DECISION_DENIED,
    DECISION_ERROR,
    MAX_FIELD_LENGTH,
    REASON_ADDRESS_SET_CHANGED,
    REASON_HOST,
    REASON_IP_LITERAL,
    REASON_MALFORMED,
    REASON_METHOD,
    REASON_PORT,
    REASON_RESOLVE_FAILED,
    REASON_TOO_LARGE,
    REASON_UPSTREAM_FAILED,
    REASON_USERINFO,
    ConnectEgressGuard,
    EgressBindError,
    EgressConfigError,
    EgressDeniedError,
    EgressPreflightError,
    EgressStateError,
    parse_connect_authority,
    parse_connect_request,
)

TARGET_HOST = "acme.example"
TARGET_PORT = 443
PUBLIC_A = "8.8.8.8"
PUBLIC_B = "1.1.1.1"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeSocket:
    """A minimal deterministic socket stand-in."""

    def __init__(self, incoming=b""):
        self._incoming = bytearray(incoming)
        self.sent = bytearray()
        self.closed = False

    def recv(self, n):
        if not self._incoming:
            return b""
        chunk = bytes(self._incoming[:n])
        del self._incoming[:n]
        return chunk

    def sendall(self, data):
        if self.closed:
            raise OSError("closed")
        self.sent.extend(data)

    def close(self):
        self.closed = True


class StaticResolver:
    def __init__(self, ips):
        self.ips = list(ips)
        self.hosts = []

    def __call__(self, host):
        self.hosts.append(host)
        return list(self.ips)


class SequenceResolver:
    def __init__(self, results):
        self._results = list(results)
        self.hosts = []

    def __call__(self, host):
        self.hosts.append(host)
        if not self._results:
            raise AssertionError("resolver called too many times")
        return self._results.pop(0)


class FlakyResolver:
    def __init__(self, first, error):
        self._first = list(first)
        self._error = error
        self.hosts = []
        self.calls = 0

    def __call__(self, host):
        self.hosts.append(host)
        self.calls += 1
        if self.calls == 1:
            return list(self._first)
        raise self._error


class FakeConnector:
    def __init__(self, upstream=None, error=None):
        self.upstream = upstream
        self.error = error
        self.calls = []

    def __call__(self, ip, port, timeout):
        self.calls.append((ip, port, timeout))
        if self.error is not None:
            raise self.error
        return self.upstream if self.upstream is not None else FakeSocket()


class ExplodingResolver:
    def __call__(self, host):
        raise AssertionError("resolver must not be called")


class ExplodingConnector:
    def __call__(self, ip, port, timeout):
        raise AssertionError("connector must not be called")


def request_bytes(
    authority,
    *,
    method="CONNECT",
    version="HTTP/1.1",
    headers=b"Host: acme.example\r\n",
):
    line = f"{method} {authority} {version}\r\n".encode("ascii", "replace")
    return line + headers + b"\r\n"


def make_guard(*, resolver=None, connector=None, relay=None, **kwargs):
    options = dict(
        bind_host="127.0.0.1",
        bind_port=0,
        resolver=resolver if resolver is not None else StaticResolver([PUBLIC_A]),
        connector=connector if connector is not None else FakeConnector(),
        relay=relay if relay is not None else (lambda a, b, e: (0, 0)),
    )
    options.update(kwargs)
    return ConnectEgressGuard(**options)


def recv_head(sock, limit=8192):
    data = b""
    sock.settimeout(5)
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data


# ---------------------------------------------------------------------------
# Pure authority / request parsing
# ---------------------------------------------------------------------------


class AuthorityParsingTests(unittest.TestCase):
    def assert_denied(self, authority, reason):
        with self.assertRaises(EgressDeniedError) as ctx:
            parse_connect_authority(
                authority, target_host=TARGET_HOST, target_port=TARGET_PORT
            )
        self.assertEqual(ctx.exception.reason, reason)
        if isinstance(authority, str) and authority:
            self.assertNotIn(authority, str(ctx.exception))

    def test_exact_and_normalized_forms_are_accepted(self):
        for authority in (
            "acme.example:443",
            "ACME.EXAMPLE:443",
            "Acme.Example:443",
            "acme.example.:443",
        ):
            with self.subTest(authority=authority):
                self.assertEqual(
                    parse_connect_authority(
                        authority, target_host=TARGET_HOST, target_port=TARGET_PORT
                    ),
                    (TARGET_HOST, TARGET_PORT),
                )

    def test_subdomains_siblings_and_other_hosts_are_rejected(self):
        for authority in (
            "sub.acme.example:443",
            "deep.sub.acme.example:443",
            "acme.example.evil.test:443",
            "evil.test:443",
            "xn--acme-xyz.lt:443",
        ):
            with self.subTest(authority=authority):
                self.assert_denied(authority, REASON_HOST)

    def test_wrong_port_is_rejected(self):
        for authority in (
            "acme.example:8443",
            "acme.example:80",
            "acme.example:notaport",
        ):
            with self.subTest(authority=authority):
                self.assert_denied(authority, REASON_PORT)

    def test_ip_literals_are_rejected(self):
        for authority in (
            "1.2.3.4:443",
            "127.0.0.1:443",
            "[::1]:443",
            "[2001:db8::1]:443",
        ):
            with self.subTest(authority=authority):
                self.assert_denied(authority, REASON_IP_LITERAL)

    def test_userinfo_is_rejected(self):
        for authority in (
            "user@acme.example:443",
            "user:pass@acme.example:443",
        ):
            with self.subTest(authority=authority):
                self.assert_denied(authority, REASON_USERINFO)

    def test_malformed_and_oversized_are_rejected(self):
        for authority in (
            "acme.example",
            "acme.example:",
            ":443",
            "::1:443",
            "acme.example:443:443",
            "acme.example:443 ",
            " acme.example:443",
            "",
            None,
            123,
        ):
            with self.subTest(authority=authority):
                self.assert_denied(authority, REASON_MALFORMED)

        long_host = ("a" * 600) + ".lt:443"
        self.assert_denied(long_host, REASON_TOO_LARGE)


class RequestParsingTests(unittest.TestCase):
    def test_valid_connect_request_parses(self):
        head = request_bytes("acme.example:443")
        self.assertEqual(
            parse_connect_request(head, target_host=TARGET_HOST, target_port=TARGET_PORT),
            (TARGET_HOST, TARGET_PORT),
        )

    def test_plain_http_methods_are_rejected(self):
        for method in ("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"):
            with self.subTest(method=method):
                head = request_bytes("acme.example:443", method=method)
                with self.assertRaises(EgressDeniedError) as ctx:
                    parse_connect_request(
                        head, target_host=TARGET_HOST, target_port=TARGET_PORT
                    )
                self.assertEqual(ctx.exception.reason, REASON_METHOD)

    def test_lowercase_connect_is_rejected(self):
        head = request_bytes("acme.example:443", method="connect")
        with self.assertRaises(EgressDeniedError) as ctx:
            parse_connect_request(
                head, target_host=TARGET_HOST, target_port=TARGET_PORT
            )
        self.assertEqual(ctx.exception.reason, REASON_METHOD)

    def test_malformed_request_lines_are_rejected(self):
        for head in (
            b"",
            b"\r\n\r\n",
            b"CONNECT\r\n\r\n",
            b"CONNECT acme.example:443\r\n\r\n",
            b"CONNECT  acme.example:443 HTTP/1.1\r\n\r\n",
            b"CONNECT acme.example:443 HTTP/1.1 extra\r\n\r\n",
            b"CONNECT acme.example:443 FTP/1.1\r\n\r\n",
            b"CONNECT acme.example:443 HTTP/1.1\x00\r\n\r\n",
            None,
        ):
            with self.subTest(head=head):
                with self.assertRaises(EgressDeniedError) as ctx:
                    parse_connect_request(
                        head, target_host=TARGET_HOST, target_port=TARGET_PORT
                    )
                self.assertEqual(
                    ctx.exception.reason,
                    REASON_MALFORMED,
                )


# ---------------------------------------------------------------------------
# Preparation / pinning
# ---------------------------------------------------------------------------


class PreparationTests(unittest.TestCase):
    def test_pins_sorted_deterministic_set_and_only_exact_host(self):
        resolver = StaticResolver([PUBLIC_A, PUBLIC_B, PUBLIC_A])
        guard = make_guard(resolver=resolver)
        self.assertFalse(guard.prepared)
        guard.prepare()
        self.assertTrue(guard.prepared)
        self.assertEqual(guard.pinned_ips, (PUBLIC_B, PUBLIC_A))
        self.assertEqual(resolver.hosts, [TARGET_HOST])

    def test_non_global_results_fail_preparation(self):
        for ips in (
            [],
            ["10.0.0.1"],
            ["127.0.0.1"],
            ["169.254.1.1"],
            ["224.0.0.1"],
            ["0.0.0.0"],
            ["192.0.2.1"],
            ["fe80::1"],
            ["::1"],
            ["::ffff:8.8.8.8"],
            [PUBLIC_A, "10.0.0.1"],
        ):
            with self.subTest(ips=ips):
                guard = make_guard(resolver=StaticResolver(ips))
                with self.assertRaises(EgressPreflightError):
                    guard.prepare()
                self.assertFalse(guard.prepared)

    def test_malformed_resolver_results_fail_preparation(self):
        for raw in (
            "8.8.8.8",
            b"8.8.8.8",
            None,
            [None],
            [b"8.8.8.8"],
            [" 8.8.8.8"],
            ["not-an-ip"],
            [123],
        ):
            with self.subTest(raw=raw):
                guard = make_guard(resolver=lambda host, raw=raw: raw)
                with self.assertRaises(EgressPreflightError):
                    guard.prepare()

    def test_resolver_exception_fails_preparation_safely(self):
        guard = make_guard(
            resolver=lambda host: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        with self.assertRaises(EgressPreflightError) as ctx:
            guard.prepare()
        self.assertNotIn("boom", str(ctx.exception))

    def test_prepare_can_re_pin_while_stopped(self):
        resolver = SequenceResolver([[PUBLIC_A], [PUBLIC_B]])
        guard = make_guard(resolver=resolver)
        guard.prepare()
        self.assertEqual(guard.pinned_ips, (PUBLIC_A,))
        guard.prepare()
        self.assertEqual(guard.pinned_ips, (PUBLIC_B,))
        self.assertEqual(resolver.hosts, [TARGET_HOST, TARGET_HOST])


# ---------------------------------------------------------------------------
# Denial before any outbound call
# ---------------------------------------------------------------------------


class RejectionBeforeOutboundTests(unittest.TestCase):
    def _guard(self):
        return make_guard(
            resolver=ExplodingResolver(), connector=ExplodingConnector()
        )

    def test_plain_methods_rejected_before_resolver_and_connector(self):
        guard = self._guard()
        for method in ("GET", "POST", "OPTIONS", "HEAD"):
            with self.subTest(method=method):
                client = FakeSocket(request_bytes("acme.example:443", method=method))
                decision = guard.handle_client(client)
                self.assertEqual(decision, DECISION_DENIED)
                self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 405"))
                self.assertIn(b"Connection: close", client.sent)

    def test_bad_authorities_rejected_before_resolver_and_connector(self):
        guard = self._guard()
        for authority in (
            "sub.acme.example:443",
            "acme.example.evil.test:443",
            "1.2.3.4:443",
            "user@acme.example:443",
            "acme.example:8443",
            "acme.example",
            "acme.example:notaport",
        ):
            with self.subTest(authority=authority):
                client = FakeSocket(request_bytes(authority))
                decision = guard.handle_client(client)
                self.assertEqual(decision, DECISION_DENIED)
                self.assertIn(b"Content-Length: 0", client.sent)

    def test_oversized_request_head_rejected_before_resolver(self):
        guard = self._guard()
        body = b"CONNECT acme.example:443 HTTP/1.1\r\n" + b"X: " + b"a" * 20000 + b"\r\n\r\n"
        client = FakeSocket(body)
        decision = guard.handle_client(client)
        self.assertEqual(decision, DECISION_DENIED)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 400"))

    def test_oversized_single_header_line_rejected(self):
        guard = self._guard()
        head = request_bytes("acme.example:443", headers=b"X: " + b"a" * 3000 + b"\r\n")
        client = FakeSocket(head)
        decision = guard.handle_client(client)
        self.assertEqual(decision, DECISION_DENIED)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 400"))

    def test_truncated_request_without_terminator_rejected(self):
        guard = self._guard()
        client = FakeSocket(b"CONNECT acme.example:443 HTTP/1.1\r\nHost: x\r\n")
        decision = guard.handle_client(client)
        self.assertEqual(decision, DECISION_DENIED)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 400"))

    def test_not_prepared_is_denied_without_resolving(self):
        guard = make_guard(
            resolver=ExplodingResolver(), connector=ExplodingConnector()
        )
        client = FakeSocket(request_bytes("acme.example:443"))
        decision = guard.handle_client(client)
        self.assertEqual(decision, DECISION_ERROR)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 503"))


# ---------------------------------------------------------------------------
# Address pinning / rebinding
# ---------------------------------------------------------------------------


class RebindingTests(unittest.TestCase):
    def test_changed_address_set_blocks_before_connector(self):
        resolver = SequenceResolver([[PUBLIC_A], [PUBLIC_B]])
        connector = FakeConnector()
        guard = make_guard(resolver=resolver, connector=connector)
        guard.prepare()
        client = FakeSocket(request_bytes("acme.example:443"))
        decision = guard.handle_client(client)
        self.assertEqual(decision, DECISION_DENIED)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 403"))
        self.assertEqual(connector.calls, [])
        record = guard.get_records()[-1]
        self.assertEqual(record["reason"], REASON_ADDRESS_SET_CHANGED)

    def test_second_resolution_failure_blocks_before_connector(self):
        resolver = FlakyResolver([PUBLIC_A], RuntimeError("dns changed"))
        connector = FakeConnector()
        guard = make_guard(resolver=resolver, connector=connector)
        guard.prepare()
        client = FakeSocket(request_bytes("acme.example:443"))
        decision = guard.handle_client(client)
        self.assertEqual(decision, DECISION_ERROR)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 502"))
        self.assertEqual(connector.calls, [])
        self.assertEqual(guard.get_records()[-1]["reason"], REASON_RESOLVE_FAILED)

    def test_reordered_pinned_set_is_still_the_same_set(self):
        resolver = SequenceResolver([[PUBLIC_A, PUBLIC_B], [PUBLIC_B, PUBLIC_A]])
        connector = FakeConnector()
        guard = make_guard(resolver=resolver, connector=connector)
        guard.prepare()
        client = FakeSocket(request_bytes("acme.example:443"))
        self.assertEqual(guard.handle_client(client), DECISION_ALLOWED)
        self.assertEqual(len(connector.calls), 1)


# ---------------------------------------------------------------------------
# Successful connect
# ---------------------------------------------------------------------------


class SuccessfulConnectTests(unittest.TestCase):
    def test_exact_connect_is_allowed_with_numeric_pinned_ip(self):
        resolver = StaticResolver([PUBLIC_A])
        connector = FakeConnector()
        guard = make_guard(
            resolver=resolver, connector=connector, relay=lambda a, b, e: (5, 7)
        )
        guard.prepare()
        client = FakeSocket(request_bytes("acme.example:443"))
        decision = guard.handle_client(client)
        self.assertEqual(decision, DECISION_ALLOWED)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 200"))

        self.assertEqual(len(connector.calls), 1)
        ip, port, _timeout = connector.calls[0]
        self.assertEqual(port, TARGET_PORT)
        self.assertTrue(ipaddress.ip_address(ip).is_global)
        self.assertEqual(ip, PUBLIC_A)
        self.assertNotEqual(ip, TARGET_HOST)

        record = guard.get_records()[-1]
        self.assertEqual(record["decision"], DECISION_ALLOWED)
        self.assertEqual(record["host"], TARGET_HOST)
        self.assertEqual(record["port"], TARGET_PORT)
        self.assertEqual(record["connected_ip"], PUBLIC_A)
        self.assertEqual(record["bytes_to_upstream"], 5)
        self.assertEqual(record["bytes_to_client"], 7)
        self.assertEqual(resolver.hosts, [TARGET_HOST, TARGET_HOST])

    def test_leftover_bytes_after_head_are_forwarded(self):
        upstream = FakeSocket()
        connector = FakeConnector(upstream=upstream)
        guard = make_guard(resolver=StaticResolver([PUBLIC_A]), connector=connector)
        guard.prepare()
        head = request_bytes("acme.example:443")
        client = FakeSocket(head + b"EARLYDATA")
        self.assertEqual(guard.handle_client(client), DECISION_ALLOWED)
        self.assertEqual(bytes(upstream.sent), b"EARLYDATA")
        self.assertEqual(guard.get_records()[-1]["bytes_to_upstream"], len(b"EARLYDATA"))

    def test_connector_tries_pinned_ips_and_uses_the_reachable_one(self):
        attempts = []

        def connector(ip, port, timeout):
            attempts.append(ip)
            if ip == PUBLIC_A:
                return FakeSocket()
            raise OSError("unreachable")

        guard = make_guard(
            resolver=StaticResolver([PUBLIC_A, PUBLIC_B]), connector=connector
        )
        guard.prepare()
        client = FakeSocket(request_bytes("acme.example:443"))
        self.assertEqual(guard.handle_client(client), DECISION_ALLOWED)
        self.assertEqual(attempts, [PUBLIC_B, PUBLIC_A])
        self.assertEqual(guard.get_records()[-1]["connected_ip"], PUBLIC_A)

    def test_all_connector_attempts_failing_is_an_error(self):
        connector = FakeConnector(error=OSError("refused"))
        guard = make_guard(resolver=StaticResolver([PUBLIC_A]), connector=connector)
        guard.prepare()
        client = FakeSocket(request_bytes("acme.example:443"))
        self.assertEqual(guard.handle_client(client), DECISION_ERROR)
        self.assertTrue(bytes(client.sent).startswith(b"HTTP/1.1 502"))
        self.assertEqual(guard.get_records()[-1]["reason"], REASON_UPSTREAM_FAILED)


# ---------------------------------------------------------------------------
# Metadata bounds / no sensitive data
# ---------------------------------------------------------------------------


class EvidenceTests(unittest.TestCase):
    def test_evidence_never_contains_request_headers_or_secrets(self):
        guard = make_guard(resolver=StaticResolver([PUBLIC_A]))
        guard.prepare()

        denied = (
            b"GET /?token=QUERYSECRET HTTP/1.1\r\n"
            b"Host: evil.test\r\n"
            b"Cookie: session=COOKIESECRET\r\n"
            b"Authorization: Bearer BEARERSECRET\r\n"
            b"X-Payload: PAYLOADSECRET\r\n\r\n"
        )
        guard.handle_client(FakeSocket(denied))

        allowed = (
            b"CONNECT acme.example:443 HTTP/1.1\r\n"
            b"Host: acme.example\r\n"
            b"Cookie: session=COOKIESECRET\r\n"
            b"Authorization: Bearer BEARERSECRET\r\n\r\n"
        )
        guard.handle_client(FakeSocket(allowed))

        blob = json.dumps(guard.evidence())
        for secret in (
            "QUERYSECRET",
            "COOKIESECRET",
            "BEARERSECRET",
            "PAYLOADSECRET",
            "Cookie:",
            "Authorization:",
            "GET ",
        ):
            self.assertNotIn(secret, blob)

    def test_record_count_is_capped(self):
        guard = make_guard(resolver=StaticResolver([PUBLIC_A]), max_records=2)
        guard.prepare()
        for _ in range(3):
            guard.handle_client(FakeSocket(request_bytes("acme.example:443", method="GET")))
        records = guard.get_records()
        self.assertEqual(len(records), 2)
        self.assertEqual(guard.evidence()["counters"]["denied"], 3)

    def test_metadata_fields_are_length_bounded(self):
        guard = make_guard(
            resolver=StaticResolver([PUBLIC_A]), now=lambda: "T" * 1000
        )
        guard.prepare()
        guard.handle_client(FakeSocket(request_bytes("acme.example:443", method="GET")))
        self.assertEqual(len(guard.get_records()[-1]["timestamp"]), MAX_FIELD_LENGTH)

    def test_evidence_snapshot_shape(self):
        guard = make_guard(resolver=StaticResolver([PUBLIC_A, PUBLIC_B]))
        guard.prepare()
        evidence = guard.evidence()
        self.assertEqual(evidence["guard"], "connect-egress")
        self.assertEqual(evidence["target"]["host"], TARGET_HOST)
        self.assertEqual(evidence["target"]["port"], TARGET_PORT)
        self.assertEqual(evidence["pinned_ips"], [PUBLIC_B, PUBLIC_A])
        self.assertFalse(evidence["running"])
        self.assertTrue(evidence["prepared"])
        self.assertEqual(evidence["bind_endpoint"], "127.0.0.1:0")
        self.assertEqual(evidence["pid"], os.getpid())


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class LifecycleTests(unittest.TestCase):
    def test_start_requires_prepare(self):
        guard = make_guard(
            resolver=ExplodingResolver(), connector=ExplodingConnector()
        )
        with self.assertRaises(EgressStateError):
            guard.start()
        self.assertFalse(guard.running)

    def test_start_stop_and_idempotence(self):
        guard = make_guard(resolver=StaticResolver([PUBLIC_A]))
        guard.prepare()
        guard.start()
        try:
            self.assertTrue(guard.running)
            host, port = guard.listener_endpoint
            self.assertEqual(host, "127.0.0.1")
            self.assertGreater(port, 0)
            self.assertEqual(os.getpid(), guard.pid)
            with self.assertRaises(EgressStateError):
                guard.start()
            with self.assertRaises(EgressStateError):
                guard.prepare()
        finally:
            guard.stop()
        self.assertFalse(guard.running)
        guard.stop()  # idempotent
        self.assertFalse(guard.running)

    def test_occupied_exact_port_fails_closed(self):
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        try:
            guard = make_guard(resolver=StaticResolver([PUBLIC_A]), bind_port=port)
            guard.prepare()
            with self.assertRaises(EgressBindError):
                guard.start()
            self.assertFalse(guard.running)
        finally:
            holder.close()

    def test_real_accept_path(self):
        guard = make_guard(
            resolver=StaticResolver([PUBLIC_A]),
            connector=FakeConnector(),
            relay=lambda a, b, e: (0, 0),
        )
        guard.prepare()
        guard.start()
        try:
            host, port = guard.listener_endpoint

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            try:
                client.sendall(request_bytes("acme.example:443"))
                response = recv_head(client)
                self.assertTrue(response.startswith(b"HTTP/1.1 200"), response)
            finally:
                client.close()

            denied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            denied.connect((host, port))
            try:
                denied.sendall(request_bytes("acme.example:443", method="GET"))
                response = recv_head(denied)
                self.assertTrue(response.startswith(b"HTTP/1.1 405"), response)
            finally:
                denied.close()
        finally:
            guard.stop()
        self.assertFalse(guard.running)

    def test_construction_performs_no_io(self):
        with mock.patch("socket.socket") as sock, mock.patch.object(
            egress, "_default_resolver"
        ) as resolver, mock.patch.object(egress, "_default_connector") as connector:
            guard = ConnectEgressGuard()
            self.assertFalse(guard.prepared)
            self.assertFalse(guard.running)
            sock.assert_not_called()
            resolver.assert_not_called()
            connector.assert_not_called()

    def test_import_has_no_side_effects(self):
        # Load a fresh interpreter so import-time behavior is observable without
        # mutating this module's class identities. The probe patches socket
        # primitives before importing the guard module.
        src = str(Path(egress.__file__).resolve().parents[3])
        code = (
            "import sys\n"
            f"sys.path.insert(0, {src!r})\n"
            "import unittest.mock as m\n"
            "with m.patch('socket.socket') as s, m.patch('socket.getaddrinfo') as g:\n"
            "    import red_teaming.tools.zap.egress as e\n"
            "    assert not s.called, 'socket.socket called at import'\n"
            "    assert not g.called, 'getaddrinfo called at import'\n"
            "print('ok')\n"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", code],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok", result.stdout)


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


class ConfigurationTests(unittest.TestCase):
    def test_non_loopback_bind_host_is_rejected(self):
        for host in ("0.0.0.0", "10.0.0.1", "example.com", "::", None):
            with self.subTest(host=host):
                with self.assertRaises(EgressConfigError):
                    ConnectEgressGuard(bind_host=host)

    def test_out_of_range_bind_port_is_rejected(self):
        for port in (-1, 70000, True, "18082"):
            with self.subTest(port=port):
                with self.assertRaises(EgressConfigError):
                    ConnectEgressGuard(bind_port=port)

    def test_invalid_target_is_rejected(self):
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(target_host="1.2.3.4")
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(target_host="")
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(target_port=0)
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(target_port=70000)

    def test_invalid_timeouts_and_limits_are_rejected(self):
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(connect_timeout=0)
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(read_timeout=-1)
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(relay_idle_timeout=float("inf"))
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(max_records=0)
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(max_connections=True)

    def test_invalid_injectables_are_rejected(self):
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(resolver="not-callable")
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(connector=123)
        with self.assertRaises(EgressConfigError):
            ConnectEgressGuard(relay="not-callable")


# ---------------------------------------------------------------------------
# Default relay (real loopback sockets only)
# ---------------------------------------------------------------------------


class RelayTests(unittest.TestCase):
    @staticmethod
    def _start_echo_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def run():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
                try:
                    server.close()
                except OSError:
                    pass

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return port

    def test_default_relay_forwards_both_directions(self):
        echo_port = self._start_echo_server()
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.connect(("127.0.0.1", echo_port))
        client, peer = socket.socketpair()
        guard = make_guard(relay=None, relay_idle_timeout=2.0)
        guard._relay = guard._default_relay

        result = {}

        def run_relay():
            result["counts"] = guard._default_relay(
                client, upstream, threading.Event()
            )

        thread = threading.Thread(target=run_relay, daemon=True)
        thread.start()
        try:
            payload = b"relay-payload"
            peer.sendall(payload)
            received = b""
            while len(received) < len(payload):
                chunk = peer.recv(4096)
                if not chunk:
                    break
                received += chunk
            self.assertEqual(received, payload)
            peer.close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result["counts"], (len(payload), len(payload)))
        finally:
            try:
                peer.close()
            except OSError:
                pass
            client.close()
            upstream.close()

    def test_default_relay_returns_immediately_when_stopped(self):
        a, b = socket.socketpair()
        guard = make_guard(relay=None)
        stop_event = threading.Event()
        stop_event.set()
        try:
            self.assertEqual(guard._default_relay(a, b, stop_event), (0, 0))
        finally:
            a.close()
            b.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
