"""RECON-002 outer egress broker: the only component that opens external sockets.

The broker runs in the trusted parent process. It owns the sole capability to
reach the outside world and mediates both authorized egress paths:

* **CONNECT/TLS** to the literal authority ``crt.sh:443``: the broker validates
  the requested literal host/port against policy, resolves ``crt.sh`` with a
  minimal bounded DNS wire query to ``1.1.1.1``, validates that every returned
  answer is a global-unicast literal, opens a TCP/443 connection to that literal
  IP, and hands the connected descriptor back to the sandboxed helper with
  ``SCM_RIGHTS``; and
* **DNS** to ``1.1.1.1:53`` (UDP with a bounded TCP fallback on truncation): the
  broker parses and validates every relayed question -- A/AAAA/CNAME for
  ``acme.example`` and its normalized subdomains only -- before any upstream
  query, applies a 5 qps limiter and a 2-way concurrency bound, validates the
  response against the transaction/question, and only then relays the raw bytes.

No system resolver API is ever used. All dependencies (DNS client, connector,
clock, sleep, transaction-id source) are injectable so the broker is fully
offline-testable. Importing this module performs no I/O.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from . import dns_wire, ipc, netpolicy
from .netpolicy import (
    DNS_SCOPE_TARGET,
    DNS_TYPE_NAMES,
    MAX_IPC_FRAME,
    RECON_002_POLICY,
    PolicyError,
    ReconNetworkPolicy,
    normalize_policy_name,
)

__all__ = [
    "BrokerDenied",
    "BrokerError",
    "BrokerEvent",
    "BrokerUpstreamError",
    "DnsWireClient",
    "EgressBroker",
    "TokenBucket",
]

_MAX_FIELD = 256


class BrokerError(ValueError):
    """Base class for broker failure."""


class BrokerDenied(BrokerError):
    """A connect or DNS request was denied by policy before any upstream I/O.

    ``str(error)`` is a fixed, request-data-free reason token safe to record.
    """

    def __init__(
        self,
        reason: str,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        qname: Optional[str] = None,
        qtype: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.host = host
        self.port = port
        self.qname = qname
        self.qtype = qtype
        self.protocol = protocol


class BrokerUpstreamError(BrokerError):
    """Allowed egress failed upstream (DNS or TCP connect)."""


def _bounded(value: object, *, limit: int = _MAX_FIELD) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    text = "".join(ch for ch in text if ord(ch) >= 0x20 and ord(ch) != 0x7F)
    return text[:limit]


def _default_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class BrokerEvent:
    """One bounded, request-data-free broker decision for evidence."""

    timestamp: str
    action: str
    decision: str
    reason: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    qname: Optional[str] = None
    qtype: Optional[str] = None
    protocol: Optional[str] = None
    upstream_ip: Optional[str] = None
    #: Explicit external destination the broker used (resolver host/port for DNS,
    #: or the CT authority for CONNECT). Never a URL or query string.
    upstream_host: Optional[str] = None
    upstream_port: Optional[int] = None

    def to_evidence(self) -> dict:
        return {
            "timestamp": _bounded(self.timestamp),
            "component": "broker",
            "action": _bounded(self.action),
            "decision": _bounded(self.decision),
            "reason": _bounded(self.reason),
            "host": _bounded(self.host),
            "port": self.port,
            "qname": _bounded(self.qname),
            "qtype": _bounded(self.qtype),
            "protocol": _bounded(self.protocol),
            "upstream_ip": _bounded(self.upstream_ip),
            "upstream_host": _bounded(self.upstream_host),
            "upstream_port": self.upstream_port,
        }


class TokenBucket:
    """A small thread-safe token-bucket rate limiter with a bounded wait."""

    def __init__(
        self,
        rate: float,
        *,
        capacity: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        max_wait: float = 10.0,
    ) -> None:
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0:
            raise BrokerError("rate must be a positive number")
        self._rate = float(rate)
        self._capacity = float(capacity if capacity is not None else rate)
        if self._capacity <= 0:
            raise BrokerError("capacity must be a positive number")
        self._clock = clock
        self._sleep = sleep
        self._max_wait = float(max_wait)
        self._tokens = self._capacity
        self._last = clock()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until *tokens* are available; raise if the bounded wait is exceeded."""

        if tokens <= 0:
            raise BrokerError("tokens must be positive")
        if tokens > self._capacity:
            raise BrokerError("requested tokens exceed bucket capacity")
        with self._lock:
            while True:
                now = self._clock()
                elapsed = now - self._last
                if elapsed > 0:
                    self._tokens = min(
                        self._capacity, self._tokens + elapsed * self._rate
                    )
                    self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                needed = (tokens - self._tokens) / self._rate
                if needed > self._max_wait:
                    raise BrokerError("rate limit wait exceeded")
                if needed > 0:
                    self._sleep(needed)


def _default_connector(ip: str, port: int, timeout: float) -> Any:
    """Connect to a validated global-unicast literal *ip*:*port*."""

    # Validate the literal before creating the socket (fail closed).
    canonical = netpolicy.validate_upstream_ip(ip)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise BrokerError("connect port must be in range")
    address = ipaddress.ip_address(canonical)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((canonical, port))
    except OSError:
        sock.close()
        raise
    return sock


def _connect_literal(ip: str, port: int, socktype: int, timeout: float) -> Any:
    canonical = netpolicy.validate_upstream_ip(ip)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise BrokerError("port must be in range")
    address = ipaddress.ip_address(canonical)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sock = socket.socket(family, socktype)
    sock.settimeout(timeout)
    try:
        sock.connect((canonical, port))
    except OSError:
        sock.close()
        raise
    return sock


class DnsWireClient:
    """A minimal bounded DNS client that talks only to the policy resolver.

    The UDP path connects the datagram socket to ``1.1.1.1:53`` so only that
    peer's replies are accepted, and the TCP path is used only when the UDP
    response is truncated. Both paths validate the literal endpoint before any
    socket is created and strictly validate the response against the query.
    """

    def __init__(
        self,
        *,
        policy: ReconNetworkPolicy = RECON_002_POLICY,
        udp_exchange: Optional[Callable[[bytes, float], bytes]] = None,
        tcp_exchange: Optional[Callable[[bytes, float], bytes]] = None,
        transaction_id: Optional[Callable[[], int]] = None,
    ) -> None:
        self._policy = policy
        self._udp = udp_exchange or self._default_udp
        self._tcp = tcp_exchange or self._default_tcp
        if transaction_id is None:
            rng = random.SystemRandom()
            transaction_id = lambda: rng.randint(0, 0xFFFF)
        self._transaction_id = transaction_id

    @property
    def policy(self) -> ReconNetworkPolicy:
        return self._policy

    def query(self, name: object, qtype: int) -> bytes:
        """Build and exchange one query, returning the validated raw response."""

        query = dns_wire.build_query(name, qtype, self._transaction_id())
        return self.exchange(query, expected_name=name, expected_type=qtype)

    def exchange(
        self, query: bytes, *, expected_name: object, expected_type: int
    ) -> bytes:
        """Forward *query* and return a validated raw response.

        The response is parsed and required to match the query's transaction id,
        name, and type; only then is it returned. A truncated UDP response is
        retried once over TCP.
        """

        parsed = dns_wire.parse_query(query, max_len=self._policy.max_dns_message)
        if parsed.qtype != expected_type:
            raise BrokerUpstreamError("query type does not match expectation")

        try:
            response = self._udp(query, self._policy.dns_udp_timeout)
        except OSError as exc:
            raise BrokerUpstreamError("upstream UDP DNS failed") from exc
        self._validate(response, parsed, expected_name, expected_type)

        if dns_wire.is_truncated(response):
            try:
                response = self._tcp(query, self._policy.dns_tcp_timeout)
            except OSError as exc:
                raise BrokerUpstreamError("upstream TCP DNS failed") from exc
            self._validate(response, parsed, expected_name, expected_type)
        return response

    def _validate(
        self, response: object, parsed: dns_wire.DnsQuery, expected_name: object, expected_type: int
    ) -> None:
        try:
            dns_wire.parse_response(
                response,
                expect_id=parsed.transaction_id,
                expect_name=expected_name,
                expect_type=expected_type,
                max_len=self._policy.max_dns_message,
            )
        except dns_wire.DnsMessageError as exc:
            raise BrokerUpstreamError("upstream DNS response failed validation") from exc

    def _default_udp(self, query: bytes, timeout: float) -> bytes:
        host = self._policy.upstream_dns_host
        port = self._policy.upstream_dns_port
        sock = _connect_literal(host, port, socket.SOCK_DGRAM, timeout)
        try:
            sock.send(query)
            return sock.recv(self._policy.max_dns_message)
        finally:
            sock.close()

    def _default_tcp(self, query: bytes, timeout: float) -> bytes:
        host = self._policy.upstream_dns_host
        port = self._policy.upstream_dns_port
        sock = _connect_literal(host, port, socket.SOCK_STREAM, timeout)
        try:
            sock.sendall(len(query).to_bytes(2, "big") + query)
            header = _recv_exact(sock, 2)
            if header is None:
                raise OSError("TCP DNS peer closed before the length prefix")
            length = int.from_bytes(header, "big")
            if length <= 0 or length > self._policy.max_dns_message:
                raise OSError("TCP DNS length is out of bounds")
            body = _recv_exact(sock, length)
            if body is None:
                raise OSError("TCP DNS peer closed inside the message")
            return body
        finally:
            sock.close()


def _recv_exact(sock: Any, count: int) -> Optional[bytes]:
    buffer = bytearray()
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            return None
        buffer.extend(chunk)
    return bytes(buffer)


class EgressBroker:
    """The trusted, policy-checked egress broker."""

    def __init__(
        self,
        *,
        policy: ReconNetworkPolicy = RECON_002_POLICY,
        dns_client: Optional[Any] = None,
        connector: Optional[Callable[[str, int, float], Any]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], str] = _default_now,
        max_events: int = 512,
    ) -> None:
        self._policy = policy
        self._dns = dns_client if dns_client is not None else DnsWireClient(policy=policy)
        self._connector = connector if connector is not None else _default_connector
        self._now = now
        self._limiter = TokenBucket(
            policy.dns_qps, capacity=policy.dns_qps, clock=clock, sleep=sleep
        )
        self._dns_sem = threading.BoundedSemaphore(policy.dns_max_concurrent)
        self._connect_sem = threading.BoundedSemaphore(policy.dns_max_concurrent)
        self._events: "deque[BrokerEvent]" = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    # -- introspection ------------------------------------------------------

    @property
    def policy(self) -> ReconNetworkPolicy:
        return self._policy

    def get_events(self) -> list[dict]:
        with self._lock:
            return [event.to_evidence() for event in self._events]

    def _record(self, event: BrokerEvent) -> None:
        with self._lock:
            self._events.append(event)

    def _event(self, action: str, decision: str, **kwargs) -> None:
        self._record(
            BrokerEvent(timestamp=self._now(), action=action, decision=decision, **kwargs)
        )

    # -- DNS -----------------------------------------------------------------

    def _bounded_dns_query(self, name: object, qtype: int) -> bytes:
        """Rate-limit and concurrency-limit one upstream DNS query."""

        self._limiter.acquire()
        if not self._dns_sem.acquire(timeout=self._policy.dns_udp_timeout):
            raise BrokerUpstreamError("DNS concurrency bound exceeded")
        try:
            return self._dns.query(name, qtype)
        finally:
            self._dns_sem.release()

    def resolve_bootstrap(self, host: object) -> tuple[str, ...]:
        """Resolve the exact CT source host to global-unicast literals.

        Only ``crt.sh`` A/AAAA answers are accepted; every returned answer is
        validated as a global-unicast literal before use.
        """

        if not self._policy.is_bootstrap_name(host):
            raise BrokerDenied("bootstrap_host_not_allowed", host=_bounded(host))

        addresses: dict[str, None] = {}
        for qtype in (netpolicy.DNS_TYPE_A, netpolicy.DNS_TYPE_AAAA):
            try:
                response = self._bounded_dns_query(self._policy.https_host, qtype)
                parsed = dns_wire.parse_response(
                    response,
                    expect_id=_response_id(response),
                    expect_name=self._policy.https_host,
                    expect_type=qtype,
                    max_len=self._policy.max_dns_message,
                )
            except (dns_wire.DnsMessageError, BrokerError):
                raise
            except Exception as exc:  # pragma: no cover - defensive
                raise BrokerUpstreamError("bootstrap DNS failed") from exc
            for value in dns_wire.extract_addresses(parsed):
                if netpolicy.is_global_literal(value):
                    addresses[value] = None
            # Make the bootstrap DNS destination explicit for the auditor.
            self._event(
                "resolve",
                "allowed",
                qname=self._policy.https_host,
                qtype=DNS_TYPE_NAMES.get(qtype, f"TYPE{qtype}"),
                protocol="udp",
                upstream_host=self._policy.upstream_dns_host,
                upstream_port=self._policy.upstream_dns_port,
            )
        if not addresses:
            self._event(
                "resolve",
                "error",
                reason="bootstrap_no_global_address",
                host=self._policy.https_host,
                upstream_host=self._policy.upstream_dns_host,
                upstream_port=self._policy.upstream_dns_port,
            )
            raise BrokerUpstreamError("crt.sh resolved to no global-unicast address")
        return tuple(addresses)

    def open_approved_socket(self, host: object, port: object) -> tuple[Any, str]:
        """Open a TCP/443 socket to the one permitted authority.

        The literal host and port are validated against policy *before* the
        resolver or connector is touched. The returned descriptor is the
        connected socket (or connector stand-in) paired with the literal IP it
        connected to.
        """

        if not self._policy.is_allowed_connect_authority(host, port):
            normalized = None
            try:
                normalized = normalize_policy_name(host)
            except PolicyError:
                normalized = None
            self._event(
                "connect",
                "denied",
                reason="connect_authority_not_allowed",
                host=normalized,
                port=port if isinstance(port, int) and not isinstance(port, bool) else None,
            )
            raise BrokerDenied(
                "connect_authority_not_allowed",
                host=normalized,
                port=port if isinstance(port, int) else None,
            )

        if not self._connect_sem.acquire(timeout=self._policy.connect_timeout):
            raise BrokerUpstreamError("connect concurrency bound exceeded")
        try:
            addresses = self.resolve_bootstrap(self._policy.https_host)
            for ip in addresses:
                try:
                    opened = self._connector(ip, self._policy.https_port, self._policy.connect_timeout)
                except Exception:
                    continue
                self._event(
                    "connect",
                    "allowed",
                    host=self._policy.https_host,
                    port=self._policy.https_port,
                    upstream_ip=ip,
                )
                return opened, ip
        finally:
            self._connect_sem.release()

        self._event(
            "connect",
            "error",
            reason="upstream_connect_failed",
            host=self._policy.https_host,
            port=self._policy.https_port,
        )
        raise BrokerUpstreamError("could not connect to any resolved crt.sh address")

    def forward_dns(self, protocol: int, query: bytes) -> bytes:
        """Validate and forward one relayed DNS query, returning raw response.

        The question must be a single IN-class A/AAAA/CNAME query for the
        authorized root or one of its normalized subdomains. Denial happens
        before any upstream call; the rate and concurrency bounds are applied to
        the upstream exchange only.
        """

        protocol_name = "udp" if protocol == netpolicy.DNS_PROTO_UDP else "tcp"
        try:
            parsed = dns_wire.parse_query(query, max_len=self._policy.max_dns_message)
        except dns_wire.DnsMessageError as exc:
            self._event("dns", "denied", reason="malformed_query", protocol=protocol_name)
            raise BrokerDenied("malformed_query", protocol=protocol_name) from exc

        scope = self._policy.classify_dns_question(parsed.name, parsed.qtype)
        qtype_name = DNS_TYPE_NAMES.get(parsed.qtype, f"TYPE{parsed.qtype}")
        if scope != DNS_SCOPE_TARGET:
            self._event(
                "dns",
                "denied",
                reason="dns_question_not_allowed",
                qname=parsed.name,
                qtype=qtype_name,
                protocol=protocol_name,
            )
            raise BrokerDenied(
                "dns_question_not_allowed",
                qname=parsed.name,
                qtype=qtype_name,
                protocol=protocol_name,
            )

        try:
            response = self._bounded_dns_query_exchange(
                query, expected_name=parsed.name, expected_type=parsed.qtype
            )
            # Defense in depth: validate the response here too, so a faulty or
            # substituted DNS client can never relay an off-question answer.
            dns_wire.parse_response(
                response,
                expect_id=parsed.transaction_id,
                expect_name=parsed.name,
                expect_type=parsed.qtype,
                max_len=self._policy.max_dns_message,
            )
        except dns_wire.DnsMessageError as exc:
            self._event(
                "dns",
                "error",
                reason="response_invalid",
                qname=parsed.name,
                qtype=qtype_name,
                protocol=protocol_name,
            )
            raise BrokerUpstreamError("upstream DNS response failed validation") from exc
        except BrokerError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise BrokerUpstreamError("upstream DNS failed") from exc

        self._event(
            "dns",
            "allowed",
            qname=parsed.name,
            qtype=qtype_name,
            protocol=protocol_name,
            upstream_host=self._policy.upstream_dns_host,
            upstream_port=self._policy.upstream_dns_port,
        )
        return response

    def _bounded_dns_query_exchange(
        self, query: bytes, *, expected_name: object, expected_type: int
    ) -> bytes:
        self._limiter.acquire()
        if not self._dns_sem.acquire(timeout=self._policy.dns_udp_timeout):
            raise BrokerUpstreamError("DNS concurrency bound exceeded")
        try:
            return self._dns.exchange(
                query, expected_name=expected_name, expected_type=expected_type
            )
        finally:
            self._dns_sem.release()

    # -- serving -------------------------------------------------------------

    def serve_connect(self, sock: Any, stop_event: threading.Event) -> None:
        """Serve the CONNECT channel: validate, open, and pass back one fd."""

        self._serve_loop(sock, stop_event, self._handle_connect_frame, with_fd=True)

    def serve_dns(self, sock: Any, stop_event: threading.Event) -> None:
        """Serve the DNS channel: validate, forward, and return raw responses."""

        self._serve_loop(sock, stop_event, self._handle_dns_frame, with_fd=False)

    def serve(
        self,
        connect_sock: Any,
        dns_sock: Any,
        stop_event: Optional[threading.Event] = None,
    ) -> list[threading.Thread]:
        """Start one daemon thread per channel and return the threads."""

        event = stop_event if stop_event is not None else self._stop_event
        threads = [
            threading.Thread(
                target=self._run_channel,
                args=(connect_sock, event, self._handle_connect_frame, True),
                name="recon-broker-connect",
                daemon=True,
            ),
            threading.Thread(
                target=self._run_channel,
                args=(dns_sock, event, self._handle_dns_frame, False),
                name="recon-broker-dns",
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        return threads

    def stop(self) -> None:
        self._stop_event.set()

    def _run_channel(self, sock: Any, stop_event: threading.Event, handler, with_fd: bool) -> None:
        self._serve_loop(sock, stop_event, handler, with_fd=with_fd)

    def _serve_loop(
        self, sock: Any, stop_event: threading.Event, handler, *, with_fd: bool
    ) -> None:
        try:
            sock.settimeout(self._policy.ipc_poll_interval)
        except (OSError, AttributeError):
            pass
        while not stop_event.is_set():
            try:
                if with_fd:
                    payload, fd = ipc.recv_message_fd(sock, max_frame=MAX_IPC_FRAME)
                    handler(sock, payload, fd)
                else:
                    payload = ipc.recv_frame(sock, max_frame=MAX_IPC_FRAME)
                    if payload is None:
                        break
                    handler(sock, payload, None)
            except socket.timeout:
                continue
            except ipc.IpcClosed:
                break
            except (ipc.IpcError, OSError) as exc:
                self._event("ipc", "error", reason=type(exc).__name__)
                break

    def _handle_connect_frame(self, sock: Any, payload: bytes, fd: Optional[int]) -> None:
        try:
            host, port = ipc.decode_connect_request(payload)
            opened, _ip = self.open_approved_socket(host, port)
        except BrokerDenied as exc:
            ipc.send_fd_message(sock, ipc.encode_connect_response(False, exc.reason))
            return
        except (ipc.IpcProtocolError, BrokerError):
            ipc.send_fd_message(sock, ipc.encode_connect_response(False, "request_rejected"))
            return

        fileno = _fileno(opened)
        if fileno is None:
            _safe_close(opened)
            ipc.send_fd_message(sock, ipc.encode_connect_response(False, "no_descriptor"))
            return
        # sendmsg does not close the descriptor; the broker retains and closes it.
        try:
            ipc.send_fd_message(sock, ipc.encode_connect_response(True), fileno)
        finally:
            _safe_close(opened)

    def _handle_dns_frame(self, sock: Any, payload: bytes, fd: Optional[int]) -> None:
        try:
            protocol, query = ipc.decode_dns_request(payload)
        except ipc.IpcProtocolError:
            ipc.send_frame(
                sock,
                ipc.encode_dns_response(netpolicy.DNS_PROTO_UDP, ipc.STATUS_ERROR),
            )
            return
        try:
            response = self.forward_dns(protocol, query)
        except BrokerDenied:
            ipc.send_frame(sock, ipc.encode_dns_response(protocol, ipc.STATUS_DENIED))
            return
        except (dns_wire.DnsMessageError, BrokerError):
            ipc.send_frame(sock, ipc.encode_dns_response(protocol, ipc.STATUS_ERROR))
            return
        ipc.send_frame(sock, ipc.encode_dns_response(protocol, ipc.STATUS_OK, response))


def _response_id(response: object) -> int:
    raw = bytes(response)  # type: ignore[arg-type]
    if len(raw) < 2:
        raise dns_wire.DnsMessageError("response too short")
    return int.from_bytes(raw[0:2], "big")


def _fileno(obj: Any) -> Optional[int]:
    try:
        return int(obj.fileno())
    except (AttributeError, OSError, ValueError):
        return None


def _safe_close(obj: Any) -> None:
    try:
        obj.close()
    except (AttributeError, OSError):
        pass
