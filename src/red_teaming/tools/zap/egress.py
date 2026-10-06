"""Loopback exact-host CONNECT egress guard for the bounded Stage 2 run.

This module implements the single, fixed local guard authorized by
``CURRENT_TASK.md`` for the artifact-routing domain ``acme.example``:

* it listens only on the fixed loopback endpoint ``127.0.0.1:18082``;
* it accepts only HTTP ``CONNECT`` requests for the normalized authority
  ``acme.example:443``;
* it rejects plain HTTP methods, malformed authorities, userinfo, IP literals,
  subdomains, sibling/lookalike hosts, and every other host/port *before* any
  resolver, connector, or outbound call;
* it resolves only the exact target host through an injectable resolver, pins a
  non-empty set of globally routable unicast addresses once via :meth:`prepare`,
  and re-resolves before every outbound connect, failing closed if the accepted
  set has changed (DNS rebinding/change);
* it connects by numeric pinned IP only, on port 443 only, through an
  injectable connector that never receives the hostname;
* on success it answers ``HTTP/1.1 200`` and relays bytes bidirectionally with
  bounded, ``select``-based logic; on denial it answers a minimal status with an
  empty body that never contains request data;
* it records bounded metadata only (timestamp, normalized host, port, decision,
  reason, connected numeric IP, byte counts) and never headers, bodies, query
  strings, cookies, credentials, or raw payloads.

Everything is standard-library only and offline-testable: the resolver,
connector, relay, clock, and ``now`` function are all injectable. Importing or
constructing the guard performs no socket, DNS, or filesystem activity; only
:meth:`prepare` resolves DNS and only :meth:`start` opens the listener.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Protocol, Sequence, Tuple

from ...projects.models import ValidationError, normalize_dns_name
from .models import ZapError

__all__ = [
    "DEFAULT_ACCEPT_POLL_INTERVAL",
    "DEFAULT_BIND_HOST",
    "DEFAULT_BIND_PORT",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_MAX_RECORDS",
    "DEFAULT_READ_TIMEOUT",
    "DEFAULT_RELAY_IDLE_TIMEOUT",
    "DEFAULT_RELAY_MAX_SECONDS",
    "DEFAULT_TARGET_HOST",
    "DEFAULT_TARGET_PORT",
    "DEFAULT_THREAD_JOIN_TIMEOUT",
    "DECISION_ALLOWED",
    "DECISION_DENIED",
    "DECISION_ERROR",
    "MAX_AUTHORITY_LENGTH",
    "MAX_FIELD_LENGTH",
    "MAX_HEADER_LINE",
    "MAX_REQUEST_HEAD",
    "REASON_ADDRESS_SET_CHANGED",
    "REASON_ALLOWED",
    "REASON_BUSY",
    "REASON_HOST",
    "REASON_IO",
    "REASON_IP_LITERAL",
    "REASON_MALFORMED",
    "REASON_METHOD",
    "REASON_PORT",
    "REASON_RELAY_FAILED",
    "REASON_RESOLVE_FAILED",
    "REASON_TIMEOUT",
    "REASON_TOO_LARGE",
    "REASON_UPSTREAM_FAILED",
    "REASON_USERINFO",
    "ConnectEgressGuard",
    "EgressBindError",
    "EgressConfigError",
    "EgressDeniedError",
    "EgressGuardError",
    "EgressPreflightError",
    "EgressRecord",
    "EgressStateError",
    "parse_connect_authority",
    "parse_connect_request",
]

# ---------------------------------------------------------------------------
# Fixed defaults
# ---------------------------------------------------------------------------

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 18082

DEFAULT_TARGET_HOST = "acme.example"
DEFAULT_TARGET_PORT = 443

DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_RELAY_IDLE_TIMEOUT = 30.0
DEFAULT_RELAY_MAX_SECONDS = 300.0
DEFAULT_ACCEPT_POLL_INTERVAL = 0.2
DEFAULT_THREAD_JOIN_TIMEOUT = 2.0
DEFAULT_MAX_CONNECTIONS = 16
DEFAULT_MAX_RECORDS = 256

#: Bounded request/authority limits (bytes/characters).
MAX_REQUEST_HEAD = 8192
MAX_HEADER_LINE = 2048
MAX_AUTHORITY_LENGTH = 512

#: Longest accepted persisted metadata field.
MAX_FIELD_LENGTH = 256

#: Relay read buffer size.
_RELAY_BUFFER = 65536

_DEFAULT_BACKLOG = 16

_DECISION_ALLOWED = "allowed"
_DECISION_DENIED = "denied"
_DECISION_ERROR = "error"

DECISION_ALLOWED = _DECISION_ALLOWED
DECISION_DENIED = _DECISION_DENIED
DECISION_ERROR = _DECISION_ERROR

REASON_ALLOWED = "allowed"
REASON_METHOD = "method_not_allowed"
REASON_MALFORMED = "malformed_request"
REASON_USERINFO = "userinfo_forbidden"
REASON_IP_LITERAL = "ip_literal_forbidden"
REASON_HOST = "host_not_allowed"
REASON_PORT = "port_not_allowed"
REASON_TOO_LARGE = "request_too_large"
REASON_TIMEOUT = "request_timeout"
REASON_IO = "io_error"
REASON_RESOLVE_FAILED = "resolve_failed"
REASON_ADDRESS_SET_CHANGED = "address_set_changed"
REASON_UPSTREAM_FAILED = "upstream_connect_failed"
REASON_RELAY_FAILED = "relay_failed"
REASON_BUSY = "too_many_connections"

_STATUS_TEXT = {
    200: "Connection Established",
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    408: "Request Timeout",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

_CRLF = b"\r\n"
_HEAD_TERMINATOR = b"\r\n\r\n"


# ---------------------------------------------------------------------------
# Typed errors
# ---------------------------------------------------------------------------


class EgressGuardError(ZapError):
    """Base class for every egress-guard failure."""


class EgressConfigError(EgressGuardError, ValueError):
    """Invalid guard configuration (bind, target, timeouts, dependencies)."""


class EgressPreflightError(EgressGuardError):
    """Preparation failed: resolution returned a missing or unusable address set."""


class EgressStateError(EgressGuardError):
    """The guard is already started, not started, or not prepared."""


class EgressBindError(EgressGuardError):
    """The loopback listener could not bind the configured exact endpoint."""


class EgressDeniedError(EgressGuardError):
    """A single connection was denied before any outbound connect.

    ``str(error)`` is always one of the fixed, request-data-free reason
    constants, so it is safe to record verbatim.
    """

    def __init__(
        self,
        reason: str,
        *,
        status: int = 403,
        host: Optional[str] = None,
        port: Optional[int] = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.host = host
        self.port = port


# ---------------------------------------------------------------------------
# Injectable dependency protocols
# ---------------------------------------------------------------------------


class Resolver(Protocol):
    """Resolve one exact host to a sequence of IP address strings."""

    def __call__(self, host: str) -> Sequence[str]: ...


class Connector(Protocol):
    """Open a TCP connection to a numeric IP and port."""

    def __call__(self, ip: str, port: int, timeout: float) -> Any: ...


class Relay(Protocol):
    """Relay bytes bidirectionally until closure/stop; return byte counts."""

    def __call__(
        self, client: Any, upstream: Any, stop_event: threading.Event
    ) -> Tuple[int, int]: ...


def _default_resolver(host: str) -> Sequence[str]:
    """Resolve *host* through the OS resolver (never a reverse lookup)."""

    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def _default_connector(ip: str, port: int, timeout: float) -> Any:
    """Connect to a numeric *ip*:*port*; never resolves or accepts a hostname."""

    address = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except OSError:
        sock.close()
        raise
    return sock


def _default_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Pure validation helpers
# ---------------------------------------------------------------------------


def _require_positive(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EgressConfigError(f"{name} must be a number")
    value = float(value)
    if value <= 0 or value != value or value in (float("inf"), float("-inf")):
        raise EgressConfigError(f"{name} must be a positive finite number")
    return value


def _require_positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EgressConfigError(f"{name} must be a positive integer")
    return value


def _bounded_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)[:MAX_FIELD_LENGTH]


def _pin_addresses(raw: Any) -> "frozenset[str]":
    """Validate and canonicalize a resolver result into a pinned IP set.

    A non-empty, all-globally-routable set is required; any malformed,
    private, loopback, link-local, multicast, unspecified, reserved, or
    IPv4-mapped address fails the whole preparation (fail closed).
    """

    if raw is None or isinstance(raw, (str, bytes)) or not hasattr(raw, "__iter__"):
        raise EgressPreflightError("resolver returned a non-sequence result")

    addresses: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item or item != item.strip():
            raise EgressPreflightError("resolver returned a malformed address")
        try:
            address = ipaddress.ip_address(item)
        except ValueError as exc:
            raise EgressPreflightError("resolver returned a malformed address") from exc
        if address.version == 6 and address.ipv4_mapped is not None:
            raise EgressPreflightError("resolver returned an IPv4-mapped address")
        if address.is_multicast or address.is_unspecified or not address.is_global:
            raise EgressPreflightError("resolver returned a non-global address")
        addresses.add(str(address))

    if not addresses:
        raise EgressPreflightError("resolver returned no addresses")
    return frozenset(addresses)


def parse_connect_authority(
    authority: Any, *, target_host: str, target_port: int
) -> Tuple[str, int]:
    """Parse and validate a CONNECT authority, failing closed before any call.

    Only ``<normalized-target-host>:<target-port>`` is accepted. Userinfo, IP
    literals (including bracketed IPv6), multiple colons, missing/empty parts,
    non-numeric ports, other ports, subdomains, siblings, and lookalike hosts
    are rejected with :class:`EgressDeniedError`.
    """

    if not isinstance(authority, str) or not authority:
        raise EgressDeniedError(REASON_MALFORMED, status=400)
    if len(authority) > MAX_AUTHORITY_LENGTH:
        raise EgressDeniedError(REASON_TOO_LARGE, status=400)
    if authority != authority.strip():
        raise EgressDeniedError(REASON_MALFORMED, status=400)
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in authority):
        raise EgressDeniedError(REASON_MALFORMED, status=400)
    if "@" in authority:
        raise EgressDeniedError(REASON_USERINFO, status=403)
    if "[" in authority or "]" in authority:
        raise EgressDeniedError(REASON_IP_LITERAL, status=403)
    if authority.count(":") != 1:
        raise EgressDeniedError(REASON_MALFORMED, status=400)

    host_text, port_text = authority.split(":", 1)
    if not host_text or not port_text:
        raise EgressDeniedError(REASON_MALFORMED, status=400)
    if not port_text.isdigit():
        raise EgressDeniedError(REASON_PORT, status=403)
    port = int(port_text)
    if port != target_port:
        raise EgressDeniedError(REASON_PORT, status=403, port=port)

    try:
        ipaddress.ip_address(host_text)
    except ValueError:
        pass
    else:
        raise EgressDeniedError(REASON_IP_LITERAL, status=403)

    try:
        normalized = normalize_dns_name(host_text)
    except ValidationError as exc:
        raise EgressDeniedError(REASON_HOST, status=403) from exc
    if normalized != target_host:
        raise EgressDeniedError(REASON_HOST, status=403, host=normalized)
    return normalized, port


def parse_connect_request(
    head: Any, *, target_host: str, target_port: int
) -> Tuple[str, int]:
    """Parse one bounded request head and require an exact-host CONNECT.

    Plain HTTP methods are rejected before any resolver/connector call.
    """

    if not isinstance(head, (bytes, bytearray)):
        raise EgressDeniedError(REASON_MALFORMED, status=400)
    try:
        text = bytes(head).decode("latin-1")
    except Exception as exc:  # pragma: no cover - latin-1 cannot fail
        raise EgressDeniedError(REASON_MALFORMED, status=400) from exc
    if "\x00" in text:
        raise EgressDeniedError(REASON_MALFORMED, status=400)

    request_line = text.split("\r\n", 1)[0]
    if not request_line:
        raise EgressDeniedError(REASON_MALFORMED, status=400)

    parts = request_line.split(" ")
    if len(parts) != 3 or any(part == "" for part in parts):
        raise EgressDeniedError(REASON_MALFORMED, status=400)
    method, authority, version = parts

    if method != "CONNECT":
        raise EgressDeniedError(REASON_METHOD, status=405)
    if not version.startswith("HTTP/") or len(version) > 16:
        raise EgressDeniedError(REASON_MALFORMED, status=400)

    return parse_connect_authority(
        authority, target_host=target_host, target_port=target_port
    )


def _read_head(sock: Any, *, max_total: int, max_line: int) -> Tuple[bytes, bytes]:
    """Read a bounded HTTP request head; return ``(head, leftover)`` bytes.

    The total head size and every individual line length are bounded, and the
    socket's own timeout bounds the wait. Request data is never stored or
    returned beyond the caller's local ``head``/``leftover`` values.
    """

    buf = bytearray()
    while _HEAD_TERMINATOR not in buf:
        if len(buf) >= max_total:
            raise EgressDeniedError(REASON_TOO_LARGE, status=400)
        try:
            chunk = sock.recv(4096)
        except socket.timeout as exc:
            raise EgressDeniedError(REASON_TIMEOUT, status=408) from exc
        except OSError as exc:
            raise EgressDeniedError(REASON_IO, status=400) from exc
        if not chunk:
            raise EgressDeniedError(REASON_MALFORMED, status=400)
        buf.extend(chunk)

    index = buf.index(_HEAD_TERMINATOR) + len(_HEAD_TERMINATOR)
    if index > max_total:
        raise EgressDeniedError(REASON_TOO_LARGE, status=400)
    head = bytes(buf[:index])
    leftover = bytes(buf[index:])
    for line in head.split(_CRLF):
        if len(line) > max_line:
            raise EgressDeniedError(REASON_TOO_LARGE, status=400)
    return head, leftover


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EgressRecord:
    """One bounded, request-data-free connection record."""

    timestamp: str
    decision: str
    reason: str
    host: Optional[str] = None
    port: Optional[int] = None
    status: Optional[int] = None
    connected_ip: Optional[str] = None
    bytes_to_upstream: int = 0
    bytes_to_client: int = 0

    def to_evidence(self) -> dict:
        return {
            "timestamp": _bounded_text(self.timestamp),
            "decision": _bounded_text(self.decision),
            "reason": _bounded_text(self.reason),
            "host": _bounded_text(self.host),
            "port": self.port,
            "status": self.status,
            "connected_ip": _bounded_text(self.connected_ip),
            "bytes_to_upstream": int(self.bytes_to_upstream),
            "bytes_to_client": int(self.bytes_to_client),
        }


class ConnectEgressGuard:
    """A loopback exact-host CONNECT egress guard.

    The guard is inert until :meth:`prepare` pins the accepted global IP set and
    :meth:`start` binds the listener. It is safe to :meth:`stop` more than once.
    """

    def __init__(
        self,
        *,
        bind_host: str = DEFAULT_BIND_HOST,
        bind_port: int = DEFAULT_BIND_PORT,
        target_host: str = DEFAULT_TARGET_HOST,
        target_port: int = DEFAULT_TARGET_PORT,
        resolver: Optional[Callable[[str], Sequence[str]]] = None,
        connector: Optional[Callable[[str, int, float], Any]] = None,
        relay: Optional[Callable[[Any, Any, threading.Event], Tuple[int, int]]] = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        relay_idle_timeout: float = DEFAULT_RELAY_IDLE_TIMEOUT,
        relay_max_seconds: float = DEFAULT_RELAY_MAX_SECONDS,
        accept_poll_interval: float = DEFAULT_ACCEPT_POLL_INTERVAL,
        thread_join_timeout: float = DEFAULT_THREAD_JOIN_TIMEOUT,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_request_head: int = MAX_REQUEST_HEAD,
        max_header_line: int = MAX_HEADER_LINE,
        now: Optional[Callable[[], str]] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        try:
            bind_address = ipaddress.ip_address(bind_host)
        except ValueError as exc:
            raise EgressConfigError(
                "bind_host must be a loopback IP literal"
            ) from exc
        if not bind_address.is_loopback:
            raise EgressConfigError("bind_host must be a loopback IP literal")
        if (
            isinstance(bind_port, bool)
            or not isinstance(bind_port, int)
            or not (0 <= bind_port <= 65535)
        ):
            raise EgressConfigError("bind_port must be an in-range integer")

        try:
            normalized_target = normalize_dns_name(target_host)
        except ValidationError as exc:
            raise EgressConfigError(
                "target_host must be a normalizable DNS name"
            ) from exc
        if (
            isinstance(target_port, bool)
            or not isinstance(target_port, int)
            or not (1 <= target_port <= 65535)
        ):
            raise EgressConfigError("target_port must be an in-range integer")

        if resolver is None:
            resolver = _default_resolver
        if not callable(resolver):
            raise EgressConfigError("resolver must be callable")
        if connector is None:
            connector = _default_connector
        if not callable(connector):
            raise EgressConfigError("connector must be callable")
        if relay is not None and not callable(relay):
            raise EgressConfigError("relay must be callable or None")
        if now is None:
            now = _default_now
        if not callable(now):
            raise EgressConfigError("now must be callable")
        if clock is None:
            clock = time.monotonic
        if not callable(clock):
            raise EgressConfigError("clock must be callable")

        self._bind_host = bind_host
        self._bind_family = (
            socket.AF_INET6 if bind_address.version == 6 else socket.AF_INET
        )
        self._bind_port = bind_port
        self._target_host = normalized_target
        self._target_port = target_port

        self._resolver = resolver
        self._connector = connector
        self._relay = relay if relay is not None else self._default_relay
        self._now = now

        self._connect_timeout = _require_positive("connect_timeout", connect_timeout)
        self._read_timeout = _require_positive("read_timeout", read_timeout)
        self._relay_idle_timeout = _require_positive(
            "relay_idle_timeout", relay_idle_timeout
        )
        self._relay_max_seconds = _require_positive(
            "relay_max_seconds", relay_max_seconds
        )
        self._accept_poll_interval = _require_positive(
            "accept_poll_interval", accept_poll_interval
        )
        self._thread_join_timeout = _require_positive(
            "thread_join_timeout", thread_join_timeout
        )
        self._max_connections = _require_positive_int(
            "max_connections", max_connections
        )
        self._max_records = _require_positive_int("max_records", max_records)
        self._max_request_head = _require_positive_int(
            "max_request_head", max_request_head
        )
        self._max_header_line = _require_positive_int(
            "max_header_line", max_header_line
        )
        self._clock = clock

        self._lock = threading.RLock()
        self._pinned_ips: Optional[frozenset[str]] = None
        self._listener: Optional[Any] = None
        self._bound_port: Optional[int] = None
        self._started = False
        self._stop_event = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        self._workers: list[threading.Thread] = []
        self._active: dict[int, Any] = {}
        self._records: "deque[EgressRecord]" = deque(maxlen=self._max_records)
        self._counters: dict[str, int] = {
            "connections": 0,
            "allowed": 0,
            "denied": 0,
            "errors": 0,
            "bytes_to_upstream": 0,
            "bytes_to_client": 0,
        }

    # -- safe introspection -------------------------------------------------

    @property
    def bind_host(self) -> str:
        return self._bind_host

    @property
    def bind_port(self) -> int:
        """Return the actual bound port once started, else the configured port."""

        if self._bound_port is not None:
            return self._bound_port
        return self._bind_port

    @property
    def listener_endpoint(self) -> Tuple[str, int]:
        return (self._bind_host, self.bind_port)

    @property
    def pid(self) -> int:
        return os.getpid()

    @property
    def prepared(self) -> bool:
        return self._pinned_ips is not None

    @property
    def running(self) -> bool:
        with self._lock:
            return self._started and self._listener is not None

    @property
    def pinned_ips(self) -> Tuple[str, ...]:
        if self._pinned_ips is None:
            return ()
        return tuple(sorted(self._pinned_ips))

    @property
    def target_endpoint(self) -> Tuple[str, int]:
        return (self._target_host, self._target_port)

    # -- preparation --------------------------------------------------------

    def prepare(self) -> "ConnectEgressGuard":
        """Resolve the exact target host and pin its accepted global IP set."""

        with self._lock:
            if self._started:
                raise EgressStateError("cannot prepare while the guard is running")
        pinned = self._resolve_pinned()
        with self._lock:
            self._pinned_ips = pinned
        return self

    def _resolve_pinned(self) -> "frozenset[str]":
        try:
            raw = self._resolver(self._target_host)
        except EgressGuardError:
            raise
        except Exception as exc:
            raise EgressPreflightError(
                "resolver failed for the exact target host"
            ) from exc
        return _pin_addresses(raw)

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> "ConnectEgressGuard":
        """Bind the exact loopback endpoint once and begin accepting clients."""

        with self._lock:
            if self._started:
                raise EgressStateError("egress guard is already started")
            if self._pinned_ips is None:
                raise EgressStateError(
                    "egress guard must be prepared before it can start"
                )
            listener = socket.socket(self._bind_family, socket.SOCK_STREAM)
            try:
                # Deliberately no SO_REUSEADDR: the exact port must be
                # exclusively bindable, so an occupied port fails closed.
                listener.bind((self._bind_host, self._bind_port))
                listener.listen(_DEFAULT_BACKLOG)
                listener.settimeout(self._accept_poll_interval)
            except OSError as exc:
                self._safe_close(listener)
                raise EgressBindError(
                    "could not bind the loopback egress listener"
                ) from exc
            self._listener = listener
            self._bound_port = listener.getsockname()[1]
            self._stop_event.clear()
            self._started = True
            thread = threading.Thread(
                target=self._accept_loop,
                name="zap-egress-accept",
                daemon=True,
            )
            self._accept_thread = thread
            thread.start()
        return self

    def stop(self, *, join_timeout: Optional[float] = None) -> None:
        """Stop the guard idempotently, closing the listener and active sockets."""

        self._stop_event.set()
        with self._lock:
            listener = self._listener
            self._listener = None
            self._started = False
            accept_thread = self._accept_thread
            self._accept_thread = None
            workers = list(self._workers)
            self._workers = []
            active = list(self._active.values())

        if listener is not None:
            self._safe_close(listener)
        for sock in active:
            self._safe_close(sock)

        timeout = (
            self._thread_join_timeout if join_timeout is None else join_timeout
        )
        for thread in [accept_thread, *workers]:
            if thread is not None:
                try:
                    thread.join(timeout=timeout)
                except RuntimeError:  # pragma: no cover - defensive
                    pass

        # Final sweep: any socket tracked after the first copy is closed here so
        # the listener and every active upstream/client connection are gone.
        with self._lock:
            remaining = list(self._active.values())
            self._active.clear()
        for sock in remaining:
            self._safe_close(sock)

    def __enter__(self) -> "ConnectEgressGuard":
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.stop()
        return False

    def _accept_loop(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop_event.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._stop_event.is_set():
                self._safe_close(conn)
                break
            try:
                conn.settimeout(self._read_timeout)
            except OSError:
                self._safe_close(conn)
                continue
            with self._lock:
                active_count = len(self._active)
            if active_count >= self._max_connections:
                self._send_status(conn, 503, _STATUS_TEXT[503])
                self._record(DECISION_DENIED, REASON_BUSY, status=503)
                self._safe_close(conn)
                continue
            self._track(conn)
            if self._stop_event.is_set():
                self._untrack(conn)
                self._safe_close(conn)
                break
            worker = threading.Thread(
                target=self._client_worker,
                args=(conn,),
                name="zap-egress-client",
                daemon=True,
            )
            with self._lock:
                self._workers = [item for item in self._workers if item.is_alive()]
                self._workers.append(worker)
            worker.start()

    def _client_worker(self, conn: Any) -> None:
        try:
            self.handle_client(conn)
        except Exception:
            self._record(DECISION_ERROR, REASON_IO)
        finally:
            self._safe_close(conn)
            self._untrack(conn)

    # -- per-connection handling -------------------------------------------

    def handle_client(self, conn: Any) -> str:
        """Handle one accepted client synchronously; return the decision string.

        Every request is parsed and validated *before* the resolver or
        connector is touched. Any denial closes after sending a minimal,
        body-free status.
        """

        with self._lock:
            self._counters["connections"] += 1

        try:
            head, leftover = _read_head(
                conn,
                max_total=self._max_request_head,
                max_line=self._max_header_line,
            )
        except EgressDeniedError as exc:
            self._deny(conn, exc)
            return DECISION_DENIED

        try:
            host, port = parse_connect_request(
                head,
                target_host=self._target_host,
                target_port=self._target_port,
            )
        except EgressDeniedError as exc:
            self._deny(conn, exc)
            return DECISION_DENIED

        if self._pinned_ips is None:
            self._record(DECISION_ERROR, REASON_RESOLVE_FAILED, status=503)
            self._send_status(conn, 503, _STATUS_TEXT[503])
            return DECISION_ERROR

        try:
            current = self._resolve_pinned()
        except EgressPreflightError:
            self._record(
                DECISION_ERROR,
                REASON_RESOLVE_FAILED,
                status=502,
                host=host,
                port=port,
            )
            self._send_status(conn, 502, _STATUS_TEXT[502])
            return DECISION_ERROR

        if current != self._pinned_ips:
            self._record(
                DECISION_DENIED,
                REASON_ADDRESS_SET_CHANGED,
                status=403,
                host=host,
                port=port,
            )
            self._send_status(conn, 403, _STATUS_TEXT[403])
            return DECISION_DENIED

        upstream = None
        connected_ip: Optional[str] = None
        for ip in sorted(current):
            try:
                upstream = self._connector(ip, self._target_port, self._connect_timeout)
            except Exception:
                upstream = None
                continue
            connected_ip = ip
            break

        if upstream is None or connected_ip is None:
            self._record(
                DECISION_ERROR,
                REASON_UPSTREAM_FAILED,
                status=502,
                host=host,
                port=port,
            )
            self._send_status(conn, 502, _STATUS_TEXT[502])
            return DECISION_ERROR

        self._track(upstream)
        try:
            self._send_status(conn, 200, _STATUS_TEXT[200])
            c2u = 0
            u2c = 0
            if leftover:
                try:
                    upstream.sendall(leftover)
                except OSError:
                    self._record(
                        DECISION_ERROR,
                        REASON_IO,
                        status=502,
                        host=host,
                        port=port,
                        connected_ip=connected_ip,
                    )
                    return DECISION_ERROR
                c2u += len(leftover)
            try:
                relayed = self._relay(conn, upstream, self._stop_event)
            except Exception:
                self._record(
                    DECISION_ERROR,
                    REASON_RELAY_FAILED,
                    status=502,
                    host=host,
                    port=port,
                    connected_ip=connected_ip,
                )
                return DECISION_ERROR
            c2u += int(relayed[0])
            u2c += int(relayed[1])
            self._record(
                DECISION_ALLOWED,
                REASON_ALLOWED,
                status=200,
                host=host,
                port=port,
                connected_ip=connected_ip,
                bytes_to_upstream=c2u,
                bytes_to_client=u2c,
            )
            return DECISION_ALLOWED
        finally:
            self._safe_close(upstream)
            self._untrack(upstream)

    def _deny(self, conn: Any, exc: EgressDeniedError) -> None:
        self._record(
            DECISION_DENIED,
            exc.reason,
            status=exc.status,
            host=exc.host,
            port=exc.port,
        )
        self._send_status(conn, exc.status, _STATUS_TEXT.get(exc.status, "Forbidden"))

    # -- relay --------------------------------------------------------------

    def _default_relay(
        self, client: Any, upstream: Any, stop_event: threading.Event
    ) -> Tuple[int, int]:
        """Relay bytes in both directions with bounded ``select`` waits."""

        c2u = 0
        u2c = 0
        socks = [client, upstream]
        started = self._clock()
        while not stop_event.is_set():
            if (self._clock() - started) > self._relay_max_seconds:
                break
            try:
                readable, _, _ = select.select(
                    socks, [], [], self._relay_idle_timeout
                )
            except (OSError, ValueError):
                break
            if not readable:
                break
            for source in readable:
                try:
                    data = source.recv(_RELAY_BUFFER)
                except OSError:
                    return c2u, u2c
                if not data:
                    return c2u, u2c
                destination = upstream if source is client else client
                try:
                    destination.sendall(data)
                except OSError:
                    return c2u, u2c
                if source is client:
                    c2u += len(data)
                else:
                    u2c += len(data)
        return c2u, u2c

    # -- statuses, records, tracking ---------------------------------------

    @staticmethod
    def _send_status(sock: Any, status: int, reason: str) -> None:
        """Send a minimal, fixed, request-data-free status line."""

        try:
            if status == 200:
                payload = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            else:
                payload = (
                    f"HTTP/1.1 {status} {reason}\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            sock.sendall(payload)
        except OSError:
            pass

    def _record(
        self,
        decision: str,
        reason: str,
        *,
        status: Optional[int] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        connected_ip: Optional[str] = None,
        bytes_to_upstream: int = 0,
        bytes_to_client: int = 0,
    ) -> None:
        record = EgressRecord(
            timestamp=self._now(),
            decision=decision,
            reason=reason,
            host=host,
            port=port,
            status=status,
            connected_ip=connected_ip,
            bytes_to_upstream=int(bytes_to_upstream),
            bytes_to_client=int(bytes_to_client),
        )
        with self._lock:
            self._records.append(record)
            if decision == DECISION_ALLOWED:
                self._counters["allowed"] += 1
            elif decision == DECISION_DENIED:
                self._counters["denied"] += 1
            else:
                self._counters["errors"] += 1
            self._counters["bytes_to_upstream"] += int(bytes_to_upstream)
            self._counters["bytes_to_client"] += int(bytes_to_client)

    def get_records(self) -> list[dict]:
        with self._lock:
            return [record.to_evidence() for record in self._records]

    def _track(self, sock: Any) -> None:
        with self._lock:
            self._active[id(sock)] = sock

    def _untrack(self, sock: Any) -> None:
        with self._lock:
            self._active.pop(id(sock), None)

    @staticmethod
    def _safe_close(sock: Any) -> None:
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass

    # -- evidence -----------------------------------------------------------

    def evidence(self) -> dict:
        """Return a deterministic, request-data-free evidence snapshot."""

        with self._lock:
            running = self._started and self._listener is not None
            pinned = (
                tuple(sorted(self._pinned_ips))
                if self._pinned_ips is not None
                else None
            )
            bound_port = self._bound_port if self._bound_port else self._bind_port
            return {
                "guard": "connect-egress",
                "running": running,
                "prepared": self._pinned_ips is not None,
                "pid": os.getpid(),
                "bind_endpoint": f"{self._bind_host}:{bound_port}",
                "listener": {"host": self._bind_host, "port": bound_port},
                "target": {
                    "scheme": "https",
                    "host": self._target_host,
                    "port": self._target_port,
                },
                "pinned_ips": list(pinned) if pinned is not None else None,
                "counters": dict(self._counters),
                "records": [record.to_evidence() for record in self._records],
            }
