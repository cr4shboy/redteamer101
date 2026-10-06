"""In-namespace helper: loopback-only CONNECT proxy and DNS relay.

This module runs **inside** the unprivileged empty network namespace created by
``/usr/bin/unshare --user --map-root-user --net``. It performs the namespace
setup itself (bringing up loopback only, assigning ``1.1.1.1/32`` to loopback so
the tool can address the relay, and refusing to continue unless the route tables
are isolated), then exposes:

* a loopback HTTP ``CONNECT`` proxy that accepts only ``CONNECT crt.sh:443`` and
  obtains the already-connected upstream descriptor from the outer broker over
  inherited IPC with ``SCM_RIGHTS``; and
* a loopback DNS relay (UDP and bounded TCP) that forwards raw queries to the
  outer broker over inherited IPC, which is the component that enforces policy.

The helper never opens an external socket: inside the empty namespace there is
no route off loopback, so any direct connect fails by construction. It can also
run a local-only self-test (``--mode selftest``) that proves those properties and
exercises canned IPC relay behavior without any external network.

Nothing in this module performs I/O at import time. It is only useful on
Linux/WSL; on other platforms it is not launched.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import posixpath
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from . import dns_wire, ipc, netpolicy
from .netns_sandbox import routes_are_isolated

__all__ = [
    "DnsRelay",
    "HelperError",
    "HttpConnectProxy",
    "MAX_CAPTURE_BYTES",
    "MAX_EXEC_FIELD",
    "NamespaceState",
    "ProxyDenied",
    "parse_exec_payload",
    "parse_proxy_connect_head",
    "run_exec",
    "run_ip",
    "setup_namespace",
]

#: Bounded capture for a tool's stdout/stderr written by the helper.
MAX_CAPTURE_BYTES = 8 * 1024 * 1024

#: Bound on a single exec-payload string field.
MAX_EXEC_FIELD = 4096

#: Best-effort kill signal for the tool's own process group.
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)

#: Environment names that may never be handed to the tool.
_EXEC_ENV_DENY_SUBSTRINGS = (
    "token",
    "secret",
    "passwd",
    "password",
    "credential",
    "auth",
    "private",
    "api_key",
    "apikey",
)

#: The only environment variables the helper permits that contain "proxy".
_EXEC_PROXY_ENV = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})

MAX_REQUEST_HEAD = 8192
MAX_HEADER_LINE = 2048
_COPY_BUFFER = 65536
_SELFTEST_CONNECT_TIMEOUT = 2.0

_HEAD_TERMINATOR = b"\r\n\r\n"

_STATUS_TEXT = {
    200: "Connection Established",
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    408: "Request Timeout",
    502: "Bad Gateway",
}

#: Bounded, explicit local-only A answers for the pinned tools' own engine
#: bootstrap probe(s). These names are infrastructure the pinned tool needs only
#: to start; they are answered **inside the empty namespace** with a synthetic,
#: non-routable loopback placeholder, without any broker request, external socket,
#: or resolver query. They are never target data and never an authorized egress.
#: Runtime evidence: the pinned Amass 5.1.1 `engine` support process aborts with
#: ``failed to obtain the BGPTools IP address`` when ``bgp.tools`` cannot resolve,
#: which prevents the engine (and therefore `enum`) from starting.
_LOCAL_BOOTSTRAP_ANSWERS = {
    "bgp.tools": "127.0.0.1",
}


class HelperError(RuntimeError):
    """The helper could not establish or maintain its contract."""


class ProxyDenied(HelperError):
    """A CONNECT request was denied before any broker request was sent."""

    def __init__(self, reason: str, *, status: int = 403) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class NamespaceState:
    """Observed state after namespace setup (evidence only)."""

    uid: int
    route4: str
    route6: str


# ---------------------------------------------------------------------------
# Namespace setup
# ---------------------------------------------------------------------------


def run_ip(ip_path: str, args: object, *, timeout: float = 5.0):
    """Run the exact ``ip`` binary with *args* (never a shell)."""

    if not isinstance(ip_path, str) or not os.path.isabs(ip_path):
        raise HelperError("ip path must be an absolute path")
    argv = [ip_path, *(str(item) for item in args)]  # type: ignore[arg-type]
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HelperError("failed to invoke the ip utility") from exc


def setup_namespace(ip_path: str, *, assign_dns: bool = True) -> NamespaceState:
    """Bring up loopback only and verify the namespace has no routed egress."""

    result = run_ip(ip_path, ["link", "set", "lo", "up"])
    if result.returncode != 0:
        raise HelperError("could not bring up loopback")

    if assign_dns:
        result = run_ip(
            ip_path,
            ["addr", "add", f"{netpolicy.UPSTREAM_DNS_HOST}/32", "dev", "lo"],
        )
        if result.returncode != 0:
            raise HelperError("could not assign the loopback resolver address")

    route4 = run_ip(ip_path, ["-4", "route", "show"]).stdout
    route6 = run_ip(ip_path, ["-6", "route", "show"]).stdout
    if not routes_are_isolated(route4, route6):
        raise HelperError("namespace route table is not isolated")
    return NamespaceState(uid=os.getuid(), route4=route4, route6=route6)


# ---------------------------------------------------------------------------
# HTTP CONNECT proxy
# ---------------------------------------------------------------------------


def parse_proxy_connect_head(head: object, policy=netpolicy.RECON_002_POLICY) -> tuple[str, int]:
    """Parse one request head and require an exact ``CONNECT crt.sh:443``.

    Every other method, malformed authority, userinfo, IP literal, host, or port
    is denied here, before any broker/IPC request is made.
    """

    if not isinstance(head, (bytes, bytearray)):
        raise ProxyDenied("malformed_request", status=400)
    text = bytes(head).decode("latin-1")
    if "\x00" in text:
        raise ProxyDenied("malformed_request", status=400)
    request_line = text.split("\r\n", 1)[0]
    if not request_line:
        raise ProxyDenied("malformed_request", status=400)
    parts = request_line.split(" ")
    if len(parts) != 3 or any(part == "" for part in parts):
        raise ProxyDenied("malformed_request", status=400)
    method, authority, version = parts
    if method != "CONNECT":
        raise ProxyDenied("method_not_allowed", status=405)
    if not version.startswith("HTTP/") or len(version) > 16:
        raise ProxyDenied("malformed_request", status=400)
    if "@" in authority:
        raise ProxyDenied("userinfo_forbidden", status=403)
    if "[" in authority or "]" in authority:
        raise ProxyDenied("ip_literal_forbidden", status=403)
    if authority.count(":") != 1:
        raise ProxyDenied("malformed_request", status=400)
    host_text, port_text = authority.split(":", 1)
    if not host_text or not port_text or not port_text.isdigit():
        raise ProxyDenied("malformed_request", status=400)
    try:
        ipaddress.ip_address(host_text)
    except ValueError:
        pass
    else:
        raise ProxyDenied("ip_literal_forbidden", status=403)
    port = int(port_text)
    if port != policy.https_port:
        raise ProxyDenied("port_not_allowed", status=403)
    try:
        normalized = netpolicy.normalize_policy_name(host_text)
    except netpolicy.PolicyError as exc:
        raise ProxyDenied("host_not_allowed", status=403) from exc
    if not policy.is_allowed_connect_authority(normalized, port):
        raise ProxyDenied("host_not_allowed", status=403)
    return normalized, port


class HttpConnectProxy:
    """A loopback CONNECT proxy that relays only the broker-supplied socket."""

    def __init__(
        self,
        *,
        listen_host: str,
        listen_port: int,
        connect_sock: socket.socket,
        stop_event: threading.Event,
        policy=netpolicy.RECON_002_POLICY,
        on_event=None,
    ) -> None:
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._connect_sock = connect_sock
        self._stop_event = stop_event
        self._policy = policy
        self._on_event = on_event
        self._lock = threading.Lock()
        self._ipc_lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._workers: list[threading.Thread] = []

    @property
    def endpoint(self) -> tuple[str, int]:
        return (self._listen_host, self._listen_port)

    def start(self) -> "HttpConnectProxy":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            listener.bind((self._listen_host, self._listen_port))
            listener.listen(8)
            listener.settimeout(self._policy.ipc_poll_interval)
        except OSError as exc:
            listener.close()
            raise HelperError("could not bind the loopback CONNECT proxy") from exc
        self._listener = listener
        self._thread = threading.Thread(
            target=self._accept_loop, name="recon-proxy-accept", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop_event.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(
                target=self._handle_client, args=(client,), daemon=True
            )
            with self._lock:
                self._workers = [t for t in self._workers if t.is_alive()]
                self._workers.append(worker)
            worker.start()

    def _handle_client(self, client: socket.socket) -> None:
        try:
            self.handle_client(client)
        except Exception:
            self._emit("proxy", "error", reason="internal_error")
        finally:
            _safe_close(client)

    def handle_client(self, client: socket.socket) -> str:
        try:
            head, leftover = _read_head(client)
        except ProxyDenied as exc:
            _send_status(client, exc.status)
            self._emit("proxy", "denied", reason=exc.reason)
            return "denied"

        try:
            host, port = parse_proxy_connect_head(head, self._policy)
        except ProxyDenied as exc:
            _send_status(client, exc.status)
            self._emit("proxy", "denied", reason=exc.reason)
            return "denied"

        try:
            with self._ipc_lock:
                ipc.send_frame(
                    self._connect_sock,
                    ipc.encode_connect_request(host, port),
                )
                reply, fd = ipc.recv_message_fd(self._connect_sock)
            ok, reason = ipc.decode_connect_response(reply)
        except (ipc.IpcError, OSError):
            _send_status(client, 502)
            self._emit("proxy", "error", reason="broker_unavailable")
            return "error"

        if not ok or fd is None:
            _send_status(client, 403)
            self._emit("proxy", "denied", reason=reason or "broker_denied")
            return "denied"

        upstream = socket.socket(fileno=fd)
        try:
            _send_status(client, 200)
            bytes_up = bytes_down = 0
            if leftover:
                upstream.sendall(leftover)
                bytes_up += len(leftover)
            up, down = _relay(client, upstream, self._stop_event, self._policy)
            bytes_up += up
            bytes_down += down
            self._emit(
                "proxy",
                "allowed",
                host=host,
                port=port,
                bytes_up=bytes_up,
                bytes_down=bytes_down,
            )
            return "allowed"
        finally:
            _safe_close(upstream)

    def _emit(self, action: str, decision: str, **fields) -> None:
        if self._on_event is not None:
            try:
                self._on_event({"action": action, "decision": decision, **fields})
            except Exception:
                pass


def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    buffer = bytearray()
    while _HEAD_TERMINATOR not in buffer:
        if len(buffer) >= MAX_REQUEST_HEAD:
            raise ProxyDenied("request_too_large", status=400)
        try:
            chunk = sock.recv(4096)
        except socket.timeout as exc:
            raise ProxyDenied("request_timeout", status=408) from exc
        except OSError as exc:
            raise ProxyDenied("io_error", status=400) from exc
        if not chunk:
            raise ProxyDenied("malformed_request", status=400)
        buffer.extend(chunk)
    index = buffer.index(_HEAD_TERMINATOR) + len(_HEAD_TERMINATOR)
    head = bytes(buffer[:index])
    leftover = bytes(buffer[index:])
    for line in head.split(b"\r\n"):
        if len(line) > MAX_HEADER_LINE:
            raise ProxyDenied("request_too_large", status=400)
    return head, leftover


def _send_status(sock: socket.socket, status: int) -> None:
    reason = _STATUS_TEXT.get(status, "Forbidden")
    try:
        if status == 200:
            sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            sock.sendall(
                (
                    f"HTTP/1.1 {status} {reason}\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
            )
    except OSError:
        pass


def _relay(
    client: socket.socket,
    upstream: socket.socket,
    stop_event: threading.Event,
    policy=netpolicy.RECON_002_POLICY,
) -> tuple[int, int]:
    """Relay bytes both directions with bounded idle/max waits."""

    bytes_up = bytes_down = 0
    started = time.monotonic()
    socks = [client, upstream]
    while not stop_event.is_set():
        if (time.monotonic() - started) > policy.relay_max_seconds:
            break
        try:
            readable, _, _ = select.select(socks, [], [], policy.relay_idle_timeout)
        except (OSError, ValueError):
            break
        if not readable:
            break
        for source in readable:
            try:
                data = source.recv(_COPY_BUFFER)
            except OSError:
                return bytes_up, bytes_down
            if not data:
                return bytes_up, bytes_down
            destination = upstream if source is client else client
            try:
                destination.sendall(data)
            except OSError:
                return bytes_up, bytes_down
            if source is client:
                bytes_up += len(data)
            else:
                bytes_down += len(data)
    return bytes_up, bytes_down


# ---------------------------------------------------------------------------
# DNS relay
# ---------------------------------------------------------------------------


def _local_bootstrap_response(query: bytes) -> bytes | None:
    """Return a synthetic local A response for a known engine-bootstrap name.

    Only an exact A-record question for a name in
    :data:`_LOCAL_BOOTSTRAP_ANSWERS` is answered; everything else returns
    ``None`` so the query is forwarded to the outer broker unchanged.
    """

    try:
        parsed = dns_wire.parse_query(query, max_len=netpolicy.MAX_DNS_MESSAGE)
    except dns_wire.DnsMessageError:
        return None
    if parsed.qtype != netpolicy.DNS_TYPE_A:
        return None
    address = _LOCAL_BOOTSTRAP_ANSWERS.get(parsed.name)
    if address is None:
        return None
    try:
        return dns_wire.build_response_for_query(
            query, [(parsed.name, netpolicy.DNS_TYPE_A, address)]
        )
    except dns_wire.DnsMessageError:  # pragma: no cover - defensive
        return None


class DnsRelay:
    """Loopback DNS relay forwarding raw queries to the outer broker over IPC."""

    def __init__(
        self,
        *,
        listen_host: str = netpolicy.UPSTREAM_DNS_HOST,
        listen_port: int = netpolicy.UPSTREAM_DNS_PORT,
        dns_sock: socket.socket,
        stop_event: threading.Event,
        policy=netpolicy.RECON_002_POLICY,
        on_event=None,
    ) -> None:
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._dns_sock = dns_sock
        self._stop_event = stop_event
        self._policy = policy
        self._on_event = on_event
        self._ipc_lock = threading.Lock()
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> "DnsRelay":
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            udp.bind((self._listen_host, self._listen_port))
            tcp.bind((self._listen_host, self._listen_port))
            tcp.listen(8)
            udp.settimeout(self._policy.ipc_poll_interval)
            tcp.settimeout(self._policy.ipc_poll_interval)
        except OSError as exc:
            udp.close()
            tcp.close()
            raise HelperError("could not bind the loopback DNS relay") from exc
        self._udp = udp
        self._tcp = tcp
        self._threads = [
            threading.Thread(target=self._udp_loop, name="recon-dns-udp", daemon=True),
            threading.Thread(target=self._tcp_loop, name="recon-dns-tcp", daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        return self

    def stop(self) -> None:
        for sock in (self._udp, self._tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._udp = None
        self._tcp = None

    def _forward(self, protocol: int, query: bytes) -> tuple[int, bytes]:
        # Answer the pinned tools' own engine-bootstrap probe locally first: no
        # broker request and no external socket. Everything else is forwarded.
        local = _local_bootstrap_response(query)
        if local is not None:
            self._emit(
                "dns",
                "local",
                protocol=(
                    "udp" if protocol == netpolicy.DNS_PROTO_UDP else "tcp"
                ),
            )
            return ipc.STATUS_OK, local
        with self._ipc_lock:
            ipc.send_frame(
                self._dns_sock, ipc.encode_dns_request(protocol, query)
            )
            reply = ipc.recv_frame(self._dns_sock)
        if reply is None:
            raise HelperError("DNS broker channel closed")
        tag, status, response = ipc.decode_dns_response(reply)
        # Defense in depth: the response must be transported over the same
        # protocol as the request, otherwise a mismatched/forged relay reply
        # could be delivered to the wrong transport.
        if tag != protocol:
            raise HelperError("DNS response transport tag does not match the request")
        return status, response

    def _udp_loop(self) -> None:
        udp = self._udp
        if udp is None:
            return
        while not self._stop_event.is_set():
            try:
                data, addr = udp.recvfrom(self._policy.max_dns_message)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) > self._policy.max_dns_message:
                continue
            try:
                status, response = self._forward(netpolicy.DNS_PROTO_UDP, data)
            except (HelperError, ipc.IpcError, OSError):
                self._emit("dns", "error", protocol="udp")
                continue
            if status != ipc.STATUS_OK or not response:
                self._emit("dns", "denied", protocol="udp")
                continue
            try:
                udp.sendto(response, addr)
                self._emit("dns", "allowed", protocol="udp")
            except OSError:
                self._emit("dns", "error", protocol="udp")

    def _tcp_loop(self) -> None:
        tcp = self._tcp
        if tcp is None:
            return
        while not self._stop_event.is_set():
            try:
                client, _ = tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_tcp_client, args=(client,), daemon=True
            ).start()

    def _handle_tcp_client(self, client: socket.socket) -> None:
        try:
            client.settimeout(self._policy.dns_tcp_timeout)
            header = _recv_exact(client, 2)
            if header is None:
                return
            length = int.from_bytes(header, "big")
            if length <= 0 or length > self._policy.max_dns_message:
                return
            body = _recv_exact(client, length)
            if body is None:
                return
            status, response = self._forward(netpolicy.DNS_PROTO_TCP, body)
            if status != ipc.STATUS_OK or not response:
                self._emit("dns", "denied", protocol="tcp")
                return
            client.sendall(len(response).to_bytes(2, "big") + response)
            self._emit("dns", "allowed", protocol="tcp")
        except (HelperError, ipc.IpcError, OSError):
            self._emit("dns", "error", protocol="tcp")
        finally:
            _safe_close(client)

    def _emit(self, action: str, decision: str, **fields) -> None:
        if self._on_event is not None:
            try:
                self._on_event({"action": action, "decision": decision, **fields})
            except Exception:
                pass


def _recv_exact(sock: socket.socket, count: int) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            return None
        buffer.extend(chunk)
    return bytes(buffer)


def _safe_close(sock: object) -> None:
    try:
        sock.close()  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------


def serve(args: argparse.Namespace) -> int:
    """Normal mode: set up the namespace and run the proxy and relay."""

    status = _wire_socket(args.status_fd)
    stop_event = threading.Event()
    _install_signal_handlers(stop_event)

    try:
        state = setup_namespace(args.ip_path)
    except HelperError as exc:
        _status(status, event="fatal", reason=str(exc))
        return 4

    connect_sock = _wire_socket(args.connect_fd)
    dns_sock = _wire_socket(args.dns_fd)
    proxy = HttpConnectProxy(
        listen_host="127.0.0.1",
        listen_port=args.http_port,
        connect_sock=connect_sock,
        stop_event=stop_event,
    )
    relay = DnsRelay(
        listen_host=netpolicy.UPSTREAM_DNS_HOST,
        listen_port=args.dns_port,
        dns_sock=dns_sock,
        stop_event=stop_event,
    )
    try:
        relay.start()
        proxy.start()
    except HelperError as exc:
        _status(status, event="fatal", reason=str(exc))
        return 4

    _status(
        status,
        event="ready",
        uid=state.uid,
        route4=state.route4.strip(),
        route6=state.route6.strip(),
        http_port=args.http_port,
        dns_port=args.dns_port,
    )
    try:
        while not stop_event.wait(netpolicy.IPC_POLL_INTERVAL):
            pass
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        pass
    finally:
        proxy.stop()
        relay.stop()
        _status(status, event="stopped")
    return 0


def run_selftest(args: argparse.Namespace) -> int:
    """Local-only self-test: prove isolation and canned IPC relay behavior."""

    status = _wire_socket(args.status_fd)
    stop_event = threading.Event()
    _install_signal_handlers(stop_event)
    results: dict[str, object] = {}

    try:
        state = setup_namespace(args.ip_path)
    except HelperError as exc:
        _status(status, event="fatal", reason=str(exc))
        return 4

    results["route4"] = state.route4.strip()
    results["route6"] = state.route6.strip()
    results["uid"] = state.uid
    results["route_isolated"] = routes_are_isolated(state.route4, state.route6)

    # Direct external TCP must fail by construction (no route off loopback).
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(_SELFTEST_CONNECT_TIMEOUT)
    try:
        tcp.connect(("8.8.8.8", 443))
        results["direct_tcp_blocked"] = False
    except OSError:
        results["direct_tcp_blocked"] = True
    finally:
        _safe_close(tcp)

    # Direct external UDP must not be able to leave either.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(_SELFTEST_CONNECT_TIMEOUT)
    try:
        udp.connect(("8.8.8.8", 53))
        udp.send(b"\x00")
        results["direct_udp_blocked"] = not udp.recv(64)
    except OSError:
        results["direct_udp_blocked"] = True
    finally:
        _safe_close(udp)

    connect_sock = _wire_socket(args.connect_fd)
    dns_sock = _wire_socket(args.dns_fd)
    proxy = HttpConnectProxy(
        listen_host="127.0.0.1",
        listen_port=args.http_port,
        connect_sock=connect_sock,
        stop_event=stop_event,
    )
    relay = DnsRelay(
        listen_host=netpolicy.UPSTREAM_DNS_HOST,
        listen_port=args.dns_port,
        dns_sock=dns_sock,
        stop_event=stop_event,
    )
    try:
        relay.start()
        proxy.start()
    except HelperError as exc:
        _status(status, event="fatal", reason=str(exc))
        return 4

    # Give the listeners a moment to accept connections.
    time.sleep(0.2)

    try:
        results["connect_denied"] = _selftest_connect_denied(args.http_port)
        results["connect_allowed"] = _selftest_connect_allowed(args.http_port)
        results["dns_allowed_udp"] = _selftest_dns_udp(
            args.dns_port, "acme.example", netpolicy.DNS_TYPE_A
        )
        results["dns_allowed_tcp"] = _selftest_dns_tcp(
            args.dns_port, "www.acme.example", netpolicy.DNS_TYPE_CNAME
        )
        results["dns_denied"] = _selftest_dns_denied(
            args.dns_port, "example.com", netpolicy.DNS_TYPE_A
        )
    except Exception as exc:  # pragma: no cover - defensive
        results["error"] = type(exc).__name__
    finally:
        proxy.stop()
        relay.stop()

    passed = bool(
        results.get("route_isolated")
        and results.get("direct_tcp_blocked")
        and results.get("direct_udp_blocked")
        and results.get("connect_denied")
        and results.get("connect_allowed")
        and results.get("dns_allowed_udp")
        and results.get("dns_allowed_tcp")
        and results.get("dns_denied")
    )
    results["passed"] = passed
    _status(status, event="done", **{k: v for k, v in results.items()})
    return 0 if passed else 5


def _selftest_connect_denied(port: int) -> bool:
    client = _connect_loopback(port)
    if client is None:
        return False
    try:
        client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        line = client.recv(128)
        return line.startswith(b"HTTP/1.1 403")
    except OSError:
        return False
    finally:
        _safe_close(client)


def _selftest_connect_allowed(port: int) -> bool:
    client = _connect_loopback(port)
    if client is None:
        return False
    try:
        client.sendall(b"CONNECT crt.sh:443 HTTP/1.1\r\n\r\n")
        status_line = client.recv(128)
        if not status_line.startswith(b"HTTP/1.1 200"):
            return False
        client.sendall(b"ping")
        echoed = client.recv(64)
        return echoed == b"pong"
    except OSError:
        return False
    finally:
        _safe_close(client)


def _selftest_dns_udp(port: int, name: str, qtype: int) -> bool:
    query = dns_wire.build_query(name, qtype, 0x2222)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(_SELFTEST_CONNECT_TIMEOUT)
    try:
        udp.sendto(query, (netpolicy.UPSTREAM_DNS_HOST, port))
        response, _ = udp.recvfrom(netpolicy.MAX_DNS_MESSAGE)
    except OSError:
        return False
    finally:
        _safe_close(udp)
    try:
        parsed = dns_wire.parse_response(
            response, expect_id=0x2222, expect_name=name, expect_type=qtype
        )
    except dns_wire.DnsMessageError:
        return False
    return bool(dns_wire.extract_addresses(parsed))


def _selftest_dns_tcp(port: int, name: str, qtype: int) -> bool:
    query = dns_wire.build_query(name, qtype, 0x3333)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(_SELFTEST_CONNECT_TIMEOUT)
    try:
        client.connect((netpolicy.UPSTREAM_DNS_HOST, port))
        client.sendall(len(query).to_bytes(2, "big") + query)
        header = _recv_exact(client, 2)
        if header is None:
            return False
        length = int.from_bytes(header, "big")
        if length <= 0 or length > netpolicy.MAX_DNS_MESSAGE:
            return False
        body = _recv_exact(client, length)
        if body is None:
            return False
    except OSError:
        return False
    finally:
        _safe_close(client)
    try:
        parsed = dns_wire.parse_response(
            body, expect_id=0x3333, expect_name=name, expect_type=qtype
        )
    except dns_wire.DnsMessageError:
        return False
    return bool(dns_wire.extract_cnames(parsed))


def _selftest_dns_denied(port: int, name: str, qtype: int) -> bool:
    query = dns_wire.build_query(name, qtype, 0x4444)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1.0)
    try:
        udp.sendto(query, (netpolicy.UPSTREAM_DNS_HOST, port))
        try:
            udp.recvfrom(netpolicy.MAX_DNS_MESSAGE)
            return False
        except socket.timeout:
            return True
    except OSError:
        return True
    finally:
        _safe_close(udp)


def _connect_loopback(port: int) -> socket.socket | None:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(_SELFTEST_CONNECT_TIMEOUT)
    try:
        client.connect(("127.0.0.1", port))
    except OSError:
        _safe_close(client)
        return None
    return client


def _wire_socket(fd: int) -> socket.socket:
    return socket.socket(fileno=fd)


def _status(status: socket.socket, **event) -> None:
    try:
        ipc.send_frame(status, ipc.encode_status_event(event))
    except (ipc.IpcError, OSError) as exc:
        sys.stderr.write(f"netns-helper: status event failed: {type(exc).__name__}: {exc}\n")
        sys.stderr.flush()


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def _handle(_signum, _frame):  # pragma: no cover - signal timing
        stop_event.set()

    for signame in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, signame, None)
        if signum is not None:
            try:
                signal.signal(signum, _handle)
            except (ValueError, OSError):  # pragma: no cover - non-main thread
                pass


# ---------------------------------------------------------------------------
# One-shot validated tool execution (mode=exec)
# ---------------------------------------------------------------------------


def _require_abs_posix(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise HelperError(f"exec {name} must be a non-empty path")
    if not posixpath.isabs(value):
        raise HelperError(f"exec {name} must be an absolute path")
    return posixpath.normpath(value)


def _require_under(name: str, value: object, root: str) -> str:
    path = _require_abs_posix(name, value)
    if posixpath.commonpath([path, root]) != root:
        raise HelperError(f"exec {name} escapes the working directory")
    return path


def _validate_exec_env(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise HelperError("exec env must be a mapping")
    env: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or not isinstance(item, str):
            raise HelperError("exec env entries must be string pairs")
        if len(key) > 128 or len(item) > MAX_EXEC_FIELD:
            raise HelperError("exec env entry exceeds its bound")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in key + item):
            raise HelperError("exec env contains control characters")
        lowered = key.lower()
        is_proxy = key.upper() in _EXEC_PROXY_ENV
        if not is_proxy and any(bad in lowered for bad in _EXEC_ENV_DENY_SUBSTRINGS):
            raise HelperError("exec env must not carry secret-like names")
        env[key] = item
    return env


def parse_exec_payload(text: object) -> dict:
    """Parse and strictly validate one exec payload (pure, bounded)."""

    if not isinstance(text, str) or not text:
        raise HelperError("exec payload must be a non-empty JSON string")
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HelperError("exec payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise HelperError("exec payload must be a JSON object")
    allowed = {
        "argv",
        "cwd",
        "env",
        "stdin_path",
        "stdout_path",
        "stderr_path",
        "status_path",
        "timeout",
    }
    if set(payload) - allowed:
        raise HelperError("exec payload has unexpected fields")

    argv = payload.get("argv")
    if not isinstance(argv, list) or not argv:
        raise HelperError("exec argv must be a non-empty list")
    normalized_argv: list[str] = []
    for item in argv:
        if not isinstance(item, str) or not item or len(item) > MAX_EXEC_FIELD:
            raise HelperError("exec argv entries must be bounded non-empty strings")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in item):
            raise HelperError("exec argv contains control characters")
        normalized_argv.append(item)
    if not posixpath.isabs(normalized_argv[0]):
        raise HelperError("exec argv[0] must be an absolute path")

    cwd = _require_abs_posix("cwd", payload.get("cwd"))
    stdout_path = _require_under("stdout_path", payload.get("stdout_path"), cwd)
    stderr_path = _require_under("stderr_path", payload.get("stderr_path"), cwd)
    status_path = _require_under("status_path", payload.get("status_path"), cwd)
    stdin_value = payload.get("stdin_path")
    stdin_path = (
        _require_under("stdin_path", stdin_value, cwd)
        if stdin_value is not None
        else None
    )

    timeout = payload.get("timeout")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or float(timeout) <= 0
        or float(timeout) > 600.0
    ):
        raise HelperError("exec timeout must be a positive finite number <= 600")

    return {
        "argv": tuple(normalized_argv),
        "cwd": cwd,
        "env": _validate_exec_env(payload.get("env", {})),
        "stdin_path": stdin_path,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "status_path": status_path,
        "timeout": float(timeout),
    }


def _drain_bounded(stream, cap: int) -> tuple[bytes, bool]:
    buffer = bytearray()
    truncated = False
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if len(buffer) < cap:
                take = min(len(chunk), cap - len(buffer))
                buffer.extend(chunk[:take])
                if take < len(chunk):
                    truncated = True
            else:
                truncated = True
    except (OSError, ValueError):  # pragma: no cover - defensive
        truncated = True
    return bytes(buffer), truncated


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)


def _write_status_file(path: str, document: dict) -> None:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii", "replace")
    _write_bytes(path, raw)


def _kill_tool_process_group(proc) -> bool:
    """Kill every process left in the tool's own process group.

    The tool is launched with ``start_new_session=True``, so its process-group id
    equals its pid; killing that group removes any descendants that outlived the
    direct child. Falls back to killing only the direct child when process-group
    signalling is unavailable.
    """

    if proc is None:
        return False
    pgid = getattr(proc, "pid", None)
    if isinstance(pgid, bool) or not isinstance(pgid, int):
        return False
    killpg = getattr(os, "killpg", None)
    if killpg is not None:
        try:
            killpg(pgid, _SIGKILL)
            return True
        except OSError:
            pass
        except AttributeError:  # pragma: no cover - defensive
            pass
    try:
        proc.kill()
        return True
    except (OSError, AttributeError):
        return False


def _execute_tool(payload: dict) -> dict:
    """Execute exactly one validated tool command inside the namespace."""

    stdin_handle = subprocess.DEVNULL
    opened_stdin = None
    if payload["stdin_path"] is not None:
        opened_stdin = open(payload["stdin_path"], "rb")
        stdin_handle = opened_stdin

    stdout_reader = stderr_reader = None
    proc = None
    stdout_data = b""
    stderr_data = b""
    stdout_truncated = False
    stderr_truncated = False
    timed_out = False
    error: str | None = None
    returncode: int | None = None
    try:
        proc = subprocess.Popen(
            list(payload["argv"]),
            cwd=payload["cwd"],
            env=dict(payload["env"]),
            stdin=stdin_handle,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            # Give the tool its own process group/session so any descendants can
            # be killed by group id and no orphan survives helper exit.
            start_new_session=True,
        )
        out_result: dict = {}
        err_result: dict = {}

        def _read(stream, store, key):
            data, truncated = _drain_bounded(stream, MAX_CAPTURE_BYTES)
            store[key] = (data, truncated)

        readers = [
            threading.Thread(target=_read, args=(proc.stdout, out_result, "out"), daemon=True),
            threading.Thread(target=_read, args=(proc.stderr, err_result, "err"), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            proc.wait(timeout=payload["timeout"])
        except subprocess.TimeoutExpired:
            timed_out = True
            # Kill the entire tool process group, then reap the direct child.
            _kill_tool_process_group(proc)
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                pass
        for reader in readers:
            reader.join(timeout=5.0)
        # On completion, kill any descendants that outlived the direct child and
        # reap it so no orphan process can survive helper exit.
        _kill_tool_process_group(proc)
        try:
            proc.wait(timeout=5.0)
        except (subprocess.TimeoutExpired, OSError):  # pragma: no cover - defensive
            pass
        stdout_data, stdout_truncated = out_result.get("out", (b"", False))
        stderr_data, stderr_truncated = err_result.get("err", (b"", False))
        if not timed_out:
            returncode = proc.returncode
    except OSError as exc:
        error = type(exc).__name__
    finally:
        if opened_stdin is not None:
            try:
                opened_stdin.close()
            except OSError:  # pragma: no cover - defensive
                pass

    _write_bytes(payload["stdout_path"], stdout_data)
    _write_bytes(payload["stderr_path"], stderr_data)
    status_document = {
        "exit_code": returncode,
        "timed_out": timed_out,
        "error": error,
        "stdout_bytes": len(stdout_data),
        "stderr_bytes": len(stderr_data),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }
    _write_status_file(payload["status_path"], status_document)
    return status_document


def run_exec(args: argparse.Namespace) -> int:
    """Normal one-shot mode: set up the namespace, run one tool, and exit."""

    status = _wire_socket(args.status_fd)
    stop_event = threading.Event()
    _install_signal_handlers(stop_event)

    try:
        state = setup_namespace(args.ip_path)
    except HelperError as exc:
        _status(status, event="fatal", reason=str(exc))
        return 4

    connect_sock = _wire_socket(args.connect_fd)
    dns_sock = _wire_socket(args.dns_fd)
    proxy = HttpConnectProxy(
        listen_host="127.0.0.1",
        listen_port=args.http_port,
        connect_sock=connect_sock,
        stop_event=stop_event,
    )
    relay = DnsRelay(
        listen_host=netpolicy.UPSTREAM_DNS_HOST,
        listen_port=args.dns_port,
        dns_sock=dns_sock,
        stop_event=stop_event,
    )
    try:
        relay.start()
        proxy.start()
    except HelperError as exc:
        _status(status, event="fatal", reason=str(exc))
        return 4

    try:
        payload = parse_exec_payload(args.exec_json)
    except HelperError as exc:
        _status(status, event="fatal", reason=str(exc))
        proxy.stop()
        relay.stop()
        return 4

    _status(
        status,
        event="ready",
        uid=state.uid,
        route4=state.route4.strip(),
        route6=state.route6.strip(),
        http_port=args.http_port,
        dns_port=args.dns_port,
    )
    result = _execute_tool(payload)
    _status(
        status,
        event="tool_exit",
        exit_code=result["exit_code"],
        timed_out=result["timed_out"],
        error=result["error"],
        stdout_bytes=result["stdout_bytes"],
        stderr_bytes=result["stderr_bytes"],
        stdout_truncated=result["stdout_truncated"],
        stderr_truncated=result["stderr_truncated"],
    )
    proxy.stop()
    relay.stop()
    _status(status, event="stopped")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red_teaming.recon.netns_helper",
        description="RECON-002 in-namespace loopback egress helper",
    )
    parser.add_argument("--mode", choices=("serve", "selftest", "exec"), default="serve")
    parser.add_argument("--connect-fd", type=int, required=True)
    parser.add_argument("--dns-fd", type=int, required=True)
    parser.add_argument("--status-fd", type=int, required=True)
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument(
        "--dns-port", type=int, default=netpolicy.UPSTREAM_DNS_PORT
    )
    parser.add_argument("--ip-path", default="/usr/sbin/ip")
    parser.add_argument("--exec-json", default=None)
    return parser


def main(argv: object = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.mode == "selftest":
            return run_selftest(args)
        if args.mode == "exec":
            return run_exec(args)
        return serve(args)
    except HelperError as exc:
        sys.stderr.write(f"netns-helper: {exc}\n")
        return 3


if __name__ == "__main__":  # pragma: no cover - module entry
    raise SystemExit(main())
