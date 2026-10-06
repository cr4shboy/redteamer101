"""Local-only namespace self-test for the RECON-002 sandbox.

:func:`run_self_test` launches the helper under
``/usr/bin/unshare --user --map-root-user --net`` connected to an in-memory
*canned* broker that runs entirely in the parent process. The canned broker
never opens an external socket and never contacts any host: it only passes back
an in-memory echo socketpair for an allowed CONNECT and returns canned DNS
responses from a local buffer.

The helper proves, inside its isolated namespace, that direct external TCP/UDP
is impossible, that a disallowed CONNECT is denied without any broker request,
that an allowed CONNECT relays over the broker-supplied descriptor, and that an
allowed DNS query relays canned data while a disallowed query is denied by the
broker (with zero upstream calls).

On non-Linux platforms this returns a fail-closed *unsupported* report instead
of attempting anything.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import dns_wire, ipc, netpolicy
from .netpolicy import (
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    RECON_002_POLICY,
)
from .netns_sandbox import (
    SandboxConfig,
    launch_helper,
    sandbox_supported,
)

__all__ = ["FakeBroker", "SelfTestReport", "run_self_test"]

_DEFAULT_TIMEOUT = 30.0


@dataclass
class SelfTestReport:
    """Result of a local-only namespace self-test."""

    supported: bool
    passed: bool
    reason: Optional[str] = None
    checks: dict = field(default_factory=dict)
    broker: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "supported": self.supported,
            "passed": self.passed,
            "reason": self.reason,
            "checks": dict(self.checks),
            "broker": dict(self.broker),
        }


class FakeBroker:
    """An in-memory canned broker used only by the self-test.

    It speaks the same bounded IPC as the real broker but opens no external
    socket: allowed CONNECT requests receive an in-memory echo descriptor and
    allowed DNS queries receive canned responses. It records how many requests
    reached it so the self-test can prove denial happens before the broker.
    """

    def __init__(
        self,
        connect_sock: socket.socket,
        dns_sock: socket.socket,
        *,
        policy=RECON_002_POLICY,
    ) -> None:
        self._connect = connect_sock
        self._dns = dns_sock
        self._policy = policy
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.connect_requests: list[tuple[str, int]] = []
        self.dns_requests: list[tuple[str, int]] = []
        self.denied_dns = 0
        self.upstream_calls = 0

    def start(self) -> "FakeBroker":
        self._threads = [
            threading.Thread(target=self._serve_connect, daemon=True),
            threading.Thread(target=self._serve_dns, daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._connect, self._dns):
            try:
                sock.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=1.0)

    @property
    def counters(self) -> dict:
        return {
            "connect_requests": len(self.connect_requests),
            "dns_requests": len(self.dns_requests),
            "denied_dns": self.denied_dns,
            "upstream_calls": self.upstream_calls,
        }

    def _serve_connect(self) -> None:
        self._connect.settimeout(0.2)
        while not self._stop.is_set():
            try:
                payload, _fd = ipc.recv_message_fd(self._connect)
            except socket.timeout:
                continue
            except (ipc.IpcClosed, OSError):
                break
            try:
                host, port = ipc.decode_connect_request(payload)
            except ipc.IpcProtocolError:
                continue
            self.connect_requests.append((host, port))
            if not self._policy.is_allowed_connect_authority(host, port):
                ipc.send_fd_message(
                    self._connect, ipc.encode_connect_response(False, "denied")
                )
                continue
            helper_end, peer = socket.socketpair()
            threading.Thread(
                target=self._echo_peer, args=(peer,), daemon=True
            ).start()
            try:
                ipc.send_fd_message(
                    self._connect,
                    ipc.encode_connect_response(True),
                    helper_end.fileno(),
                )
            finally:
                helper_end.close()

    def _echo_peer(self, peer: socket.socket) -> None:
        try:
            peer.settimeout(5.0)
            data = peer.recv(64)
            if b"ping" in data:
                peer.sendall(b"pong")
        except OSError:
            pass
        finally:
            try:
                peer.close()
            except OSError:
                pass

    def _serve_dns(self) -> None:
        self._dns.settimeout(0.2)
        while not self._stop.is_set():
            try:
                payload = ipc.recv_frame(self._dns)
            except socket.timeout:
                continue
            except (ipc.IpcClosed, OSError):
                break
            if payload is None:
                break
            try:
                protocol, query = ipc.decode_dns_request(payload)
            except ipc.IpcProtocolError:
                continue
            try:
                parsed = dns_wire.parse_query(query)
                scope = self._policy.classify_dns_question(parsed.name, parsed.qtype)
            except dns_wire.DnsMessageError:
                scope = None
                parsed = None
            if scope != netpolicy.DNS_SCOPE_TARGET or parsed is None:
                self.denied_dns += 1
                ipc.send_frame(
                    self._dns, ipc.encode_dns_response(protocol, ipc.STATUS_DENIED)
                )
                continue
            self.dns_requests.append((parsed.name, parsed.qtype))
            self.upstream_calls += 1
            response = dns_wire.build_response_for_query(
                query, self._canned_answers(parsed)
            )
            ipc.send_frame(
                self._dns,
                ipc.encode_dns_response(protocol, ipc.STATUS_OK, response),
            )

    @staticmethod
    def _canned_answers(parsed: dns_wire.DnsQuery):
        if parsed.qtype == DNS_TYPE_CNAME:
            return [(parsed.name, DNS_TYPE_CNAME, "target.acme.example")]
        if parsed.qtype == DNS_TYPE_AAAA:
            return [(parsed.name, DNS_TYPE_AAAA, "2001:db8::7")]
        return [(parsed.name, DNS_TYPE_A, "203.0.113.7")]


def _free_loopback_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def _default_src_path() -> str:
    # .../src/red_teaming/recon/netns_selftest.py -> .../src
    return os.fspath(Path(__file__).resolve().parents[2])


def run_self_test(
    *,
    src_path: Optional[str] = None,
    http_port: Optional[int] = None,
    dns_port: int = netpolicy.UPSTREAM_DNS_PORT,
    deadline: float = _DEFAULT_TIMEOUT,
    policy=RECON_002_POLICY,
) -> SelfTestReport:
    """Run the local-only namespace self-test and return a structured report."""

    if not sandbox_supported():
        return SelfTestReport(
            supported=False,
            passed=False,
            reason="unsupported_platform",
            checks={"platform": sys.platform},
        )

    if src_path is None:
        src_path = _default_src_path()
    if http_port is None:
        http_port = _free_loopback_port()

    connect_parent, connect_child = socket.socketpair()
    dns_parent, dns_child = socket.socketpair()
    status_parent, status_child = socket.socketpair()

    broker = FakeBroker(connect_parent, dns_parent, policy=policy).start()
    checks: dict = {}
    reason: Optional[str] = None

    config = SandboxConfig(
        connect_fd=connect_child.fileno(),
        dns_fd=dns_child.fileno(),
        status_fd=status_child.fileno(),
        http_port=http_port,
        dns_port=dns_port,
        mode="selftest",
        src_path=src_path,
    )

    proc = None
    try:
        proc = launch_helper(config)
    except Exception as exc:
        broker.stop()
        for sock in (connect_parent, connect_child, dns_parent, dns_child, status_parent, status_child):
            try:
                sock.close()
            except OSError:
                pass
        return SelfTestReport(
            supported=True,
            passed=False,
            reason=f"launch_failed:{type(exc).__name__}",
        )
    finally:
        for sock in (connect_child, dns_child, status_child):
            try:
                sock.close()
            except OSError:
                pass

    status_parent.settimeout(0.5)
    started = time.monotonic()
    try:
        while True:
            if time.monotonic() - started > deadline:
                reason = "timeout"
                break
            try:
                payload = ipc.recv_frame(status_parent)
            except socket.timeout:
                if proc.poll() is not None:
                    reason = f"helper_exited:{proc.returncode}"
                    break
                continue
            except ipc.IpcClosed:
                reason = "helper_closed_status"
                break
            if payload is None:
                reason = "helper_closed_status"
                break
            try:
                event = ipc.decode_status_event(payload)
            except ipc.IpcProtocolError:
                continue
            if event.get("event") == "done":
                checks = {k: v for k, v in event.items() if k != "event"}
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except Exception:
                proc.kill()
        broker.stop()
        for sock in (connect_parent, dns_parent, status_parent):
            try:
                sock.close()
            except OSError:
                pass

    counters = broker.counters
    passed = bool(checks.get("passed")) and reason is None
    return SelfTestReport(
        supported=True,
        passed=passed,
        reason=reason,
        checks=checks,
        broker=counters,
    )


def main(argv: object = None) -> int:
    parser = argparse.ArgumentParser(
        prog="red_teaming.recon.netns_selftest",
        description="Local-only RECON-002 namespace sandbox self-test",
    )
    parser.add_argument("--src-path", default=None)
    parser.add_argument("--http-port", type=int, default=None)
    parser.add_argument("--dns-port", type=int, default=netpolicy.UPSTREAM_DNS_PORT)
    parser.add_argument("--deadline", type=float, default=_DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    report = run_self_test(
        src_path=args.src_path,
        http_port=args.http_port,
        dns_port=args.dns_port,
        deadline=args.deadline,
    )
    sys.stdout.write(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover - module entry
    raise SystemExit(main())
