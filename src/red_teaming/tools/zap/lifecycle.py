"""Offline-testable daemon identity and local-inspection primitives.

This module contains only pure data types and parsing/matching logic used to
distinguish an Install4j ``ZAP.exe`` launcher from the detached JVM daemon it
spawns. It never opens a socket, starts a process, or imports a platform
facility at import time.

The Windows-specific, PowerShell-backed implementation lives in
:mod:`red_teaming.tools.zap.smoke` (``PowerShellLocalInspector``) so this module
stays importable and fully fake-able for tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Protocol

__all__ = [
    "ConnectionRecord",
    "DaemonIdentity",
    "IdentityResult",
    "LifecycleSystem",
    "ProcessRecord",
    "SystemSnapshot",
    "command_line_has_dir",
    "connections_for_pid",
    "reverify_daemon_identity",
    "scope_snapshot",
    "split_command_line",
    "verify_daemon_identity",
]

_LISTEN_STATES = frozenset({"listen", "listening", "bound"})

#: Inspection method sentinels that mean the observation is unavailable.
_UNAVAILABLE_METHODS = frozenset(
    {"", "unavailable", "get-nettcpconnection-unavailable", "get-ciminstance-unavailable"}
)

#: Inspection methods that do *not* include a process enumeration. ``netstat``
#: only yields TCP endpoints, and the ``*-unavailable`` sentinels mean the
#: corresponding observation failed. Absence of a specific process can only be
#: asserted from a snapshot whose method actually enumerated processes.
_PROCESS_OBSERVATION_UNAVAILABLE_METHODS = frozenset(
    {"", "unavailable", "get-ciminstance-unavailable", "netstat"}
)


def _is_int_like(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _is_listening_state(state: Any) -> bool:
    return str(state or "").strip().lower() in _LISTEN_STATES


def split_command_line(command_line: str) -> list[str]:
    """Split a Windows command line into arguments.

    Implements the ``CommandLineToArgvW``-style rules closely enough for daemon
    identity matching: double quotes group tokens, and backslashes immediately
    preceding a quote are treated as escapes. A path containing spaces may be
    quoted and still parses to the unquoted value.
    """

    if not isinstance(command_line, str) or not command_line:
        return []

    args: list[str] = []
    index = 0
    length = len(command_line)
    while index < length:
        while index < length and command_line[index] in " \t":
            index += 1
        if index >= length:
            break

        buffer: list[str] = []
        in_quotes = False
        while index < length:
            char = command_line[index]
            if char == "\\":
                run_start = index
                while index < length and command_line[index] == "\\":
                    index += 1
                backslashes = index - run_start
                if index < length and command_line[index] == '"':
                    buffer.append("\\" * (backslashes // 2))
                    if backslashes % 2 == 1:
                        buffer.append('"')
                    else:
                        in_quotes = not in_quotes
                    index += 1
                else:
                    buffer.append("\\" * backslashes)
                continue
            if char == '"':
                in_quotes = not in_quotes
                index += 1
                continue
            if char in " \t" and not in_quotes:
                break
            buffer.append(char)
            index += 1

        args.append("".join(buffer))

    return args


def _normalize_path(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    return os.path.normcase(os.path.normpath(text))


def command_line_has_dir(command_line: str, zap_home: Any) -> bool:
    """Return True when *command_line* carries the exact ``-dir <zap_home>`` arg.

    Matching is argument-bounded and normalized: the ``-dir`` value must equal
    the canonical per-run zap-home path exactly, so a sibling path that merely
    shares a prefix (or a substring) never matches. Windows quoting around a
    path with spaces is tolerated.
    """

    target = _normalize_path(zap_home)
    if not target:
        return False
    args = split_command_line(command_line)
    for position, arg in enumerate(args):
        lowered = arg.lower()
        if lowered == "-dir":
            if position + 1 < len(args) and _normalize_path(args[position + 1]) == target:
                return True
        elif lowered.startswith("-dir="):
            if _normalize_path(arg[len("-dir="):]) == target:
                return True
    return False


@dataclass(frozen=True)
class ProcessRecord:
    """A read-only snapshot record for one OS process."""

    pid: int
    parent_pid: Optional[int] = None
    name: str = ""
    command_line: str = ""
    executable_path: Optional[str] = None
    creation_time: Optional[float] = None

    def to_evidence(self, *, redact: Any = None) -> dict:
        command_line = self.command_line
        if callable(redact):
            command_line = redact(command_line)
        return {
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "name": self.name,
            "command_line": command_line,
            "executable_path": self.executable_path,
            "creation_time": self.creation_time,
        }


@dataclass(frozen=True)
class ConnectionRecord:
    """A read-only snapshot record for one TCP endpoint."""

    local_address: str = ""
    local_port: Optional[int] = None
    remote_address: str = ""
    remote_port: Optional[int] = None
    state: str = ""
    pid: Optional[int] = None

    @property
    def is_listening(self) -> bool:
        return _is_listening_state(self.state)

    def to_evidence(self) -> dict:
        return {
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
        }


@dataclass(frozen=True)
class SystemSnapshot:
    """A read-only local process/TCP observation."""

    method: Optional[str] = None
    processes: tuple[ProcessRecord, ...] = ()
    connections: tuple[ConnectionRecord, ...] = ()
    error: Optional[str] = None

    @property
    def observation_available(self) -> bool:
        method = str(self.method or "").strip().lower()
        return method not in _UNAVAILABLE_METHODS

    @property
    def process_observation_available(self) -> bool:
        """Whether this snapshot actually enumerated OS processes.

        An empty process list from a process-capable method still proves that a
        specific PID is absent; a connection-only fallback (``netstat``) does
        not. Callers that assert a process is gone must require this to be
        ``True`` and fail closed otherwise.
        """

        if self.processes:
            # Any captured process record proves an enumeration happened, even
            # when the snapshot's method was overwritten by a connection-only
            # fallback.
            return True
        method = str(self.method or "").strip().lower()
        return method not in _PROCESS_OBSERVATION_UNAVAILABLE_METHODS

    def process(self, pid: Optional[int]) -> Optional[ProcessRecord]:
        if not _is_int_like(pid):
            return None
        for record in self.processes:
            if record.pid == pid:
                return record
        return None

    def listeners(self) -> tuple[ConnectionRecord, ...]:
        return tuple(record for record in self.connections if record.is_listening)

    def connections_for_pid(self, pid: Optional[int]) -> tuple[ConnectionRecord, ...]:
        if not _is_int_like(pid):
            return ()
        return tuple(record for record in self.connections if record.pid == pid)

    def listener_ports(self) -> set[int]:
        ports: set[int] = set()
        for record in self.connections:
            if record.is_listening and _is_int_like(record.local_port):
                ports.add(int(record.local_port))
        return ports

    def has_listener_on(self, port: Optional[int]) -> bool:
        return _is_int_like(port) and any(
            record.is_listening and record.local_port == port
            for record in self.connections
        )

    def to_evidence(self, *, redact: Any = None) -> dict:
        return {
            "method": self.method,
            "observation_available": self.observation_available,
            "process_observation_available": self.process_observation_available,
            "processes": [
                record.to_evidence(redact=redact) for record in self.processes
            ],
            "connections": [record.to_evidence() for record in self.connections],
            "listener_ports": sorted(self.listener_ports()),
            "error": self.error,
        }


@dataclass(frozen=True)
class DaemonIdentity:
    """A verified daemon identity for one run."""

    pid: int
    api_port: int
    parent_pid: Optional[int] = None
    name: str = ""
    command_line: str = ""
    executable_path: Optional[str] = None
    creation_time: Optional[float] = None
    parent_matched: bool = False

    def to_evidence(self, *, redact: Any = None) -> dict:
        command_line = self.command_line
        if callable(redact):
            command_line = redact(command_line)
        return {
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "name": self.name,
            "command_line": command_line,
            "executable_path": self.executable_path,
            "creation_time": self.creation_time,
            "api_port": self.api_port,
            "parent_matched": self.parent_matched,
        }


@dataclass(frozen=True)
class IdentityResult:
    """The outcome of daemon identity verification."""

    status: str
    identity: Optional[DaemonIdentity] = None
    candidate_pids: tuple[int, ...] = ()
    owner_pids: tuple[int, ...] = ()
    reason: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "verified" and self.identity is not None

    def to_evidence(self, *, redact: Any = None) -> dict:
        identity = self.identity.to_evidence(redact=redact) if self.identity else None
        return {
            "status": self.status,
            "verified": self.verified,
            "candidate_pids": list(self.candidate_pids),
            "owner_pids": list(self.owner_pids),
            "reason": self.reason,
            "identity": identity,
        }


def verify_daemon_identity(
    snapshot: SystemSnapshot,
    *,
    zap_home: Any,
    api_port: int,
    launcher_pid: Optional[int] = None,
    launched_after: Optional[float] = None,
    creation_tolerance: float = 2.0,
) -> IdentityResult:
    """Verify the single daemon that belongs to this run, failing closed.

    A candidate is only valid when *all* of the following hold:

    * it owns a listening socket on ``api_port``;
    * its command line carries the exact canonical ``-dir <zap_home>`` argument
      (argument-bounded, never a prefix/substring match);
    * its creation metadata is consistent with this launch (present and not
      older than ``launched_after``, within ``creation_tolerance``).

    Zero, multiple, or mismatched candidates never yield a verified identity.
    """

    if not isinstance(snapshot, SystemSnapshot):
        return IdentityResult(
            "unavailable", reason="no local inspection snapshot was produced"
        )
    if not snapshot.observation_available:
        return IdentityResult(
            "unavailable", reason="local listener observation is unavailable"
        )

    owners = tuple(
        sorted(
            {
                int(record.pid)
                for record in snapshot.connections
                if record.local_port == api_port
                and record.is_listening
                and _is_int_like(record.pid)
            }
        )
    )
    if not owners:
        return IdentityResult(
            "absent",
            owner_pids=(),
            reason=f"no process owns a listening socket on API port {api_port}",
        )

    candidates: list[tuple[ProcessRecord, bool]] = []
    rejections: list[str] = []
    for pid in owners:
        record = snapshot.process(pid)
        if record is None:
            rejections.append(f"{pid}: no matching process metadata")
            continue
        if not command_line_has_dir(record.command_line, zap_home):
            rejections.append(f"{pid}: command line lacks the exact -dir marker")
            continue
        if launched_after is not None:
            if record.creation_time is None:
                rejections.append(f"{pid}: creation time is unavailable")
                continue
            if record.creation_time < launched_after - creation_tolerance:
                rejections.append(f"{pid}: stale/PID-reused creation time")
                continue
        parent_matched = (
            launcher_pid is not None and record.parent_pid == launcher_pid
        )
        candidates.append((record, parent_matched))

    if len(candidates) == 1:
        record, parent_matched = candidates[0]
        identity = DaemonIdentity(
            pid=record.pid,
            api_port=api_port,
            parent_pid=record.parent_pid,
            name=record.name,
            command_line=record.command_line,
            executable_path=record.executable_path,
            creation_time=record.creation_time,
            parent_matched=parent_matched,
        )
        return IdentityResult(
            "verified",
            identity=identity,
            candidate_pids=(record.pid,),
            owner_pids=owners,
            reason=(
                "exactly one API-port owner carries the exact -dir marker and "
                "consistent creation metadata"
            ),
        )

    if len(candidates) > 1:
        return IdentityResult(
            "ambiguous",
            candidate_pids=tuple(record.pid for record, _ in candidates),
            owner_pids=owners,
            reason=(
                f"{len(candidates)} API-port owners carry the exact -dir marker; "
                "daemon identity is ambiguous"
            ),
        )

    return IdentityResult(
        "mismatched",
        owner_pids=owners,
        reason="; ".join(rejections[:10]) or "no valid daemon candidate",
    )


def reverify_daemon_identity(
    snapshot: SystemSnapshot,
    identity: DaemonIdentity,
    *,
    zap_home: Any,
    creation_tolerance: float = 2.0,
) -> IdentityResult:
    """Reconfirm a *previously verified* identity after the API listener closed.

    Once a daemon identity has been verified for the run, a later snapshot may
    no longer show it owning the API port (for example after the API listener
    has been closed during shutdown while the JVM is still alive). This helper
    safely re-identifies that same daemon without requiring continued API-port
    ownership, using:

    * the same PID;
    * the exact canonical ``-dir <zap_home>`` argument;
    * unchanged creation metadata (creation time within ``creation_tolerance``
      and the recorded parent where available);
    * the recorded executable path and process name where available.

    It fails closed on PID reuse, a changed command line or path, and
    absent/ambiguous/unavailable process metadata. It never looks up or adopts a
    different PID.
    """

    if not isinstance(snapshot, SystemSnapshot):
        return IdentityResult(
            "unavailable", reason="no local inspection snapshot was produced"
        )
    if not snapshot.process_observation_available:
        return IdentityResult(
            "unavailable",
            reason="process observation is unavailable; cannot reconfirm identity",
        )

    record = snapshot.process(identity.pid)
    if record is None:
        return IdentityResult(
            "absent",
            reason=f"previously verified daemon process {identity.pid} is absent",
        )

    if not command_line_has_dir(record.command_line, zap_home):
        return IdentityResult(
            "mismatched",
            reason="command line no longer carries the exact -dir marker",
        )

    if identity.creation_time is None or record.creation_time is None:
        return IdentityResult(
            "mismatched",
            reason="creation metadata is unavailable; refusing to reconfirm",
        )
    if abs(record.creation_time - identity.creation_time) > creation_tolerance:
        return IdentityResult(
            "mismatched",
            reason="creation time changed (possible PID reuse)",
        )

    if identity.parent_pid is not None and record.parent_pid != identity.parent_pid:
        return IdentityResult(
            "mismatched",
            reason="parent identity changed (possible PID reuse)",
        )

    if identity.executable_path and record.executable_path != identity.executable_path:
        return IdentityResult(
            "mismatched",
            reason="executable path changed",
        )
    if identity.name and record.name != identity.name:
        return IdentityResult(
            "mismatched",
            reason="process name changed",
        )

    reconfirmed = DaemonIdentity(
        pid=identity.pid,
        api_port=identity.api_port,
        parent_pid=record.parent_pid,
        name=record.name or identity.name,
        command_line=record.command_line,
        executable_path=record.executable_path or identity.executable_path,
        creation_time=record.creation_time,
        parent_matched=identity.parent_matched,
    )
    return IdentityResult(
        "verified",
        identity=reconfirmed,
        candidate_pids=(identity.pid,),
        owner_pids=(identity.pid,),
        reason=(
            "previously verified identity reconfirmed by PID, exact -dir, and "
            "unchanged creation metadata"
        ),
    )


def relevant_pids(
    snapshot: SystemSnapshot,
    *,
    api_port: Optional[int] = None,
    callback_port: Optional[int] = None,
    extra_pids: Iterable[Optional[int]] = (),
) -> set[int]:
    """Return the bounded set of PIDs relevant to the two fixed ports.

    The result is the union of any supplied ``extra_pids`` (for example the
    launcher and verified daemon) and the owners of listeners/connections on the
    API and callback ports. Only strictly positive process IDs are admitted: a
    fixed-port record with PID ``0`` (or any non-positive/absent owner) is a
    kernel/system placeholder such as a ``TIME_WAIT`` endpoint and must never
    pull unrelated PID-0 system records into a scoped snapshot. It never
    includes unrelated system processes.
    """

    pids: set[int] = set()
    for pid in extra_pids:
        if _is_int_like(pid) and int(pid) > 0:
            pids.add(int(pid))
    fixed = {port for port in (api_port, callback_port) if _is_int_like(port)}
    for record in snapshot.connections:
        if (
            record.local_port in fixed
            and _is_int_like(record.pid)
            and int(record.pid) > 0
        ):
            pids.add(int(record.pid))
    return pids


def scope_snapshot(
    snapshot: SystemSnapshot,
    *,
    api_port: Optional[int] = None,
    callback_port: Optional[int] = None,
    extra_pids: Iterable[Optional[int]] = (),
) -> SystemSnapshot:
    """Return a bounded copy of *snapshot* with unrelated process data removed.

    Only process records for :func:`relevant_pids` are retained, and only
    connections owned by those PIDs or bound to the two fixed ports. This keeps
    command lines and endpoints of unrelated system processes out of persisted
    evidence while preserving the records needed for verification.
    """

    pids = relevant_pids(
        snapshot,
        api_port=api_port,
        callback_port=callback_port,
        extra_pids=extra_pids,
    )
    fixed = {port for port in (api_port, callback_port) if _is_int_like(port)}
    connections = tuple(
        record
        for record in snapshot.connections
        if record.pid in pids or record.local_port in fixed
    )
    processes = tuple(record for record in snapshot.processes if record.pid in pids)
    return SystemSnapshot(
        method=snapshot.method,
        processes=processes,
        connections=connections,
        error=snapshot.error,
    )


def connections_for_pid(
    snapshot: SystemSnapshot, pid: Optional[int]
) -> tuple[ConnectionRecord, ...]:
    """Return every TCP record owned by *pid* (empty when unavailable)."""

    return snapshot.connections_for_pid(pid)


class LifecycleSystem(Protocol):
    """Read-only inspection plus identity-scoped process control.

    Implementations must never mutate system configuration. ``terminate`` and
    ``kill`` are expected to be called only by the manager, and only after the
    target PID has been re-verified as this run's daemon.
    """

    def snapshot(self) -> SystemSnapshot:
        """Return one read-only local process/TCP observation."""

    def terminate(self, pid: int) -> None:
        """Request a graceful process termination for an already-verified pid."""

    def kill(self, pid: int) -> None:
        """Forcefully stop an already-verified pid."""
