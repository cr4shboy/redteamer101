"""Local-only OWASP ZAP daemon health smoke component.

This module implements the narrowly authorized *tool-health* smoke test: start
the already-installed ZAP daemon once, bound to ``127.0.0.1`` on an explicit
local port, confirm the version over the loopback API, shut it down gracefully,
verify process exit, and persist Markdown + JSON evidence beneath the explicit
per-run directory.

Strict boundaries enforced here:

* the only API operations that can reach the wire are ``core/view/version``
  and ``core/action/shutdown`` -- :class:`AllowlistedTransport` rejects any
  other component/operation/path, any query string, and any endpoint that is
  not exactly ``127.0.0.1`` *before* the request is sent;
* there is no target URL, no scan API, no browser, and no report API;
* the daemon runs keyless and offline-hardened, with its own outbound proxy
  pointed at a closed loopback guard port;
* every attempted API call is recorded (path only, never a query or secret)
  with a timestamp, status, and redacted error;
* a planned state is written before launch and final evidence is written on
  every outcome, including pre-launch blockers.

Everything is standard-library only, and the clock, port checker, local
inspector, API client, and process manager are injectable so the whole flow is
exercised offline with fakes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit

from ...orchestration.state import atomic_write_json
from ...projects.paths import ScanPath
from .client import UrllibTransport, ZapApiClient
from .lifecycle import (
    ConnectionRecord,
    LifecycleSystem,
    ProcessRecord,
    SystemSnapshot,
    scope_snapshot,
)
from .models import (
    DEFAULT_API_TIMEOUT,
    DEFAULT_MIN_ZAP_VERSION,
    ZapConfigError,
    ZapEndpoint,
    ZapError,
    redact_secret,
    version_at_least,
)
from .process import (
    DEFAULT_GRACEFUL_TIMEOUT,
    DEFAULT_KILL_TIMEOUT,
    DEFAULT_OAST_CALLBACK_PORT,
    DEFAULT_OFFLINE_GUARD_HOST,
    DEFAULT_OFFLINE_GUARD_PORT,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_STARTUP_TIMEOUT,
    DEFAULT_TERMINATE_TIMEOUT,
    OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR,
    OFFLINE_CONFIG_OAST_CALLBACK_PORT,
    OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR,
    ZapProcessManager,
)

__all__ = [
    "ALLOWED_OPERATIONS",
    "ApiCallRecorder",
    "AllowlistedTransport",
    "EXACT_BIND_HOST",
    "OAST_CALLBACK_ADDON",
    "OAST_CALLBACK_ADDON_VERSION",
    "OAST_CALLBACK_VERIFICATION_SOURCES",
    "OAST_CALLBACK_VERIFIED_KEYS",
    "PowerShellLocalInspector",
    "SMOKE_JSON_FILENAME",
    "SMOKE_MARKDOWN_FILENAME",
    "SMOKE_STATE_FILENAME",
    "SCHEMA_VERSION",
    "SmokeAllowlistError",
    "SmokeConfigurationError",
    "SmokeInspectionCapabilityError",
    "SmokePortInUseError",
    "SmokeProcessControlError",
    "ZapSmokeRunner",
    "analyze_inspection",
    "check_port_free",
    "inspect_artifacts",
    "render_markdown",
]

#: Evidence schema version. Bumped to 2 when the detached-daemon lifecycle,
#: per-listener containment, and preflight gates were added.
SCHEMA_VERSION = 2

SMOKE_JSON_FILENAME = "zap-daemon-smoke.json"
SMOKE_MARKDOWN_FILENAME = "ZAP_DAEMON_SMOKE.md"
SMOKE_STATE_FILENAME = "smoke-state.json"

EXACT_BIND_HOST = "127.0.0.1"

#: Static, deterministic provenance for the OAST callback ``-config`` keys.
#: These three keys were verified *read-only* from the installed OAST 0.24.0
#: add-on before this work package; the verification is recorded once and the
#: installed tool/add-on is never inspected or modified again at runtime.
OAST_CALLBACK_ADDON = "OAST"
OAST_CALLBACK_ADDON_VERSION = "0.24.0"
OAST_CALLBACK_VERIFICATION_SOURCES = (
    "CallbackParam bytecode",
    "embedded help",
)
OAST_CALLBACK_VERIFIED_KEYS = (
    OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR,
    OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR,
    OFFLINE_CONFIG_OAST_CALLBACK_PORT,
)

#: The complete set of ZAP API component/kind/operation triples the smoke may
#: ever call. Any other triple is rejected before it can be sent.
ALLOWED_OPERATIONS = frozenset(
    {
        ("core", "view", "version"),
        ("core", "action", "shutdown"),
    }
)

#: Components that would indicate scan activity. The allowlist makes these
#: unreachable; the count is still computed and recorded as a hard check.
SCAN_COMPONENTS = frozenset(
    {"spider", "ajaxSpider", "ascan", "pscan", "search", "ajaxspider"}
)

_MAX_LOG_BYTES = 2_000_000
_MAX_ERROR_EXCERPTS = 50
_MAX_EXCERPT_CHARS = 300
#: Hard bound on the continuation lines folded into a single error incident.
#: ``at ...`` stack frames are grouped under their ERROR/FATAL anchor rather
#: than each becoming its own record.
_MAX_INCIDENT_LINES = 20

#: The complete, explicit allowlist of runtime files the artifact inspection
#: may content-scan. Each entry is ``relative_path -> kind`` where ``kind`` is
#: ``"log"`` or ``"config"``. Bundled assets (browser extensions, JavaScript,
#: wordlists, fuzzers, HUD libraries, add-ons, script templates, jars, and any
#: other ``zap-home`` content) are never scanned.
_ARTIFACT_ALLOWLIST: tuple[tuple[str, str], ...] = (
    ("logs/zap-stdout.log", "log"),
    ("logs/zap-stderr.log", "log"),
    ("zap-home/zap.log", "log"),
    ("zap-home/config.xml", "config"),
)

_ARTIFACT_METHOD = "allowlisted runtime-file content scan (read-only)"

#: Context-specific API authorization secret patterns. Each entry is
#: ``(kind, compiled_pattern, applicable_file_kinds)``. The patterns are only
#: applied to allowlisted runtime files -- never to bundled assets -- and are
#: intentionally narrow so ordinary text is not misclassified as a secret.
_KEY_MATERIAL_PATTERNS = (
    (
        "api.key",
        re.compile(r"(api\.key\s*[=:]\s*)([^\s\"'<>]+)", re.IGNORECASE),
        ("log", "config"),
    ),
    (
        "apikey",
        re.compile(r"([?&]apikey=)([^\s\"'&<>]+)", re.IGNORECASE),
        ("log", "config"),
    ),
    (
        "config.key",
        re.compile(r"(<key>)([^<\r\n]+)", re.IGNORECASE),
        ("config",),
    ),
)

#: A runtime log level token. Matched case-sensitively so ordinary prose such
#: as ``"no error"`` is never promoted to an ERROR finding.
_ERROR_LEVEL_RE = re.compile(r"\b(?:ERROR|FATAL)\b")

#: Exception/stacktrace context: a class-name-shaped ``*Exception``/``*Error``
#: token, a Python/Java stack frame, or an explicit cause marker. Used only to
#: fold *continuation* lines into an open ERROR/FATAL incident -- it never
#: classifies a line as an error on its own. Bare prose containing ``error``
#: does not match.
_STACKTRACE_CONTEXT_RE = re.compile(
    r"(Traceback \(most recent call last\)"
    r"|\bCaused by:"
    r"|\b[\w.$]+(?:Exception|Error)\b"
    r'|^\s*File \".*\", line \d+'
    r"|^\s*at\s+[^\s(]+\()",
    re.IGNORECASE | re.MULTILINE,
)


class SmokeConfigurationError(ZapError, ValueError):
    """The smoke component was configured with an invalid value."""


class SmokeAllowlistError(ZapError):
    """A request was rejected by the strict API allowlist before sending."""


class SmokeInspectionCapabilityError(ZapError):
    """Local process/TCP inspection is unavailable, so no launch is permitted.

    The smoke takes one read-only inspection snapshot before *any* launch and
    requires both process enumeration and TCP observation to be available. When
    either is missing the run fails preflight and no manager is constructed.
    """


class SmokePortInUseError(ZapError):
    """The explicit local port was already occupied before launch."""


class SmokeProcessControlError(ZapError):
    """A bounded, identity-scoped process control command failed.

    Raised when the ``Stop-Process`` control command returns a nonzero exit
    code, so a failed control action is never silently counted as success. The
    message is bounded and contains only the action name and exit code.
    """


# ---------------------------------------------------------------------------
# Strict API allowlist
# ---------------------------------------------------------------------------


class ApiCallRecorder:
    """Ordered, secret-free record of every attempted API call."""

    def __init__(self, now: Callable[[], str]) -> None:
        self._now = now
        self.calls: list[dict] = []

    def record(
        self,
        attempt: Mapping[str, Any],
        *,
        status: Optional[int],
        error: Optional[str],
    ) -> None:
        entry: dict[str, Any] = {
            "timestamp": self._now(),
            "component": attempt.get("component"),
            "operation": attempt.get("operation"),
            "kind": attempt.get("kind"),
            "path": attempt.get("path"),
            "allowed": bool(attempt.get("allowed")),
            "status": status,
            "error": error,
        }
        if not entry["allowed"] and attempt.get("reason"):
            entry["reason"] = attempt["reason"]
        self.calls.append(entry)


class AllowlistedTransport:
    """Transport wrapper enforcing the smoke's exact API allowlist.

    A request is classified from its URL *before* the inner transport is
    touched. Only ``core/view/version`` and ``core/action/shutdown`` on exactly
    ``127.0.0.1`` with no query string are allowed. Every attempt -- allowed or
    rejected -- is recorded by :class:`ApiCallRecorder`; only the path is
    stored, never a query string or any secret.
    """

    def __init__(
        self,
        inner: Any,
        *,
        endpoint: ZapEndpoint,
        recorder: ApiCallRecorder,
        allowed_operations: Iterable[tuple[str, str, str]] = ALLOWED_OPERATIONS,
    ) -> None:
        if not isinstance(endpoint, ZapEndpoint):
            raise SmokeConfigurationError("endpoint must be a ZapEndpoint")
        if endpoint.host != EXACT_BIND_HOST:
            raise SmokeConfigurationError(
                "the smoke allowlist requires the exact 127.0.0.1 endpoint"
            )
        if not hasattr(inner, "request"):
            raise SmokeConfigurationError("inner transport must expose request()")
        if not isinstance(recorder, ApiCallRecorder):
            raise SmokeConfigurationError("recorder must be an ApiCallRecorder")

        self._inner = inner
        self._endpoint = endpoint
        self._recorder = recorder
        self._allowed = frozenset(allowed_operations)

    @property
    def endpoint(self) -> ZapEndpoint:
        return self._endpoint

    def _classify(self, url: str) -> dict:
        info: dict[str, Any] = {
            "component": None,
            "operation": None,
            "kind": None,
            "path": None,
            "allowed": False,
            "reason": None,
        }

        try:
            parts = urlsplit(url)
        except ValueError:
            info["reason"] = "malformed URL"
            return info

        info["path"] = parts.path or None

        if parts.scheme.lower() not in ("http", "https"):
            info["reason"] = "unsupported scheme"
            return info
        if parts.hostname != EXACT_BIND_HOST:
            info["reason"] = "endpoint host is not exactly 127.0.0.1"
            return info
        try:
            port = parts.port
        except ValueError:
            info["reason"] = "invalid endpoint port"
            return info
        if port != self._endpoint.port:
            info["reason"] = "endpoint port does not match the smoke endpoint"
            return info

        # Capture the component/kind/operation first so a rejected attempt is
        # still identifiable in the evidence, then enforce the allowlist.
        segments = [segment for segment in (parts.path or "").split("/") if segment]
        if len(segments) != 4 or segments[0].upper() != "JSON":
            info["reason"] = "path is not a ZAP JSON API path"
            return info

        component, kind, operation = segments[1], segments[2], segments[3]
        info["component"] = component
        info["kind"] = kind
        info["operation"] = operation

        if parts.query:
            info["reason"] = "query parameters are not allowed for this operation"
            return info
        if (component, kind, operation) not in self._allowed:
            info["reason"] = "API operation is not allowlisted"
            return info

        info["allowed"] = True
        return info

    def request(self, method: str, url: str, timeout: float):
        attempt = self._classify(url)
        if not attempt["allowed"]:
            self._recorder.record(
                attempt, status=None, error=str(attempt["reason"])
            )
            raise SmokeAllowlistError(
                f"refusing non-allowlisted ZAP API request: {attempt['reason']}"
            )

        try:
            response = self._inner.request(method, url, timeout)
        except Exception as exc:
            self._recorder.record(
                attempt,
                status=None,
                error=f"{type(exc).__name__}: {redact_secret(str(exc), '')}",
            )
            raise

        self._recorder.record(
            attempt, status=getattr(response, "status", None), error=None
        )
        return response


# ---------------------------------------------------------------------------
# Read-only local inspection
# ---------------------------------------------------------------------------


def _parse_ip(value: Any):
    if not isinstance(value, str) or not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_listening(connection: Mapping[str, Any]) -> bool:
    state = str(connection.get("state") or "").strip().lower()
    return state in ("listen", "listening", "bound")


#: Recognized established-state token. ``Get-NetTCPConnection`` emits
#: ``Established`` while ``netstat -ano`` emits ``ESTABLISHED``; both normalize
#: to this token, so the comparison tolerates the casing (and any separator)
#: produced by the supported Windows inspection paths.
_ESTABLISHED_STATE = "established"


def _is_established_state(state: Any) -> bool:
    """Return True only for an established TCP connection state."""

    normalized = re.sub(r"[^a-z]", "", str(state or "").lower())
    return normalized == _ESTABLISHED_STATE


def _is_active_external(connection: Mapping[str, Any]) -> bool:
    """Return True for an observed non-loopback *established* connection.

    Only a live established connection counts as active external traffic. A
    historical or closing state -- ``TimeWait``/``TIME_WAIT``, ``CloseWait``,
    ``FinWait*``, ``SynSent``, and similar -- describes a session that has
    already ended or is ending, so it must never be misclassified as active
    external traffic. Listeners and loopback/unspecified remote addresses keep
    their existing non-external semantics.
    """

    if _is_listening(connection):
        return False
    if not _is_established_state(connection.get("state")):
        return False
    address = _parse_ip(connection.get("remote_address"))
    if address is None:
        return False
    return not (address.is_loopback or address.is_unspecified)


def _split_endpoint(value: str) -> tuple[str, Optional[int]]:
    """Split ``host:port`` / ``[v6]:port`` into its components."""

    if not value:
        return value, None
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        rest = rest.lstrip(":")
        try:
            return host, int(rest)
        except ValueError:
            return host, None
    host, separator, port = value.rpartition(":")
    if not separator:
        return value, None
    try:
        return host, int(port)
    except ValueError:
        return value, None


def _parse_netstat(text: str, pids: set[int]) -> list[dict]:
    connections: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "TCPV6"):
            continue
        local, remote, state, pid_text = parts[1], parts[2], parts[3], parts[4]
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        if pids and pid not in pids:
            continue
        local_address, local_port = _split_endpoint(local)
        remote_address, remote_port = _split_endpoint(remote)
        connections.append(
            {
                "local_address": local_address,
                "local_port": local_port,
                "remote_address": remote_address,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
            }
        )
    return connections


def analyze_inspection(raw: Mapping[str, Any]) -> dict:
    """Derive listener/external-traffic conclusions from raw inspection data.

    ``observation_available`` is an explicit indicator that a real local
    listener/connection inspection actually produced usable observations. It is
    False when no inspection was captured or when the inspection method was
    unavailable, so callers can avoid reporting an unobserved
    "no external connections" conclusion as verified.
    """

    connections = list(raw.get("connections") or [])
    port = raw.get("port")
    callback_port = raw.get("callback_port")

    method = raw.get("method")
    observation_available = bool(
        isinstance(method, str)
        and method
        and method not in ("Get-NetTCPConnection-unavailable", "unavailable")
    )

    listeners = [
        connection
        for connection in connections
        if _is_listening(connection) and connection.get("local_port") == port
    ]
    listener_addresses = sorted(
        {str(connection.get("local_address")) for connection in listeners}
    )
    listener_ok = bool(listener_addresses) and all(
        address == EXACT_BIND_HOST for address in listener_addresses
    )

    # Broad containment: every listener owned by the verified daemon, on any
    # port, must be loopback-only. A wildcard listener on any daemon-owned port
    # fails this check even when the API listener itself is loopback-only.
    all_listeners = [
        connection for connection in connections if _is_listening(connection)
    ]
    all_listener_addresses = sorted(
        {str(connection.get("local_address")) for connection in all_listeners}
    )
    all_listener_ok = bool(all_listener_addresses) and all(
        address == EXACT_BIND_HOST for address in all_listener_addresses
    )

    callback_listeners = [
        connection
        for connection in connections
        if _is_listening(connection)
        and callback_port is not None
        and connection.get("local_port") == callback_port
    ]
    callback_addresses = sorted(
        {str(connection.get("local_address")) for connection in callback_listeners}
    )
    # Callback containment acceptance requires at least one callback listener on
    # the fixed callback port *and* every one of them to be loopback-only. An
    # empty listener set is not vacuously contained.
    callback_ok = bool(callback_addresses) and all(
        address == EXACT_BIND_HOST for address in callback_addresses
    )

    external = [connection for connection in connections if _is_active_external(connection)]

    result = dict(raw)
    result["listeners"] = listeners
    result["listener_local_addresses"] = listener_addresses
    result["listener_loopback_only"] = listener_ok
    result["api_listener_loopback_only"] = listener_ok
    result["all_listeners"] = all_listeners
    result["all_listener_local_addresses"] = all_listener_addresses
    result["all_listener_loopback_only"] = all_listener_ok
    result["callback_listeners"] = callback_listeners
    result["callback_listener_loopback_only"] = callback_ok
    result["non_loopback_connections"] = external
    result["non_loopback_connection_count"] = len(external)
    result["observation_available"] = observation_available
    return result


_PS_SNAPSHOT_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$method = 'Get-NetTCPConnection'
$procs = @()
try {
  $raw = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate -ErrorAction Stop)
  foreach ($p in $raw) {
    $ct = $null
    if ($null -ne $p.CreationDate) {
      try { $ct = ([DateTimeOffset]([DateTime]$p.CreationDate)).ToUnixTimeSeconds() } catch { $ct = $null }
    }
    $procs += [pscustomobject]@{
      pid = [int]$p.ProcessId
      parent_pid = [int]$p.ParentProcessId
      name = [string]$p.Name
      command_line = [string]$p.CommandLine
      executable_path = [string]$p.ExecutablePath
      creation_time = $ct
    }
  }
} catch {
  $method = 'Get-CimInstance-unavailable'
}
$conns = @()
try {
  $raw = @(Get-NetTCPConnection -ErrorAction Stop)
  foreach ($c in $raw) {
    $conns += [pscustomobject]@{
      local_address = [string]$c.LocalAddress
      local_port = [int]$c.LocalPort
      remote_address = [string]$c.RemoteAddress
      remote_port = [int]$c.RemotePort
      state = [string]$c.State
      pid = [int]$c.OwningProcess
    }
  }
} catch {
  $method = 'Get-NetTCPConnection-unavailable'
}
[pscustomobject]@{ method = $method; processes = @($procs); connections = @($conns) } | ConvertTo-Json -Depth 5 -Compress
"""


def _default_command_runner(cmd: list[str], timeout: float):
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


class PowerShellLocalInspector:
    """Read-only local process/TCP inspection and identity-scoped control.

    Implements the offline-testable
    :class:`~red_teaming.tools.zap.lifecycle.LifecycleSystem` protocol:

    * :meth:`snapshot` returns a full read-only process + TCP observation that
      can locate the API-port owner even after the Install4j launcher has
      exited;
    * :meth:`terminate` / :meth:`kill` stop exactly one already-verified PID.

    Uses ``Get-CimInstance`` for processes (PID, PPID, name, command line,
    executable path, creation time) and ``Get-NetTCPConnection`` for TCP state,
    falling back to parsing ``netstat -ano`` when the cmdlet is unavailable. No
    connection is ever created and no data is ever sent.
    """

    def __init__(
        self,
        *,
        command_runner: Optional[Callable[[list[str], float], Any]] = None,
        timeout: float = 30.0,
        powershell: Optional[str] = None,
    ) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise SmokeConfigurationError("inspection timeout must be positive")
        self._run = command_runner or _default_command_runner
        self._timeout = float(timeout)
        self._powershell = (
            powershell
            or shutil.which("powershell")
            or shutil.which("pwsh")
            or "powershell.exe"
        )

    # -- LifecycleSystem protocol ------------------------------------------

    def snapshot(self) -> SystemSnapshot:
        """Return one read-only local process/TCP observation."""

        script = _PS_SNAPSHOT_TEMPLATE
        output = None
        error: Optional[str] = None
        try:
            completed = self._run(self._powershell_argv(script), self._timeout)
            if completed.returncode == 0 and completed.stdout.strip():
                output = json.loads(completed.stdout)
            else:
                error = (
                    "PowerShell inspection failed with exit code "
                    f"{completed.returncode}"
                )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            error = f"PowerShell inspection failed: {type(exc).__name__}"

        method: Optional[str] = None
        processes: list[ProcessRecord] = []
        connections: list[ConnectionRecord] = []
        if isinstance(output, Mapping):
            method = output.get("method")
            processes = _coerce_process_records(output.get("processes"))
            connections = _coerce_connection_records(output.get("connections"))

        if _is_unavailable_method(method) or not connections:
            fallback = self._netstat_all_connections()
            if fallback:
                if _is_unavailable_method(method):
                    method = "netstat"
                connections = fallback

        return SystemSnapshot(
            method=method,
            processes=tuple(processes),
            connections=tuple(connections),
            error=error,
        )

    def terminate(self, pid: int) -> None:
        """Request graceful termination of an already-verified *pid*."""

        self._stop_process(pid, force=False)

    def kill(self, pid: int) -> None:
        """Forcefully stop an already-verified *pid*."""

        self._stop_process(pid, force=True)

    # -- legacy inspection API ---------------------------------------------

    def collect(self, pid: Optional[int], port: int) -> dict:
        """Return the legacy inspection dict for the tree rooted at *pid*."""

        snapshot = self.snapshot()
        raw = snapshot_to_inspection_raw(
            snapshot,
            port=port,
            pids=_descendant_pids(snapshot, pid),
            root_pid=pid,
        )
        return analyze_inspection(raw)

    # -- internals ---------------------------------------------------------

    def _powershell_argv(self, script: str) -> list[str]:
        return [
            self._powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]

    def _stop_process(self, pid: int, *, force: bool) -> None:
        if not _is_int_like(pid) or pid <= 0:
            raise SmokeConfigurationError("refusing to stop an invalid process id")
        flag = "-Force " if force else ""
        action = "kill" if force else "terminate"
        script = (
            "$ErrorActionPreference = 'Stop'; "
            f"Stop-Process -Id {int(pid)} {flag}-ErrorAction Stop"
        )
        completed = self._run(self._powershell_argv(script), self._timeout)
        returncode = getattr(completed, "returncode", None)
        if returncode != 0:
            # A nonzero control result is a failure, never a silent success. The
            # message is bounded and contains no captured command output.
            raise SmokeProcessControlError(
                f"{action} process control failed with exit code {returncode}"
            )

    def _netstat_all_connections(self) -> list[ConnectionRecord]:
        try:
            completed = self._run(["netstat", "-ano"], self._timeout)
        except (OSError, subprocess.SubprocessError):
            return []
        if completed.returncode != 0 or not completed.stdout:
            return []
        parsed = _parse_netstat(completed.stdout, set())
        return _coerce_connection_records(parsed)


def _is_unavailable_method(method: Any) -> bool:
    return str(method or "").strip().lower() in (
        "",
        "unavailable",
        "get-nettcpconnection-unavailable",
    )


def _is_int_like(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _coerce_process_records(value: Any) -> list[ProcessRecord]:
    items = value if isinstance(value, list) else ([] if value is None else [value])
    records: list[ProcessRecord] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        pid = _to_int(item.get("pid"))
        if pid is None or pid <= 0:
            continue
        creation = item.get("creation_time")
        creation_time: Optional[float]
        try:
            creation_time = None if creation in (None, "") else float(creation)
        except (TypeError, ValueError):
            creation_time = None
        records.append(
            ProcessRecord(
                pid=pid,
                parent_pid=_to_int(item.get("parent_pid")),
                name=str(item.get("name") or ""),
                command_line=str(item.get("command_line") or ""),
                executable_path=(
                    str(item.get("executable_path"))
                    if item.get("executable_path")
                    else None
                ),
                creation_time=creation_time,
            )
        )
    return records


def _coerce_connection_records(value: Any) -> list[ConnectionRecord]:
    items = value if isinstance(value, list) else ([] if value is None else [value])
    records: list[ConnectionRecord] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        records.append(
            ConnectionRecord(
                local_address=str(item.get("local_address") or ""),
                local_port=_to_int(item.get("local_port")),
                remote_address=str(item.get("remote_address") or ""),
                remote_port=_to_int(item.get("remote_port")),
                state=str(item.get("state") or ""),
                pid=_to_int(item.get("pid")),
            )
        )
    return records


def _descendant_pids(snapshot: SystemSnapshot, root: Optional[int]) -> Optional[set[int]]:
    if not _is_int_like(root) or root <= 0:
        return None
    children: dict[int, list[int]] = {}
    for record in snapshot.processes:
        if record.parent_pid is not None:
            children.setdefault(record.parent_pid, []).append(record.pid)
    selected = {root}
    queue = [root]
    while queue:
        parent = queue.pop()
        for child in children.get(parent, []):
            if child not in selected:
                selected.add(child)
                queue.append(child)
    return selected


def snapshot_to_inspection_raw(
    snapshot: SystemSnapshot,
    *,
    port: int,
    pids: Optional[set[int]] = None,
    root_pid: Optional[int] = None,
    callback_port: Optional[int] = None,
) -> dict:
    """Build the legacy inspection dict from a :class:`SystemSnapshot`."""

    connections = [
        record
        for record in snapshot.connections
        if pids is None or record.pid in pids
    ]
    processes = [
        record
        for record in snapshot.processes
        if pids is None or record.pid in pids
    ]
    return {
        "method": snapshot.method,
        "root_pid": root_pid,
        "port": port,
        "callback_port": callback_port,
        "pids": sorted({record.pid for record in connections if record.pid}),
        "processes": [record.to_evidence() for record in processes],
        "connections": [record.to_evidence() for record in connections],
        "error": snapshot.error,
    }


# Backwards-compatible aliases for the older, narrower coercion helpers.
def _coerce_processes(value: Any) -> list[dict]:
    return [record.to_evidence() for record in _coerce_process_records(value)]


def _coerce_connections(value: Any) -> list[dict]:
    return [record.to_evidence() for record in _coerce_connection_records(value)]


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Port preflight (no data is sent)
# ---------------------------------------------------------------------------


def check_port_free(host: str, port: int, *, timeout: float = 1.0) -> bool:
    """Return True when *host*:*port* can be bound locally.

    This is a bind probe only: no data is sent and the socket is closed
    immediately. A failure indicates the port is already occupied.
    """

    if not isinstance(host, str) or host != EXACT_BIND_HOST:
        raise SmokeConfigurationError("port preflight requires host 127.0.0.1")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise SmokeConfigurationError("port preflight requires an in-range port")

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(timeout)
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


# ---------------------------------------------------------------------------
# Project-local artifact inspection
# ---------------------------------------------------------------------------


def _read_text_limited(path: Path, limit: int) -> Optional[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > limit:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    return data.decode("utf-8", errors="replace")


def _redact_key_material(text: str) -> tuple[str, int]:
    """Return ``(sanitized_text, match_count)`` for evidence use only.

    This helper never touches a source file; it is used solely to build
    redacted excerpts so a detected secret value never appears in returned
    evidence.
    """

    found = 0

    def replace(match: "re.Match[str]") -> str:
        nonlocal found
        secret = match.group(2)
        if not secret or secret.strip() in ("", '""', "***"):
            return match.group(0)
        found += 1
        return f"{match.group(1)}***"

    sanitized = text
    for _kind, pattern, _file_kinds in _KEY_MATERIAL_PATTERNS:
        sanitized = pattern.sub(replace, sanitized)
    return sanitized, found


def _find_key_material(text: str, relative: str, kind: str) -> list[dict]:
    """Return redacted, context-specific API-key findings for one file.

    Only patterns applicable to *kind* are considered, and every excerpt is
    passed through :func:`_redact_key_material` first so the actual secret value
    is never returned.
    """

    findings: list[dict] = []
    for material_kind, pattern, file_kinds in _KEY_MATERIAL_PATTERNS:
        if kind not in file_kinds:
            continue
        for line in text.splitlines():
            matches = [
                match.group(2)
                for match in pattern.finditer(line)
                if match.group(2)
                and match.group(2).strip() not in ("", '""', "***")
            ]
            if not matches:
                continue
            redacted, _ = _redact_key_material(line)
            findings.append(
                {
                    "path": relative,
                    "kind": material_kind,
                    "count": len(matches),
                    "excerpt": " ".join(redacted.split())[:_MAX_EXCERPT_CHARS],
                }
            )
    return findings


def _error_lines(text: str, relative: str) -> list[dict]:
    """Return runtime-log-aware, bounded *incident* excerpts for one log file.

    Detection is log-level-aware: a line carrying a runtime log-level token
    (``ERROR``/``FATAL``) starts exactly one incident. Immediately following
    exception/cause/stack-frame lines are folded into that same incident, so an
    ``at ...`` frame never becomes a separate record. A later ``ERROR``/``FATAL``
    line starts a new incident. Standalone stack frames or exception-looking
    prose without an ERROR/FATAL anchor are ignored, and ordinary prose or
    ``INFO`` lines that merely mention ``error`` are never classified.

    Each incident becomes one redacted, bounded excerpt; the per-file incident
    count and the excerpt length are both strictly bounded.
    """

    incidents: list[dict] = []
    current: list[str] = []

    def commit() -> None:
        if not current:
            return
        redacted, _ = _redact_key_material("\n".join(current))
        cleaned = " ".join(redacted.split())
        if cleaned:
            incidents.append(
                {"path": relative, "excerpt": cleaned[:_MAX_EXCERPT_CHARS]}
            )
        current.clear()

    for line in text.splitlines():
        if _ERROR_LEVEL_RE.search(line):
            # A new log-level anchor closes any open incident first; a second
            # ERROR/FATAL line therefore yields a second, separate record.
            commit()
            if len(incidents) >= _MAX_ERROR_EXCERPTS:
                break
            current.append(line)
            continue
        if not current:
            # No ERROR/FATAL anchor is open: standalone exception text and
            # stack frames are not independent incidents.
            continue
        if len(current) >= _MAX_INCIDENT_LINES:
            # Incident is full: keep it bounded and stop folding further lines.
            commit()
            continue
        if _STACKTRACE_CONTEXT_RE.search(line):
            current.append(line)
        else:
            # A non-continuation line ends the incident excerpt.
            commit()
    commit()
    return incidents


def _empty_key_material() -> dict:
    return {
        "detected": False,
        "remediated": False,
        # Inspection is strictly read-only; the inspected source is never
        # modified or rewritten.
        "source_mutated": False,
        "match_count": 0,
        "files": [],
        "matches": [],
    }


def inspect_artifacts(scan_dir: os.PathLike | str) -> dict:
    """Read-only, allowlisted inspection of project-local runtime artifacts.

    Only the explicit runtime allowlist (captured daemon logs plus
    ``zap-home/zap.log`` and ``zap-home/config.xml``) is content-scanned.
    Bundled assets are never scanned. Inspected files are only ever read; no
    file is ever modified, rewritten, or redacted in place, so ``remediated``
    and ``source_mutated`` always remain ``False``. Run-generated smoke
    evidence is intentionally excluded from the scan to avoid self-referential
    instability.
    """

    root = Path(scan_dir)
    result: dict[str, Any] = {
        "scan_dir": str(root),
        "method": _ARTIFACT_METHOD,
        "files": [],
        "errors": [],
        "key_material": _empty_key_material(),
        "total_files": 0,
        "notes": [
            "Only the explicit runtime allowlist is content-scanned; bundled "
            "assets (extensions, JavaScript, wordlists, add-ons, templates, "
            "jars) are never scanned.",
            "Inspection is read-only: no inspected file is modified, and "
            "source_mutated remains false.",
            "Run-generated smoke state/JSON/Markdown evidence is intentionally "
            "not content-scanned to avoid self-reference.",
        ],
    }

    for relative, kind in _ARTIFACT_ALLOWLIST:
        path = root / relative
        try:
            if not path.is_file():
                continue
            size = path.stat().st_size
        except OSError:
            continue

        result["files"].append(
            {
                "path": relative,
                "size_bytes": size,
                "kind": kind,
                "content_scanned": True,
            }
        )

        text = _read_text_limited(path, _MAX_LOG_BYTES)
        if text is None:
            result["notes"].append(
                f"skipped oversized or binary runtime file: {relative}"
            )
            continue

        findings = _find_key_material(text, relative, kind)
        if findings:
            key_material = result["key_material"]
            key_material["detected"] = True
            if relative not in key_material["files"]:
                key_material["files"].append(relative)
            key_material["matches"].extend(findings)
            key_material["match_count"] += sum(
                finding["count"] for finding in findings
            )

        if kind == "log":
            result["errors"].extend(_error_lines(text, relative))

    result["total_files"] = len(result["files"])
    return result


# ---------------------------------------------------------------------------
# Evidence rendering
# ---------------------------------------------------------------------------


def _md_value(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def render_markdown(evidence: Mapping[str, Any]) -> str:
    """Render the evidence object as the human-readable Markdown record."""

    lines: list[str] = []
    lines.append("# OWASP ZAP daemon smoke test")
    lines.append("")
    lines.append(
        "Local-only, loopback-only tool-health smoke. No target interaction, "
        "no scan API, and no external traffic are authorized by this run."
    )
    lines.append("")

    lines.append("## Outcome")
    lines.append("")
    outcome = [
        ("status", evidence.get("status")),
        ("phase", evidence.get("phase")),
        ("schema_version", evidence.get("schema_version")),
        ("created_at", evidence.get("created_at")),
        ("ready_at", evidence.get("ready_at")),
        ("finished_at", evidence.get("finished_at")),
    ]
    for key, value in outcome:
        lines.append(f"- {key}: {_md_value(value)}")
    lines.append("")

    lines.append("## Run identity")
    lines.append("")
    identity = [
        ("domain", evidence.get("domain")),
        ("target_url", evidence.get("target_url")),
        ("artifact_route", evidence.get("artifact_route")),
        ("scan_id", evidence.get("scan_id")),
        ("workspace_root", evidence.get("workspace_root")),
        ("run_dir", evidence.get("run_dir")),
    ]
    for key, value in identity:
        lines.append(f"- {key}: {_md_value(value)}")
    lines.append("")

    lines.append("## Executable and command")
    lines.append("")
    executable = evidence.get("executable") or {}
    lines.append(f"- executable: {_md_value(executable.get('path'))}")
    lines.append(f"- exists: {_md_value(executable.get('exists'))}")
    lines.append(f"- is_file: {_md_value(executable.get('is_file'))}")
    lines.append(f"- size_bytes: {_md_value(executable.get('size_bytes'))}")
    lines.append(f"- sha256: {_md_value(executable.get('sha256'))}")
    lines.append(f"- safe_command: {_md_value(evidence.get('safe_command'))}")
    lines.append("")

    lines.append("## Endpoints and offline posture")
    lines.append("")
    lines.append(f"- bind_endpoint: {_md_value(evidence.get('bind_endpoint'))}")
    lines.append(f"- guard_endpoint: {_md_value(evidence.get('guard_endpoint'))}")
    lines.append(f"- keyless: {_md_value(evidence.get('keyless'))}")
    lines.append(f"- offline_smoke: {_md_value(evidence.get('offline_smoke'))}")
    lines.append(f"- offline_flags: {_md_value(evidence.get('offline_flags'))}")
    oast = evidence.get("oast_callback_config_verification") or {}
    oast_addon_label = " ".join(
        str(value)
        for value in (oast.get("addon"), oast.get("version"))
        if value
    ) or "n/a"
    lines.append(f"- oast_callback_addon: {oast_addon_label}")
    lines.append(f"- oast_callback_verified: {_md_value(oast.get('verified'))}")
    lines.append(
        f"- oast_callback_verification_mode: "
        f"{_md_value(oast.get('verification_mode'))}"
    )
    lines.append(f"- oast_callback_read_only: {_md_value(oast.get('read_only'))}")
    lines.append(f"- oast_callback_offline: {_md_value(oast.get('offline'))}")
    lines.append(f"- oast_callback_sources: {_md_value(oast.get('sources'))}")
    lines.append(
        f"- oast_callback_verified_keys: {_md_value(oast.get('verified_keys'))}"
    )
    lines.append(
        f"- oast_callback_installed_tool_modified: "
        f"{_md_value(oast.get('installed_tool_modified'))}"
    )
    lines.append(
        f"- oast_callback_installed_addon_modified: "
        f"{_md_value(oast.get('installed_addon_modified'))}"
    )
    lines.append(f"- expected_version: {_md_value(evidence.get('expected_version'))}")
    lines.append(f"- observed_version: {_md_value(evidence.get('observed_version'))}")
    lines.append("")

    lines.append("## Preflight")
    lines.append("")
    preflight = evidence.get("port_preflight") or {}
    lines.append(f"- method: {_md_value(preflight.get('method'))}")
    lines.append(f"- ports_free: {_md_value(preflight.get('free'))}")
    preflight_api = preflight.get("api") or {}
    preflight_callback = preflight.get("callback") or {}
    preflight_guard = preflight.get("guard") or {}
    lines.append(f"- api_port_free: {_md_value(preflight_api.get('free'))}")
    lines.append(f"- callback_port_free: {_md_value(preflight_callback.get('free'))}")
    lines.append(f"- guard_port_closed: {_md_value(preflight_guard.get('closed'))}")
    lines.append(
        f"- inspection_available: "
        f"{_md_value(preflight.get('inspection_available'))}"
    )
    inspection_preflight = preflight.get("inspection") or {}
    lines.append(
        f"- inspection_method: {_md_value(inspection_preflight.get('method'))}"
    )
    lines.append(
        f"- process_observation_available: "
        f"{_md_value(inspection_preflight.get('process_observation_available'))}"
    )
    lines.append(
        f"- connection_observation_available: "
        f"{_md_value(inspection_preflight.get('connection_observation_available'))}"
    )
    if inspection_preflight.get("error") is not None:
        lines.append(
            f"- inspection_error: {_md_value(inspection_preflight.get('error'))}"
        )
    lines.append("")

    lines.append("## API calls")
    lines.append("")
    lines.append(f"- allowlist: {_md_value(evidence.get('api_allowlist'))}")
    lines.append(f"- scan_api_call_count: {_md_value(evidence.get('scan_api_call_count'))}")
    lines.append(f"- target_input_count: {_md_value(evidence.get('target_input_count'))}")
    lines.append(f"- external_host_input_count: {_md_value(evidence.get('external_host_input_count'))}")
    lines.append("")
    calls = evidence.get("api_calls") or []
    if not calls:
        lines.append("_No API calls were attempted._")
    else:
        for call in calls:
            lines.append(
                "- "
                f"{call.get('timestamp')} "
                f"{call.get('kind')}/{call.get('operation')} "
                f"path={call.get('path')} "
                f"allowed={call.get('allowed')} "
                f"status={call.get('status')} "
                f"error={call.get('error')}"
            )
    lines.append("")

    lines.append("## Listener and process inspection")
    lines.append("")
    inspection = evidence.get("listener_evidence") or {}
    lines.append(f"- method: {_md_value(inspection.get('method'))}")
    lines.append(
        f"- api_listener_loopback_only: "
        f"{_md_value(inspection.get('listener_loopback_only'))}"
    )
    lines.append(
        f"- all_listener_loopback_only: "
        f"{_md_value(inspection.get('all_listener_loopback_only'))}"
    )
    lines.append(
        f"- callback_listener_loopback_only: "
        f"{_md_value(inspection.get('callback_listener_loopback_only'))}"
    )
    lines.append(
        f"- listener_local_addresses: "
        f"{_md_value(inspection.get('listener_local_addresses'))}"
    )
    lines.append(
        f"- all_listener_local_addresses: "
        f"{_md_value(inspection.get('all_listener_local_addresses'))}"
    )
    lines.append(f"- observed_pids: {_md_value(inspection.get('pids'))}")
    lines.append(
        f"- non_loopback_connection_count: "
        f"{_md_value(inspection.get('non_loopback_connection_count'))}"
    )
    lines.append(
        f"- non_loopback_connections: "
        f"{_md_value(inspection.get('non_loopback_connections'))}"
    )
    aggregate = evidence.get("external_connection_observation") or {}
    lines.append(
        f"- external_connection_observation_available: "
        f"{_md_value(aggregate.get('available'))}"
    )
    lines.append(
        f"- external_connection_required_stage_count: "
        f"{_md_value(aggregate.get('required_stage_count'))}"
    )
    lines.append(
        f"- external_connection_observation_stages: "
        f"{_md_value(aggregate.get('stages'))}"
    )
    lines.append(
        f"- aggregated_non_loopback_connection_count: "
        f"{_md_value(aggregate.get('non_loopback_connection_count'))}"
    )
    lines.append(
        f"- aggregated_non_loopback_connections: "
        f"{_md_value(aggregate.get('non_loopback_connections'))}"
    )
    lines.append(f"- process_ids: {_md_value(evidence.get('process_ids'))}")
    lines.append(f"- daemon_identity: {_md_value(evidence.get('daemon_identity'))}")
    lines.append("")

    lines.append("## Lifecycle snapshots")
    lines.append("")
    lifecycle = evidence.get("lifecycle") or {}
    for stage in ("launcher", "daemon", "identity", "detach", "ready", "pre_shutdown", "final"):
        lines.append(f"- {stage}: {_md_value(lifecycle.get(stage))}")
    lines.append(
        f"- pre_shutdown_inspection: "
        f"{_md_value(evidence.get('pre_shutdown_inspection'))}"
    )
    lines.append(
        f"- final_inspection: {_md_value(evidence.get('final_inspection'))}"
    )
    lines.append("")

    lines.append("## Shutdown and process exit")
    lines.append("")
    lines.append(f"- shutdown: {_md_value(evidence.get('shutdown'))}")
    lines.append(
        f"- process_exit_verification: "
        f"{_md_value(evidence.get('process_exit_verification'))}"
    )
    lines.append("")

    lines.append("## Acceptance checks")
    lines.append("")
    for key, value in (evidence.get("acceptance") or {}).items():
        lines.append(f"- {key}: {_md_value(value)}")
    lines.append("")

    lines.append("## Artifact inspection")
    lines.append("")
    artifacts = evidence.get("artifact_inspection") or {}
    lines.append(f"- method: {_md_value(artifacts.get('method'))}")
    lines.append(f"- total_files: {_md_value(artifacts.get('total_files'))}")
    lines.append(
        f"- key_material: {_md_value(artifacts.get('key_material'))}"
    )
    lines.append(f"- error_count: {_md_value(len(artifacts.get('errors') or []))}")
    lines.append(f"- files: {_md_value(artifacts.get('files'))}")
    lines.append(f"- errors: {_md_value(artifacts.get('errors'))}")
    lines.append(f"- notes: {_md_value(artifacts.get('notes'))}")
    lines.append("")

    lines.append("## Errors and limitations")
    lines.append("")
    lines.append(f"- errors: {_md_value(evidence.get('errors'))}")
    lines.append(f"- limitations: {_md_value(evidence.get('limitations'))}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Smoke runner
# ---------------------------------------------------------------------------

#: Hard bound on any inspection error text retained in preflight evidence.
_INSPECTION_ERROR_LIMIT = 200


def _bounded_inspection_error(value: Any) -> Optional[str]:
    """Return a bounded, single-line inspection error or ``None``.

    Only an already-bounded string is retained; it is whitespace-collapsed and
    truncated so preflight evidence never carries unbounded or multi-line
    inspection output. No process list or connection record is ever included.
    """

    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    return text[:_INSPECTION_ERROR_LIMIT]


def _bounded_connection_record(record: Mapping[str, Any]) -> dict:
    """Return only the bounded, non-sensitive fields of one TCP record.

    This is redaction by construction: command lines, executable paths, and any
    future record fields are never copied into persisted aggregate evidence.
    """

    return {
        "local_address": record.get("local_address"),
        "local_port": record.get("local_port"),
        "remote_address": record.get("remote_address"),
        "remote_port": record.get("remote_port"),
        "state": record.get("state"),
        "pid": record.get("pid"),
    }


def _validate_timeout(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SmokeConfigurationError(f"{name} must be a number")
    if value <= 0:
        raise SmokeConfigurationError(f"{name} must be a positive number")
    return float(value)


class ZapSmokeRunner:
    """Runs one local-only ZAP daemon health smoke and writes its evidence."""

    EXPECTED_VERSION = "2.17.0"

    #: Daemon-scoped in-run inspections aggregated for the connection-absence
    #: acceptance check. The ready inspection alone is not sufficient: an
    #: external connection can appear or persist at pre-shutdown.
    _IN_RUN_INSPECTION_STAGES = (
        ("ready", "ready_inspection"),
        ("pre_shutdown", "pre_shutdown_inspection"),
    )

    def __init__(
        self,
        *,
        scan_path: ScanPath,
        executable: os.PathLike | str,
        bind_host: str = EXACT_BIND_HOST,
        bind_port: int = 18080,
        callback_port: int = DEFAULT_OAST_CALLBACK_PORT,
        guard_host: str = DEFAULT_OFFLINE_GUARD_HOST,
        guard_port: int = DEFAULT_OFFLINE_GUARD_PORT,
        expected_version: str = EXPECTED_VERSION,
        min_version: str = DEFAULT_MIN_ZAP_VERSION,
        manager_factory: Optional[Callable[..., Any]] = None,
        client_factory: Optional[Callable[..., Any]] = None,
        system: Optional[LifecycleSystem] = None,
        port_checker: Optional[Callable[[str, int], bool]] = None,
        now: Optional[Callable[[], str]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
        graceful_timeout: float = DEFAULT_GRACEFUL_TIMEOUT,
        terminate_timeout: float = DEFAULT_TERMINATE_TIMEOUT,
        kill_timeout: float = DEFAULT_KILL_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        request_timeout: float = DEFAULT_API_TIMEOUT,
    ) -> None:
        if not isinstance(scan_path, ScanPath):
            raise SmokeConfigurationError("scan_path must be a ScanPath instance")
        self._scan_path = scan_path

        executable_path = Path(os.fspath(executable))
        if not executable_path.is_absolute():
            raise SmokeConfigurationError("executable path must be absolute")
        self._executable = executable_path

        if bind_host != EXACT_BIND_HOST:
            raise SmokeConfigurationError("bind host must be exactly 127.0.0.1")

        # The offline process settings are fixed: the OAST callback is pinned to
        # loopback on exactly 18081 and the HTTP guard is exactly 127.0.0.1:1.
        # Reject any other value so evidence can never disagree with the runtime
        # ``-config`` pairs the process manager always appends.
        if isinstance(callback_port, bool) or callback_port != DEFAULT_OAST_CALLBACK_PORT:
            raise SmokeConfigurationError(
                f"callback port must be exactly {DEFAULT_OAST_CALLBACK_PORT}"
            )
        if guard_host != EXACT_BIND_HOST:
            raise SmokeConfigurationError("guard host must be exactly 127.0.0.1")
        if isinstance(guard_port, bool) or guard_port != DEFAULT_OFFLINE_GUARD_PORT:
            raise SmokeConfigurationError(
                f"guard port must be exactly {DEFAULT_OFFLINE_GUARD_PORT}"
            )

        self._endpoint = ZapEndpoint.from_host_port(bind_host, bind_port)
        self._callback_endpoint = ZapEndpoint.from_host_port(
            EXACT_BIND_HOST, callback_port
        )
        self._guard_endpoint = ZapEndpoint.from_host_port(guard_host, guard_port)

        if not isinstance(expected_version, str) or not expected_version:
            raise SmokeConfigurationError("expected_version must be a non-blank string")
        self._expected_version = expected_version
        if not isinstance(min_version, str) or not min_version:
            raise SmokeConfigurationError("min_version must be a non-blank string")
        self._min_version = min_version

        self._startup_timeout = _validate_timeout("startup_timeout", startup_timeout)
        self._graceful_timeout = _validate_timeout("graceful_timeout", graceful_timeout)
        self._terminate_timeout = _validate_timeout("terminate_timeout", terminate_timeout)
        self._kill_timeout = _validate_timeout("kill_timeout", kill_timeout)
        self._poll_interval = _validate_timeout("poll_interval", poll_interval)
        self._request_timeout = _validate_timeout("request_timeout", request_timeout)

        self._manager_factory = manager_factory or self._default_manager_factory
        self._client_factory = client_factory or self._default_client_factory
        self._system: LifecycleSystem = system or PowerShellLocalInspector()
        self._port_checker = port_checker or check_port_free

        self._now = now or self._default_now
        self._clock = clock
        self._sleep = sleep

        self._state: dict[str, Any] = {}
        self._recorder: Optional[ApiCallRecorder] = None
        self._client: Any = None
        self._manager: Any = None
        self._stop_attempted = False
        self._stop_error: Optional[BaseException] = None
        self._errors: list[dict] = []

    # -- introspection ------------------------------------------------------

    @property
    def state(self) -> dict:
        return self._state

    @property
    def scan_path(self) -> ScanPath:
        return self._scan_path

    @property
    def endpoint(self) -> ZapEndpoint:
        return self._endpoint

    # -- default components -------------------------------------------------

    def _default_client_factory(self, endpoint: ZapEndpoint, transport: Any) -> ZapApiClient:
        return ZapApiClient(
            endpoint,
            None,
            keyless=True,
            transport=transport,
            timeout=self._request_timeout,
        )

    def _default_manager_factory(self, **kwargs: Any) -> ZapProcessManager:
        return ZapProcessManager(**kwargs)

    @staticmethod
    def _default_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # -- execution ----------------------------------------------------------

    def run(self) -> dict:
        """Run the smoke once and return the final evidence object.

        This never raises for an in-band failure: a failed run is reported
        through the returned evidence, and final evidence files are always
        written. A failure to persist evidence is the only propagated error.
        """

        self._state = self._initial_state()
        self._errors = []
        try:
            self._execute()
        except Exception as exc:
            self._record_error(exc)
        self._finalize()
        return self._state

    def _inspection_preflight(self) -> dict:
        """Take one read-only snapshot and summarize inspection capability.

        The returned mapping is bounded and non-sensitive: it records the
        inspection method, the process/connection observation-availability
        flags, and an already-bounded error string. It never serializes the
        process list, connection records, command lines, or executable paths.
        """

        snapshot = self._system.snapshot()
        process_available = bool(snapshot.process_observation_available)
        connection_available = bool(snapshot.observation_available)
        inspection: dict[str, Any] = {
            "method": snapshot.method,
            "process_observation_available": process_available,
            "connection_observation_available": connection_available,
            # Backwards-compatible alias for the TCP/connection observation.
            "observation_available": connection_available,
            "available": bool(process_available and connection_available),
        }
        error = _bounded_inspection_error(snapshot.error)
        if error is not None:
            inspection["error"] = error
        return inspection

    def _run_preflight(self) -> dict:
        """Probe the API/callback/guard gates and local inspection capability.

        No data is sent. A read-only inspection snapshot is taken *before* any
        manager is constructed so a launch is only attempted when both process
        enumeration and TCP observation are available.
        """

        api_free = bool(self._port_checker(self._endpoint.host, self._endpoint.port))
        callback_free = bool(
            self._port_checker(
                self._callback_endpoint.host, self._callback_endpoint.port
            )
        )
        guard_closed = bool(
            self._port_checker(self._guard_endpoint.host, self._guard_endpoint.port)
        )
        inspection = self._inspection_preflight()
        ports_free = bool(api_free and callback_free and guard_closed)
        return {
            "host": self._endpoint.host,
            "method": "local-bind-probe",
            "data_sent": False,
            "api": {"port": self._endpoint.port, "free": api_free},
            "callback": {
                "port": self._callback_endpoint.port,
                "free": callback_free,
            },
            "guard": {"port": self._guard_endpoint.port, "closed": guard_closed},
            "inspection": inspection,
            "inspection_available": bool(inspection["available"]),
            "ports_free": ports_free,
            "free": ports_free,
        }

    def _aggregate_external_connection_observation(self) -> dict:
        """Aggregate daemon-scoped in-run inspections for connection absence.

        Acceptance cannot rest on the ready snapshot alone: an external
        connection may appear only at pre-shutdown. Every required stage must be
        captured and available, and no stage may contain a non-loopback active
        connection. Only bounded, non-sensitive stage summaries and connection
        records are persisted; unrelated process data is never included.
        """

        stages: list[dict] = []
        total = 0
        records: list[dict] = []
        available = True
        for stage_name, state_key in self._IN_RUN_INSPECTION_STAGES:
            inspection = self._state.get(state_key)
            if not isinstance(inspection, Mapping):
                available = False
                stages.append(
                    {
                        "stage": stage_name,
                        "captured": False,
                        "method": None,
                        "observation_available": False,
                        "non_loopback_connection_count": None,
                        "connections": [],
                    }
                )
                continue
            stage_available = bool(inspection.get("observation_available"))
            count = int(inspection.get("non_loopback_connection_count") or 0)
            stage_records = [
                _bounded_connection_record(record)
                for record in (inspection.get("non_loopback_connections") or [])
                if isinstance(record, Mapping)
            ]
            if not stage_available:
                available = False
            total += count
            records.extend(stage_records)
            stages.append(
                {
                    "stage": stage_name,
                    "captured": True,
                    "method": inspection.get("method"),
                    "observation_available": stage_available,
                    "non_loopback_connection_count": count,
                    "connections": stage_records,
                }
            )

        return {
            "available": available,
            "source": (
                "aggregate: daemon-scoped ready + pre-shutdown inspections"
            ),
            "required_stage_count": len(self._IN_RUN_INSPECTION_STAGES),
            "stages": stages,
            "non_loopback_connection_count": total,
            "non_loopback_connections": records,
        }

    def _manager_lifecycle(self) -> dict:
        manager = self._manager
        fn = getattr(manager, "lifecycle_evidence", None)
        if callable(fn):
            value = fn()
            if isinstance(value, Mapping):
                return dict(value)
        return {}

    def _scoped_snapshot(
        self, snapshot: SystemSnapshot, *, extra_pids: Iterable[Optional[int]] = ()
    ) -> SystemSnapshot:
        """Return a bounded snapshot containing only relevant records.

        Retains the launcher, the projected daemon, the owners of the API and
        callback ports, and connections owned by those PIDs or bound to the two
        fixed ports. Unrelated system processes and their command lines never
        enter persisted evidence.
        """

        return scope_snapshot(
            snapshot,
            api_port=self._endpoint.port,
            callback_port=self._callback_endpoint.port,
            extra_pids=extra_pids,
        )

    def _inspect(self, snapshot: SystemSnapshot, *, pids: Optional[set[int]] = None) -> dict:
        raw = snapshot_to_inspection_raw(
            snapshot,
            port=self._endpoint.port,
            pids=pids,
            callback_port=self._callback_endpoint.port,
        )
        return analyze_inspection(raw)

    def _execute(self) -> None:
        self._scan_path.create()
        self._persist_state()

        self._state["phase"] = "port-preflight"
        preflight = self._run_preflight()
        self._state["port_preflight"] = preflight
        self._persist_state()
        if not preflight["free"]:
            raise SmokePortInUseError(
                f"local port preflight failed (api "
                f"{self._endpoint.port} free="
                f"{preflight['api']['free']}, callback "
                f"{self._callback_endpoint.port} free="
                f"{preflight['callback']['free']}, guard "
                f"{self._guard_endpoint.port} closed="
                f"{preflight['guard']['closed']}); refusing to launch"
            )
        if not preflight["inspection_available"]:
            inspection = preflight.get("inspection") or {}
            raise SmokeInspectionCapabilityError(
                "local inspection capability preflight failed "
                f"(method={inspection.get('method')!r}, "
                "process_observation_available="
                f"{inspection.get('process_observation_available')}, "
                "connection_observation_available="
                f"{inspection.get('connection_observation_available')}); "
                "refusing to construct or launch a manager"
            )

        recorder = ApiCallRecorder(self._now)
        self._recorder = recorder
        transport = AllowlistedTransport(
            UrllibTransport(), endpoint=self._endpoint, recorder=recorder
        )
        self._client = self._client_factory(self._endpoint, transport)

        self._state["phase"] = "starting"
        self._state["started_at"] = self._now()
        self._persist_state()

        manager = self._manager_factory(
            executable=self._executable,
            scan_path=self._scan_path,
            api_key=None,
            keyless=True,
            offline_smoke=True,
            guard_host=self._guard_endpoint.host,
            guard_port=self._guard_endpoint.port,
            host=self._endpoint.host,
            port=self._endpoint.port,
            client=self._client,
            startup_timeout=self._startup_timeout,
            graceful_timeout=self._graceful_timeout,
            terminate_timeout=self._terminate_timeout,
            kill_timeout=self._kill_timeout,
            poll_interval=self._poll_interval,
            system=self._system,
        )
        self._manager = manager
        safe_command = getattr(manager, "safe_command", None)
        self._state["safe_command"] = (
            list(safe_command()) if callable(safe_command) else []
        )

        try:
            manager.start()
            # Capture and persist the managed launcher pid immediately after a
            # successful start, before readiness polling: even if the launcher
            # detaches, the evidence must retain the pid we actually spawned.
            launcher_pid = getattr(manager, "launcher_pid", None)
            if launcher_pid is None:
                launcher_pid = getattr(manager, "pid", None)
            self._state["process_ids"]["root_pid"] = launcher_pid
            self._state["process_ids"]["launcher_pid"] = launcher_pid
            self._persist_state()
            version = manager.wait_until_ready()
            self._state["observed_version"] = version
            self._state["ready_at"] = self._now()
            self._persist_state()

            self._state["phase"] = "inspecting"
            self._persist_state()
            daemon_pid = getattr(manager, "daemon_pid", None)
            snapshot = self._system.snapshot()
            scoped = self._scoped_snapshot(
                snapshot, extra_pids=(launcher_pid, daemon_pid)
            )
            inspection = self._inspect(scoped)
            self._state["listener_evidence"] = inspection
            self._state["ready_inspection"] = inspection
            self._state["process_ids"]["daemon_pid"] = daemon_pid
            self._state["process_ids"]["observed_pids"] = list(
                inspection.get("pids") or []
            )
            self._state["process_ids"]["connections"] = list(
                inspection.get("connections") or []
            )
            identity = getattr(manager, "identity", None)
            self._state["daemon_identity"] = (
                identity.to_evidence() if identity is not None else None
            )
            self._persist_state()

            self._state["phase"] = "stopping"
            self._persist_state()
        finally:
            self._stop_manager()

    def _stop_manager(self) -> None:
        manager = self._manager
        if manager is None or self._stop_attempted:
            return
        self._stop_attempted = True

        running_before = bool(getattr(manager, "running", False))
        launcher_pid_before = getattr(manager, "launcher_pid", None)
        daemon_pid_before = getattr(manager, "daemon_pid", None)
        identity_verified = daemon_pid_before is not None

        scoped_pids = (launcher_pid_before, daemon_pid_before)
        pre_snapshot = self._system.snapshot()
        pre_scoped = self._scoped_snapshot(pre_snapshot, extra_pids=scoped_pids)
        self._state["pre_shutdown_inspection"] = self._inspect(pre_scoped)
        self._persist_state()

        requested_at = self._now()
        try:
            manager.stop()
        except Exception as exc:  # bounded, but may still surface
            self._stop_error = exc
            self._record_error(exc, phase="shutdown")

        final_snapshot = self._scoped_snapshot(
            self._system.snapshot(), extra_pids=scoped_pids
        )
        final_inspection = self._inspect(final_snapshot)
        self._state["final_inspection"] = final_inspection
        self._state["final_snapshot"] = final_snapshot.to_evidence()

        lifecycle = self._manager_lifecycle()
        self._state["lifecycle"] = lifecycle
        stop = lifecycle.get("shutdown") or {}

        daemon_running_after = bool(getattr(manager, "running", False))
        daemon_pid_after = (
            getattr(manager, "daemon_pid", None) if daemon_running_after else None
        )
        identity_reverified = bool(stop.get("identity_reverified"))
        daemon_gone = identity_verified and (
            not daemon_running_after
            or bool(stop.get("process_exited"))
        )
        # A verified daemon that is no longer running counts as gone even when
        # the stop evidence was not populated by an injected manager.
        if identity_verified and not daemon_running_after:
            daemon_gone = True

        api_attempted = (
            bool(stop.get("api_attempted"))
            if isinstance(stop, Mapping) and "api_attempted" in stop
            else running_before
        )
        api_result = stop.get("api_result") if isinstance(stop, Mapping) else None

        api_port_closed = not final_snapshot.has_listener_on(self._endpoint.port)
        callback_port_closed = not final_snapshot.has_listener_on(
            self._callback_endpoint.port
        )
        both_ports_closed = bool(api_port_closed and callback_port_closed)

        if api_attempted:
            method = "api_core_shutdown"
        elif identity_verified:
            method = "not_sent_daemon_not_running"
        else:
            method = "not_sent_no_verified_daemon"

        if self._stop_error is not None:
            result = "error"
        elif daemon_running_after:
            result = "failed"
        elif api_attempted and daemon_gone and both_ports_closed:
            result = "graceful"
        elif not api_attempted and not running_before:
            result = "not_sent_process_already_exited"
        elif daemon_gone and both_ports_closed:
            result = "verified_exit"
        else:
            result = "failed"

        launcher_exit_code = getattr(manager, "launcher_exit_code", None)
        if launcher_exit_code is None:
            launcher_exit_code = getattr(manager, "exit_code", None)

        self._state["shutdown"] = {
            "method": method,
            "requested_at": requested_at if api_attempted else None,
            "recorded_at": self._now(),
            "result": result,
            "api_attempted": api_attempted,
            "api_result": api_result,
            "launcher_pid_before": launcher_pid_before,
            "launcher_pid_after": getattr(manager, "launcher_pid", None),
            "daemon_pid_before": daemon_pid_before,
            "daemon_pid_after": daemon_pid_after,
            "pid_after": daemon_pid_after,
            "fallbacks": list(stop.get("fallbacks") or []),
            "identity_verified": identity_verified,
            "identity_reverified": identity_reverified,
            "process_exited": daemon_gone,
            "exit_code": launcher_exit_code,
            "api_port_closed": api_port_closed,
            "callback_port_closed": callback_port_closed,
            "both_ports_closed": both_ports_closed,
        }
        self._state["process_exit_verification"] = {
            "exited": daemon_gone,
            "managed_process_present": daemon_running_after,
            "launcher_pid": launcher_pid_before,
            "launcher_exit_code": launcher_exit_code,
            "pid_before": self._state.get("process_ids", {}).get("root_pid"),
            "daemon_pid_before": daemon_pid_before,
            "daemon_pid_after": daemon_pid_after,
            "pid_after": daemon_pid_after,
            "exit_code": launcher_exit_code,
            "api_port_closed": api_port_closed,
            "callback_port_closed": callback_port_closed,
            "both_ports_closed": both_ports_closed,
        }
        self._persist_state()

    # -- state and evidence -------------------------------------------------

    def _initial_state(self) -> dict:
        timestamp = self._now()
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "planned",
            "phase": "plan",
            "created_at": timestamp,
            "updated_at": timestamp,
            "started_at": None,
            "ready_at": None,
            "finished_at": None,
            "domain": self._scan_path.domain,
            "target_url": None,
            "artifact_route": {
                "domain": self._scan_path.domain,
                "target": self._scan_path.target,
            },
            "scan_id": self._scan_path.scan_id,
            "workspace_root": str(self._scan_path.workspace_root),
            "run_dir": str(self._scan_path.scan_dir),
            "executable": self._describe_executable(),
            "safe_command": [],
            "bind_endpoint": self._endpoint.base_url,
            "callback_endpoint": self._callback_endpoint.base_url,
            "guard_endpoint": self._guard_endpoint.base_url,
            "keyless": True,
            "offline_smoke": True,
            "offline_flags": self._offline_flags(),
            "oast_callback_config_verification": (
                self._oast_callback_config_verification()
            ),
            "expected_version": self._expected_version,
            "min_version": self._min_version,
            "observed_version": None,
            "api_allowlist": sorted(
                f"{component}/{kind}/{operation}"
                for component, kind, operation in ALLOWED_OPERATIONS
            ),
            "api_calls": [],
            "scan_api_call_count": 0,
            "target_input_count": 0,
            "external_host_input_count": 0,
            "port_preflight": None,
            "process_ids": {
                "root_pid": None,
                "launcher_pid": None,
                "daemon_pid": None,
                "observed_pids": [],
                "connections": [],
            },
            "daemon_identity": None,
            "listener_evidence": None,
            "ready_inspection": None,
            "pre_shutdown_inspection": None,
            "final_inspection": None,
            "final_snapshot": None,
            "lifecycle": None,
            "external_connection_observation": None,
            "shutdown": None,
            "process_exit_verification": None,
            "artifact_inspection": None,
            "acceptance": {},
            "errors": [],
            "limitations": [
                "Traffic conclusions are based on observed process-tree TCP "
                "state plus configured prevention controls; they are not a "
                "mathematical proof that no packet left the host.",
                "Inspection is best-effort: portable PowerShell and netstat "
                "output may omit transient connections.",
            ],
        }

    def _offline_flags(self) -> dict:
        from .process import (
            DEFAULT_OAST_CALLBACK_PORT,
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
        )

        return {
            OFFLINE_CONFIG_CHECK_ON_START: "false",
            OFFLINE_CONFIG_DOWNLOAD_NEW_RELEASE: "false",
            OFFLINE_CONFIG_CHECK_ADDON_UPDATES: "false",
            OFFLINE_CONFIG_INSTALL_ADDON_UPDATES: "false",
            OFFLINE_CONFIG_INSTALL_SCANNER_RULES: "false",
            # Suppress callhome telemetry so no startup/shutdown egress is even
            # attempted; this mirrors the deterministic runtime pair.
            OFFLINE_CONFIG_CALLHOME_TEL_ENABLED: "false",
            OFFLINE_CONFIG_HTTP_PROXY_ENABLED: "true",
            OFFLINE_CONFIG_HTTP_PROXY_HOST: self._guard_endpoint.host,
            OFFLINE_CONFIG_HTTP_PROXY_PORT: str(self._guard_endpoint.port),
            # OAST callback containment is fixed loopback and mirrors the exact
            # runtime ``-config`` pairs the process manager appends in offline
            # mode. These are literal constants, not derived from the
            # configurable guard host.
            OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR: "127.0.0.1",
            OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR: "127.0.0.1",
            OFFLINE_CONFIG_OAST_CALLBACK_PORT: str(DEFAULT_OAST_CALLBACK_PORT),
        }

    def _oast_callback_config_verification(self) -> dict:
        """Return the static OAST callback ``-config`` provenance record.

        The three OAST callback keys were verified read-only from the installed
        OAST 0.24.0 ``CallbackParam`` bytecode and its embedded help before this
        work package. This record is static and deterministic: it performs no
        inspection and never modifies the installed tool or add-on.
        """

        return {
            "verified": True,
            "addon": OAST_CALLBACK_ADDON,
            "version": OAST_CALLBACK_ADDON_VERSION,
            "verification_mode": "read-only offline inspection of installed add-on",
            "read_only": True,
            "offline": True,
            "sources": list(OAST_CALLBACK_VERIFICATION_SOURCES),
            "verified_keys": list(OAST_CALLBACK_VERIFIED_KEYS),
            "installed_tool_modified": False,
            "installed_addon_modified": False,
        }

    def _describe_executable(self) -> dict:
        path = self._executable
        info: dict[str, Any] = {
            "path": str(path),
            "exists": path.is_file(),
            "is_file": path.is_file(),
            "size_bytes": None,
            "modified_utc": None,
            "sha256": None,
        }
        if not path.is_file():
            return info
        try:
            stat = path.stat()
            info["size_bytes"] = stat.st_size
            info["modified_utc"] = datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat()
            info["sha256"] = _sha256_file(path)
        except OSError:
            pass
        return info

    def _record_error(self, exc: BaseException, *, phase: Optional[str] = None) -> None:
        self._errors.append(
            {
                "type": type(exc).__name__,
                "message": redact_secret(str(exc), "").strip() or type(exc).__name__,
                "phase": phase or self._state.get("phase"),
            }
        )

    def _persist_state(self) -> Path:
        self._state["updated_at"] = self._now()
        self._state["errors"] = list(self._errors)
        state_path = self._scan_path.state_file_path(SMOKE_STATE_FILENAME)
        return atomic_write_json(
            state_path, self._state, scan_dir=self._scan_path.scan_dir
        )

    def _finalize(self) -> None:
        recorder = self._recorder
        calls = list(recorder.calls) if recorder is not None else []
        self._state["api_calls"] = calls
        self._state["scan_api_call_count"] = sum(
            1
            for call in calls
            if str(call.get("component") or "").lower() in SCAN_COMPONENTS
        )

        # Artifact inspection runs before the final success evaluation so its
        # read-only key-material/source-mutation results can gate acceptance.
        try:
            self._state["artifact_inspection"] = inspect_artifacts(
                self._scan_path.scan_dir
            )
        except Exception as exc:
            self._record_error(exc, phase="artifacts")
            self._state["artifact_inspection"] = {
                "scan_dir": str(self._scan_path.scan_dir),
                "method": _ARTIFACT_METHOD,
                "files": [],
                "errors": [],
                "key_material": _empty_key_material(),
                "total_files": 0,
                "notes": [f"inspection failed: {type(exc).__name__}"],
            }

        inspection = self._state.get("listener_evidence") or {}
        api_listener_ok = bool(inspection.get("listener_loopback_only"))
        all_listener_ok = bool(inspection.get("all_listener_loopback_only"))
        callback_listener_ok = bool(
            inspection.get("callback_listener_loopback_only")
        )

        # Connection-absence acceptance aggregates every required daemon-scoped
        # in-run stage (ready + pre-shutdown); the ready snapshot alone is not
        # sufficient.
        aggregate = self._aggregate_external_connection_observation()
        self._state["external_connection_observation"] = aggregate
        observation_available = bool(aggregate.get("available"))
        non_loopback_count = int(aggregate.get("non_loopback_connection_count") or 0)

        observed = self._state.get("observed_version")
        version_matches = observed == self._expected_version
        version_ok = bool(observed) and version_at_least(observed, self._min_version)
        shutdown = self._state.get("shutdown") or {}
        daemon_gone = bool(shutdown.get("process_exited"))
        api_shutdown_attempted = bool(shutdown.get("api_attempted"))
        api_port_closed = bool(shutdown.get("api_port_closed"))
        callback_port_closed = bool(shutdown.get("callback_port_closed"))
        both_ports_closed = bool(
            shutdown.get("both_ports_closed")
            or (api_port_closed and callback_port_closed)
        )
        daemon_identity_verified = bool(self._state.get("daemon_identity"))
        preflight = self._state.get("port_preflight") or {}
        preflight_free = bool(preflight.get("free"))
        inspection_preflight_available = bool(
            preflight.get("inspection_available")
        )
        callback_preflight_free = bool(
            (preflight.get("callback") or {}).get("free")
        )
        guard_port_closed = bool((preflight.get("guard") or {}).get("closed"))

        artifact = self._state.get("artifact_inspection") or {}
        key_material = artifact.get("key_material") or {}
        key_material_detected = bool(key_material.get("detected"))
        source_mutated = bool(key_material.get("source_mutated"))

        acceptance = {
            "version_observed": bool(observed),
            "version_matches_expected": version_matches,
            "version_at_least_minimum": version_ok,
            "bind_host_is_127_0_0_1": self._endpoint.host == EXACT_BIND_HOST,
            "api_listener_loopback_only": api_listener_ok,
            "all_listener_loopback_only": all_listener_ok,
            "callback_listener_loopback_only": callback_listener_ok,
            # Backwards-compatible alias for the API listener containment.
            "listener_loopback_only": api_listener_ok,
            "no_scan_api_calls": self._state["scan_api_call_count"] == 0,
            "no_target_input": True,
            "inspection_preflight_available": inspection_preflight_available,
            "external_connection_observation_available": observation_available,
            # Without every required captured/available listener/connection
            # observation we cannot verify the absence of external connections,
            # so the check must be false rather than defaulting to a verified
            # true. Acceptance also requires that *no* aggregated stage observed
            # a non-loopback active connection.
            "no_external_connections": bool(
                observation_available and non_loopback_count == 0
            ),
            "artifact_key_material_not_detected": not key_material_detected,
            "artifact_source_not_mutated": not source_mutated,
            "api_shutdown_attempted": api_shutdown_attempted,
            "daemon_identity_verified": daemon_identity_verified,
            "daemon_gone": daemon_gone,
            "api_port_closed": api_port_closed,
            "callback_port_closed": callback_port_closed,
            "both_ports_closed": both_ports_closed,
            "process_exited": daemon_gone,
            "offline_smoke": True,
            "keyless": True,
            "port_preflight_free": preflight_free,
            "callback_preflight_free": callback_preflight_free,
            "guard_port_closed": guard_port_closed,
        }
        self._state["acceptance"] = acceptance

        self._state["errors"] = list(self._errors)
        self._state["finished_at"] = self._now()
        self._state["updated_at"] = self._state["finished_at"]

        succeeded = (
            not self._errors
            and all(
                acceptance[key]
                for key in (
                    "version_matches_expected",
                    "version_at_least_minimum",
                    "api_listener_loopback_only",
                    "all_listener_loopback_only",
                    "callback_listener_loopback_only",
                    "inspection_preflight_available",
                    "external_connection_observation_available",
                    "no_external_connections",
                    "artifact_key_material_not_detected",
                    "artifact_source_not_mutated",
                    "api_shutdown_attempted",
                    "daemon_identity_verified",
                    "daemon_gone",
                    "both_ports_closed",
                    "no_scan_api_calls",
                    "no_target_input",
                    "port_preflight_free",
                    "callback_preflight_free",
                    "guard_port_closed",
                )
            )
        )
        self._state["status"] = "succeeded" if succeeded else "failed"

        # ``done`` describes a completed successful run only. A failed run keeps
        # the factual phase in which the failure occurred (for example
        # ``starting``) instead of claiming completion merely because evidence
        # finalization finished.
        if succeeded:
            self._state["phase"] = "done"
        else:
            failure_phase = None
            for record in reversed(self._errors):
                if record.get("phase"):
                    failure_phase = record["phase"]
                    break
            self._state["phase"] = (
                failure_phase or self._state.get("phase") or "failed"
            )

        self._write_evidence()

    def _write_evidence(self) -> None:
        self._persist_state()
        json_path = self._scan_path.state_file_path(SMOKE_JSON_FILENAME)
        atomic_write_json(
            json_path, self._state, scan_dir=self._scan_path.scan_dir
        )
        markdown_path = self._scan_path.state_file_path(SMOKE_MARKDOWN_FILENAME)
        markdown_path.write_text(
            render_markdown(self._state), encoding="utf-8", newline="\n"
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
