"""Daemon lifecycle management for OWASP ZAP.

``ZapProcessManager`` is the *only* component that starts or stops the ZAP
daemon. It:

* validates an explicit absolute executable path and a loopback host/port;
* builds deterministic daemon/headless arguments (no target URLs ever appear
  in the process command);
* creates only process-owned directories and logs beneath the supplied
  :class:`~red_teaming.projects.paths.ScanPath` scan directory;
* launches the daemon with its working directory set to the executable's own
  install directory (not the scan directory) so the installed launcher's
  relative classpath resolves, while ``-dir`` remains the sole project-local
  ZAP home/output location;
* distinguishes the Install4j ``ZAP.exe`` launcher from the detached JVM
  daemon: the launcher may exit cleanly (code 0) while the daemon keeps
  running, so launcher exit 0 never means daemon exit;
* polls boundedly for API readiness, verifies a minimum ZAP version, and then
  (when a lifecycle system is injected) requires exactly one identity-verified
  daemon that owns the API port and carries the exact per-run ``-dir`` marker
  with consistent creation metadata;
* attempts graceful API shutdown whenever a verified daemon/API is alive --
  even when the launcher has already exited -- and only falls back to
  ``terminate``/``kill`` after the same daemon identity is immediately
  re-verified, otherwise failing closed.

The launcher/daemon split, identity verification, and process control are
injectable via :class:`~red_teaming.tools.zap.lifecycle.LifecycleSystem` so the
whole detached-daemon lifecycle is exercised offline with fakes. When no
lifecycle system is supplied the manager retains the legacy Popen-only
behaviour required by the non-smoke scan path.

API-key protection is the default. Two explicit opt-ins support the
project-local, loopback-only daemon health smoke: ``keyless=True`` starts ZAP
with ``api.disablekey=true`` and no ``api.key`` argument, and
``offline_smoke=True`` adds deterministic ``-config`` hardening that suppresses
automatic update/add-on/scanner-rule activity, routes ZAP's own outbound
HTTP(S) proxy to a closed loopback guard port (``127.0.0.1:1`` by default), and
pins any OAST callback listener to loopback on fixed port ``18081``.

The clock, sleep function, ``Popen`` factory, and API client are injectable so
the whole lifecycle can be exercised offline with fakes.
"""

from __future__ import annotations

import math
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

from ...projects.paths import ScanPath, is_within
from .client import ZapApiClient
from .lifecycle import (
    DaemonIdentity,
    IdentityResult,
    LifecycleSystem,
    SystemSnapshot,
    reverify_daemon_identity,
    scope_snapshot,
    verify_daemon_identity,
)
from .models import (
    DEFAULT_MIN_ZAP_VERSION,
    ZapApiError,
    ZapConfigError,
    ZapEndpoint,
    ZapError,
    ZapVersionError,
    parse_version,
    redact_secret,
    validate_api_key,
    version_at_least,
)

__all__ = [
    "DEFAULT_GRACEFUL_TIMEOUT",
    "DEFAULT_KILL_TIMEOUT",
    "DEFAULT_OAST_CALLBACK_PORT",
    "DEFAULT_OFFLINE_GUARD_HOST",
    "DEFAULT_OFFLINE_GUARD_PORT",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_STARTUP_TIMEOUT",
    "DEFAULT_TERMINATE_TIMEOUT",
    "LOG_DIRNAME",
    "OFFLINE_CONFIG_CALLHOME_TEL_ENABLED",
    "OFFLINE_CONFIG_CHECK_ADDON_UPDATES",
    "OFFLINE_CONFIG_CHECK_ON_START",
    "OFFLINE_CONFIG_DOWNLOAD_NEW_RELEASE",
    "OFFLINE_CONFIG_HTTP_PROXY_ENABLED",
    "OFFLINE_CONFIG_HTTP_PROXY_HOST",
    "OFFLINE_CONFIG_HTTP_PROXY_PORT",
    "OFFLINE_CONFIG_INSTALL_ADDON_UPDATES",
    "OFFLINE_CONFIG_INSTALL_SCANNER_RULES",
    "OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR",
    "OFFLINE_CONFIG_OAST_CALLBACK_PORT",
    "OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR",
    "SILENT_FLAG",
    "STDERR_FILENAME",
    "STDOUT_FILENAME",
    "ZAP_HOME_DIRNAME",
    "ZapDaemonIdentityError",
    "ZapExecutableError",
    "ZapProcessError",
    "ZapProcessExitedError",
    "ZapProcessManager",
    "ZapProcessStateError",
    "ZapReadyTimeoutError",
    "ZapStartError",
    "ZapStopError",
]

ZAP_HOME_DIRNAME = "zap-home"
LOG_DIRNAME = "logs"
STDOUT_FILENAME = "zap-stdout.log"
STDERR_FILENAME = "zap-stderr.log"

DEFAULT_STARTUP_TIMEOUT = 60.0
DEFAULT_GRACEFUL_TIMEOUT = 10.0
DEFAULT_TERMINATE_TIMEOUT = 10.0
DEFAULT_KILL_TIMEOUT = 5.0
DEFAULT_POLL_INTERVAL = 0.25

# -- Offline smoke hardening ------------------------------------------------
#
# ZAP configuration keys verified against the installed OWASP ZAP 2.17.0
# ``config.xml``. Each is added as a deterministic ``-config <key>=<value>``
# pair, never as a target URL or external hostname. Update-check behaviour is
# configured under the top-level ``start`` node.

#: Do not check for new ZAP releases on startup.
OFFLINE_CONFIG_CHECK_ON_START = "start.checkForUpdates"
#: Never download a new ZAP release.
OFFLINE_CONFIG_DOWNLOAD_NEW_RELEASE = "start.downloadNewRelease"
#: Do not check for add-on updates on startup.
OFFLINE_CONFIG_CHECK_ADDON_UPDATES = "start.checkAddonUpdates"
#: Never auto-install add-on updates.
OFFLINE_CONFIG_INSTALL_ADDON_UPDATES = "start.installAddonUpdates"
#: Never auto-install scanner-rule updates.
OFFLINE_CONFIG_INSTALL_SCANNER_RULES = "start.installScannerRules"

#: Suppress the callhome add-on telemetry upload. The qualification run
#: ``20261003T121208Z-79bdb0`` showed callhome 0.20.0 attempting telemetry
#: through the closed outbound proxy at both startup and shutdown. The key and
#: its default ``true`` were verified *read-only* from the installed add-on
#: bytecode. Explicitly setting it false prevents any startup/shutdown telemetry
#: egress from being attempted at all.
OFFLINE_CONFIG_CALLHOME_TEL_ENABLED = "callhome.tel.enabled"

#: Suppress every ZAP-initiated *unsolicited* request at the process level.
#: ZAP's documented ``-silent`` switch sets ``Constant.setSilent(true)``; the
#: only consumer is :class:`~zaproxy.zap.extension.autoupdate.ExtensionAutoUpdate`,
#: which otherwise performs an off-host "check for updates"/news request to
#: ``news.zaproxy.org`` during daemon startup, independently of the
#: ``start.checkForUpdates`` configuration value. Suppressing it removes the
#: last ZAP-initiated off-host egress attempt without weakening any target,
#: scope, rate, depth, concurrency, or method control.
SILENT_FLAG = "-silent"

#: ZAP's own outbound HTTP(S) proxy lives under ``network.connection``.
#: Pointing it at a closed loopback guard port is defense in depth against
#: accidental outbound HTTP(S) during the offline smoke.
OFFLINE_CONFIG_HTTP_PROXY_ENABLED = "network.connection.httpProxy.enabled"
OFFLINE_CONFIG_HTTP_PROXY_HOST = "network.connection.httpProxy.host"
OFFLINE_CONFIG_HTTP_PROXY_PORT = "network.connection.httpProxy.port"

#: Loopback-only guard endpoint defaults (port 1 is closed by default).
DEFAULT_OFFLINE_GUARD_HOST = "127.0.0.1"
DEFAULT_OFFLINE_GUARD_PORT = 1

# -- OAST callback containment (offline) ------------------------------------
#
# In offline smoke mode the following fixed, non-user-configurable ``-config``
# pairs pin any locally started OAST callback listener to loopback on a
# deterministic callback port. They are project-local runtime arguments only:
# configuration continues to live in the per-run ``-dir`` tree.
#
# The key names and their default semantics were verified *read-only* from the
# installed OAST 0.24.0 ``CallbackParam`` bytecode and its embedded help. This
# work package does not uninstall, disable, reconfigure, or otherwise modify the
# installed OAST add-on; it only supplies these project-local runtime
# ``-config`` arguments.

#: OAST callback bind address (fixed loopback, non-user-configurable).
OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR = "oast.callback.localaddr"
#: OAST callback advertised/remote address (fixed loopback, non-configurable).
OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR = "oast.callback.remoteaddr"
#: OAST callback bind port key.
OFFLINE_CONFIG_OAST_CALLBACK_PORT = "oast.callback.port"

#: Deterministic OAST callback port used by the offline smoke.
DEFAULT_OAST_CALLBACK_PORT = 18081

#: Fixed loopback host used for both OAST callback address pairs. It is a
#: literal rather than the configurable guard host so the containment values
#: remain exactly ``127.0.0.1`` regardless of guard configuration.
_OAST_CALLBACK_HOST = "127.0.0.1"


class ZapProcessError(ZapError):
    """Base class for ZAP process lifecycle failures."""


class ZapProcessStateError(ZapProcessError):
    """The manager is already started or has not been started."""


class ZapExecutableError(ZapProcessError):
    """The configured executable is missing or is not a regular file."""


class ZapStartError(ZapProcessError):
    """The operating system refused to start the ZAP process."""


class ZapProcessExitedError(ZapProcessError):
    """The ZAP process exited before the API became ready."""


class ZapDaemonIdentityError(ZapProcessError):
    """The detached daemon could not be unambiguously identified (fail closed)."""


class ZapReadyTimeoutError(ZapProcessError):
    """The ZAP API did not become ready within the startup timeout."""


class ZapStopError(ZapProcessError):
    """The ZAP process was still alive after every bounded shutdown attempt."""


def _validate_timeout(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ZapConfigError(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise ZapConfigError(f"{name} must be a positive finite number")
    return float(value)


def _validate_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ZapConfigError(f"{name} must be a boolean")
    return value


def _validate_extra_config(
    extra_config: Optional[Sequence[tuple[str, str]]],
) -> tuple[tuple[str, str], ...]:
    """Validate deterministic extra ``-config`` key/value pairs.

    Keys must be non-blank dotted identifiers without whitespace or control
    characters; values must be non-blank strings without control characters.
    The API-key keys are reserved: key handling stays on the explicit main
    path so a caller can never smuggle a second key source.
    """

    if extra_config is None:
        return ()
    if isinstance(extra_config, (str, bytes)) or not hasattr(extra_config, "__iter__"):
        raise ZapConfigError("extra_config must be a sequence of (key, value) pairs")
    validated: list[tuple[str, str]] = []
    for pair in extra_config:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ZapConfigError("extra_config entries must be (key, value) pairs")
        key, value = pair
        if not isinstance(key, str) or not key or key != key.strip():
            raise ZapConfigError("extra_config key must be a non-blank string")
        if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in key):
            raise ZapConfigError(
                "extra_config key must not contain whitespace or control characters"
            )
        lowered = key.lower()
        if lowered == "api.key" or lowered.endswith(".apikey") or lowered == "apikey":
            raise ZapConfigError("extra_config must not set API-key configuration")
        if not isinstance(value, str) or not value or value != value.strip():
            raise ZapConfigError("extra_config value must be a non-blank string")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ZapConfigError(
                "extra_config value must not contain control characters"
            )
        validated.append((key, value))
    return tuple(validated)


class ZapProcessManager:
    """Owns the lifecycle of a single ZAP daemon process."""

    def __init__(
        self,
        *,
        executable: Union[os.PathLike, str],
        scan_path: ScanPath,
        api_key: Optional[str] = None,
        keyless: bool = False,
        offline_smoke: bool = False,
        silent: bool = False,
        callback_port: Optional[int] = None,
        guard_host: str = DEFAULT_OFFLINE_GUARD_HOST,
        guard_port: int = DEFAULT_OFFLINE_GUARD_PORT,
        host: str = "127.0.0.1",
        port: int = 8080,
        client: Optional[Union[ZapApiClient, Callable[[], ZapApiClient]]] = None,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
        graceful_timeout: float = DEFAULT_GRACEFUL_TIMEOUT,
        terminate_timeout: float = DEFAULT_TERMINATE_TIMEOUT,
        kill_timeout: float = DEFAULT_KILL_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        min_version: str = DEFAULT_MIN_ZAP_VERSION,
        extra_config: Optional[Sequence[tuple[str, str]]] = None,
        popen_factory: Callable[..., Any] = subprocess.Popen,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        system: Optional[LifecycleSystem] = None,
        wall_clock: Callable[[], float] = time.time,
        creation_tolerance: float = 2.0,
    ) -> None:
        executable_path = Path(os.fspath(executable))
        if not executable_path.is_absolute():
            raise ZapConfigError("ZAP executable path must be absolute")
        self._executable = executable_path

        if not isinstance(scan_path, ScanPath):
            raise ZapConfigError("scan_path must be a ScanPath instance")
        self._scan_path = scan_path

        # API-key protection is the default. Keyless mode is an explicit,
        # loopback-only opt-in for the local health smoke and never supplies a
        # secret.
        self._keyless = _validate_bool("keyless", keyless)
        if self._keyless:
            if api_key is not None:
                raise ZapConfigError("api_key must be omitted when keyless=True")
            self._api_key: Optional[str] = None
        else:
            self._api_key = validate_api_key(api_key)

        self._endpoint = ZapEndpoint.from_host_port(host, port)
        self._host = self._endpoint.host
        self._port = self._endpoint.port

        # The guard endpoint is validated here and reused verbatim in the
        # offline smoke command. ``ZapEndpoint`` rejects non-loopback hosts and
        # out-of-range ports.
        self._offline_smoke = _validate_bool("offline_smoke", offline_smoke)
        # ``-silent`` is an explicit process-level switch that suppresses every
        # ZAP-initiated unsolicited request (notably the auto-update news fetch).
        # It defaults on for the offline smoke and is set explicitly by the
        # bounded Stage 2 launch.
        self._silent = _validate_bool("silent", silent) or self._offline_smoke
        try:
            self._guard_endpoint = ZapEndpoint.from_host_port(guard_host, guard_port)
        except ZapConfigError as exc:
            raise ZapConfigError(f"offline guard endpoint is invalid: {exc}") from exc

        self._startup_timeout = _validate_timeout("startup_timeout", startup_timeout)
        self._graceful_timeout = _validate_timeout("graceful_timeout", graceful_timeout)
        self._terminate_timeout = _validate_timeout("terminate_timeout", terminate_timeout)
        self._kill_timeout = _validate_timeout("kill_timeout", kill_timeout)
        self._poll_interval = _validate_timeout("poll_interval", poll_interval)

        parse_min = min_version
        if not isinstance(parse_min, str) or not parse_min:
            raise ZapConfigError("min_version must be a non-blank string")
        parse_version(parse_min)
        self._min_version = min_version

        # Optional deterministic ``-config`` pairs appended verbatim (for
        # example the bounded Stage 2 spider scope/rate/thread controls). They
        # must be non-secret scalar configuration: the reserved API-key keys are
        # rejected so key handling stays exclusively on the main path.
        self._extra_config: tuple[tuple[str, str], ...] = _validate_extra_config(
            extra_config
        )

        if client is None:
            endpoint = self._endpoint
            key = self._api_key
            minimum = self._min_version
            keyless = self._keyless

            def _default_client() -> ZapApiClient:
                return ZapApiClient(
                    endpoint, key, keyless=keyless, min_version=minimum
                )

            self._client_factory: Callable[[], ZapApiClient] = _default_client
        elif isinstance(client, ZapApiClient):
            # A concrete injected client must agree on keyless mode so the
            # daemon and the client cannot silently disagree about auth.
            if client.keyless != self._keyless:
                raise ZapConfigError(
                    "injected client keyless mode does not match the process "
                    "manager"
                )
            self._client_factory = lambda: client
        elif callable(client):
            self._client_factory = client
        elif callable(getattr(client, "get_version", None)) and callable(
            getattr(client, "shutdown", None)
        ):
            self._client_factory = lambda: client
        else:
            raise ZapConfigError("client must be a ZapApiClient, callable, or None")

        self._popen_factory = popen_factory
        self._clock = clock
        self._sleep = sleep

        if system is None:
            self._system: Optional[LifecycleSystem] = None
        elif callable(getattr(system, "snapshot", None)):
            self._system = system
        else:
            raise ZapConfigError("system must expose a snapshot() method")
        if not callable(wall_clock):
            raise ZapConfigError("wall_clock must be callable")
        self._wall_clock = wall_clock
        self._creation_tolerance = max(0.0, float(creation_tolerance))

        # The OAST callback port to verify is fixed in offline-smoke mode. A
        # caller may also request verification of one explicit loopback callback
        # port (for example the bounded Stage 2 run), without enabling any
        # offline proxy hardening.
        if callback_port is not None:
            if (
                isinstance(callback_port, bool)
                or not isinstance(callback_port, int)
                or not (1 <= callback_port <= 65535)
            ):
                raise ZapConfigError(
                    "callback_port must be an in-range integer or None"
                )
        self._callback_port = (
            DEFAULT_OAST_CALLBACK_PORT if self._offline_smoke else callback_port
        )

        self._process: Optional[Any] = None
        self._stdout_handle: Optional[Any] = None
        self._stderr_handle: Optional[Any] = None
        self._client_instance: Optional[ZapApiClient] = None
        self._ready = False
        self._last_exit_code: Optional[int] = None

        # Launcher/daemon separation. The launcher is the Popen handle; the
        # daemon is a separately-verified OS process that may outlive it.
        self._launcher_pid: Optional[int] = None
        self._launcher_exit_code: Optional[int] = None
        self._daemon_identity: Optional[DaemonIdentity] = None
        self._daemon_running = False
        self._identity_result: Optional[IdentityResult] = None
        self._launch_started_epoch: Optional[float] = None
        self._detach_snapshot: Optional[SystemSnapshot] = None
        self._ready_snapshot: Optional[SystemSnapshot] = None
        self._pre_shutdown_snapshot: Optional[SystemSnapshot] = None
        self._final_snapshot: Optional[SystemSnapshot] = None
        self._stop_evidence: Optional[dict] = None
        self._control_errors: list[str] = []

    # -- safe introspection -------------------------------------------------

    @property
    def scan_dir(self) -> Path:
        return self._scan_path.scan_dir

    @property
    def zap_home(self) -> Path:
        return self._scan_path.scan_dir / ZAP_HOME_DIRNAME

    @property
    def logs_dir(self) -> Path:
        return self._scan_path.scan_dir / LOG_DIRNAME

    @property
    def stdout_path(self) -> Path:
        return self.logs_dir / STDOUT_FILENAME

    @property
    def stderr_path(self) -> Path:
        return self.logs_dir / STDERR_FILENAME

    @property
    def endpoint(self) -> ZapEndpoint:
        return self._endpoint

    @property
    def keyless(self) -> bool:
        """Return True when the daemon is started without an API key."""

        return self._keyless

    @property
    def offline_smoke(self) -> bool:
        """Return True when offline smoke hardening flags are enabled."""

        return self._offline_smoke

    @property
    def guard_endpoint(self) -> ZapEndpoint:
        """Return the validated loopback guard endpoint used in offline mode."""

        return self._guard_endpoint

    @property
    def extra_config(self) -> tuple[tuple[str, str], ...]:
        """Return the validated deterministic extra ``-config`` pairs."""

        return self._extra_config

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def running(self) -> bool:
        """Return whether the managed daemon (or legacy launcher) is alive.

        When a daemon identity has been verified this reflects the daemon;
        otherwise it reflects the live launcher handle.
        """

        if self._daemon_identity is not None:
            return bool(self._daemon_running)
        return self._is_running()

    @property
    def pid(self) -> Optional[int]:
        """Return the verified daemon PID when known, else the launcher PID.

        This is safe introspection only: it never opens a socket, sends data,
        or exposes the API key.
        """

        if self._daemon_identity is not None:
            return self._daemon_identity.pid
        return self._launcher_pid if self._launcher_pid is not None else None

    @property
    def launcher_pid(self) -> Optional[int]:
        """Return the launcher (``ZAP.exe``) PID, preserved after detachment."""

        return self._launcher_pid

    @property
    def launcher_exit_code(self) -> Optional[int]:
        """Return the observed launcher exit code, preserved after detach."""

        if self._launcher_exit_code is not None:
            return self._launcher_exit_code
        process = self._process
        if process is not None:
            return process.poll()
        return None

    @property
    def daemon_pid(self) -> Optional[int]:
        """Return the verified daemon PID, or ``None`` when unverified."""

        if self._daemon_identity is None:
            return None
        return self._daemon_identity.pid

    @property
    def identity(self) -> Optional[DaemonIdentity]:
        """Return the verified daemon identity, or ``None``."""

        return self._daemon_identity

    @property
    def identity_result(self) -> Optional[IdentityResult]:
        """Return the most recent identity-verification result."""

        return self._identity_result

    @property
    def silent(self) -> bool:
        """Return whether ZAP unsolicited requests are suppressed."""

        return self._silent

    @property
    def callback_port(self) -> Optional[int]:
        """Return the fixed OAST callback port in offline mode, else ``None``."""

        return self._callback_port

    @property
    def exit_code(self) -> Optional[int]:
        """Return the observed exit code, before or after shutdown.

        While the process is live this reports ``poll()``; after a successful
        bounded exit it reports the code captured during shutdown. It is
        ``None`` until an exit has actually been observed.
        """

        process = self._process
        if process is not None:
            return process.poll()
        return self._last_exit_code

    def __repr__(self) -> str:
        return (
            f"ZapProcessManager(endpoint={self._endpoint.base_url!r}, "
            f"keyless={self._keyless!r}, offline_smoke={self._offline_smoke!r}, "
            f"silent={self._silent!r}, "
            f"command={self.safe_command()!r}, running={self._is_running()!r})"
        )

    def _redact(self, text: str) -> str:
        return redact_secret(str(text), self._api_key or "")

    def safe_command(self) -> list[str]:
        """Return the daemon command with any API key redacted.

        Keyless/offline flags appear as-is; only ``api.key=`` values are
        redacted, and in keyless mode no such argument is built at all.
        """

        safe: list[str] = []
        for arg in self._build_command():
            if arg.startswith("api.key="):
                safe.append("api.key=***")
            else:
                safe.append(redact_secret(arg, self._api_key or ""))
        return safe

    def _build_command(self) -> list[str]:
        """Build the deterministic daemon/headless command.

        No domain or target URL is ever part of the command. API-key
        protection is the default; the explicit keyless and offline-smoke
        options only change ``-config`` hardening pairs. All ZAP configuration
        continues to live in the per-run ``-dir`` under the scan path.
        """

        command = [
            str(self._executable),
            "-daemon",
            "-host",
            self._host,
            "-port",
            str(self._port),
            "-dir",
            str(self.zap_home),
        ]

        if self._silent:
            # Suppress all ZAP-initiated unsolicited requests (auto-update/news).
            command.append(SILENT_FLAG)

        if self._keyless:
            command += ["-config", "api.disablekey=true"]
        else:
            command += [
                "-config",
                "api.disablekey=false",
                "-config",
                f"api.key={self._api_key}",
            ]

        if self._offline_smoke:
            for key, value in self._offline_config_pairs():
                command += ["-config", f"{key}={value}"]

        for key, value in self._extra_config:
            command += ["-config", f"{key}={value}"]

        return command

    def _offline_config_pairs(self) -> tuple[tuple[str, str], ...]:
        """Return the deterministic offline-smoke ``-config`` key/value pairs.

        The pairs suppress automatic update/add-on/scanner-rule/callhome
        telemetry activity, point ZAP's own outbound HTTP(S) proxy at the
        validated loopback guard endpoint, and pin any OAST callback listener to
        loopback on the fixed callback port. No target URL or external hostname
        is ever included.
        """

        return (
            (OFFLINE_CONFIG_CHECK_ON_START, "false"),
            (OFFLINE_CONFIG_DOWNLOAD_NEW_RELEASE, "false"),
            (OFFLINE_CONFIG_CHECK_ADDON_UPDATES, "false"),
            (OFFLINE_CONFIG_INSTALL_ADDON_UPDATES, "false"),
            (OFFLINE_CONFIG_INSTALL_SCANNER_RULES, "false"),
            (OFFLINE_CONFIG_CALLHOME_TEL_ENABLED, "false"),
            (OFFLINE_CONFIG_HTTP_PROXY_ENABLED, "true"),
            (OFFLINE_CONFIG_HTTP_PROXY_HOST, self._guard_endpoint.host),
            (OFFLINE_CONFIG_HTTP_PROXY_PORT, str(self._guard_endpoint.port)),
            (OFFLINE_CONFIG_OAST_CALLBACK_LOCALADDR, _OAST_CALLBACK_HOST),
            (OFFLINE_CONFIG_OAST_CALLBACK_REMOTEADDR, _OAST_CALLBACK_HOST),
            (OFFLINE_CONFIG_OAST_CALLBACK_PORT, str(DEFAULT_OAST_CALLBACK_PORT)),
        )

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> "ZapProcessManager":
        """Start the ZAP daemon once, returning this manager."""

        if self._process is not None:
            raise ZapProcessStateError("ZAP process has already been started")
        if not self._executable.is_file():
            raise ZapExecutableError(
                f"ZAP executable not found or not a file: {self._executable}"
            )

        self._prepare_scan_layout()
        command = self._build_command()

        stdout_handle = open(self.stdout_path, "wb")
        stderr_handle = open(self.stderr_path, "wb")
        # The installed launcher (ZAP.exe/install4j) resolves part of its Java
        # classpath relative to its own install directory, so the working
        # directory must be the executable's parent. Project-local ZAP state is
        # still routed exclusively through the ``-dir`` argument below.
        install_dir = self._executable.parent
        try:
            process = self._popen_factory(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                shell=False,
                cwd=str(install_dir),
            )
        except OSError as exc:
            stdout_handle.close()
            stderr_handle.close()
            raise ZapStartError(self._redact(f"failed to start ZAP process: {exc}")) from exc

        self._process = process
        self._stdout_handle = stdout_handle
        self._stderr_handle = stderr_handle
        self._ready = False
        self._launcher_pid = self._coerce_pid(getattr(process, "pid", None))
        self._launcher_exit_code = None
        self._daemon_identity = None
        self._daemon_running = False
        self._identity_result = None
        self._detach_snapshot = None
        self._ready_snapshot = None
        self._pre_shutdown_snapshot = None
        self._final_snapshot = None
        self._stop_evidence = None
        # Wall-clock instant used to reject stale/PID-reused candidates: the
        # daemon cannot have been created before we asked the launcher to start.
        self._launch_started_epoch = float(self._wall_clock())
        return self

    def wait_until_ready(self) -> str:
        """Poll boundedly until the API answers and the daemon is verified.

        A nonzero launcher exit before readiness is a startup failure. A clean
        launcher exit (code 0) is treated as a possible Install4j detach, not a
        daemon exit, and polling continues. Once the API answers, the detached
        daemon must be unambiguously identified before readiness is reported.
        """

        process = self._require_process()
        client = self._get_client()

        deadline = self._clock() + self._startup_timeout
        max_attempts = max(1, int(math.ceil(self._startup_timeout / self._poll_interval)))
        attempts = 0

        while True:
            exit_code = process.poll()
            if exit_code is not None:
                self._observe_launcher_exit(exit_code)
                if exit_code != 0:
                    raise ZapProcessExitedError(
                        f"ZAP launcher exited during startup with code {exit_code!r}"
                    )
                # Exit code 0: possible clean detach. Keep polling the API.
                self._record_detach_snapshot()

            try:
                version = client.get_version()
            except ZapApiError:
                version = None

            if version is not None:
                if not version_at_least(version, self._min_version):
                    self._ready = False
                    raise ZapVersionError(
                        f"ZAP version {version!r} is below the required minimum "
                        f"{self._min_version!r}"
                    )
                if self._system is not None:
                    identity = self._verify_daemon_identity()
                    if identity.status in ("ambiguous", "mismatched"):
                        self._ready = False
                        raise ZapDaemonIdentityError(
                            "refusing to report readiness: daemon identity is "
                            f"{identity.status} ({identity.reason})"
                        )
                    if identity.verified:
                        self._ready = True
                        self._record_ready_snapshot()
                        return version
                    # absent/unavailable: keep polling within the bound.
                else:
                    self._ready = True
                    return version

            attempts += 1
            if attempts >= max_attempts or self._clock() >= deadline:
                if self._system is not None and self._daemon_identity is None:
                    raise ZapReadyTimeoutError(
                        "timed out waiting for an identity-verified ZAP API daemon"
                    )
                raise ZapReadyTimeoutError(
                    "timed out waiting for the ZAP API to become ready"
                )
            self._sleep(self._poll_interval)

    def stop(self) -> None:
        """Stop the daemon gracefully, falling back to terminate then kill.

        Safe to call more than once and from ``finally``/context-manager paths.
        Log handles are always closed and readiness is always cleared.

        With an injected lifecycle system the API shutdown is attempted whenever
        a verified daemon is alive (even if the launcher has detached/exited),
        then the manager waits boundedly for the verified daemon and the fixed
        API/callback listeners to disappear. Fallback ``terminate``/``kill`` is
        only called after the *same* daemon identity is immediately
        re-verified; otherwise the stop fails closed and no unrelated process is
        touched.
        """

        try:
            if self._system is not None:
                self._stop_with_system()
            else:
                self._stop_legacy()
        finally:
            self._ready = False
            self._close_logs()

    def lifecycle_evidence(self) -> dict:
        """Return structured launcher/daemon/identity/shutdown evidence.

        Snapshots are serialized through :meth:`_snapshot_evidence`, which
        retains only the launcher, API/callback port owners, the verified daemon,
        and connections owned by those PIDs or bound to the two fixed ports.
        Unrelated system processes and their command lines are never persisted.
        """

        launcher = {
            "pid": self._launcher_pid,
            "exit_code": self.launcher_exit_code,
            "running": self._is_running(),
        }
        identity = self._identity_result
        return {
            "launcher": launcher,
            "daemon": (
                self._daemon_identity.to_evidence(redact=self._redact)
                if self._daemon_identity is not None
                else None
            ),
            "daemon_running": self._daemon_running,
            "identity": (
                identity.to_evidence(redact=self._redact)
                if identity is not None
                else None
            ),
            "detach": self._snapshot_evidence(self._detach_snapshot),
            "ready": self._snapshot_evidence(self._ready_snapshot),
            "pre_shutdown": self._snapshot_evidence(self._pre_shutdown_snapshot),
            "final": self._snapshot_evidence(self._final_snapshot),
            "shutdown": self._stop_evidence,
        }

    def _snapshot_evidence(self, snapshot: Optional[SystemSnapshot]) -> Optional[dict]:
        """Serialize one snapshot with unrelated process data removed."""

        if snapshot is None:
            return None
        daemon_pid = self._daemon_identity.pid if self._daemon_identity else None
        scoped = scope_snapshot(
            snapshot,
            api_port=self._port,
            callback_port=self._callback_port,
            extra_pids=(self._launcher_pid, daemon_pid),
        )
        return scoped.to_evidence(redact=self._redact)

    def __enter__(self) -> "ZapProcessManager":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.stop()
        return False

    # -- internals ----------------------------------------------------------

    def _prepare_scan_layout(self) -> None:
        self._scan_path.create()
        boundary = self._scan_path.scan_dir
        for path in (self.zap_home, self.logs_dir):
            if not is_within(path, boundary):
                raise ZapProcessError(
                    "refusing to create a process directory outside the scan directory"
                )
        self.zap_home.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def _get_client(self) -> ZapApiClient:
        if self._client_instance is None:
            self._client_instance = self._client_factory()
        return self._client_instance

    def _require_process(self) -> Any:
        if self._process is None:
            raise ZapProcessStateError("ZAP process has not been started")
        return self._process

    def _is_running(self) -> bool:
        process = self._process
        return process is not None and process.poll() is None

    @staticmethod
    def _coerce_pid(value: Any) -> Optional[int]:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return None
        return value

    # -- daemon identity / snapshots ---------------------------------------

    def _observe_launcher_exit(self, code: int) -> None:
        if self._launcher_exit_code is None:
            self._launcher_exit_code = code
            self._last_exit_code = code

    def _record_detach_snapshot(self) -> None:
        if self._system is not None and self._detach_snapshot is None:
            self._detach_snapshot = self._system.snapshot()

    def _record_ready_snapshot(self) -> None:
        if self._system is not None and self._ready_snapshot is None:
            self._ready_snapshot = self._system.snapshot()

    def _verify_daemon_identity(self) -> IdentityResult:
        if self._system is None:
            return IdentityResult(
                "unavailable", reason="no lifecycle system is configured"
            )
        snapshot = self._system.snapshot()
        existing = self._daemon_identity
        if existing is None:
            # First identification: require the API-port-owning candidate.
            result = verify_daemon_identity(
                snapshot,
                zap_home=self.zap_home,
                api_port=self._port,
                launcher_pid=self._launcher_pid,
                launched_after=self._launch_started_epoch,
                creation_tolerance=self._creation_tolerance,
            )
        else:
            result = self._reverify_same_identity(snapshot, existing)

        self._identity_result = result
        if result.verified:
            if existing is None:
                # First identification: adopt it.
                self._daemon_identity = result.identity
                self._daemon_running = True
                if self._ready_snapshot is None:
                    self._ready_snapshot = snapshot
            else:
                self._daemon_running = True
        elif existing is None:
            self._daemon_running = False
        return result

    def _reverify_same_identity(
        self, snapshot: SystemSnapshot, existing: DaemonIdentity
    ) -> IdentityResult:
        """Reconfirm the *existing* daemon identity, never adopting a new PID.

        The strict API-port-ownership verifier runs first so an ambiguous or
        reused API owner still fails closed. When it reports no API owner (for
        example the listener closed while the JVM remains), the pure continuity
        helper reconfirms the previously verified PID from its exact ``-dir``
        and unchanged creation metadata, without requiring API-port ownership.
        """

        strict = verify_daemon_identity(
            snapshot,
            zap_home=self.zap_home,
            api_port=self._port,
            launcher_pid=self._launcher_pid,
            launched_after=self._launch_started_epoch,
            creation_tolerance=self._creation_tolerance,
        )
        if strict.verified:
            if strict.identity is not None and strict.identity.pid == existing.pid:
                return strict
            # A freshly verified but different PID must never replace this run's
            # daemon: treat it as stale/PID-reuse/mismatch and fail closed.
            return IdentityResult(
                "mismatched",
                candidate_pids=(
                    (strict.identity.pid,) if strict.identity is not None else ()
                ),
                owner_pids=strict.owner_pids,
                reason=(
                    "fresh API-port owner differs from the verified daemon pid; "
                    "refusing to adopt a different PID"
                ),
            )
        if strict.status == "ambiguous":
            # Multiple exact-marker owners remain ambiguous; never terminate/kill.
            return strict
        # No API owner (or a mismatched/absent owner): fall back to reconfirming
        # the previously verified identity by PID and unchanged metadata.
        return reverify_daemon_identity(
            snapshot,
            existing,
            zap_home=self.zap_home,
            creation_tolerance=self._creation_tolerance,
        )

    def _should_attempt_api_shutdown(self) -> bool:
        if self._daemon_identity is not None and self._daemon_running:
            return True
        # Even if the daemon has not been identity-verified yet, a live launcher
        # implies a possible API; attempting the loopback shutdown is safe.
        return self._is_running()

    def _port_state(self, snapshot: Optional[SystemSnapshot]) -> tuple[bool, bool]:
        if snapshot is None or not snapshot.observation_available:
            return False, False
        api_closed = not snapshot.has_listener_on(self._port)
        callback_closed = (
            self._callback_port is None
            or not snapshot.has_listener_on(self._callback_port)
        )
        return api_closed, callback_closed

    def _wait_for_daemon_gone(self, timeout: float) -> bool:
        """Boundedly confirm the verified daemon and fixed listeners are gone.

        Process exit means process *absence*: for a verified daemon this requires
        an available process observation that actually enumerated processes and
        does not contain the verified PID, plus listener-free API and callback
        ports. If process observation is unavailable the check fails closed
        (returns ``False``) rather than claiming success from port state alone.
        """

        assert self._system is not None
        deadline = self._clock() + timeout
        max_attempts = max(1, int(math.ceil(timeout / self._poll_interval)))
        for _ in range(max_attempts):
            snapshot = self._system.snapshot()
            self._final_snapshot = snapshot
            if self._daemon_identity is not None:
                pid = self._daemon_identity.pid
                daemon_gone = bool(
                    snapshot.observation_available
                    and snapshot.process_observation_available
                    and snapshot.process(pid) is None
                )
            else:
                daemon_gone = not self._is_running()
            api_closed, callback_closed = self._port_state(snapshot)
            if daemon_gone and api_closed and callback_closed:
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(self._poll_interval)
        return False

    # -- stop implementations ----------------------------------------------

    def _stop_legacy(self) -> None:
        """Legacy Popen-only shutdown used when no lifecycle system is set."""

        self._attempt_api_shutdown()
        process = self._process
        if process is None:
            self._stop_evidence = {
                "mode": "legacy_launcher",
                "api_attempted": False,
                "reason": "no managed process handle",
            }
            return
        if self._wait_for_exit(process, self._graceful_timeout):
            self._process = None
            self._stop_evidence = {
                "mode": "legacy_launcher",
                "api_attempted": True,
                "fallbacks": [],
                "exit_code": self._last_exit_code,
            }
            return
        self._safe_call(process.terminate)
        if self._wait_for_exit(process, self._terminate_timeout):
            self._process = None
            self._stop_evidence = {
                "mode": "legacy_launcher",
                "api_attempted": True,
                "fallbacks": ["terminate"],
                "exit_code": self._last_exit_code,
            }
            return
        self._safe_call(process.kill)
        if self._wait_for_exit(process, self._kill_timeout):
            self._process = None
            self._stop_evidence = {
                "mode": "legacy_launcher",
                "api_attempted": True,
                "fallbacks": ["terminate", "kill"],
                "exit_code": self._last_exit_code,
            }
            return
        self._stop_evidence = {
            "mode": "legacy_launcher",
            "api_attempted": True,
            "fallbacks": ["terminate", "kill"],
            "exit_code": self._last_exit_code,
            "result": "failed",
        }
        raise ZapStopError(
            self._redact(
                "ZAP process is still alive after graceful shutdown, "
                "terminate, and kill"
            )
        )

    def _stop_with_system(self) -> None:
        assert self._system is not None
        system = self._system

        self._pre_shutdown_snapshot = system.snapshot()
        identity_before = self._daemon_identity
        daemon_pid_before = identity_before.pid if identity_before else None
        launcher_pid_before = self._launcher_pid

        api_attempted = False
        api_result: Optional[str] = None
        api_error: Optional[str] = None
        if self._should_attempt_api_shutdown():
            api_attempted = True
            try:
                self._get_client().shutdown()
                api_result = "sent"
            except Exception as exc:  # best-effort; fallbacks remain bounded
                api_result = "error"
                api_error = type(exc).__name__

        fallbacks: list[str] = []
        identity_reverified = False
        # Bounded, secret-free record of any failed terminate/kill control
        # command so evidence never silently claims successful control.
        self._control_errors: list[str] = []

        if self._wait_for_daemon_gone(self._graceful_timeout):
            self._daemon_running = False
            self._process = None
            self._finish_system_stop(
                api_attempted=api_attempted,
                api_result=api_result,
                api_error=api_error,
                launcher_pid_before=launcher_pid_before,
                daemon_pid_before=daemon_pid_before,
                fallbacks=fallbacks,
                identity_reverified=False,
                result="graceful" if api_attempted else "verified_absent",
            )
            return

        # Fallback is only permitted after the *same* daemon identity is
        # immediately re-verified. Otherwise fail closed without touching any
        # process.
        reverify = self._verify_daemon_identity()
        same_identity = reverify.verified and (
            identity_before is None or reverify.identity.pid == identity_before.pid
        )
        if not same_identity:
            self._daemon_running = self._daemon_identity is not None
            self._finish_system_stop(
                api_attempted=api_attempted,
                api_result=api_result,
                api_error=api_error,
                launcher_pid_before=launcher_pid_before,
                daemon_pid_before=daemon_pid_before,
                fallbacks=fallbacks,
                identity_reverified=False,
                result="fail_closed_identity",
            )
            raise ZapStopError(
                self._redact(
                    "refusing terminate/kill: daemon identity could not be "
                    f"immediately re-verified ({reverify.status}: {reverify.reason})"
                )
            )

        target_pid = reverify.identity.pid
        identity_reverified = True

        fallbacks.append("terminate")
        try:
            system.terminate(target_pid)
        except Exception as exc:
            self._control_errors.append(f"terminate: {type(exc).__name__}")
        if self._wait_for_daemon_gone(self._terminate_timeout):
            self._daemon_running = False
            self._process = None
            self._finish_system_stop(
                api_attempted=api_attempted,
                api_result=api_result,
                api_error=api_error,
                launcher_pid_before=launcher_pid_before,
                daemon_pid_before=daemon_pid_before,
                fallbacks=fallbacks,
                identity_reverified=identity_reverified,
                result="terminated",
            )
            return

        # Re-verify once more before the stronger action; never kill an
        # unverified/reused pid.
        reverify_kill = self._verify_daemon_identity()
        if not (reverify_kill.verified and reverify_kill.identity.pid == target_pid):
            self._daemon_running = self._daemon_identity is not None
            self._finish_system_stop(
                api_attempted=api_attempted,
                api_result=api_result,
                api_error=api_error,
                launcher_pid_before=launcher_pid_before,
                daemon_pid_before=daemon_pid_before,
                fallbacks=fallbacks,
                identity_reverified=identity_reverified,
                result="fail_closed_identity",
            )
            raise ZapStopError(
                self._redact(
                    "refusing kill: daemon identity could not be re-verified "
                    f"immediately before kill ({reverify_kill.status})"
                )
            )

        fallbacks.append("kill")
        try:
            system.kill(target_pid)
        except Exception as exc:
            self._control_errors.append(f"kill: {type(exc).__name__}")
        if self._wait_for_daemon_gone(self._kill_timeout):
            self._daemon_running = False
            self._process = None
            self._finish_system_stop(
                api_attempted=api_attempted,
                api_result=api_result,
                api_error=api_error,
                launcher_pid_before=launcher_pid_before,
                daemon_pid_before=daemon_pid_before,
                fallbacks=fallbacks,
                identity_reverified=identity_reverified,
                result="killed",
            )
            return

        self._finish_system_stop(
            api_attempted=api_attempted,
            api_result=api_result,
            api_error=api_error,
            launcher_pid_before=launcher_pid_before,
            daemon_pid_before=daemon_pid_before,
            fallbacks=fallbacks,
            identity_reverified=identity_reverified,
            result="failed",
        )
        raise ZapStopError(
            self._redact(
                "ZAP daemon is still alive after API shutdown, terminate, and kill"
            )
        )

    def _finish_system_stop(
        self,
        *,
        api_attempted: bool,
        api_result: Optional[str],
        api_error: Optional[str],
        launcher_pid_before: Optional[int],
        daemon_pid_before: Optional[int],
        fallbacks: list[str],
        identity_reverified: bool,
        result: str,
    ) -> None:
        api_closed, callback_closed = self._port_state(self._final_snapshot)
        daemon_pid_after = (
            self._daemon_identity.pid
            if (self._daemon_identity is not None and self._daemon_running)
            else None
        )
        self._stop_evidence = {
            "mode": "identities_verified",
            "api_attempted": api_attempted,
            "api_result": api_result,
            "api_error": api_error,
            "launcher_pid_before": launcher_pid_before,
            "daemon_pid_before": daemon_pid_before,
            "daemon_pid_after": daemon_pid_after,
            "fallbacks": list(fallbacks),
            "control_errors": list(getattr(self, "_control_errors", [])),
            "identity_reverified": identity_reverified,
            "identity_evidence": (
                self._identity_result.to_evidence(redact=self._redact)
                if self._identity_result is not None
                else None
            ),
            "daemon_running_after": bool(self._daemon_running),
            "api_port_closed": api_closed,
            "callback_port_closed": callback_closed,
            "both_ports_closed": bool(api_closed and callback_closed),
            "launcher_exit_code": self.launcher_exit_code,
            "process_exited": not self._daemon_running,
            "result": result,
        }

    def _attempt_api_shutdown(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            self._get_client().shutdown()
        except Exception:
            # Shutdown is best-effort; fall back to terminate/kill below.
            pass

    def _wait_for_exit(self, process: Any, timeout: float) -> bool:
        deadline = self._clock() + timeout
        max_attempts = max(1, int(math.ceil(timeout / self._poll_interval)))
        for _ in range(max_attempts):
            code = process.poll()
            if code is not None:
                self._last_exit_code = code
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(self._poll_interval)
        code = process.poll()
        if code is not None:
            self._last_exit_code = code
        return code is not None

    @staticmethod
    def _safe_call(func: Callable[[], Any]) -> None:
        try:
            func()
        except OSError:
            pass

    def _close_logs(self) -> None:
        for handle in (self._stdout_handle, self._stderr_handle):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
        self._stdout_handle = None
        self._stderr_handle = None
