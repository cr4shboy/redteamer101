"""Production sandbox runner: the only way RECON-002 launches a pinned tool.

The runner is a ``subprocess.run``-compatible callable. It:

1. **independently validates** the argv against the exact permitted inspection
   or live form (:mod:`red_teaming.recon.tool_argv`); anything else is refused
   before any process is started;
2. builds a sanitized, run-local environment (redirected ``HOME``/XDG roots and,
   for live Subfinder/Amass, only a process-local loopback ``HTTP_PROXY``/
   ``HTTPS_PROXY`` with an empty ``NO_PROXY``);
3. launches the in-namespace helper, which executes the exact tool argv inside
   the empty network namespace; and
4. serves the helper's IPC channels with either the real outer
   :class:`~red_teaming.recon.egress_broker.EgressBroker` (live discovery) or a
   deny-only broker (inspection), so the running tool can never reach the network
   except through the policy-checked broker.

On timeout the entire ``unshare``/helper/tool process group is terminated and a
``subprocess.TimeoutExpired`` is raised so the existing adapter layer records a
structured timeout. No shell is ever used.

Every dependency (launch, broker, ports, clock, status reader) is injectable so
the runner is fully offline-testable with fakes.
"""

from __future__ import annotations

import json
import os
import posixpath
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import ipc, netpolicy
from .netpolicy import RECON_002_POLICY
from .netns_sandbox import SandboxConfig, launch_helper
from .tool_argv import LIVE, ArgvError, ToolCommandSpec, classify_argv

__all__ = [
    "DenyBroker",
    "HelperOutcome",
    "SandboxRunnerError",
    "SandboxToolRunner",
    "ToolScopedBroker",
    "allowed_channels_for",
    "default_helper_runner",
]

_DEADLINE_SLACK = 15.0
_STATUS_POLL = 0.2
_ENV_DENY_SUBSTRINGS = (
    "token",
    "secret",
    "passwd",
    "password",
    "credential",
    "private",
    "api_key",
    "apikey",
)


class SandboxRunnerError(OSError):
    """An invalid or failed sandbox invocation (mapped to a tool failure)."""


@dataclass
class HelperOutcome:
    """Child-side result collected by the helper runner."""

    returncode: Optional[int]
    events: tuple[dict, ...] = ()
    timed_out: bool = False


class DenyBroker:
    """An inspection-only broker that opens no external socket and denies all.

    It speaks the same bounded IPC as the real broker so version/help inspection
    cannot accidentally depend on any external egress path.
    """

    def __init__(self, *, policy=RECON_002_POLICY) -> None:
        self._policy = policy
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._events: list[dict] = []
        self._lock = threading.Lock()

    def get_events(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def _record(self, action: str, decision: str, **fields) -> None:
        with self._lock:
            self._events.append({"component": "broker", "action": action, "decision": decision, **fields})

    def serve(self, connect_sock, dns_sock, stop_event=None) -> list[threading.Thread]:
        event = stop_event if stop_event is not None else self._stop
        self._threads = [
            threading.Thread(target=self.serve_connect, args=(connect_sock, event), daemon=True),
            threading.Thread(target=self.serve_dns, args=(dns_sock, event), daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        return self._threads

    def serve_connect(self, sock, event) -> None:
        self._serve_connect(sock, event)

    def serve_dns(self, sock, event) -> None:
        self._serve_dns(sock, event)

    def stop(self) -> None:
        self._stop.set()

    def _serve_connect(self, sock, event) -> None:
        try:
            sock.settimeout(_STATUS_POLL)
        except (OSError, AttributeError):
            pass
        while not event.is_set():
            try:
                payload, _fd = ipc.recv_message_fd(sock)
            except socket.timeout:
                continue
            except (ipc.IpcClosed, OSError):
                break
            except ipc.IpcError:
                break
            try:
                host, port = ipc.decode_connect_request(payload)
                self._record("connect", "denied", host=host, port=port)
                ipc.send_fd_message(sock, ipc.encode_connect_response(False, "denied"))
            except (ipc.IpcError, OSError):
                break

    def _serve_dns(self, sock, event) -> None:
        try:
            sock.settimeout(_STATUS_POLL)
        except (OSError, AttributeError):
            pass
        while not event.is_set():
            try:
                payload = ipc.recv_frame(sock)
            except socket.timeout:
                continue
            except (ipc.IpcClosed, OSError):
                break
            except ipc.IpcError:
                break
            if payload is None:
                break
            try:
                protocol, _query = ipc.decode_dns_request(payload)
                name = "udp" if protocol == netpolicy.DNS_PROTO_UDP else "tcp"
                self._record("dns", "denied", protocol=name)
                ipc.send_frame(sock, ipc.encode_dns_response(protocol, ipc.STATUS_DENIED))
            except (ipc.IpcError, OSError):
                break


def _kill_process_group(proc) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
    except (OSError, AttributeError):  # pragma: no cover - fall back below
        pass
    try:
        proc.kill()
    except OSError:  # pragma: no cover - defensive
        pass


#: IPC channels a tool identity may use.
_CONNECT_CHANNEL = "connect"
_DNS_CHANNEL = "dns"


def allowed_channels_for(tool: str, invocation: str) -> frozenset[str]:
    """Return the exact external-egress channels a tool identity may use.

    Live Subfinder/Amass may use only the broker CONNECT channel (``crt.sh:443``)
    and may never relay DNS; live dnsx may use only the target DNS relay channel
    and may never CONNECT; every inspection and every other identity may use
    neither. This is chosen from the exact tool name and invocation class.
    """

    if invocation != LIVE:
        return frozenset()
    if tool in ("subfinder", "amass"):
        return frozenset({_CONNECT_CHANNEL})
    if tool == "dnsx":
        return frozenset({_DNS_CHANNEL})
    return frozenset()


class ToolScopedBroker:
    """Serve exactly the egress channels allowed for one tool identity.

    Each disallowed channel is served by a deny-only handler, so a tool can never
    reach the external connector or upstream DNS client for a channel it is not
    entitled to use. Inspection identities allow neither channel.
    """

    def __init__(
        self,
        *,
        tool: str,
        invocation: str,
        policy=RECON_002_POLICY,
        egress=None,
    ) -> None:
        self._tool = tool
        self._invocation = invocation
        self._policy = policy
        self._allowed = allowed_channels_for(tool, invocation)
        self._egress = None
        if self._allowed:
            if egress is not None:
                self._egress = egress
            else:
                from .egress_broker import EgressBroker

                self._egress = EgressBroker(policy=policy)
        self._deny = DenyBroker(policy=policy)
        self._stop = threading.Event()

    @property
    def allowed_channels(self) -> frozenset[str]:
        return self._allowed

    def channel_owner(self, channel: str) -> str:
        """Return ``"egress"`` or ``"deny"`` for one IPC channel."""

        return "egress" if channel in self._allowed else "deny"

    def get_events(self) -> list:
        events: list = []
        if self._egress is not None:
            events.extend(self._egress.get_events())
        events.extend(self._deny.get_events())
        return events

    def serve(self, connect_sock, dns_sock, stop_event=None):
        event = stop_event if stop_event is not None else self._stop
        threads = [
            threading.Thread(
                target=self._serve_connect, args=(connect_sock, event), daemon=True
            ),
            threading.Thread(
                target=self._serve_dns, args=(dns_sock, event), daemon=True
            ),
        ]
        for thread in threads:
            thread.start()
        return threads

    def _serve_connect(self, sock, event) -> None:
        if _CONNECT_CHANNEL in self._allowed:
            self._egress.serve_connect(sock, event)
        else:
            self._deny.serve_connect(sock, event)

    def _serve_dns(self, sock, event) -> None:
        if _DNS_CHANNEL in self._allowed:
            self._egress.serve_dns(sock, event)
        else:
            self._deny.serve_dns(sock, event)

    def stop(self) -> None:
        self._stop.set()
        if self._egress is not None:
            self._egress.stop()
        self._deny.stop()


def default_helper_runner(config: SandboxConfig, status_parent, deadline: float) -> HelperOutcome:
    """Launch the helper and collect its status events until exit or *deadline*."""

    proc = launch_helper(config)
    events: list[dict] = []
    timed_out = False
    try:
        status_parent.settimeout(_STATUS_POLL)
    except (OSError, AttributeError):
        pass
    try:
        while True:
            if time.monotonic() > deadline:
                timed_out = True
                break
            try:
                payload = ipc.recv_frame(status_parent)
            except socket.timeout:
                if proc.poll() is not None:
                    break
                continue
            except (ipc.IpcClosed, OSError):
                break
            if payload is None:
                break
            try:
                event = ipc.decode_status_event(payload)
            except ipc.IpcProtocolError:
                continue
            events.append(event)
            if event.get("event") == "stopped":
                break
            if proc.poll() is not None:
                # Drain any remaining frames quickly, then stop.
                status_parent.settimeout(0.05)
        if timed_out:
            _kill_process_group(proc)
        try:
            proc.wait(timeout=5.0)
        except Exception:
            _kill_process_group(proc)
    finally:
        returncode = proc.poll()
        if returncode is None:
            _kill_process_group(proc)
            try:
                proc.wait(timeout=5.0)
            except Exception:  # pragma: no cover - defensive
                pass
            returncode = proc.poll()
    return HelperOutcome(
        returncode=returncode, events=tuple(events), timed_out=timed_out
    )


def _free_loopback_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def _default_src_path() -> str:
    # .../src/red_teaming/recon/runner.py -> .../src
    return os.fspath(Path(__file__).resolve().parents[2])


def _strip_proxy_and_secrets(env: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for name, value in env.items():
        lowered = name.lower()
        if any(bad in lowered for bad in _ENV_DENY_SUBSTRINGS):
            continue
        if name.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"):
            continue
        if "proxy" in lowered:
            continue
        cleaned[name] = value
    return cleaned


#: The one fixed POSIX system directory used to resolve Amass's known internal
#: launcher. Static analysis of pinned Amass 5.1.1 shows ``main.startEngine``
#: runs ``exec.Command("nohup", <absolute-pinned-amass>, "engine")``: the pinned
#: binary is already absolute, and the bare command resolved through PATH is the
#: system ``nohup``. ``/usr/bin`` is the minimal fixed directory that provides it.
AMASS_LAUNCHER_PATH = "/usr/bin/nohup"
AMASS_LAUNCHER_DIR = "/usr/bin"


def _default_launcher_is_executable(path: Path) -> bool:
    """Return True only for an existing, executable launcher file."""

    return path.is_file() and os.access(path, os.X_OK)


def _amass_launcher_directory(
    *, is_executable: Callable[[Path], bool] = _default_launcher_is_executable
) -> str:
    """Return the fixed process-local ``PATH`` directory for pinned Amass.

    Pinned Amass 5.1.1 starts its internal engine before it parses ``enum`` flags
    by running ``nohup <absolute-pinned-amass> engine``. The pinned binary is
    already passed by absolute path, so the only bare command that must resolve
    through ``PATH`` is the fixed system launcher ``/usr/bin/nohup``.

    For Amass only, the child ``PATH`` is therefore replaced with exactly
    ``/usr/bin`` (never inherited or prepended, never the pinned-install or
    Windows directories). This is ephemeral per-invocation wiring, not a
    persistent ``PATH``/shell/config change. It fails closed unless the exact
    launcher path exists and is executable. The executable predicate is
    injectable so this wiring is testable off-platform.
    """

    if not AMASS_LAUNCHER_PATH.startswith("/") or not AMASS_LAUNCHER_DIR.startswith("/"):
        raise SandboxRunnerError("amass launcher paths must be absolute POSIX paths")
    if posixpath.dirname(AMASS_LAUNCHER_PATH) != AMASS_LAUNCHER_DIR:
        raise SandboxRunnerError(
            "amass launcher is not in the expected system directory"
        )
    if not is_executable(Path(AMASS_LAUNCHER_PATH)):
        raise SandboxRunnerError(
            "amass launcher must exist and be executable for process-local PATH wiring"
        )
    return AMASS_LAUNCHER_DIR


class SandboxToolRunner:
    """``subprocess.run``-compatible runner that executes one pinned tool."""

    def __init__(
        self,
        *,
        spec: ToolCommandSpec,
        work_dir: os.PathLike | str,
        src_path: Optional[str] = None,
        timeout: float = 120.0,
        policy=RECON_002_POLICY,
        broker_factory: Optional[Callable[[str], object]] = None,
        helper_runner: Optional[Callable[[SandboxConfig, socket.socket, float], HelperOutcome]] = None,
        port_factory: Callable[[], int] = _free_loopback_port,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        evidence: Optional[list] = None,
        http_port: Optional[int] = None,
        dns_port: Optional[int] = None,
        amass_launcher_check: Optional[Callable[[Path], bool]] = None,
    ) -> None:
        if not isinstance(spec, ToolCommandSpec):
            raise SandboxRunnerError("spec must be a ToolCommandSpec")
        self._spec = spec
        self._work_dir = Path(os.fspath(work_dir))
        if not self._work_dir.is_absolute():
            raise SandboxRunnerError("work dir must be an absolute path")
        # Amass-specific, process-local PATH wiring. Computed once and validated
        # eagerly so a missing/non-executable launcher fails closed before launch.
        # The executable predicate is injectable for off-platform tests only.
        self._amass_child_path: Optional[str] = None
        if spec.tool == "amass":
            launcher_kwargs = {}
            if amass_launcher_check is not None:
                launcher_kwargs["is_executable"] = amass_launcher_check
            self._amass_child_path = _amass_launcher_directory(**launcher_kwargs)
        self._src_path = src_path
        self._timeout = float(timeout)
        self._policy = policy
        self._broker_factory = broker_factory
        self._helper_runner = helper_runner or default_helper_runner
        self._port_factory = port_factory
        self._clock = clock
        self._sleep = sleep
        self._evidence = evidence if evidence is not None else []
        self._http_port = http_port
        self._dns_port = dns_port if dns_port is not None else policy.upstream_dns_port

    # -- introspection ------------------------------------------------------

    @property
    def spec(self) -> ToolCommandSpec:
        return self._spec

    @property
    def evidence(self) -> list:
        return self._evidence

    # -- subprocess.run compatible entry point ------------------------------

    def __call__(self, argv, **kwargs):
        args = tuple(argv) if not isinstance(argv, (str, bytes)) else (argv,)
        try:
            invocation = classify_argv(self._spec, args)
        except ArgvError as exc:
            raise SandboxRunnerError("recon-sandbox: refused argv") from exc

        timeout = float(kwargs.get("timeout", self._timeout))
        if not (timeout > 0):
            raise SandboxRunnerError("recon-sandbox: invalid timeout")
        base_env = kwargs.get("env") or {}
        if not isinstance(base_env, dict):
            base_env = dict(base_env)
        stdin_text = kwargs.get("input")

        return self._invoke(
            invocation=invocation,
            argv=args,
            timeout=timeout,
            base_env=base_env,
            stdin_text=stdin_text,
        )

    # -- orchestration ------------------------------------------------------

    def _broker_for(self, invocation: str):
        if self._broker_factory is not None:
            return self._broker_factory(invocation)
        if invocation != LIVE:
            return DenyBroker(policy=self._policy)
        return ToolScopedBroker(
            tool=self._spec.tool, invocation=invocation, policy=self._policy
        )

    def _invoke(self, *, invocation: str, argv, timeout: float, base_env: dict, stdin_text):
        work = self._work_dir
        if not work.is_dir():
            raise SandboxRunnerError("recon-sandbox: work dir is not an existing directory")
        sandbox_dir = work / "_sandbox"
        sandbox_dir.mkdir(exist_ok=True)
        stdout_path = sandbox_dir / "stdout.bin"
        stderr_path = sandbox_dir / "stderr.bin"
        status_path = sandbox_dir / "status.json"
        stdin_path = sandbox_dir / "stdin.bin"

        http_port = self._http_port if self._http_port is not None else self._port_factory()
        env = _strip_proxy_and_secrets(dict(base_env))
        if self._amass_child_path is not None:
            # Amass only: replace (never inherit/prepend) the child PATH with the
            # fixed system directory that resolves the known internal launcher
            # (``/usr/bin/nohup``). Applies to both inspection and live
            # invocations; subfinder/dnsx are untouched. See
            # _amass_launcher_directory for the static-evidence note.
            env["PATH"] = self._amass_child_path
        if invocation == LIVE and self._spec.tool in ("subfinder", "amass"):
            endpoint = f"http://127.0.0.1:{http_port}"
            env["HTTP_PROXY"] = endpoint
            env["HTTPS_PROXY"] = endpoint
            env["NO_PROXY"] = ""

        if stdin_text is not None:
            stdin_path.write_bytes(str(stdin_text).encode("utf-8"))
            stdin_value = str(stdin_path)
        else:
            stdin_value = None

        # Remove any stale outputs so a failed run cannot read old evidence.
        for stale in (stdout_path, stderr_path, status_path):
            try:
                stale.unlink()
            except OSError:
                pass

        payload = {
            "argv": [str(item) for item in argv],
            "cwd": str(work),
            "env": env,
            "stdin_path": stdin_value,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "status_path": str(status_path),
            "timeout": float(timeout),
        }

        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        connect_parent, connect_child = socket.socketpair()
        dns_parent, dns_child = socket.socketpair()
        status_parent, status_child = socket.socketpair()
        broker = None
        deadline = self._clock() + timeout + _DEADLINE_SLACK
        outcome: Optional[HelperOutcome] = None
        try:
            broker = self._broker_for(invocation)
            broker.serve(connect_parent, dns_parent)
            config = SandboxConfig(
                connect_fd=connect_child.fileno(),
                dns_fd=dns_child.fileno(),
                status_fd=status_child.fileno(),
                http_port=int(http_port),
                dns_port=int(self._dns_port),
                mode="exec",
                src_path=self._src_path or _default_src_path(),
                exec_payload=encoded,
            )
            try:
                outcome = self._helper_runner(config, status_parent, deadline)
            finally:
                for child in (connect_child, dns_child, status_child):
                    try:
                        child.close()
                    except OSError:
                        pass
        finally:
            if broker is not None:
                try:
                    broker.stop()
                except Exception:  # pragma: no cover - defensive
                    pass
            for sock in (connect_parent, dns_parent, status_parent):
                try:
                    sock.close()
                except OSError:
                    pass

        self._record_evidence(invocation, argv, broker, outcome)
        return self._assemble(
            outcome, stdout_path, stderr_path, status_path, timeout, args=argv
        )

    # -- helpers ------------------------------------------------------------

    def _record_evidence(self, invocation: str, argv, broker, outcome) -> None:
        events: list[dict] = []
        if broker is not None and hasattr(broker, "get_events"):
            events = list(broker.get_events())
        helper_events = list(outcome.events) if outcome is not None else []
        sandbox = next(
            (event for event in helper_events if event.get("event") == "ready"), None
        )
        self._evidence.append(
            {
                "tool": self._spec.tool,
                "invocation": invocation,
                "argv": [str(item) for item in argv],
                "helper_returncode": None if outcome is None else outcome.returncode,
                "helper_timed_out": bool(outcome.timed_out) if outcome else False,
                "helper_events": helper_events,
                "sandbox": sandbox,
                "broker_events": events,
            }
        )

    def _assemble(self, outcome, stdout_path, stderr_path, status_path, timeout, *, args):
        stdout = _read_text(stdout_path)
        stderr = _read_text(stderr_path)
        status = _read_status(status_path)
        if status is not None:
            if status.get("error"):
                raise SandboxRunnerError(
                    f"recon-sandbox: tool launch failed: {status.get('error')}"
                )
            if status.get("timed_out"):
                exc = subprocess.TimeoutExpired(list(args), timeout, output=stdout, stderr=stderr)
                raise exc
            returncode = status.get("exit_code")
        else:
            returncode = None if outcome is None else outcome.returncode
        if returncode is None:
            returncode = 1
        return subprocess.CompletedProcess(list(args), int(returncode), stdout=stdout, stderr=stderr)


def _read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8", "replace")
    except OSError:
        return ""


def _read_status(path: Path) -> Optional[dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None
