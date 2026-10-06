"""Unprivileged network-namespace launch layer for the RECON-002 sandbox.

The sandboxed helper is launched as::

    /usr/bin/unshare --user --map-root-user --net -- \
        /usr/bin/python3 -m red_teaming.recon.netns_helper ...

using only exact absolute binaries. The helper inherits in-memory
``AF_UNIX`` socketpair descriptors via ``pass_fds`` (never filesystem sockets)
and brings up **only** loopback inside the empty network namespace.

This module is Linux/WSL-specific and fails closed with a clear status on any
other platform or when a required capability is missing. It performs no network
activity: it only constructs an argv/environment and (when asked) starts a
child process. The route-table parser is pure and unit-testable everywhere.
"""

from __future__ import annotations

import os
import posixpath
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from . import netpolicy

__all__ = [
    "HELPER_MODULE",
    "IP_PATH",
    "PYTHON_PATH",
    "SandboxConfig",
    "SandboxError",
    "SandboxUnsupported",
    "UNSHARE_FLAGS",
    "UNSHARE_PATH",
    "build_helper_argv",
    "build_helper_env",
    "ensure_sandbox_supported",
    "launch_helper",
    "routes_are_isolated",
    "sandbox_supported",
    "unsafe_route_lines",
]

UNSHARE_PATH = "/usr/bin/unshare"
PYTHON_PATH = "/usr/bin/python3"
IP_PATH = "/usr/sbin/ip"
HELPER_MODULE = "red_teaming.recon.netns_helper"

#: Exact, minimal namespace flags: a user namespace mapped to root and an empty
#: network namespace. No mount/pid/uts/ipc namespaces are requested and no
#: privilege is gained on the host.
UNSHARE_FLAGS = ("--user", "--map-root-user", "--net")

_ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TZ", "TERM")
_ENV_DENY_SUBSTRINGS = (
    "proxy",
    "token",
    "key",
    "secret",
    "passwd",
    "password",
    "credential",
    "auth",
    "private",
)

_VALID_MODES = ("serve", "selftest", "exec")

#: Upper bound on the encoded exec payload handed to the helper.
MAX_EXEC_PAYLOAD = 16 * 1024


class SandboxError(RuntimeError):
    """Base class for sandbox launch failure."""


class SandboxUnsupported(SandboxError):
    """The platform or capability required for the sandbox is unavailable."""


def sandbox_supported() -> bool:
    """Return True when the host can run the unprivileged namespace sandbox."""

    return sys.platform.startswith("linux")


def ensure_sandbox_supported() -> None:
    """Raise :class:`SandboxUnsupported` unless the sandbox can run here."""

    if not sandbox_supported():
        raise SandboxUnsupported(
            f"network-namespace sandbox requires Linux/WSL, not {sys.platform!r}"
        )


def _check_binary(name: str, path: str) -> None:
    if not os.path.isfile(path):
        raise SandboxUnsupported(f"required binary is missing: {name} ({path})")
    if not os.access(path, os.X_OK):
        raise SandboxUnsupported(f"required binary is not executable: {name} ({path})")


def _require_absolute(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SandboxError(f"{name} must be a non-empty path")
    # These are Linux/WSL paths by construction, so validate POSIX absoluteness
    # even when the test process itself runs on Windows (where a Windows-absolute
    # path is also accepted for test convenience).
    if not (posixpath.isabs(value) or os.path.isabs(value)):
        raise SandboxError(f"{name} must be an absolute path")
    return value


def _require_fd(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SandboxError(f"{name} must be a non-negative integer descriptor")
    return value


def _require_port(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise SandboxError(f"{name} must be an in-range TCP/UDP port")
    return value


@dataclass(frozen=True)
class SandboxConfig:
    """Immutable description of one sandboxed helper launch."""

    connect_fd: int
    dns_fd: int
    status_fd: int
    http_port: int
    dns_port: int = netpolicy.UPSTREAM_DNS_PORT
    mode: str = "serve"
    unshare_path: str = UNSHARE_PATH
    python_path: str = PYTHON_PATH
    ip_path: str = IP_PATH
    module: str = HELPER_MODULE
    src_path: Optional[str] = None
    #: Encoded JSON exec payload for ``mode="exec"`` (exact validated tool argv,
    #: cwd, env, stdin/stdout/stderr/status paths, and timeout).
    exec_payload: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "connect_fd", _require_fd("connect_fd", self.connect_fd))
        object.__setattr__(self, "dns_fd", _require_fd("dns_fd", self.dns_fd))
        object.__setattr__(self, "status_fd", _require_fd("status_fd", self.status_fd))
        object.__setattr__(self, "http_port", _require_port("http_port", self.http_port))
        object.__setattr__(self, "dns_port", _require_port("dns_port", self.dns_port))
        if self.mode not in _VALID_MODES:
            raise SandboxError(f"unknown sandbox mode: {self.mode!r}")
        if self.mode == "exec":
            if not isinstance(self.exec_payload, str) or not self.exec_payload:
                raise SandboxError("exec mode requires a non-empty exec_payload")
            if len(self.exec_payload) > MAX_EXEC_PAYLOAD:
                raise SandboxError("exec_payload exceeds the bounded maximum")
        elif self.exec_payload is not None:
            raise SandboxError("exec_payload is only valid in exec mode")
        object.__setattr__(
            self, "unshare_path", _require_absolute("unshare_path", self.unshare_path)
        )
        object.__setattr__(
            self, "python_path", _require_absolute("python_path", self.python_path)
        )
        object.__setattr__(self, "ip_path", _require_absolute("ip_path", self.ip_path))
        if (
            not isinstance(self.module, str)
            or self.module != self.module.strip()
            or not self.module
            or not all(part.isidentifier() for part in self.module.split("."))
        ):
            raise SandboxError("module must be a dotted Python module name")
        if self.src_path is not None:
            object.__setattr__(
                self, "src_path", _require_absolute("src_path", self.src_path)
            )


def build_helper_argv(config: SandboxConfig) -> tuple[str, ...]:
    """Build the exact, shell-free namespace helper argv for *config*."""

    if not isinstance(config, SandboxConfig):
        raise SandboxError("config must be a SandboxConfig")
    argv = [
        config.unshare_path,
        *UNSHARE_FLAGS,
        "--",
        config.python_path,
        "-m",
        config.module,
        "--mode",
        config.mode,
        "--connect-fd",
        str(config.connect_fd),
        "--dns-fd",
        str(config.dns_fd),
        "--status-fd",
        str(config.status_fd),
        "--http-port",
        str(config.http_port),
        "--dns-port",
        str(config.dns_port),
        "--ip-path",
        config.ip_path,
    ]
    if config.exec_payload is not None:
        argv.extend(["--exec-json", config.exec_payload])
    return tuple(argv)


def build_helper_env(
    src_path: str,
    *,
    base_env: Optional[Mapping[str, str]] = None,
    extra: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """Build a minimal helper environment with only the in-tree package importable.

    Proxy/token/key/secret-like variables are never inherited, bytecode writing
    is disabled so no ``__pycache__`` is created under the (9p) source tree, and
    ``PYTHONPATH`` points at the in-tree ``src`` directory so the helper module
    is imported from the project and nowhere else.
    """

    src = _require_absolute("src_path", src_path)
    source = dict(os.environ if base_env is None else base_env)

    env: dict[str, str] = {}
    allowed = {name.upper() for name in _ENV_ALLOWLIST}
    for name, value in source.items():
        if name.upper() not in allowed:
            continue
        if any(fragment in name.lower() for fragment in _ENV_DENY_SUBSTRINGS):
            continue
        if isinstance(value, str) and value:
            env[name] = value

    env.setdefault("PATH", "/usr/bin:/bin")
    env["PYTHONPATH"] = src
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault("LANG", "C")
    env.setdefault("LC_ALL", "C")

    if extra:
        for name, value in extra.items():
            if not isinstance(name, str) or not name or not isinstance(value, str):
                raise SandboxError("extra env entries must be string pairs")
            if any(fragment in name.lower() for fragment in _ENV_DENY_SUBSTRINGS):
                raise SandboxError("extra env must not carry proxy/secret-like names")
            env[name] = value
    return env


def launch_helper(
    config: SandboxConfig,
    *,
    popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    base_env: Optional[Mapping[str, str]] = None,
) -> subprocess.Popen:
    """Start the sandboxed helper, inheriting the three IPC descriptors.

    The child receives the descriptors named in *config* with ``pass_fds`` and
    the minimal environment from :func:`build_helper_env`. No shell is used.
    """

    ensure_sandbox_supported()
    if config.src_path is None:
        raise SandboxError("src_path is required to launch the helper")
    _check_binary("unshare", config.unshare_path)
    _check_binary("python", config.python_path)
    _check_binary("ip", config.ip_path)
    argv = build_helper_argv(config)
    env = build_helper_env(config.src_path, base_env=base_env)
    return popen(
        list(argv),
        pass_fds=(config.connect_fd, config.dns_fd, config.status_fd),
        env=env,
        shell=False,
        close_fds=True,
        start_new_session=True,
    )


# ---------------------------------------------------------------------------
# Pure route-table validation (used by the helper after namespace setup)
# ---------------------------------------------------------------------------


def _is_loopback_only_route(line: str) -> bool:
    """Return True only for an acceptable loopback-local route line."""

    if "dev lo" not in line:
        return False
    return line.startswith("local ") or line.startswith("broadcast ")


def unsafe_route_lines(text: object) -> tuple[str, ...]:
    """Return route lines that violate the empty/loopback-only invariant.

    ``ip route show`` prints the main table; inside the empty namespace it is
    empty, and assigning ``1.1.1.1/32`` to loopback adds only a *local-table*
    entry, which never appears here. Any default, gateway, or non-loopback route
    is returned as unsafe so the helper can fail closed.
    """

    if not isinstance(text, str):
        return ("<non-text route output>",)
    unsafe: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("default") or " via " in f" {line} ":
            unsafe.append(line)
            continue
        if not _is_loopback_only_route(line):
            unsafe.append(line)
    return tuple(unsafe)


def routes_are_isolated(ipv4_text: object, ipv6_text: object) -> bool:
    """Return True when neither route table contains a non-loopback route."""

    return not unsafe_route_lines(ipv4_text) and not unsafe_route_lines(ipv6_text)
