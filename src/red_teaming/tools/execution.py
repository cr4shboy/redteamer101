"""Shared bounded, shell-free subprocess execution for discovery adapters.

Design goals:

* never use a shell (``shell=False`` is hard-coded, argv is always a sequence);
* sanitize the child environment so user/home provider configuration, proxies,
  tokens, and API keys cannot be inherited;
* turn missing executables, timeouts, and OS errors into structured outcomes
  rather than uncontrolled exceptions;
* bound retained stdout/stderr to the canonical
  :data:`~red_teaming.recon.models.MAX_TOOL_OUTPUT_CHARS`;
* allow executable lookup and the subprocess call to be injected so adapters are
  fully testable offline with fakes.

This module performs no network activity and nothing at import time.
"""

from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from ..recon.models import MAX_TOOL_OUTPUT_CHARS, ToolRunStatus

__all__ = [
    "DEFAULT_TIMEOUT",
    "ExecutionError",
    "MAX_PARSE_CHARS",
    "MAX_RAW_CHARS",
    "PROCESS_ENV_ALLOWLIST",
    "ProcessOutcome",
    "bound_text",
    "build_sanitized_env",
    "parse_version_text",
    "require_work_dir",
    "resolve_executable",
    "run_process",
    "status_for_outcome",
]

DEFAULT_TIMEOUT = 120.0

#: Maximum number of characters retained from a single untrusted output line.
MAX_RAW_CHARS = 512

#: Hard cap for the parser-facing capture. This is intentionally much larger
#: than the 4096-character retained evidence so parsers can consume complete
#: machine-readable output while stored evidence stays small. Output beyond
#: this cap is marked truncated and must fail closed at the adapter layer.
MAX_PARSE_CHARS = 1024 * 1024

#: Environment variables that may be inherited by a child process. Everything
#: else is dropped, so proxy/token/key-like variables cannot leak by default.
PROCESS_ENV_ALLOWLIST = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)

#: Extra name fragments that must never be inherited (defense in depth).
ENV_DENY_SUBSTRINGS = (
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

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?")


class ExecutionError(ValueError):
    """Invalid execution *configuration* (never used for tool outcomes)."""


def require_work_dir(work_dir: os.PathLike | str) -> Path:
    """Return an absolute, existing work directory or raise ``ExecutionError``."""

    path = Path(os.fspath(work_dir))
    if not path.is_absolute():
        raise ExecutionError("work dir must be an absolute path")
    if not path.is_dir():
        raise ExecutionError("work dir must be an existing directory")
    return path


def build_sanitized_env(
    work_dir: os.PathLike | str,
    *,
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimal child environment with home/config roots redirected.

    Only :data:`PROCESS_ENV_ALLOWLIST` entries (matched case-insensitively) are
    inherited; everything else -- including proxy/token/key-like variables -- is
    dropped. ``HOME``/``USERPROFILE`` and common tool config roots are
    redirected into *work_dir* so per-user provider configuration cannot be
    silently inherited.
    """

    work = require_work_dir(work_dir)
    source = dict(os.environ if base_env is None else base_env)

    allowed = {name.upper() for name in PROCESS_ENV_ALLOWLIST}
    env: dict[str, str] = {}
    for name, value in source.items():
        if name.upper() not in allowed:
            continue
        if any(fragment in name.lower() for fragment in ENV_DENY_SUBSTRINGS):
            continue
        if isinstance(value, str) and value:
            env[name] = value

    env["HOME"] = str(work)
    env["USERPROFILE"] = str(work)
    env["XDG_CONFIG_HOME"] = str(work / "config")
    env["XDG_CACHE_HOME"] = str(work / "cache")
    env["XDG_DATA_HOME"] = str(work / "data")
    env["APPDATA"] = str(work / "appdata")
    env["LOCALAPPDATA"] = str(work / "localappdata")
    return env


def bound_text(value: object, *, max_chars: int = MAX_TOOL_OUTPUT_CHARS) -> tuple[str, bool]:
    """Return *value* as text bounded to *max_chars*, plus a truncation flag."""

    if value is None:
        return "", False
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    elif not isinstance(value, str):
        value = str(value)
    if len(value) > max_chars:
        return value[:max_chars], True
    return value, False


def resolve_executable(
    name: str, *, which: Callable[[str], str | None] = shutil.which
) -> str | None:
    """Resolve *name* to an absolute path, or ``None`` when not found."""

    if not isinstance(name, str) or not name or name != name.strip():
        raise ExecutionError("executable name must be a non-empty string")
    if any(ch in name for ch in ("/", "\\")):
        # A path, not a bare command: require it to already be absolute.
        candidate = Path(name)
        if not candidate.is_absolute():
            raise ExecutionError("executable path must be absolute")
        return str(candidate) if candidate.is_file() else None
    found = which(name)
    if not found or not isinstance(found, str):
        return None
    path = Path(found)
    if not path.is_absolute():
        path = Path(os.path.abspath(os.fspath(path)))
    return str(path)


def parse_version_text(*texts: str | None) -> str | None:
    """Return the first version-like token found in *texts*, else ``None``."""

    for text in texts:
        if not isinstance(text, str):
            continue
        match = _VERSION_RE.search(text)
        if match:
            return match.group(0)
    return None


@dataclass(frozen=True)
class ProcessOutcome:
    """Structured result of one subprocess invocation.

    ``stdout``/``stderr`` are the small, serializable *retained evidence*
    (bounded to ``MAX_TOOL_OUTPUT_CHARS``). ``parse_stdout`` is the larger
    *parser-facing* payload (bounded to :data:`MAX_PARSE_CHARS`) and is
    deliberately excluded from :meth:`to_dict`; when the parser cap is exceeded
    ``parse_truncated`` is set so callers can fail closed.
    """

    argv: tuple[str, ...]
    executable: str
    returncode: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool = False
    error: str | None = None
    parse_stdout: str = ""
    parse_truncated: bool = False

    @property
    def ok(self) -> bool:
        return (
            not self.timed_out
            and self.error is None
            and self.returncode == 0
        )

    @property
    def parser_text(self) -> str:
        """Return the parser-facing payload (falls back to retained stdout)."""

        return self.parse_stdout if self.parse_stdout else self.stdout

    def to_dict(self) -> dict:
        return {
            "argv": list(self.argv),
            "executable": self.executable,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "timed_out": self.timed_out,
            "error": self.error,
        }


def status_for_outcome(outcome: ProcessOutcome) -> ToolRunStatus:
    """Map a process outcome to a canonical tool-run status."""

    if outcome.timed_out:
        return ToolRunStatus.TIMEOUT
    if outcome.error is not None:
        return ToolRunStatus.TOOL_FAILED
    if outcome.returncode != 0:
        return ToolRunStatus.TOOL_FAILED
    return ToolRunStatus.SUCCEEDED


def _validate_argv(argv: object) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise ExecutionError("argv must be a sequence of strings, not a string")
    try:
        args = tuple(argv)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ExecutionError("argv must be a sequence of strings") from exc
    if not args:
        raise ExecutionError("argv must not be empty")
    for arg in args:
        if not isinstance(arg, str) or not arg:
            raise ExecutionError("argv entries must be non-empty strings")
    return args


def _coerce_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else str(value)


def run_process(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: os.PathLike | str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    stdin_text: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    max_output: int = MAX_TOOL_OUTPUT_CHARS,
    parse_max: int = MAX_PARSE_CHARS,
) -> ProcessOutcome:
    """Run *argv* once, without a shell, returning a bounded outcome.

    A timeout, a missing executable, or any other OS error is returned as a
    structured :class:`ProcessOutcome`; it never raises for those conditions.
    Retained evidence is bounded to *max_output*; the parser-facing payload is
    bounded separately to *parse_max*.
    """

    args = _validate_argv(argv)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ExecutionError("timeout must be a positive finite number")
    if not isinstance(env, Mapping):
        raise ExecutionError("env must be a mapping")

    executable = args[0]
    try:
        completed = runner(
            list(args),
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=float(timeout),
            shell=False,
            env=dict(env),
            cwd=str(cwd) if cwd is not None else None,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        full_stdout = _coerce_text(
            getattr(exc, "stdout", None) or getattr(exc, "output", None)
        )
        stdout, stdout_truncated = bound_text(full_stdout, max_chars=max_output)
        parse_stdout, parse_truncated = bound_text(full_stdout, max_chars=parse_max)
        stderr, stderr_truncated = bound_text(
            _coerce_text(getattr(exc, "stderr", None)), max_chars=max_output
        )
        return ProcessOutcome(
            argv=args,
            executable=executable,
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            timed_out=True,
            parse_stdout=parse_stdout,
            parse_truncated=parse_truncated,
        )
    except OSError as exc:
        return ProcessOutcome(
            argv=args,
            executable=executable,
            returncode=None,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            error=type(exc).__name__,
        )

    full_stdout = _coerce_text(getattr(completed, "stdout", None))
    stdout, stdout_truncated = bound_text(full_stdout, max_chars=max_output)
    parse_stdout, parse_truncated = bound_text(full_stdout, max_chars=parse_max)
    stderr, stderr_truncated = bound_text(
        _coerce_text(getattr(completed, "stderr", None)), max_chars=max_output
    )
    returncode = getattr(completed, "returncode", None)
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        returncode = None
    return ProcessOutcome(
        argv=args,
        executable=executable,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        parse_stdout=parse_stdout,
        parse_truncated=parse_truncated,
    )
