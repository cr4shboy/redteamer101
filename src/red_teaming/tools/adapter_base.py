"""Shared base class for discovery-tool adapters.

Subclasses own the tool-specific executable name, argv construction, capability
evaluation, and output parsing. This base centralizes single-root scope and
work-dir validation, executable resolution, sanitized-environment construction,
structured local inspection, and mapping a bounded :class:`ProcessOutcome` to a
canonical :class:`~red_teaming.recon.models.ToolResult`.

Nothing here performs network activity or real tool execution; lookup and the
subprocess call are injectable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from ..recon.models import ToolResult, ToolRunStatus
from ..recon.scope import DomainScope
from .execution import (
    DEFAULT_TIMEOUT,
    MAX_PARSE_CHARS,
    ExecutionError,
    ProcessOutcome,
    bound_text,
    build_sanitized_env,
    parse_version_text,
    require_work_dir,
    resolve_executable as _resolve_executable,
    run_process,
    status_for_outcome,
)

__all__ = ["DiscoveryAdapter", "Inspection"]

#: Statuses an inspection may report.
_INSPECTION_STATUSES = frozenset(
    {
        ToolRunStatus.TOOL_NOT_AVAILABLE,
        ToolRunStatus.UNSUPPORTED,
        ToolRunStatus.TIMEOUT,
        ToolRunStatus.TOOL_FAILED,
        ToolRunStatus.SUCCEEDED,
    }
)

#: Maximum number of characters retained in a single inspection warning.
_WARNING_MAX = 256

#: Maximum number of characters retained in a bounded local failure hint.
_HINT_MAX = 120

#: Matches an HTTP(S) URL and its optional query string, so the query is stripped.
_HINT_URL_QUERY_RE = re.compile(r"(?i)(https?://[^\s\"'<>]+)\?[^\s\"'<>]*")
#: Matches secret-like ``key: value`` / ``key=value`` material to redact.
_HINT_SECRET_RE = re.compile(
    r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"authorization|auth|cookie|credential|bearer|session)\b\s*[:=]\s*\S+"
)
#: Matches environment-style ``NAME=value`` assignments to redact.
_HINT_ENV_ASSIGN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}=\S+")
#: Matches control characters (including newlines/tabs) to drop.
_HINT_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
#: Generic parent-side engine health-wait text that must not mask a child error.
_HINT_GENERIC_TIMEOUT_RE = re.compile(
    r"(?i)amass engine did not respond|did not respond within the timeout period"
)
#: Concrete child startup failure/error signals that make a line actionable.
_HINT_ACTIONABLE_RE = re.compile(
    r"(?i)\b("
    r"failed to|error|panic|fatal|exception|"
    r"bind|listen|address already in use|cannot assign requested address|"
    r"database|sqlite|postgres|neo4j|plugin|"
    r"permission denied|no such file|not found|unable to|cannot|"
    r"connection refused|connection reset|dial tcp|executable file"
    r")\b"
)


def _warning(text: str) -> str:
    bounded, _ = bound_text(text, max_chars=_WARNING_MAX)
    return bounded


def _sanitize_hint_line(line: str) -> str:
    """Sanitize one raw output line into a single bounded-safe line."""

    line = _HINT_CONTROL_RE.sub(" ", line)
    line = _HINT_URL_QUERY_RE.sub(r"\1?<redacted>", line)
    line = _HINT_SECRET_RE.sub(r"\1=<redacted>", line)
    line = _HINT_ENV_ASSIGN_RE.sub("<redacted>", line)
    return " ".join(line.split())


def _failure_hint(text: object) -> str:
    """Return a short, sanitized, single-line hint from retained tool output.

    All non-empty retained lines are sanitized (control characters replaced,
    HTTP(S) URL query strings stripped, secret-like key/value and ``NAME=value``
    material redacted). The most actionable line is then selected
    deterministically: the first line that signals a concrete child
    startup/error/panic/bind/listen/database/plugin/permission failure is
    preferred over generic parent-side engine health-timeout text. When no
    concrete signal exists, the first sanitized line is retained as a fallback.

    The result is a single line capped to :data:`_HINT_MAX` characters and never
    contains full help/environment output. It never alters inspection status.
    """

    if not isinstance(text, str) or not text.strip():
        return ""
    lines: list[str] = []
    for raw in text.splitlines():
        candidate = _sanitize_hint_line(raw)
        if candidate:
            lines.append(candidate)
    if not lines:
        return ""
    actionable = [line for line in lines if _HINT_ACTIONABLE_RE.search(line)]
    concrete = [
        line for line in actionable if not _HINT_GENERIC_TIMEOUT_RE.search(line)
    ]
    if concrete:
        return concrete[0][:_HINT_MAX]
    if actionable:
        return actionable[0][:_HINT_MAX]
    return lines[0][:_HINT_MAX]


def _normalize_markers(markers: object) -> tuple[str, ...]:
    """Return a validated, de-duplicated, order-preserving option-token tuple."""

    if isinstance(markers, (str, bytes)):
        raise ExecutionError("required_markers must be an iterable of option tokens")
    try:
        items = tuple(markers)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ExecutionError("required_markers must be an iterable of option tokens") from exc
    ordered: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.startswith("-"):
            raise ExecutionError("required_markers entries must be option tokens")
        if item not in ordered:
            ordered.append(item)
    return tuple(ordered)


@dataclass(frozen=True)
class Inspection:
    """Structured availability/version/capability result for one tool.

    ``status`` is one of ``tool_not_available`` (missing), ``unsupported``
    (present but required capability/option evidence is absent), ``timeout`` or
    ``tool_failed`` (inspection itself failed), or ``succeeded`` (available and
    capability-confirmed).
    """

    tool: str
    status: ToolRunStatus
    executable: str | None = None
    version: str | None = None
    capabilities: tuple[str, ...] = ()
    options: tuple[tuple[str, str], ...] = ()
    reason: str | None = None
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not self.tool:
            raise ExecutionError("inspection tool must be a non-empty string")
        status = ToolRunStatus.parse(self.status)
        if status not in _INSPECTION_STATUSES:
            raise ExecutionError(f"invalid inspection status: {status!r}")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        object.__setattr__(self, "options", tuple(tuple(pair) for pair in self.options))
        warnings = tuple(self.warnings)
        for entry in warnings:
            if not isinstance(entry, str) or not entry:
                raise ExecutionError("inspection warnings must be non-empty strings")
        object.__setattr__(self, "warnings", warnings)

    @property
    def available(self) -> bool:
        return self.status is not ToolRunStatus.TOOL_NOT_AVAILABLE

    @property
    def supported(self) -> bool:
        return self.status is ToolRunStatus.SUCCEEDED

    def option(self, key: str, default: str | None = None) -> str | None:
        for name, value in self.options:
            if name == key:
                return value
        return default

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "status": self.status.value,
            "executable": self.executable,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "options": {key: value for key, value in sorted(self.options)},
            "reason": self.reason,
            "warnings": list(self.warnings),
        }


class DiscoveryAdapter:
    """Base for single-root, offline-testable discovery-tool adapters."""

    TOOL_NAME = ""

    def __init__(
        self,
        *,
        scope: DomainScope,
        work_dir: os.PathLike | str,
        executable: os.PathLike | str | None = None,
        which: Callable[[str], str | None] = shutil.which,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        timeout: float = DEFAULT_TIMEOUT,
        parse_max: int = MAX_PARSE_CHARS,
        required_version: str | None = None,
        required_markers: Sequence[str] | None = None,
        command_spec=None,
        prevalidated_inspection: "Inspection | None" = None,
    ) -> None:
        if not isinstance(scope, DomainScope):
            raise ExecutionError("scope must be a DomainScope")
        if len(scope.roots) != 1:
            raise ExecutionError("adapter requires a single-root scope")

        self._scope = scope
        self._root = scope.roots[0]
        self._work_dir = require_work_dir(work_dir)

        if executable is None:
            self._executable: str | None = None
        else:
            path = os.fspath(executable)
            if not os.path.isabs(path):
                raise ExecutionError("executable path must be absolute")
            self._executable = path

        if command_spec is not None:
            from ..recon.tool_argv import ToolCommandSpec, required_markers_for

            if not isinstance(command_spec, ToolCommandSpec):
                raise ExecutionError("command_spec must be a ToolCommandSpec or None")
            if required_version is None:
                required_version = command_spec.version
            if required_markers is None:
                required_markers = required_markers_for(command_spec)
        if required_version is not None and (
            not isinstance(required_version, str) or not required_version
        ):
            raise ExecutionError("required_version must be a non-empty string or None")
        if required_markers is not None:
            required_markers = _normalize_markers(required_markers)

        self._which = which
        self._runner = runner
        self._timeout = timeout
        self._parse_max = parse_max
        self._required_version = required_version
        self._required_markers = required_markers
        self._command_spec = command_spec
        if prevalidated_inspection is not None and not isinstance(
            prevalidated_inspection, Inspection
        ):
            raise ExecutionError("prevalidated_inspection must be an Inspection or None")
        self._prevalidated_inspection = prevalidated_inspection

    # -- introspection ------------------------------------------------------

    @property
    def scope(self) -> DomainScope:
        return self._scope

    @property
    def root(self):
        return self._root

    @property
    def work_dir(self) -> Path:
        return self._work_dir

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def required_version(self) -> str | None:
        return self._required_version

    @property
    def required_markers(self) -> tuple[str, ...] | None:
        return self._required_markers

    @property
    def command_spec(self):
        return self._command_spec

    @property
    def prevalidated_inspection(self) -> "Inspection | None":
        return self._prevalidated_inspection

    def _validate_cached_inspection(self, cached: "Inspection") -> Inspection:
        """Return *cached* only when it matches this adapter exactly.

        A cached preflight inspection is accepted only when it is a successful
        :class:`Inspection` for this exact tool, the exact resolved executable,
        the pinned version, and every required live capability. Anything else
        fails closed before the live tool is launched.
        """

        if not isinstance(cached, Inspection):
            raise ExecutionError("cached inspection must be an Inspection")
        if cached.tool != self.TOOL_NAME:
            raise ExecutionError("cached inspection tool does not match this adapter")
        if cached.status is not ToolRunStatus.SUCCEEDED:
            raise ExecutionError(
                f"cached inspection is not successful: {cached.status.value}"
            )
        executable = self.resolve_executable()
        if executable is None:
            raise ExecutionError("cached inspection executable cannot be resolved")
        if cached.executable != executable:
            raise ExecutionError("cached inspection executable does not match")
        if (
            self._required_version is not None
            and cached.version != self._required_version
        ):
            raise ExecutionError(
                "cached inspection version does not match the pinned version"
            )
        if self._required_markers:
            missing = [m for m in self._required_markers if m not in cached.capabilities]
            if missing:
                raise ExecutionError(
                    "cached inspection lacks required capabilities: "
                    + ",".join(missing)
                )
        return cached

    def _resolve_inspection(self) -> Inspection:
        """Return the validated preflight inspection, or inspect when absent.

        Production adapters receive the successful preflight inspection so the
        actual tool stage performs exactly one live invocation and never repeats
        the version/help inspection. A missing cache falls back to a fresh local
        inspection (offline fixture behavior); an invalid cache fails closed.
        """

        cached = self._prevalidated_inspection
        if cached is None:
            return self.inspect()
        try:
            return self._validate_cached_inspection(cached)
        except ExecutionError as exc:
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.TOOL_FAILED,
                executable=getattr(cached, "executable", None),
                version=getattr(cached, "version", None),
                reason=f"cached inspection rejected: {exc}",
            )

    def resolve_executable(self) -> str | None:
        """Return the absolute executable path, or ``None`` when unavailable."""

        if self._executable is not None:
            path = Path(self._executable)
            return str(path) if path.is_file() else None
        return _resolve_executable(self.TOOL_NAME, which=self._which)

    # -- execution helpers --------------------------------------------------

    def build_env(self, *, base_env: Mapping[str, str] | None = None) -> dict[str, str]:
        return build_sanitized_env(self._work_dir, base_env=base_env)

    def _run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        stdin_text: str | None = None,
    ) -> ProcessOutcome:
        return run_process(
            argv,
            cwd=self._work_dir,
            env=self.build_env() if env is None else env,
            timeout=self._timeout,
            stdin_text=stdin_text,
            runner=self._runner,
            parse_max=self._parse_max,
        )

    # -- capability inspection (local only) --------------------------------

    def version_argv(self, executable: str) -> tuple[str, ...]:
        """Return the local version-inspection argv (subclasses may override)."""

        return (str(executable), "-version")

    def help_argv(self, executable: str) -> tuple[str, ...]:
        """Return the local help-inspection argv (subclasses may override)."""

        return (str(executable), "-h")

    def evaluate_capabilities(
        self, help_text: str
    ) -> tuple[bool, tuple[str, ...], tuple[tuple[str, str], ...], str | None]:
        """Return ``(supported, capabilities, options, reason)`` for *help_text*.

        Subclasses must implement this using exact option-token matching.
        """

        raise NotImplementedError

    def inspect(self) -> Inspection:
        """Return structured availability/version/capability without discovery.

        Only local version/help commands are executed. Missing tool =>
        ``tool_not_available``; unconfirmed capability => ``unsupported``;
        inspection timeout/failure => ``timeout``/``tool_failed``; otherwise
        ``succeeded``.

        Version inspection is truthful and structured:

        * version timeout => ``timeout`` (help is not consulted);
        * version OS/execution error => ``tool_failed`` (help is not consulted);
        * version nonzero exit => no version captured; a bounded warning is
          recorded and help continues to be evaluated (some tools expose usable
          capabilities despite a nonzero version flag), so status reflects the
          capability result;
        * version output without a parseable token => no version captured; a
          bounded warning is recorded and help continues.

        Capability inspection follows the same truthfulness rule:

        * help timeout/OS error => ``timeout``/``tool_failed``;
        * help nonzero exit => the combined help text is still evaluated
          exactly. Positive evidence for every required option is accepted as
          ``succeeded`` with a bounded warning (some tools print full help and
          exit nonzero); a nonzero exit *without* complete evidence stays
          fail-closed as ``tool_failed`` with a bounded reason. A clean exit
          without complete evidence is ``unsupported``.

        On a nonzero help exit without complete evidence, the ``tool_failed``
        reason also carries a short, sanitized, single-line hint derived from the
        retained stderr (or retained stdout when stderr is empty). The hint is
        length-bounded and strips control characters, URL query strings, and
        secret-like key/value material. It never changes the failure status.
        """

        executable = self.resolve_executable()
        if executable is None:
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.TOOL_NOT_AVAILABLE,
                reason=f"{self.TOOL_NAME} executable not found",
            )

        env = self.build_env()
        warnings: list[str] = []

        version_outcome = self._run(self.version_argv(executable), env=env)
        if version_outcome.timed_out:
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.TIMEOUT,
                executable=executable,
                reason="version inspection timed out",
            )
        if version_outcome.error is not None:
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.TOOL_FAILED,
                executable=executable,
                reason=f"version inspection failed: {version_outcome.error}",
            )

        version = None
        if version_outcome.returncode != 0:
            warnings.append(
                _warning(
                    "version inspection exited with code "
                    f"{version_outcome.returncode}; version was not captured"
                )
            )
        else:
            version = parse_version_text(version_outcome.stdout, version_outcome.stderr)
            if version is None:
                warnings.append(
                    _warning(
                        "version output did not contain a parseable version token; "
                        "version was not captured"
                    )
                )

        if self._required_version is not None and version != self._required_version:
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.UNSUPPORTED,
                executable=executable,
                version=version,
                warnings=tuple(warnings),
                reason=(
                    f"{self.TOOL_NAME} version {version!r} does not match the "
                    f"required pinned version {self._required_version!r}"
                ),
            )

        help_outcome = self._run(self.help_argv(executable), env=env)
        if help_outcome.timed_out:
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.TIMEOUT,
                executable=executable,
                version=version,
                warnings=tuple(warnings),
                reason="capability inspection timed out",
            )
        if help_outcome.error is not None:
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.TOOL_FAILED,
                executable=executable,
                version=version,
                warnings=tuple(warnings),
                reason=f"capability inspection failed: {help_outcome.error}",
            )

        # The combined help text is the authoritative capability evidence and is
        # always evaluated exactly, even when the tool exits nonzero while
        # printing it. Positive evidence is accepted with a bounded warning; a
        # nonzero exit *without* complete evidence stays fail-closed as
        # ``tool_failed`` with a bounded reason (a clean exit without evidence is
        # ``unsupported``). The bounded reason never contains raw help text.
        help_text = help_outcome.stdout + "\n" + help_outcome.stderr
        supported, capabilities, options, reason = self.evaluate_capabilities(help_text)
        if not supported:
            fallback = (
                reason
                or f"{self.TOOL_NAME} does not advertise the required capabilities"
            )
            if help_outcome.returncode != 0:
                warnings.append(
                    _warning(
                        "capability inspection exited with code "
                        f"{help_outcome.returncode}"
                    )
                )
                # A bounded, sanitized local hint (retained stderr, else retained
                # stdout) makes an engine/launcher failure actionable without
                # persisting full help output. It never changes the failed status.
                hint = _failure_hint(help_outcome.stderr) or _failure_hint(
                    help_outcome.stdout
                )
                reason_parts = [
                    "capability inspection failed with exit code "
                    f"{help_outcome.returncode}"
                ]
                if hint:
                    reason_parts.append(f"hint: {hint}")
                reason_parts.append(fallback)
                return Inspection(
                    tool=self.TOOL_NAME,
                    status=ToolRunStatus.TOOL_FAILED,
                    executable=executable,
                    version=version,
                    capabilities=capabilities,
                    options=options,
                    warnings=tuple(warnings),
                    reason=_warning(": ".join(reason_parts)),
                )
            return Inspection(
                tool=self.TOOL_NAME,
                status=ToolRunStatus.UNSUPPORTED,
                executable=executable,
                version=version,
                capabilities=capabilities,
                options=options,
                warnings=tuple(warnings),
                reason=fallback,
            )

        if help_outcome.returncode != 0:
            warnings.append(
                _warning(
                    "capability inspection exited with code "
                    f"{help_outcome.returncode}; required capabilities were "
                    "still advertised"
                )
            )
        return Inspection(
            tool=self.TOOL_NAME,
            status=ToolRunStatus.SUCCEEDED,
            executable=executable,
            version=version,
            capabilities=capabilities,
            options=options,
            warnings=tuple(warnings),
        )

    # -- canonical results --------------------------------------------------

    def _inspection_result(self, inspection: Inspection) -> ToolResult:
        errors = list(inspection.warnings)
        if inspection.reason:
            errors.insert(0, inspection.reason)
        return ToolResult(
            tool=self.TOOL_NAME,
            status=inspection.status,
            executable=inspection.executable,
            version=inspection.version,
            errors=errors,
            timeout=self._timeout,
        )

    def _result(
        self,
        *,
        outcome: ProcessOutcome,
        executable: str,
        version: str | None,
        observations: Sequence = (),
        resolutions: Sequence = (),
        errors: Sequence[str] = (),
        status_override: ToolRunStatus | None = None,
    ) -> ToolResult:
        status = (
            status_override
            if status_override is not None
            else status_for_outcome(outcome)
        )
        return ToolResult(
            tool=self.TOOL_NAME,
            status=status,
            executable=executable,
            version=version,
            argv=outcome.argv,
            exit_code=outcome.returncode,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            stdout_truncated=outcome.stdout_truncated,
            stderr_truncated=outcome.stderr_truncated,
            observations=tuple(observations),
            resolutions=tuple(resolutions),
            errors=tuple(errors),
            timeout=self._timeout,
        )
