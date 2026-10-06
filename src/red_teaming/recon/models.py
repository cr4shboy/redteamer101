"""Canonical, offline-only models for scope intake and asset discovery.

Nothing in this module resolves DNS, opens a socket, launches a subprocess, or
touches the filesystem. Every model is a frozen dataclass that normalizes and
validates its inputs on construction and exposes a deterministic, JSON-ready
``to_dict``.

The DNS object is evidence only. In particular, CNAME targets (which may point
outside the authorized scope) are stored as data and there is deliberately no
mechanism here that turns them into :class:`Asset` records.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from enum import Enum

from ..projects.models import ValidationError, normalize_dns_name

__all__ = [
    "MAX_TOOL_OUTPUT_CHARS",
    "SCHEMA_VERSION",
    "Asset",
    "AssetKind",
    "DiscoveryObservation",
    "DnsRecords",
    "DnsResolution",
    "ObservationState",
    "ResolutionStatus",
    "ToolResult",
    "ToolRunStatus",
]

#: Schema version stamped into every JSON document produced by this package.
SCHEMA_VERSION = 1

#: Maximum number of characters retained from a tool's stdout/stderr.
MAX_TOOL_OUTPUT_CHARS = 4096


class _StringEnum(str, Enum):
    """A ``str`` enum that validates untrusted input via :meth:`parse`."""

    @classmethod
    def parse(cls, value: object) -> "_StringEnum":
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValidationError(f"invalid {cls.__name__}: {value!r}")
        try:
            return cls(value)
        except ValueError as exc:
            raise ValidationError(f"invalid {cls.__name__}: {value!r}") from exc


class ObservationState(_StringEnum):
    """Lifecycle state of a discovery observation."""

    SEED = "seed"
    DISCOVERED = "discovered"
    EXCLUDED = "excluded"
    OUT_OF_SCOPE = "out_of_scope"
    REJECTED = "rejected"


class ResolutionStatus(_StringEnum):
    """Whether an asset's hostname resolved."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    NXDOMAIN = "nxdomain"


class AssetKind(_StringEnum):
    """Whether an asset is an authorized root or one of its subdomains."""

    ROOT_DOMAIN = "root_domain"
    SUBDOMAIN = "subdomain"


class ToolRunStatus(_StringEnum):
    """Outcome of one external discovery-tool invocation."""

    SUCCEEDED = "succeeded"
    TOOL_NOT_AVAILABLE = "tool_not_available"
    TOOL_FAILED = "tool_failed"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise ValidationError(f"{label} must not contain surrounding whitespace")
    return value


def _iter_strings(values: object, label: str) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValidationError(f"{label} must be an iterable of strings, not a string")
    try:
        items = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValidationError(f"{label} must be an iterable of strings") from exc
    return tuple(_require_text(item, label) for item in items)


def _normalize_sources(sources: object) -> tuple[str, ...]:
    return tuple(sorted(set(_iter_strings(sources, "source"))))


def _normalize_argv(argv: object) -> tuple[str, ...]:
    # Argument order is meaningful for a command line, so it is preserved.
    return _iter_strings(argv, "argv element")


def _normalize_ip_values(values: object, version: int) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValidationError("IP records must be an iterable of strings, not a string")
    try:
        items = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValidationError("IP records must be an iterable of strings") from exc

    unique: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
    for value in items:
        if not isinstance(value, str):
            raise ValidationError("IP record must be a string")
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValidationError(f"invalid IP address: {value!r}") from exc
        if address.version != version:
            raise ValidationError(f"expected an IPv{version} address: {value!r}")
        unique[str(address)] = address
    ordered = sorted(unique.items(), key=lambda item: item[1].packed)
    return tuple(text for text, _ in ordered)


def _normalize_cname_values(values: object) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValidationError(
            "CNAME records must be an iterable of strings, not a string"
        )
    try:
        items = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValidationError("CNAME records must be an iterable of strings") from exc

    unique: set[str] = set()
    for value in items:
        if not isinstance(value, str):
            raise ValidationError("CNAME record must be a string")
        unique.add(normalize_dns_name(value))
    return tuple(sorted(unique))


def _bound_output(value: object) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if not isinstance(value, str):
        raise ValidationError("tool output must be a string or None")
    if len(value) > MAX_TOOL_OUTPUT_CHARS:
        return value[:MAX_TOOL_OUTPUT_CHARS], True
    return value, False


def _validate_exit_code(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("exit code must be an integer or None")
    return value


@dataclass(frozen=True)
class DnsRecords:
    """Deterministic, deduplicated DNS evidence for one hostname."""

    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "a", _normalize_ip_values(self.a, 4))
        object.__setattr__(self, "aaaa", _normalize_ip_values(self.aaaa, 6))
        object.__setattr__(self, "cname", _normalize_cname_values(self.cname))

    @property
    def has_cname(self) -> bool:
        return bool(self.cname)

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "a": list(self.a),
            "aaaa": list(self.aaaa),
            "cname": list(self.cname),
        }


@dataclass(frozen=True)
class DnsResolution:
    """Canonical DNS-resolution result for one hostname.

    The DNS records are evidence only: an external CNAME target is retained in
    :class:`DnsRecords` but is never promoted to a candidate or asset.
    """

    hostname: str
    status: ResolutionStatus
    dns: DnsRecords = field(default_factory=DnsRecords)

    def __post_init__(self) -> None:
        object.__setattr__(self, "hostname", normalize_dns_name(self.hostname))
        object.__setattr__(self, "status", ResolutionStatus.parse(self.status))
        if not isinstance(self.dns, DnsRecords):
            raise ValidationError("dns must be a DnsRecords instance")

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "hostname": self.hostname,
            "status": self.status.value,
            "dns": self.dns.to_dict(),
        }


@dataclass(frozen=True)
class DiscoveryObservation:
    """One raw candidate hostname and how it was classified."""

    raw: str
    source: str
    state: ObservationState
    normalized: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw", _require_text(self.raw, "raw hostname"))
        object.__setattr__(self, "source", _require_text(self.source, "source"))
        object.__setattr__(self, "state", ObservationState.parse(self.state))
        if self.normalized is not None:
            object.__setattr__(self, "normalized", normalize_dns_name(self.normalized))
        if self.reason is not None:
            object.__setattr__(self, "reason", _require_text(self.reason, "reason"))

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "raw": self.raw,
            "source": self.source,
            "state": self.state.value,
            "normalized": self.normalized,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Asset:
    """A canonical discovered host with its DNS evidence and resolution state."""

    hostname: str
    kind: AssetKind
    sources: tuple[str, ...] = ()
    dns: DnsRecords = field(default_factory=DnsRecords)
    resolution_status: ResolutionStatus = ResolutionStatus.UNRESOLVED

    def __post_init__(self) -> None:
        object.__setattr__(self, "hostname", normalize_dns_name(self.hostname))
        object.__setattr__(self, "kind", AssetKind.parse(self.kind))
        object.__setattr__(self, "sources", _normalize_sources(self.sources))
        object.__setattr__(
            self,
            "resolution_status",
            ResolutionStatus.parse(self.resolution_status),
        )
        if not isinstance(self.dns, DnsRecords):
            raise ValidationError("dns must be a DnsRecords instance")

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "hostname": self.hostname,
            "kind": self.kind.value,
            "sources": list(self.sources),
            "dns": self.dns.to_dict(),
            "resolution_status": self.resolution_status.value,
        }


@dataclass(frozen=True)
class ToolResult:
    """Structured result of one external discovery-tool invocation.

    This is a record only; it never executes the tool. There are deliberately no
    credential/secret fields.
    """

    tool: str
    status: ToolRunStatus
    executable: str | None = None
    version: str | None = None
    argv: tuple[str, ...] = ()
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    observations: tuple[DiscoveryObservation, ...] = ()
    errors: tuple[str, ...] = ()
    resolutions: tuple[DnsResolution, ...] = ()
    timeout: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool", _require_text(self.tool, "tool"))
        object.__setattr__(self, "status", ToolRunStatus.parse(self.status))
        if self.executable is not None:
            object.__setattr__(
                self, "executable", _require_text(self.executable, "executable")
            )
        if self.version is not None:
            object.__setattr__(self, "version", _require_text(self.version, "version"))
        object.__setattr__(self, "argv", _normalize_argv(self.argv))
        object.__setattr__(self, "exit_code", _validate_exit_code(self.exit_code))

        stdout, stdout_was_truncated = _bound_output(self.stdout)
        stderr, stderr_was_truncated = _bound_output(self.stderr)
        object.__setattr__(self, "stdout", stdout)
        object.__setattr__(self, "stderr", stderr)
        object.__setattr__(
            self, "stdout_truncated", bool(self.stdout_truncated or stdout_was_truncated)
        )
        object.__setattr__(
            self, "stderr_truncated", bool(self.stderr_truncated or stderr_was_truncated)
        )

        observations = tuple(self.observations or ())
        for observation in observations:
            if not isinstance(observation, DiscoveryObservation):
                raise ValidationError(
                    "observations must contain DiscoveryObservation instances"
                )
        object.__setattr__(self, "observations", observations)

        resolutions = tuple(self.resolutions or ())
        for resolution in resolutions:
            if not isinstance(resolution, DnsResolution):
                raise ValidationError(
                    "resolutions must contain DnsResolution instances"
                )
        object.__setattr__(self, "resolutions", resolutions)
        object.__setattr__(self, "errors", _iter_strings(self.errors, "error"))

        if self.timeout is not None:
            if (
                isinstance(self.timeout, bool)
                or not isinstance(self.timeout, (int, float))
                or not math.isfinite(self.timeout)
                or self.timeout <= 0
            ):
                raise ValidationError(
                    "timeout must be a positive finite number or None"
                )
            object.__setattr__(self, "timeout", float(self.timeout))

    @property
    def succeeded(self) -> bool:
        return self.status is ToolRunStatus.SUCCEEDED

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": self.tool,
            "status": self.status.value,
            "executable": self.executable,
            "version": self.version,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "observations": [observation.to_dict() for observation in self.observations],
            "resolutions": [resolution.to_dict() for resolution in self.resolutions],
            "errors": list(self.errors),
            "timeout": self.timeout,
        }
