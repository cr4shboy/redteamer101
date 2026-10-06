"""Pipeline-facing acceptance helpers.

Adapters always parse partial output for evidence, but these helpers are the
only place that promotes parsed evidence into *accepted* pipeline candidates.
They return nothing unless the tool run actually succeeded, so a failed,
timed-out, unsupported, truncated, or missing-tool run can never be consumed as
discovered hosts or resolutions.
"""

from __future__ import annotations

from ..recon.models import DnsResolution, ToolResult, ToolRunStatus
from .observations import accepted_hosts as _accepted_hosts

__all__ = ["accepted_hosts_from_result", "accepted_resolutions_from_result"]


def _succeeded(result: object) -> bool:
    return isinstance(result, ToolResult) and result.status is ToolRunStatus.SUCCEEDED


def accepted_hosts_from_result(result: object) -> tuple[str, ...]:
    """Return sorted accepted hostnames, only when *result* succeeded."""

    if not _succeeded(result):
        return ()
    return _accepted_hosts(result.observations)


def accepted_resolutions_from_result(result: object) -> tuple[DnsResolution, ...]:
    """Return sorted accepted DNS resolutions, only when *result* succeeded."""

    if not _succeeded(result):
        return ()
    return tuple(sorted(result.resolutions, key=lambda resolution: resolution.hostname))
