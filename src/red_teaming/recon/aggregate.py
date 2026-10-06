"""Deterministic, per-root aggregation of discovery and DNS results.

Aggregation is pure and offline. It:

* starts every root with an explicit ``scope`` seed asset;
* consumes only *successful* tool results (via the success-gated helpers);
* re-normalizes and re-validates every accepted hostname against the
  single-root scope (defense in depth);
* deduplicates by hostname with sorted **tool-level** provenance
  (``scope``/``subfinder``/``amass``), not provider-config names;
* keeps excluded/out_of_scope/rejected observations as evidence but never sends
  them to DNS;
* applies only successful dnsx resolutions to matching candidates; external
  CNAME targets stay in that asset's DNS evidence and never become candidates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..recon.models import (
    Asset,
    AssetKind,
    DiscoveryObservation,
    DnsResolution,
    ObservationState,
    ToolResult,
    ToolRunStatus,
)
from ..recon.scope import DomainScope
from ..tools.acceptance import (
    accepted_hosts_from_result,
    accepted_resolutions_from_result,
)
from ..tools.observations import classify_candidate, dedupe_observations

__all__ = [
    "SEED_SOURCE",
    "DiscoveryAggregate",
    "aggregate_discovery",
    "build_assets",
    "seed_observation",
]

#: Tool-level provenance label for the root seed.
SEED_SOURCE = "scope"


class AggregateError(ValueError):
    """Raised when aggregation is asked to mix roots or misuse a result."""


@dataclass(frozen=True)
class DiscoveryAggregate:
    """Deterministic in-scope candidates, per-host provenance, and evidence."""

    root: str
    provenance: tuple[tuple[str, tuple[str, ...]], ...]
    observations: tuple[DiscoveryObservation, ...]
    candidates: tuple[str, ...]


def _single_root(scope: DomainScope) -> str:
    if not isinstance(scope, DomainScope):
        raise AggregateError("scope must be a DomainScope")
    if len(scope.roots) != 1:
        raise AggregateError("aggregation requires a single-root scope")
    return scope.roots[0].name


def seed_observation(scope: DomainScope) -> DiscoveryObservation:
    """Return the explicit seed observation for the scope's root."""

    root = _single_root(scope)
    return DiscoveryObservation(
        raw=root,
        source=SEED_SOURCE,
        state=ObservationState.SEED,
        normalized=root,
        reason="seed",
    )


def aggregate_discovery(
    scope: DomainScope, results: Mapping[str, ToolResult]
) -> DiscoveryAggregate:
    """Merge successful discovery results into deterministic candidates.

    *results* maps a **tool-level** name (for example ``"subfinder"``) to its
    :class:`ToolResult`. Observations from every result are retained as
    evidence; only hosts from successful results become candidates.
    """

    root = _single_root(scope)
    provenance: dict[str, set[str]] = {root: {SEED_SOURCE}}
    observations: list[DiscoveryObservation] = [seed_observation(scope)]

    for tool_name in sorted(results):
        result = results[tool_name]
        if not isinstance(result, ToolResult):
            raise AggregateError(f"result for {tool_name!r} must be a ToolResult")
        observations.extend(result.observations)
        if result.status is not ToolRunStatus.SUCCEEDED:
            continue
        for host in accepted_hosts_from_result(result):
            if scope.contains(host):
                provenance.setdefault(host, set()).add(tool_name)
            else:  # pragma: no cover - defense in depth; adapters already filter
                observations.append(
                    classify_candidate(host, host, scope, source=tool_name)
                )

    candidates = tuple(sorted(host for host in provenance if scope.contains(host)))
    ordered_provenance = tuple(
        (host, tuple(sorted(sources))) for host, sources in sorted(provenance.items())
    )
    return DiscoveryAggregate(
        root=root,
        provenance=ordered_provenance,
        observations=dedupe_observations(observations),
        candidates=candidates,
    )


def build_assets(
    scope: DomainScope,
    aggregate: DiscoveryAggregate,
    dnsx_result: ToolResult | None = None,
) -> tuple[Asset, ...]:
    """Build canonical assets, applying only successful dnsx resolutions."""

    root = _single_root(scope)
    if not isinstance(aggregate, DiscoveryAggregate):
        raise AggregateError("aggregate must be a DiscoveryAggregate")
    if aggregate.root != root:
        raise AggregateError(
            f"aggregate root {aggregate.root!r} does not match scope root {root!r}"
        )
    for host, _sources in aggregate.provenance:
        if not scope.contains(host):
            raise AggregateError(
                f"provenance host is not in scope for {root!r}: {host!r}"
            )

    resolutions: dict[str, DnsResolution] = {}
    if dnsx_result is not None:
        if not isinstance(dnsx_result, ToolResult):
            raise AggregateError("dnsx_result must be a ToolResult or None")
        if dnsx_result.status is ToolRunStatus.SUCCEEDED:
            for resolution in accepted_resolutions_from_result(dnsx_result):
                if scope.contains(resolution.hostname):
                    resolutions[resolution.hostname] = resolution

    assets: list[Asset] = []
    for host, sources in aggregate.provenance:
        kind = AssetKind.ROOT_DOMAIN if host == root else AssetKind.SUBDOMAIN
        resolution = resolutions.get(host)
        if resolution is not None:
            assets.append(
                Asset(
                    hostname=host,
                    kind=kind,
                    sources=sources,
                    dns=resolution.dns,
                    resolution_status=resolution.status,
                )
            )
        else:
            assets.append(Asset(hostname=host, kind=kind, sources=sources))
    return tuple(sorted(assets, key=lambda asset: asset.hostname))
