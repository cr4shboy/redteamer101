"""Shared, deterministic helpers for turning untrusted candidates into
canonical :class:`~red_teaming.recon.models.DiscoveryObservation` records.

The scope classification and DNS normalization are delegated to the canonical
:class:`~red_teaming.recon.scope.DomainScope` / ``normalize_dns_name`` logic; no
alternate validation exists here. Nothing in this module performs network or
process activity.
"""

from __future__ import annotations

from typing import Mapping

from ..projects.models import ValidationError, normalize_dns_name
from ..recon.models import DiscoveryObservation, ObservationState
from ..recon.scope import EXCLUDED, OUT_OF_SCOPE, DomainScope
from .execution import MAX_RAW_CHARS

__all__ = [
    "MAX_RAW_CHARS",
    "accepted_hosts",
    "classify_candidate",
    "dedupe_observations",
    "provenance",
    "rejected",
    "sanitize_raw",
]

_STATE_PRIORITY = {
    ObservationState.SEED: 0,
    ObservationState.EXCLUDED: 1,
    ObservationState.OUT_OF_SCOPE: 2,
    ObservationState.DISCOVERED: 3,
    ObservationState.REJECTED: 4,
}


def sanitize_raw(text: object, *, limit: int = MAX_RAW_CHARS) -> str:
    """Return bounded text with control characters removed (never empty)."""

    if not isinstance(text, str):
        text = "" if text is None else str(text)
    cleaned = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
    if len(cleaned) > limit:
        return cleaned[:limit] + "..."
    return cleaned or "<nonprintable>"


def provenance(obj: Mapping[str, object], fallback: str) -> str:
    """Return a sanitized provenance string from an untrusted record."""

    value = obj.get("source") if isinstance(obj, Mapping) else None
    if isinstance(value, str) and value.strip():
        return sanitize_raw(value.strip(), limit=128)
    return fallback


def rejected(raw: object, source: str, reason: str) -> DiscoveryObservation:
    """Build a rejected observation with bounded raw evidence."""

    return DiscoveryObservation(
        raw=sanitize_raw(raw),
        source=sanitize_raw(source, limit=128),
        state=ObservationState.REJECTED,
        reason=reason,
    )


def classify_candidate(
    raw: object,
    candidate: object,
    scope: DomainScope,
    *,
    source: str,
) -> DiscoveryObservation:
    """Normalize and classify one untrusted candidate against *scope*."""

    if not isinstance(candidate, str):
        return rejected(raw, source, "invalid_host_type")
    try:
        normalized = normalize_dns_name(candidate)
    except ValidationError:
        return rejected(candidate, source, "malformed_host")

    classification = scope.classify(normalized)
    if classification == EXCLUDED:
        return DiscoveryObservation(
            raw=sanitize_raw(candidate),
            source=sanitize_raw(source, limit=128),
            state=ObservationState.EXCLUDED,
            normalized=normalized,
            reason="excluded",
        )
    if classification == OUT_OF_SCOPE:
        return DiscoveryObservation(
            raw=sanitize_raw(candidate),
            source=sanitize_raw(source, limit=128),
            state=ObservationState.OUT_OF_SCOPE,
            normalized=normalized,
            reason="out_of_scope",
        )
    return DiscoveryObservation(
        raw=sanitize_raw(candidate),
        source=sanitize_raw(source, limit=128),
        state=ObservationState.DISCOVERED,
        normalized=normalized,
        reason="in_scope",
    )


def _split_provenance(value: str) -> set[str]:
    return {part for part in value.split(",") if part}


def _merge(left: DiscoveryObservation, right: DiscoveryObservation) -> DiscoveryObservation:
    merged_sources = sorted(
        _split_provenance(left.source) | _split_provenance(right.source)
    )
    winner = min(
        (left, right),
        key=lambda obs: (_STATE_PRIORITY[obs.state], obs.reason or "", obs.raw),
    )
    return DiscoveryObservation(
        raw=min(left.raw, right.raw),
        source=",".join(merged_sources) or winner.source,
        state=winner.state,
        normalized=winner.normalized,
        reason=winner.reason,
    )


def dedupe_observations(
    observations: object,
) -> tuple[DiscoveryObservation, ...]:
    """Merge duplicate observations deterministically, preserving provenance."""

    merged: dict[str, DiscoveryObservation] = {}
    for observation in observations or ():
        if observation.normalized is not None:
            key = "host:" + observation.normalized
        else:
            key = "rejected:" + observation.raw
        existing = merged.get(key)
        merged[key] = (
            observation if existing is None else _merge(existing, observation)
        )
    return tuple(merged[key] for key in sorted(merged))


def accepted_hosts(
    observations: object,
) -> tuple[str, ...]:
    """Return sorted normalized hostnames that are in-scope and not excluded."""

    return tuple(
        sorted(
            {
                observation.normalized
                for observation in observations or ()
                if observation.state is ObservationState.DISCOVERED
                and observation.normalized is not None
            }
        )
    )
