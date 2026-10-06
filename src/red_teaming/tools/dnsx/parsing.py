"""Deterministic, fail-closed parsing for the dnsx adapter.

Two pure functions live here:

* :func:`prepare_candidates` revalidates and deduplicates caller-supplied
  candidate hostnames against the single-root scope before any execution;
* :func:`parse_json_lines` parses untrusted dnsx JSON Lines output into canonical
  :class:`~red_teaming.recon.models.DnsResolution` records plus rejected/scope
  observations.

Invalid IP/CNAME values never reach canonical records. An external CNAME target
is retained as evidence only and is never promoted to a candidate or asset.
"""

from __future__ import annotations

import json

from ...projects.models import ValidationError, normalize_dns_name
from ...recon.models import (
    DiscoveryObservation,
    DnsRecords,
    DnsResolution,
    ResolutionStatus,
)
from ...recon.scope import IN_SCOPE, DomainScope
from ..execution import ExecutionError
from ..help_text import has_options
from ..observations import (
    classify_candidate,
    dedupe_observations,
    rejected,
)

__all__ = [
    "HOST_FIELDS",
    "REQUIRED_CAPABILITY_MARKERS",
    "TOOL_NAME",
    "parse_json_lines",
    "prepare_candidates",
    "supports_required_capabilities",
]

TOOL_NAME = "dnsx"

#: Documented JSON object field carrying the queried hostname.
HOST_FIELDS = ("host",)

#: Capability markers that must appear in the tool's own help output.
REQUIRED_CAPABILITY_MARKERS = ("-json", "-a", "-aaaa", "-cname")


def supports_required_capabilities(help_text: object) -> bool:
    """Return True when *help_text* advertises the required exact JSON options."""

    return has_options(help_text, REQUIRED_CAPABILITY_MARKERS)


def prepare_candidates(
    candidates: object, scope: DomainScope
) -> tuple[tuple[str, ...], tuple[DiscoveryObservation, ...]]:
    """Return sorted in-scope hostnames plus observations for rejected inputs.

    Every candidate is re-normalized and re-validated against *scope*; excluded,
    out-of-scope, and malformed inputs are retained as observations and never
    passed to the tool.
    """

    if candidates is None:
        return (), ()
    if isinstance(candidates, (str, bytes)):
        raise ExecutionError("candidates must be a sequence of hostnames, not a string")
    try:
        items = tuple(candidates)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ExecutionError("candidates must be a sequence of hostnames") from exc

    accepted: set[str] = set()
    observations: list[DiscoveryObservation] = []
    for value in items:
        if not isinstance(value, str):
            observations.append(rejected(repr(value), TOOL_NAME, "invalid_host_type"))
            continue
        try:
            normalized = normalize_dns_name(value)
        except ValidationError:
            observations.append(rejected(value, TOOL_NAME, "malformed_host"))
            continue
        if scope.classify(normalized) == IN_SCOPE:
            accepted.add(normalized)
        else:
            observations.append(
                classify_candidate(value, value, scope, source=TOOL_NAME)
            )
    return tuple(sorted(accepted)), dedupe_observations(observations)


def _status(record: dict, dns: DnsRecords) -> ResolutionStatus:
    if dns.a or dns.aaaa or dns.cname:
        return ResolutionStatus.RESOLVED
    code = record.get("status_code")
    if isinstance(code, str) and code.strip().upper() == "NXDOMAIN":
        return ResolutionStatus.NXDOMAIN
    return ResolutionStatus.UNRESOLVED


def _parse_line(
    line: str, scope: DomainScope
) -> tuple[DiscoveryObservation | None, DnsResolution | None]:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return rejected(line, TOOL_NAME, "invalid_json"), None
    if not isinstance(record, dict):
        return rejected(line, TOOL_NAME, "non_object"), None

    host = record.get("host")
    if host is None:
        return rejected(line, TOOL_NAME, "missing_host"), None
    if not isinstance(host, str):
        return rejected(line, TOOL_NAME, "invalid_host_type"), None
    try:
        normalized = normalize_dns_name(host)
    except ValidationError:
        return rejected(host, TOOL_NAME, "malformed_host"), None

    classification = scope.classify(normalized)
    if classification != IN_SCOPE:
        return classify_candidate(host, host, scope, source=TOOL_NAME), None

    try:
        dns = DnsRecords(
            a=record.get("a", ()),
            aaaa=record.get("aaaa", ()),
            cname=record.get("cname", ()),
        )
    except ValidationError:
        return rejected(json.dumps(record, ensure_ascii=False, sort_keys=True), TOOL_NAME, "invalid_dns_records"), None

    return None, DnsResolution(
        hostname=normalized, status=_status(record, dns), dns=dns
    )


def _merge_resolutions(left: DnsResolution, right: DnsResolution) -> DnsResolution:
    combined = DnsRecords(
        a=set(left.dns.a) | set(right.dns.a),
        aaaa=set(left.dns.aaaa) | set(right.dns.aaaa),
        cname=set(left.dns.cname) | set(right.dns.cname),
    )
    statuses = {left.status, right.status}
    if ResolutionStatus.RESOLVED in statuses:
        status = ResolutionStatus.RESOLVED
    elif ResolutionStatus.NXDOMAIN in statuses:
        status = ResolutionStatus.NXDOMAIN
    else:
        status = ResolutionStatus.UNRESOLVED
    return DnsResolution(hostname=left.hostname, status=status, dns=combined)


def _dedupe_resolutions(
    resolutions: list[DnsResolution],
) -> tuple[DnsResolution, ...]:
    merged: dict[str, DnsResolution] = {}
    for resolution in resolutions:
        existing = merged.get(resolution.hostname)
        merged[resolution.hostname] = (
            resolution
            if existing is None
            else _merge_resolutions(existing, resolution)
        )
    return tuple(merged[host] for host in sorted(merged))


def parse_json_lines(
    text: object, scope: DomainScope
) -> tuple[tuple[DiscoveryObservation, ...], tuple[DnsResolution, ...]]:
    """Parse untrusted dnsx JSON Lines output.

    Returns ``(observations, resolutions)``. Malformed lines/records are
    retained as ``rejected`` observations; canonical resolutions never contain
    invalid DNS or IP data.
    """

    if not isinstance(text, str):
        return (), ()
    observations: list[DiscoveryObservation] = []
    resolutions: list[DnsResolution] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        observation, resolution = _parse_line(line, scope)
        if observation is not None:
            observations.append(observation)
        if resolution is not None:
            resolutions.append(resolution)
    return dedupe_observations(observations), _dedupe_resolutions(resolutions)
