"""Deterministic, fail-closed parsing of Subfinder JSON Lines output.

All input is untrusted. Records are line-delimited JSON objects; only the
documented ``host`` field is treated as a candidate hostname. Malformed or
out-of-scope records are retained as observations and are never accepted as
candidates.
"""

from __future__ import annotations

import json

from ...recon.models import DiscoveryObservation
from ...recon.scope import DomainScope
from ..help_text import has_options
from ..observations import (
    accepted_hosts,
    classify_candidate,
    dedupe_observations,
    provenance,
    rejected,
)

__all__ = [
    "HOST_FIELDS",
    "REQUIRED_CAPABILITY_MARKERS",
    "TOOL_NAME",
    "accepted_hosts",
    "parse_json_lines",
    "supports_required_capabilities",
]

TOOL_NAME = "subfinder"

#: Documented JSON object field carrying the discovered hostname.
HOST_FIELDS = ("host",)

#: Capability markers that must appear in the tool's own help output. The JSON
#: Lines output mode and the silent/non-interactive flags are required.
REQUIRED_CAPABILITY_MARKERS = ("-json", "-silent", "-d")


def supports_required_capabilities(help_text: object) -> bool:
    """Return True when *help_text* advertises every required exact option."""

    return has_options(help_text, REQUIRED_CAPABILITY_MARKERS)


def _parse_line(line: str, scope: DomainScope) -> DiscoveryObservation:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return rejected(line, TOOL_NAME, "invalid_json")

    if not isinstance(record, dict):
        return rejected(line, TOOL_NAME, "non_object")

    host = None
    for field in HOST_FIELDS:
        if field in record:
            host = record[field]
            break
    if host is None:
        return rejected(line, TOOL_NAME, "missing_host")
    if not isinstance(host, str):
        return rejected(line, TOOL_NAME, "invalid_host_type")

    return classify_candidate(
        host, host, scope, source=provenance(record, TOOL_NAME)
    )


def parse_json_lines(
    text: object, scope: DomainScope
) -> tuple[DiscoveryObservation, ...]:
    """Parse authoritative Subfinder JSON Lines output into observations.

    Blank lines are skipped. Duplicate hostnames are merged deterministically
    while preserving provenance; malformed records are retained as ``rejected``
    observations. The result never includes out-of-scope or excluded hosts as
    accepted candidates (see :func:`accepted_hosts`).
    """

    if not isinstance(text, str):
        return ()
    observations: list[DiscoveryObservation] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        observations.append(_parse_line(line, scope))
    return dedupe_observations(observations)
