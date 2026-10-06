"""Deterministic, fail-closed parsing of Amass ``enum`` JSON output.

All input is untrusted. Amass may emit a single JSON array, a single JSON
object, or newline-delimited JSON objects; all three are handled
deterministically. Only documented hostname fields are treated as candidates,
and malformed/out-of-scope records are retained as observations.
"""

from __future__ import annotations

import json

from ...recon.models import DiscoveryObservation
from ...recon.scope import DomainScope
from ..help_text import has_options, select_option
from ..observations import (
    accepted_hosts,
    classify_candidate,
    dedupe_observations,
    rejected,
    sanitize_raw,
)

__all__ = [
    "DOMAIN_OPTIONS",
    "HOST_FIELDS",
    "TOOL_NAME",
    "accepted_hosts",
    "parse_output",
    "select_domain_option",
    "supports_required_capabilities",
]

TOOL_NAME = "amass"

#: Documented JSON object fields carrying a discovered hostname.
HOST_FIELDS = ("name", "hostname")

#: Supported domain-option spellings, in preference order.
DOMAIN_OPTIONS = ("-d", "-domain")


def select_domain_option(help_text: object) -> str | None:
    """Return the exact domain option Amass advertises, or ``None``."""

    return select_option(help_text, DOMAIN_OPTIONS)


def supports_required_capabilities(help_text: object) -> bool:
    """Return True when Amass ``enum`` help advertises passive JSON support.

    Pinned Amass 5.1.1 has no ``-json`` flag; JSON output is produced via the
    ``-oA`` output prefix (which writes ``<prefix>.json``).
    """

    return (
        has_options(help_text, ("-passive", "-oA"))
        and select_domain_option(help_text) is not None
    )


def _record_source(record: dict) -> str:
    value = record.get("sources")
    if isinstance(value, list):
        parts = sorted(
            {
                sanitize_raw(item.strip(), limit=128)
                for item in value
                if isinstance(item, str) and item.strip()
            }
        )
        if parts:
            return ",".join(parts)
    if isinstance(value, str) and value.strip():
        return sanitize_raw(value.strip(), limit=128)
    return TOOL_NAME


def _parse_record(raw: str, record: object, scope: DomainScope) -> DiscoveryObservation:
    if not isinstance(record, dict):
        return rejected(raw, TOOL_NAME, "non_object")

    host = None
    for field in HOST_FIELDS:
        if field in record:
            host = record[field]
            break
    if host is None:
        return rejected(raw, TOOL_NAME, "missing_host")
    if not isinstance(host, str):
        return rejected(raw, TOOL_NAME, "invalid_host_type")

    return classify_candidate(host, host, scope, source=_record_source(record))


def _parse_json_line(line: str, scope: DomainScope) -> DiscoveryObservation:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return rejected(line, TOOL_NAME, "invalid_json")
    return _parse_record(line, record, scope)


def parse_output(text: object, scope: DomainScope) -> tuple[DiscoveryObservation, ...]:
    """Parse Amass JSON output (array, object, or JSON Lines) into observations."""

    if not isinstance(text, str):
        return ()

    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        observations = [
            _parse_json_line(line, scope)
            for line in text.splitlines()
            if line.strip()
        ]
        return dedupe_observations(observations)

    observations = []
    if isinstance(document, list):
        for item in document:
            raw = json.dumps(item, ensure_ascii=False, sort_keys=True)
            observations.append(_parse_record(raw, item, scope))
    elif isinstance(document, dict):
        raw = json.dumps(document, ensure_ascii=False, sort_keys=True)
        observations.append(_parse_record(raw, document, scope))
    else:
        observations.append(rejected(repr(document), TOOL_NAME, "non_object"))
    return dedupe_observations(observations)
