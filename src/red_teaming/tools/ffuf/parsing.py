"""Deterministic, fail-closed parsing of ffuf subdomain-fuzzing JSON output.

All input is untrusted. ffuf written with ``-of json`` emits a single JSON
object with a ``results`` array; ffuf's ``-json`` stdout mode emits
newline-delimited result objects. Both shapes are handled deterministically.
Only documented hostname evidence (``host``, then the ``url`` host, then the
reconstructed ``<FUZZ>.<root>`` from the fuzz keyword) is treated as a candidate,
and malformed/out-of-scope records are retained as observations only.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from ...recon.models import DiscoveryObservation
from ...recon.scope import DomainScope
from ..help_text import has_options
from ..observations import classify_candidate, dedupe_observations, rejected

__all__ = [
    "REQUIRED_CAPABILITY_MARKERS",
    "RESULT_FIELD",
    "TOOL_NAME",
    "parse_ffuf_output",
    "supports_required_capabilities",
]

TOOL_NAME = "ffuf"

#: JSON object field carrying the array of matched results in ``-of json`` mode.
RESULT_FIELD = "results"

#: Capability markers that must appear in the tool's own help output. These are
#: the core wordlist/URL/output flags required to drive a bounded, file-based
#: subdomain-fuzzing run.
REQUIRED_CAPABILITY_MARKERS = ("-w", "-u", "-o", "-of")


def supports_required_capabilities(help_text: object) -> bool:
    """Return True when *help_text* advertises the required exact ffuf options."""

    return has_options(help_text, REQUIRED_CAPABILITY_MARKERS)


def _extract_host(record: dict, scope: DomainScope) -> str | None:
    """Return the discovered hostname from one ffuf result record, or ``None``.

    Preference order: the documented ``host`` field, then the host component of
    the result ``url``, then a reconstruction of ``<FUZZ>.<root>`` from the
    substituted fuzz keyword. The reconstruction keeps a result usable even when
    ffuf reports only the input word.
    """

    host = record.get("host")
    if isinstance(host, str) and host.strip():
        return host.strip()

    url = record.get("url")
    if isinstance(url, str) and url.strip():
        hostname = urlsplit(url.strip()).hostname
        if hostname:
            return hostname

    inputs = record.get("input")
    if isinstance(inputs, dict):
        fuzz = inputs.get("FUZZ")
        if isinstance(fuzz, str) and fuzz.strip() and scope.roots:
            return f"{fuzz.strip()}.{scope.roots[0].name}"
    return None


def _parse_result(raw: str, record: object, scope: DomainScope) -> DiscoveryObservation:
    if not isinstance(record, dict):
        return rejected(raw, TOOL_NAME, "non_object")
    host = _extract_host(record, scope)
    if host is None:
        return rejected(raw, TOOL_NAME, "missing_host")
    return classify_candidate(host, host, scope, source=TOOL_NAME)


def _parse_json_line(line: str, scope: DomainScope) -> DiscoveryObservation:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return rejected(line, TOOL_NAME, "invalid_json")
    return _parse_result(line, record, scope)


def _results_from_document(document: object) -> list:
    """Return the list of result records from a parsed ffuf document.

    A ``-of json`` document is an object whose ``results`` key holds the array.
    A bare array (defensive) is treated as the result list directly. A single
    object without ``results`` is treated as one result record.
    """

    if isinstance(document, dict):
        if RESULT_FIELD in document:
            value = document[RESULT_FIELD]
            return list(value) if isinstance(value, list) else [value]
        return [document]
    if isinstance(document, list):
        return list(document)
    return [document]


def parse_ffuf_output(text: object, scope: DomainScope) -> tuple[DiscoveryObservation, ...]:
    """Parse ffuf JSON output (``-of json`` object or ``-json`` lines).

    Returns observations only; canonical in-scope hostnames are reported as
    ``DISCOVERED`` observations, while out-of-scope, excluded, and malformed
    records are retained as evidence and never promoted to candidates.
    """

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
    for item in _results_from_document(document):
        raw = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        observations.append(_parse_result(raw, item, scope))
    return dedupe_observations(observations)
