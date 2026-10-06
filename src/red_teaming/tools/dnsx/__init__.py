"""Bounded dnsx resolution adapter (offline-testable)."""

from .adapter import DnsxAdapter
from .parsing import (
    HOST_FIELDS,
    REQUIRED_CAPABILITY_MARKERS,
    TOOL_NAME,
    parse_json_lines,
    prepare_candidates,
    supports_required_capabilities,
)

__all__ = [
    "HOST_FIELDS",
    "REQUIRED_CAPABILITY_MARKERS",
    "TOOL_NAME",
    "DnsxAdapter",
    "parse_json_lines",
    "prepare_candidates",
    "supports_required_capabilities",
]
