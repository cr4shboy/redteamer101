"""Passive-only Subfinder discovery adapter (offline-testable)."""

from .adapter import SubfinderAdapter
from .parsing import (
    HOST_FIELDS,
    REQUIRED_CAPABILITY_MARKERS,
    TOOL_NAME,
    accepted_hosts,
    parse_json_lines,
    supports_required_capabilities,
)

__all__ = [
    "HOST_FIELDS",
    "REQUIRED_CAPABILITY_MARKERS",
    "TOOL_NAME",
    "SubfinderAdapter",
    "accepted_hosts",
    "parse_json_lines",
    "supports_required_capabilities",
]
