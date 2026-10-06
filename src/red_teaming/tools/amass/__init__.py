"""Passive-only Amass ``enum`` discovery adapter (offline-testable)."""

from .adapter import AmassAdapter
from .parsing import (
    DOMAIN_OPTIONS,
    HOST_FIELDS,
    TOOL_NAME,
    accepted_hosts,
    parse_output,
    select_domain_option,
    supports_required_capabilities,
)

__all__ = [
    "DOMAIN_OPTIONS",
    "HOST_FIELDS",
    "TOOL_NAME",
    "AmassAdapter",
    "accepted_hosts",
    "parse_output",
    "select_domain_option",
    "supports_required_capabilities",
]
