"""Bounded, active ffuf subdomain-fuzzing adapter (offline-testable)."""

from .adapter import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAXTIME,
    DEFAULT_RATE,
    DEFAULT_THREADS,
    SCHEME,
    FfufAdapter,
)
from .parsing import (
    REQUIRED_CAPABILITY_MARKERS,
    RESULT_FIELD,
    TOOL_NAME,
    parse_ffuf_output,
    supports_required_capabilities,
)

__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_MAXTIME",
    "DEFAULT_RATE",
    "DEFAULT_THREADS",
    "REQUIRED_CAPABILITY_MARKERS",
    "RESULT_FIELD",
    "SCHEME",
    "TOOL_NAME",
    "FfufAdapter",
    "parse_ffuf_output",
    "supports_required_capabilities",
]
