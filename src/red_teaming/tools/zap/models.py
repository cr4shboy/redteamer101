"""Typed configuration, endpoint, and error models for the ZAP integration.

Only pure parsing/validation happens here: no sockets, no subprocesses, and no
filesystem creation. Secrets (the ZAP API key) are never stored in this module;
callers redact them before composing any human-readable message.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from typing import Mapping, Protocol
from urllib.parse import urlsplit

__all__ = [
    "DEFAULT_API_TIMEOUT",
    "DEFAULT_MIN_ZAP_VERSION",
    "HttpResponse",
    "LOOPBACK_HOSTNAME",
    "MAX_PORT",
    "MIN_PORT",
    "Transport",
    "ZapApiError",
    "ZapApiResultError",
    "ZapConfigError",
    "ZapEndpoint",
    "ZapError",
    "ZapHttpError",
    "ZapResponseError",
    "ZapTransportError",
    "ZapVersionError",
    "compare_versions",
    "parse_version",
    "redact_secret",
    "validate_api_key",
    "version_at_least",
]

#: ZAP version required by default before a scan may proceed.
DEFAULT_MIN_ZAP_VERSION = "2.17.0"

#: Bounded per-request timeout (seconds) for the default runtime transport.
DEFAULT_API_TIMEOUT = 10.0

MIN_PORT = 1
MAX_PORT = 65535

LOOPBACK_HOSTNAME = "localhost"

SUPPORTED_ENDPOINT_SCHEMES = ("http", "https")

_VERSION_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

#: Query parameters that callers may not provide themselves.
RESERVED_PARAM_NAMES = frozenset({"apikey"})

_REDACTED = "***"


class ZapError(Exception):
    """Base class for every ZAP integration error."""


class ZapConfigError(ZapError, ValueError):
    """Invalid configuration: endpoint, API key, executable, or timeouts."""


class ZapApiError(ZapError):
    """Base class for ZAP API failures.

    Implementations guarantee that the API key is never part of ``str()``.
    """


class ZapTransportError(ZapApiError):
    """The transport failed before an HTTP response could be read."""


class ZapHttpError(ZapApiError):
    """The ZAP API returned a non-2xx HTTP status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"ZAP API returned HTTP {status}: {message}")
        self.status = status


class ZapResponseError(ZapApiError):
    """The response body was not UTF-8 JSON with an object root."""


class ZapApiResultError(ZapApiError):
    """ZAP reported an application-level error inside a JSON object."""

    def __init__(self, code: str, message: str) -> None:
        detail = code if not message else f"{code}: {message}"
        super().__init__(f"ZAP API reported an error: {detail}")
        self.code = code
        self.message = message


class ZapVersionError(ZapApiError):
    """The detected ZAP version is below the configured minimum."""


@dataclass(frozen=True)
class HttpResponse:
    """Minimal transport-agnostic HTTP response."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class Transport(Protocol):
    """Injectable HTTP transport used by :class:`ZapApiClient`."""

    def request(self, method: str, url: str, timeout: float) -> HttpResponse:
        """Perform one bounded request and return :class:`HttpResponse`."""


def redact_secret(text: str, secret: str) -> str:
    """Replace every occurrence of *secret* in *text* with ``***``."""

    if not secret:
        return text
    return text.replace(secret, _REDACTED)


def _has_control_characters(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _normalize_loopback_host(host: str) -> str:
    if not isinstance(host, str):
        raise ZapConfigError("endpoint host must be a string")
    if not host or host != host.strip():
        raise ZapConfigError("endpoint host must be non-blank without whitespace")
    if _has_control_characters(host):
        raise ZapConfigError("endpoint host must not contain control characters")

    if host.lower() == LOOPBACK_HOSTNAME:
        return LOOPBACK_HOSTNAME

    candidate = host
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ZapConfigError("endpoint host must be a loopback host") from exc
    if not address.is_loopback:
        raise ZapConfigError("endpoint host must be a loopback host")
    return str(address)


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise ZapConfigError("endpoint port must be an integer")
    if port < MIN_PORT or port > MAX_PORT:
        raise ZapConfigError("endpoint port is out of range")
    return port


@dataclass(frozen=True)
class ZapEndpoint:
    """A validated loopback-only ZAP API endpoint.

    Only ``http``/``https`` schemes, loopback hosts, explicit in-range ports,
    and root paths are accepted. Credentials, queries, and fragments are
    rejected outright.
    """

    scheme: str
    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> "ZapEndpoint":
        if not isinstance(value, str):
            raise ZapConfigError("endpoint must be a string")
        if not value or value != value.strip():
            raise ZapConfigError("endpoint must be non-blank without whitespace")
        if _has_control_characters(value):
            raise ZapConfigError("endpoint must not contain control characters")

        try:
            parts = urlsplit(value)
        except ValueError as exc:  # pragma: no cover - urlsplit is tolerant
            raise ZapConfigError(f"malformed endpoint: {exc}") from exc

        scheme = parts.scheme.lower()
        if scheme not in SUPPORTED_ENDPOINT_SCHEMES:
            raise ZapConfigError("endpoint scheme must be http or https")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ZapConfigError("endpoint must not contain credentials")
        if parts.query or parts.fragment:
            raise ZapConfigError("endpoint must not contain a query or fragment")
        if parts.path not in ("", "/"):
            raise ZapConfigError("endpoint must not contain a path")

        host = parts.hostname
        if not host:
            raise ZapConfigError("endpoint has no host")
        try:
            port = parts.port
        except ValueError as exc:
            raise ZapConfigError("endpoint has an invalid port") from exc
        if port is None:
            raise ZapConfigError("endpoint must include an explicit port")

        return cls(
            scheme=scheme,
            host=_normalize_loopback_host(host),
            port=_validate_port(port),
        )

    @classmethod
    def from_host_port(
        cls, host: str, port: int, *, scheme: str = "http"
    ) -> "ZapEndpoint":
        normalized_scheme = scheme.lower() if isinstance(scheme, str) else scheme
        if normalized_scheme not in SUPPORTED_ENDPOINT_SCHEMES:
            raise ZapConfigError("endpoint scheme must be http or https")
        return cls(
            scheme=normalized_scheme,
            host=_normalize_loopback_host(host),
            port=_validate_port(port),
        )

    @property
    def base_url(self) -> str:
        host = self.host
        if ":" in host:
            host = f"[{host}]"
        return f"{self.scheme}://{host}:{self.port}"

    def __str__(self) -> str:
        return self.base_url


def validate_api_key(api_key: str) -> str:
    """Return a validated API key or raise :class:`ZapConfigError`."""

    if not isinstance(api_key, str):
        raise ZapConfigError("API key must be a string")
    if not api_key or api_key != api_key.strip():
        raise ZapConfigError("API key must be non-blank without surrounding whitespace")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in api_key):
        raise ZapConfigError("API key must not contain whitespace or control characters")
    return api_key


def parse_version(value: str) -> tuple[int, ...]:
    """Parse the leading dotted-integer components of a version string."""

    if not isinstance(value, str):
        raise ZapConfigError("version must be a string")
    match = _VERSION_RE.match(value)
    if not match:
        raise ZapConfigError(f"invalid version: {value!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0, or 1 comparing two version strings component-wise."""

    left_parts = parse_version(left)
    right_parts = parse_version(right)
    width = max(len(left_parts), len(right_parts))
    left_padded = left_parts + (0,) * (width - len(left_parts))
    right_padded = right_parts + (0,) * (width - len(right_parts))
    return (left_padded > right_padded) - (left_padded < right_padded)


def version_at_least(actual: str, minimum: str) -> bool:
    """Return True when *actual* is greater than or equal to *minimum*."""

    return compare_versions(actual, minimum) >= 0
