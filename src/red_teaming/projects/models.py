"""Domain-neutral input models for projects and targets.

Only string/URL parsing happens here. Validating or normalizing a domain or
target never touches the filesystem, resolves DNS, or opens a socket.

Safety rules implemented in this module:

* only ``http``/``https`` target URLs are accepted;
* userinfo, query strings, and fragments are rejected;
* blank/malformed hosts, IP literals, and traversal-like host input are
  rejected;
* only the scheme-default port (``80``/``443``) is accepted;
* DNS names are lowercased, one trailing dot is removed, and the result is
  IDNA-encoded to ASCII;
* a target host must equal the project domain or be one of its subdomains;
* an explicit URL path is preserved (percent-encoded where required) without
  changing its meaning.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

__all__ = [
    "DEFAULT_PORTS",
    "SUPPORTED_SCHEMES",
    "ProjectDomain",
    "Target",
    "ValidationError",
    "normalize_dns_name",
    "normalize_url_path",
]

SUPPORTED_SCHEMES = ("http", "https")

#: Only the scheme-default port is accepted; any other explicit port is
#: treated as unsupported.
DEFAULT_PORTS = {"http": 80, "https": 443}

_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63
_MIN_LABELS = 2

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ALL_NUMERIC_RE = re.compile(r"^[0-9.]+$")
_ENCODED_DOTDOT_RE = re.compile(r"%2e%2e", re.IGNORECASE)

# Keep reserved path characters and existing percent escapes untouched so the
# semantic meaning of the path is preserved.
_PATH_SAFE = "/!$&'()*+,;=:@-._~%"


class ValidationError(ValueError):
    """Raised when a domain, target URL, or path fails validation."""


def _is_ip_literal(host: str) -> bool:
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def normalize_dns_name(value: str) -> str:
    """Normalize and validate a DNS name.

    The result is lowercase ASCII (IDNA), has no trailing dot, contains at
    least two labels, and only contains valid LDH labels. IP literals,
    whitespace, traversal-like input, and invalid characters are rejected.
    """

    if not isinstance(value, str):
        raise ValidationError("DNS name must be a string")
    if not value:
        raise ValidationError("DNS name is blank")
    if value != value.strip():
        raise ValidationError("DNS name must not contain leading/trailing whitespace")
    if _is_ip_literal(value):
        raise ValidationError("IP literals are not allowed")

    lowered = value.lower()
    if lowered.endswith("."):
        lowered = lowered[:-1]
    if not lowered:
        raise ValidationError("DNS name is blank after removing the trailing dot")
    if ".." in lowered:
        raise ValidationError("DNS name contains an empty label")

    try:
        ascii_name = lowered.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"invalid DNS name: {exc}") from exc

    if len(ascii_name) > _MAX_DOMAIN_LENGTH:
        raise ValidationError("DNS name is too long")

    labels = ascii_name.split(".")
    if len(labels) < _MIN_LABELS:
        raise ValidationError("DNS name must contain at least two labels")
    for label in labels:
        if not label:
            raise ValidationError("DNS name contains an empty label")
        if len(label) > _MAX_LABEL_LENGTH:
            raise ValidationError("DNS label is too long")
        if not _LABEL_RE.match(label):
            raise ValidationError(f"invalid DNS label: {label!r}")

    if _ALL_NUMERIC_RE.match(ascii_name):
        raise ValidationError("IP-like all-numeric hosts are not allowed")

    return ascii_name


def normalize_url_path(path: str) -> str:
    """Normalize a URL path while preserving its semantic meaning.

    Empty paths are returned unchanged. Non-ASCII or otherwise unsafe bytes
    are percent-encoded; existing percent escapes are preserved. Traversal-like
    dot segments are rejected rather than rewritten.
    """

    if not isinstance(path, str):
        raise ValidationError("URL path must be a string")
    if path == "":
        return ""
    if "\\" in path:
        raise ValidationError("URL path must not contain backslashes")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        raise ValidationError("URL path must not contain control characters")
    if not path.startswith("/"):
        raise ValidationError("URL path must be absolute")
    if ".." in path.split("/"):
        raise ValidationError("URL path must not contain '..' segments")
    if _ENCODED_DOTDOT_RE.search(path):
        raise ValidationError("URL path must not contain encoded '..' segments")
    return quote(path, safe=_PATH_SAFE)


@dataclass(frozen=True)
class ProjectDomain:
    """A validated, normalized project domain."""

    name: str

    @classmethod
    def parse(cls, value: str) -> "ProjectDomain":
        return cls(normalize_dns_name(value))

    def contains(self, host: str) -> bool:
        """Return True when *host* is this domain or one of its subdomains."""

        normalized = normalize_dns_name(host)
        return normalized == self.name or normalized.endswith("." + self.name)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass(frozen=True)
class Target:
    """A validated, normalized target within a project domain."""

    domain: str
    scheme: str
    host: str
    port: int
    path: str
    url: str

    @classmethod
    def parse(cls, url: str, domain: "ProjectDomain | str") -> "Target":
        if not isinstance(url, str):
            raise ValidationError("target URL must be a string")
        if not url:
            raise ValidationError("target URL is blank")
        if url != url.strip():
            raise ValidationError("target URL must not contain leading/trailing whitespace")
        if "?" in url or "#" in url:
            raise ValidationError("target URL must not contain a query or fragment")
        if any(ord(ch) < 0x20 for ch in url):
            raise ValidationError("target URL must not contain control characters")

        try:
            parts = urlsplit(url)
        except ValueError as exc:  # pragma: no cover - urlsplit is very tolerant
            raise ValidationError(f"malformed target URL: {exc}") from exc

        scheme = parts.scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            raise ValidationError(f"unsupported URL scheme: {parts.scheme!r}")

        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ValidationError("target URL must not contain userinfo")

        host = parts.hostname
        if not host:
            raise ValidationError("target URL has no host")

        try:
            explicit_port = parts.port
        except ValueError as exc:
            raise ValidationError("target URL has an invalid port") from exc
        if explicit_port is None and parts.netloc.endswith(":"):
            raise ValidationError("target URL has a malformed port")

        expected_port = DEFAULT_PORTS[scheme]
        if explicit_port is not None and explicit_port != expected_port:
            raise ValidationError(f"unsupported port: {explicit_port}")

        normalized_host = normalize_dns_name(host)
        if isinstance(domain, ProjectDomain):
            normalized_domain = domain.name
        else:
            normalized_domain = normalize_dns_name(domain)

        if normalized_host != normalized_domain and not normalized_host.endswith(
            "." + normalized_domain
        ):
            raise ValidationError("target host is not the project domain or a subdomain")

        path = normalize_url_path(parts.path)
        canonical = f"{scheme}://{normalized_host}{path}"

        return cls(
            domain=normalized_domain,
            scheme=scheme,
            host=normalized_host,
            port=expected_port,
            path=path,
            url=canonical,
        )
