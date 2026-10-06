"""Offline, bounded facts derived from a supplied HTTP Server header.

These facts describe what a response *reported*. They do not verify the server
implementation, patch level, or vulnerability status. No network access occurs.
The caller owns the source observation; ``source_id`` is an opaque label, not a
durable evidence reference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..projects.models import ValidationError, normalize_dns_name

__all__ = ["WebServerFingerprint", "fingerprint_server_header"]

_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PRODUCT = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_FIRST_TOKEN = re.compile(
    r"([A-Za-z][A-Za-z0-9._-]{0,63})"
    r"(?:/([A-Za-z0-9][A-Za-z0-9._+-]{0,63}))?(?=\s|\Z)"
)
_SCHEMES = frozenset(("http", "https"))
_STATUSES = frozenset(("reported", "unknown"))


@dataclass(frozen=True)
class WebServerFingerprint:
    """One source-bound statement about a single in-scope web endpoint."""

    host: str
    scheme: str
    port: int
    source_id: str
    status: str
    claimed_product: str | None = None
    claimed_version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", normalize_dns_name(self.host))
        if not isinstance(self.scheme, str) or self.scheme not in _SCHEMES:
            raise ValidationError("fingerprint scheme must be http or https")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValidationError("fingerprint port must be in 1..65535")
        if not isinstance(self.source_id, str) or not _SOURCE_ID.fullmatch(self.source_id):
            raise ValidationError("fingerprint source_id must be an opaque identifier")
        if not isinstance(self.status, str) or self.status not in _STATUSES:
            raise ValidationError("fingerprint status must be reported or unknown")
        if self.status == "unknown":
            if self.claimed_product is not None or self.claimed_version is not None:
                raise ValidationError("unknown fingerprint cannot claim a product or version")
        elif (
            not isinstance(self.claimed_product, str)
            or not _PRODUCT.fullmatch(self.claimed_product)
            or (
                self.claimed_version is not None
                and (
                    not isinstance(self.claimed_version, str)
                    or not _VERSION.fullmatch(self.claimed_version)
                )
            )
        ):
            raise ValidationError("reported fingerprint has an invalid product or version")

    @property
    def identity(self) -> tuple[str, str, int, str]:
        return (self.host, self.scheme, self.port, self.source_id)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "source_id": self.source_id,
            "status": self.status,
            "claimed_product": self.claimed_product,
            "claimed_version": self.claimed_version,
        }


def fingerprint_server_header(
    *,
    host: str,
    scheme: str,
    port: int,
    source_id: str,
    server_header: str | None,
) -> WebServerFingerprint:
    """Extract only a bounded first product token; never retain raw headers."""

    common = {"host": host, "scheme": scheme, "port": port, "source_id": source_id}
    if server_header is None:
        return WebServerFingerprint(**common, status="unknown")
    if not isinstance(server_header, str):
        raise ValidationError("server_header must be a string or None")
    if (
        len(server_header) > 256
        or any(ord(char) < 32 or ord(char) == 127 for char in server_header)
        or server_header != server_header.strip()
    ):
        return WebServerFingerprint(**common, status="unknown")
    match = _FIRST_TOKEN.match(server_header)
    if match is None:
        return WebServerFingerprint(**common, status="unknown")
    return WebServerFingerprint(
        **common,
        status="reported",
        claimed_product=match.group(1),
        claimed_version=match.group(2),
    )
