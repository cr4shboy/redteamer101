"""One-request HTTP metadata adapter; this module has no socket transport.

The injected transport is responsible for enforcing the request contract and
network egress. Until such a transport is composed, this is an offline adapter,
not a production target-fetch path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ...intel.fingerprint import WebServerFingerprint, fingerprint_server_header
from ...projects.models import Target, ValidationError
from ...recon.scope import DomainScope

MAX_SERVER_HEADER_CHARS = 256
REQUEST_TIMEOUT_SECONDS = 10.0


class HttpFetchError(ValueError):
    """The injected transport or its bounded metadata failed validation."""


@dataclass(frozen=True)
class FetchRequest:
    method: str
    url: str
    timeout_seconds: float
    max_server_header_chars: int
    follow_redirects: bool


@dataclass(frozen=True)
class FetchResponse:
    status_code: int
    server_header: str | None


@dataclass(frozen=True)
class FetchResult:
    status_code: int
    fingerprint: WebServerFingerprint

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise ValueError("fetch result status must be an HTTP status")
        if not isinstance(self.fingerprint, WebServerFingerprint):
            raise ValueError("fetch result fingerprint is invalid")


class HttpFetchAdapter:
    """Invoke one injected transport once and retain only status and claim."""

    def __init__(self, transport: Callable[[FetchRequest], FetchResponse]) -> None:
        if not callable(transport):
            raise TypeError("transport must be callable")
        self._transport = transport

    def fetch(self, *, url: str, scope: DomainScope, source_id: str) -> FetchResult:
        if not isinstance(scope, DomainScope) or len(scope.roots) != 1:
            raise ValidationError("fetch requires a single-root domain scope")
        target = Target.parse(url, scope.roots[0].name)
        if not scope.contains(target.host):
            raise ValidationError("fetch target is outside the domain scope")
        # Validate the source identity before any injected transport is called.
        fingerprint_server_header(
            host=target.host, scheme=target.scheme, port=target.port,
            source_id=source_id, server_header=None,
        )
        request = FetchRequest(
            method="GET",
            url=target.url,
            timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            max_server_header_chars=MAX_SERVER_HEADER_CHARS,
            follow_redirects=False,
        )
        try:
            response = self._transport(request)
        except Exception:
            # Transport errors may contain response data or network details.
            raise HttpFetchError("HTTP metadata transport failed") from None
        if not isinstance(response, FetchResponse):
            raise HttpFetchError("HTTP metadata response has invalid shape")
        status = response.status_code
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise HttpFetchError("HTTP metadata status is invalid")
        header = response.server_header
        if header is not None and (
            not isinstance(header, str)
            or not header
            or len(header) > MAX_SERVER_HEADER_CHARS
            or header != header.strip()
            or any(ord(char) < 32 or ord(char) > 126 for char in header)
        ):
            raise HttpFetchError("HTTP Server header is invalid")
        fingerprint = fingerprint_server_header(
            host=target.host, scheme=target.scheme, port=target.port,
            source_id=source_id, server_header=header,
        )
        if header is not None and fingerprint.status != "reported":
            raise HttpFetchError("HTTP Server header is invalid")
        return FetchResult(status_code=status, fingerprint=fingerprint)
