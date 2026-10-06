"""Low-level, loopback-only OWASP ZAP API client.

``ZapApiClient`` is the single owner of every HTTP request to the ZAP daemon.
It builds URLs only for a validated loopback endpoint, adds the API key at
request time, and converts transport/HTTP/JSON/application failures into typed
exceptions that never contain the API key.

A non-blank API key is required by default. An explicit, opt-in *keyless* mode
(``keyless=True``) is available only for the project-local, loopback-only
daemon health smoke test: it is permitted only for an already validated
loopback endpoint, never creates or sends an ``apikey`` parameter, and never
implies that a secret exists.

The generic ``_call`` method is intentionally tool-local. The public surface is
made of explicit, typed foundations (:meth:`ZapApiClient.get_version`,
:meth:`ZapApiClient.health`, :meth:`ZapApiClient.check_version`,
:meth:`ZapApiClient.shutdown`) plus explicit context/scope, traditional Spider,
and AJAX Spider operations. Callers never build requests themselves, and every
returned id/status/progress/result structure is validated defensively.
"""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from typing import Any, Mapping, Optional, Union
from urllib.parse import urlencode

from .models import (
    DEFAULT_API_TIMEOUT,
    DEFAULT_MIN_ZAP_VERSION,
    RESERVED_PARAM_NAMES,
    HttpResponse,
    Transport,
    ZapApiError,
    ZapApiResultError,
    ZapConfigError,
    ZapEndpoint,
    ZapError,
    ZapHttpError,
    ZapResponseError,
    ZapTransportError,
    ZapVersionError,
    parse_version,
    redact_secret,
    validate_api_key,
    version_at_least,
)

__all__ = ["UrllibTransport", "ZapApiClient"]

_JSON_FORMAT = "JSON"
_BODY_EXCERPT_LIMIT = 200
_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_MAX_CONTEXT_NAME_LENGTH = 255
_MAX_REGEX_LENGTH = 4096


def _validate_keyless(value: Any) -> bool:
    """Return *value* as a boolean flag or raise :class:`ZapConfigError`."""

    if not isinstance(value, bool):
        raise ZapConfigError("keyless must be a boolean")
    return value


class UrllibTransport:
    """Default runtime transport built on :mod:`urllib.request`.

    The per-request timeout is bounded by the caller and every low-level
    socket/URL failure is converted to :class:`ZapTransportError`.
    """

    def request(self, method: str, url: str, timeout: float) -> HttpResponse:
        request = urllib.request.Request(url, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return HttpResponse(
                    status=getattr(response, "status", 200),
                    body=response.read(),
                    headers=dict(response.headers),
                )
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:  # pragma: no cover - defensive
                body = b""
            return HttpResponse(
                status=exc.code,
                body=body,
                headers=dict(exc.headers or {}),
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ZapTransportError("ZAP API transport failed") from exc


class ZapApiClient:
    """Owns all low-level requests to one loopback ZAP API endpoint."""

    def __init__(
        self,
        endpoint: Union[ZapEndpoint, str],
        api_key: Optional[str],
        *,
        keyless: bool = False,
        transport: Optional[Transport] = None,
        timeout: float = DEFAULT_API_TIMEOUT,
        min_version: str = DEFAULT_MIN_ZAP_VERSION,
    ) -> None:
        if isinstance(endpoint, ZapEndpoint):
            self._endpoint = endpoint
        else:
            self._endpoint = ZapEndpoint.parse(endpoint)

        self._keyless = _validate_keyless(keyless)
        if self._keyless:
            # Keyless mode is only ever allowed for a validated loopback
            # endpoint. Re-validate even a pre-built ``ZapEndpoint`` because
            # its dataclass fields are public and could bypass parsing.
            self._endpoint = ZapEndpoint.parse(self._endpoint.base_url)
            if api_key is not None:
                raise ZapConfigError("api_key must be omitted when keyless=True")
            self._api_key: Optional[str] = None
        else:
            # Accidental ``api_key=None`` without the explicit opt-in stays a
            # configuration error.
            self._api_key = validate_api_key(api_key)

        self._transport: Transport = transport if transport is not None else UrllibTransport()

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ZapConfigError("timeout must be a number")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ZapConfigError("timeout must be a positive finite number")
        self._timeout = float(timeout)

        parse_version(min_version)
        self._min_version = min_version

    # -- safe introspection -------------------------------------------------

    @property
    def endpoint(self) -> ZapEndpoint:
        return self._endpoint

    @property
    def min_version(self) -> str:
        return self._min_version

    @property
    def keyless(self) -> bool:
        """Return True when this client runs without an API key."""

        return self._keyless

    def __repr__(self) -> str:
        if self._keyless:
            # Never imply that a secret exists in keyless mode.
            return (
                f"ZapApiClient(endpoint={self._endpoint.base_url!r}, "
                f"keyless=True, timeout={self._timeout!r})"
            )
        return (
            f"ZapApiClient(endpoint={self._endpoint.base_url!r}, "
            f"api_key='***', timeout={self._timeout!r})"
        )

    # -- foundation operations ---------------------------------------------

    def get_version(self) -> str:
        """Return the ZAP core version string reported by the daemon."""

        payload = self._call("core", "version")
        version = payload.get("version")
        if not isinstance(version, str) or not version.strip():
            raise ZapResponseError("ZAP API version response is missing 'version'")
        return version

    def health(self) -> bool:
        """Return True when the ZAP API answers the version probe."""

        try:
            self.get_version()
        except ZapApiError:
            return False
        return True

    def check_version(self, minimum: Optional[str] = None) -> str:
        """Return the version if it meets *minimum*, otherwise raise."""

        required = self._min_version if minimum is None else minimum
        parse_version(required)
        actual = self.get_version()
        if not version_at_least(actual, required):
            raise ZapVersionError(
                f"ZAP version {actual!r} is below the required minimum {required!r}"
            )
        return actual

    def shutdown(self) -> None:
        """Request a graceful ZAP core shutdown."""

        self._call("core", "shutdown", action=True)

    # -- context and scope operations --------------------------------------

    def create_context(self, context_name: str) -> int:
        """Create a named context and return its numeric id."""

        name = self._validate_context_name(context_name)
        payload = self._call(
            "context", "newContext", {"contextName": name}, action=True
        )
        return self._require_int_field(payload, "contextId", minimum=0)

    def include_in_context(self, context_name: str, regex: str) -> None:
        """Add an anchored include-URL regex to a named context."""

        name = self._validate_context_name(context_name)
        pattern = self._validate_regex(regex)
        self._call(
            "context",
            "includeInContext",
            {"contextName": name, "regex": pattern},
            action=True,
        )

    def access_url(self, url: str) -> None:
        """Ask ZAP to fetch *url* into the current session/site tree."""

        target = self._validate_url_param(url)
        self._call("core", "accessUrl", {"url": target}, action=True)

    # -- traditional spider operations -------------------------------------

    def start_spider(
        self,
        url: str,
        *,
        context_name: Optional[str] = None,
        subtree_only: bool = True,
        recurse: bool = True,
        max_children: Optional[int] = None,
    ) -> int:
        """Start a traditional Spider scan and return its numeric id."""

        params: dict[str, Any] = {
            "url": self._validate_url_param(url),
            "recurse": bool(recurse),
            "subtreeOnly": bool(subtree_only),
        }
        if context_name is not None:
            params["contextName"] = self._validate_context_name(context_name)
        if max_children is not None:
            params["maxChildren"] = self._require_nonnegative_int(
                "max_children", max_children
            )
        payload = self._call("spider", "scan", params, action=True)
        return self._require_int_field(payload, "scan", minimum=0)

    def spider_status(self, scan_id: int) -> int:
        """Return integer Spider progress in the inclusive range 0..100."""

        payload = self._call("spider", "status", {"scanId": self._require_scan_id(scan_id)})
        return self._require_int_field(payload, "status", minimum=0, maximum=100)

    def spider_results(self, scan_id: int) -> list:
        """Return the Spider result list for *scan_id*."""

        payload = self._call(
            "spider", "results", {"scanId": self._require_scan_id(scan_id)}
        )
        return self._require_list_field(payload, "results")

    def stop_spider(self, scan_id: int) -> None:
        """Request that a traditional Spider scan stop."""

        self._call("spider", "stop", {"scanId": self._require_scan_id(scan_id)}, action=True)

    # -- AJAX spider operations --------------------------------------------

    def start_ajax_spider(
        self,
        url: str,
        *,
        context_name: Optional[str] = None,
        in_scope_only: bool = True,
        subtree_only: bool = True,
    ) -> Optional[int]:
        """Start an AJAX Spider scan.

        Returns the scan id when ZAP reports one, otherwise ``None``; the AJAX
        Spider status/results operations are not keyed by scan id.
        """

        params: dict[str, Any] = {
            "url": self._validate_url_param(url),
            "inScope": bool(in_scope_only),
            "subtreeOnly": bool(subtree_only),
        }
        if context_name is not None:
            params["contextName"] = self._validate_context_name(context_name)
        payload = self._call("ajaxSpider", "scan", params, action=True)
        if "scan" in payload:
            return self._require_int_field(payload, "scan", minimum=0)
        return None

    def ajax_spider_status(self) -> str:
        """Return the documented AJAX Spider status string (e.g. running/stopped)."""

        payload = self._call("ajaxSpider", "status")
        status = payload.get("status")
        if not isinstance(status, str) or not status.strip():
            raise ZapResponseError("ZAP AJAX spider status response is missing 'status'")
        return status.strip()

    def ajax_spider_results(
        self, *, start: Optional[int] = None, count: Optional[int] = None
    ) -> list:
        """Return one page of AJAX Spider results."""

        params: dict[str, Any] = {}
        if start is not None:
            params["start"] = self._require_nonnegative_int("start", start)
        if count is not None:
            params["count"] = self._require_nonnegative_int("count", count)
        payload = self._call("ajaxSpider", "results", params)
        return self._require_list_field(payload, "results")

    def stop_ajax_spider(self) -> None:
        """Request that the AJAX Spider stop."""

        self._call("ajaxSpider", "stop", action=True)

    # -- internal request machinery ----------------------------------------

    def _redact(self, text: str) -> str:
        return redact_secret(str(text), self._api_key or "")

    @staticmethod
    def _validate_identifier(value: str) -> str:
        if not isinstance(value, str) or not _IDENTIFIER_RE.match(value):
            raise ZapConfigError(f"invalid ZAP API identifier: {value!r}")
        return value

    @staticmethod
    def _validate_param_name(name: str) -> str:
        if not isinstance(name, str) or not name:
            raise ZapConfigError(f"invalid API parameter name: {name!r}")
        if name.lower() in RESERVED_PARAM_NAMES:
            raise ZapConfigError(f"API parameter name is reserved: {name!r}")
        if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
            raise ZapConfigError("API parameter name must not contain whitespace or control characters")
        return name

    @staticmethod
    def _stringify_param(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (str, int, float)):
            return str(value)
        raise ZapConfigError(
            f"API parameter values must be scalar, got {type(value).__name__}"
        )

    @staticmethod
    def _validate_context_name(context_name: str) -> str:
        if not isinstance(context_name, str) or not context_name.strip():
            raise ZapConfigError("context name must be a non-blank string")
        if context_name != context_name.strip():
            raise ZapConfigError("context name must not have surrounding whitespace")
        if len(context_name) > _MAX_CONTEXT_NAME_LENGTH:
            raise ZapConfigError("context name is too long")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in context_name):
            raise ZapConfigError("context name must not contain control characters")
        return context_name

    @staticmethod
    def _validate_regex(regex: str) -> str:
        if not isinstance(regex, str) or not regex.strip():
            raise ZapConfigError("scope regex must be a non-blank string")
        if len(regex) > _MAX_REGEX_LENGTH:
            raise ZapConfigError("scope regex is too long")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in regex):
            raise ZapConfigError("scope regex must not contain control characters")
        return regex

    @staticmethod
    def _validate_url_param(url: str) -> str:
        if not isinstance(url, str) or not url.strip():
            raise ZapConfigError("URL parameter must be a non-blank string")
        if url != url.strip():
            raise ZapConfigError("URL parameter must not have surrounding whitespace")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
            raise ZapConfigError("URL parameter must not contain control characters")
        lowered = url.lower()
        if not (lowered.startswith("http://") or lowered.startswith("https://")):
            raise ZapConfigError("URL parameter must use http or https")
        return url

    @staticmethod
    def _require_nonnegative_int(name: str, value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ZapConfigError(f"{name} must be a non-negative integer")
        if value < 0:
            raise ZapConfigError(f"{name} must be a non-negative integer")
        return value

    @staticmethod
    def _require_scan_id(scan_id: Any) -> int:
        if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id < 0:
            raise ZapConfigError("scan id must be a non-negative integer")
        return scan_id

    @staticmethod
    def _require_int_field(
        payload: Mapping[str, Any],
        key: str,
        *,
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
    ) -> int:
        if key not in payload:
            raise ZapResponseError(f"ZAP API response is missing {key!r}")
        raw = payload[key]
        if isinstance(raw, bool):
            raise ZapResponseError(f"ZAP API field {key!r} must be an integer")
        if isinstance(raw, int):
            value = raw
        elif isinstance(raw, str):
            try:
                value = int(raw.strip())
            except ValueError as exc:
                raise ZapResponseError(
                    f"ZAP API field {key!r} is not an integer"
                ) from exc
        else:
            raise ZapResponseError(f"ZAP API field {key!r} must be an integer")
        if minimum is not None and value < minimum:
            raise ZapResponseError(f"ZAP API field {key!r} is below the allowed minimum")
        if maximum is not None and value > maximum:
            raise ZapResponseError(f"ZAP API field {key!r} is above the allowed maximum")
        return value

    @staticmethod
    def _require_list_field(payload: Mapping[str, Any], key: str) -> list:
        if key not in payload:
            raise ZapResponseError(f"ZAP API response is missing {key!r}")
        value = payload[key]
        if not isinstance(value, list):
            raise ZapResponseError(f"ZAP API field {key!r} must be a list")
        return value

    def _build_url(
        self, component: str, operation: str, params: Mapping[str, str], *, action: bool
    ) -> str:
        encoded = urlencode(dict(params))
        kind = "action" if action else "view"
        return (
            f"{self._endpoint.base_url}/{_JSON_FORMAT}/{component}/{kind}/"
            f"{operation}/?{encoded}"
        )

    def _call(
        self,
        component: str,
        operation: str,
        params: Optional[Mapping[str, Any]] = None,
        *,
        action: bool = False,
    ) -> dict:
        """Build, send, and parse one ZAP API request.

        This is deliberately internal: callers should use the explicit
        foundation operations above. When a key is configured it is injected
        here, at request time, and is never embedded in a stored/repr-visible
        structure; in keyless mode no ``apikey`` parameter is created at all.
        """

        component = self._validate_identifier(component)
        operation = self._validate_identifier(operation)

        safe_params: dict[str, str] = {}
        for key, value in (params or {}).items():
            safe_params[self._validate_param_name(key)] = self._stringify_param(value)
        api_key = self._api_key
        if not self._keyless and api_key is not None:
            # The key is injected here, at request time only; keyless mode
            # deliberately never creates an ``apikey`` parameter.
            safe_params["apikey"] = api_key

        url = self._build_url(component, operation, safe_params, action=action)
        response = self._send(url)
        return self._parse_response(response)

    def _send(self, url: str) -> HttpResponse:
        try:
            response = self._transport.request("GET", url, self._timeout)
        except ZapTransportError as exc:
            raise ZapTransportError(self._redact(str(exc))) from exc
        except ZapError:
            raise
        except Exception as exc:  # transports may raise anything
            raise ZapTransportError(
                self._redact(f"ZAP API transport failed: {type(exc).__name__}")
            ) from exc
        if not isinstance(response, HttpResponse):
            raise ZapTransportError("ZAP API transport returned an invalid response")
        return response

    def _parse_response(self, response: HttpResponse) -> dict:
        if not 200 <= response.status < 300:
            raise ZapHttpError(response.status, self._redact(self._body_excerpt(response.body)))

        try:
            text = response.body.decode("utf-8")
        except (UnicodeDecodeError, AttributeError) as exc:
            raise ZapResponseError("ZAP API response was not valid UTF-8") from exc

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ZapResponseError("ZAP API response was not valid JSON") from exc

        if not isinstance(payload, dict):
            raise ZapResponseError("ZAP API response root must be a JSON object")

        if "error" in payload or "code" in payload:
            raw_code = payload.get("code", payload.get("error", ""))
            raw_message = payload.get("message", "")
            raise ZapApiResultError(
                self._redact(str(raw_code)), self._redact(str(raw_message))
            )
        return payload

    @staticmethod
    def _body_excerpt(body: Any) -> str:
        if isinstance(body, (bytes, bytearray)):
            try:
                text = bytes(body).decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover - defensive
                text = repr(body)
        else:
            text = str(body)
        text = " ".join(text.split())
        if len(text) > _BODY_EXCERPT_LIMIT:
            text = text[:_BODY_EXCERPT_LIMIT] + "..."
        return text or "empty response body"
