"""Narrowly bounded Stage 2 traditional-Spider profile.

This module is deliberately *separate* from the generic Spider/AJAX wrapper. It
implements only the single, fixed work package authorized by ``CURRENT_TASK.md``
for the artifact-routing domain ``acme.example``:

* one unauthenticated traditional Spider against exactly
  ``https://acme.example/``;
* an exact-host, no-subdomain, https/default-443 scope;
* depth <= 3, runtime <= 300 s, concurrency exactly 1, <= 1 request/s;
* GET/HEAD only, no form processing/submission, no AJAX/browser, no active
  scan, no authentication, no API import, no report API, no ``core/accessUrl``;
* an explicit API operation allowlist enforced *before* the local transport;
* a deterministic ZAP 2.17.0 ``-config`` control set whose persisted values are
  read back from the project-local ``zap-home/config.xml`` before the first
  target request;
* a keyless local ZAP API (no API key or other secret is generated, accepted,
  logged, persisted, or retained);
* a project-owned exact-host CONNECT egress guard bound to
  ``127.0.0.1:18082`` with ZAP's outbound HTTP(S) proxy pinned to it, so the
  guard is the only point of target DNS resolution and the only process that
  may own an outbound connection (to the pinned public IP set on port 443);
* structured JSON plus human-readable Markdown evidence under the run
  directory.

Everything here is standard-library only and offline-testable: the guard,
manager, API client, transport, local inspector, clock, and sleep function are
all injectable, so the whole flow can be exercised with fakes and no socket,
process, DNS, or target call.

Fail-closed doctrine: if a required control cannot be proven from deterministic
runtime configuration, a project-local read-back, the guard's pinned target
set, or a read-only local inspection that does not itself exceed the API
allowlist, the runner records a blocker and refuses to issue the first target
request.
"""

from __future__ import annotations

import ipaddress
import math
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from ...orchestration.state import atomic_write_json
from ...projects.models import ProjectDomain, Target, ValidationError
from ...projects.paths import ScanPath, is_within
from .discovery import DEFAULT_POLL_INTERVAL, SpiderRunner
from .lifecycle import LifecycleSystem, scope_snapshot
from .models import (
    DEFAULT_API_TIMEOUT,
    ZapEndpoint,
    ZapError,
)
from .process import (
    DEFAULT_GRACEFUL_TIMEOUT,
    DEFAULT_KILL_TIMEOUT,
    DEFAULT_STARTUP_TIMEOUT,
    DEFAULT_TERMINATE_TIMEOUT,
    OFFLINE_CONFIG_CALLHOME_TEL_ENABLED,
    SILENT_FLAG,
    ZapProcessManager,
)
from .smoke import analyze_inspection, snapshot_to_inspection_raw

__all__ = [
    "ALLOWED_METHODS",
    "ALLOWED_OPERATIONS",
    "ApiCallRecorder",
    "CONCURRENCY",
    "ControlCheck",
    "EXPECTED_ZAP_VERSION",
    "GUARD_HOST",
    "GUARD_PORT",
    "MAX_DEPTH",
    "MAX_DURATION_MINUTES",
    "MAX_DURATION_SECONDS",
    "MAX_REQUESTS_PER_SECOND",
    "OAST_CALLBACK_PORT",
    "OAST_CONTAINMENT_PAIRS",
    "PREFLIGHT_FILENAME",
    "PRELAUNCH_FILENAME",
    "PROXY_CONFIG_PAIRS",
    "REQUEST_WAIT_MS",
    "SILENT_FLAG",
    "SPIDER_CONFIG_CONTROLS",
    "SPIDER_CONFIG_PAIRS",
    "STAGE2_DOMAIN",
    "STAGE2_HOST",
    "STAGE2_MODE",
    "STAGE2_PORT",
    "STAGE2_SCHEME",
    "STAGE2_SEED",
    "STAGE2_JSON_FILENAME",
    "STAGE2_MARKDOWN_FILENAME",
    "STAGE2_STATE_FILENAME",
    "Stage2AllowlistError",
    "Stage2AllowlistedTransport",
    "Stage2ApiClient",
    "Stage2Error",
    "Stage2PreflightError",
    "Stage2Profile",
    "Stage2ProfileError",
    "Stage2SpiderRunner",
    "Stage2TargetPolicy",
    "build_stage2_profile",
    "evaluate_prelaunch_controls",
    "evaluate_runtime_controls",
    "read_callhome_config",
    "read_proxy_config",
    "read_spider_config",
    "render_markdown",
]

# ---------------------------------------------------------------------------
# Authorized profile constants
# ---------------------------------------------------------------------------

STAGE2_DOMAIN = "acme.example"
STAGE2_HOST = "acme.example"
STAGE2_SCHEME = "https"
STAGE2_PORT = 443
STAGE2_SEED = "https://acme.example/"
STAGE2_MODE = "spider"
EXPECTED_ZAP_VERSION = "2.17.0"

MAX_DEPTH = 3
MAX_DURATION_SECONDS = 300.0
MAX_DURATION_MINUTES = 5
CONCURRENCY = 1
MAX_REQUESTS_PER_SECOND = 1.0
REQUEST_WAIT_MS = 1000

ALLOWED_METHODS = ("GET", "HEAD")

#: The complete set of ZAP API component/kind/operation triples the Stage 2
#: run may ever call. Any other triple is rejected before the inner transport
#: is touched. Note that ``core/accessUrl`` and every ``ajaxSpider``/``ascan``/
#: import/report operation are deliberately absent.
ALLOWED_OPERATIONS = frozenset(
    {
        ("core", "view", "version"),
        ("context", "action", "newContext"),
        ("context", "action", "includeInContext"),
        ("spider", "action", "scan"),
        ("spider", "view", "status"),
        ("spider", "view", "results"),
        ("spider", "action", "stop"),
        ("core", "action", "shutdown"),
    }
)

#: ZAP 2.17.0 traditional-Spider options used to enforce the bounded controls.
#: Each key was established by read-only inspection of the installed ZAP
#: 2.17.0 ``SpiderParam``/``OptionsSpiderPanel`` bytecode and its bundled
#: ``Messages.properties`` (the persisted element name is the last dotted
#: segment below ``spider``). Units: ``maxDuration`` minutes, ``requestwait``
#: milliseconds.
SPIDER_CONFIG_CONTROLS: tuple[tuple[str, str, str, str], ...] = (
    ("max_depth", "maxDepth", "3", "depth <= 3"),
    ("concurrency", "thread", "1", "exactly 1 spider thread"),
    ("duration", "maxDuration", "5", "<= 5 minutes (<= 300 s)"),
    ("request_rate", "requestwait", "1000", ">= 1000 ms between requests"),
    ("process_form", "processform", "false", "form processing disabled"),
    ("post_form", "postform", "false", "form submission disabled"),
)

#: Deterministic ``-config`` pairs handed to the daemon at launch.
SPIDER_CONFIG_PAIRS: tuple[tuple[str, str], ...] = tuple(
    (f"spider.{key}", value) for _name, key, value, _note in SPIDER_CONFIG_CONTROLS
)

#: Read-only launch hardening. Automatic update/add-on/rule activity and the
#: callhome add-on telemetry are suppressed. The outbound HTTP(S) path is
#: guarded separately by ``PROXY_CONFIG_PAIRS``, which pins ZAP's outbound proxy
#: to the exact-host CONNECT egress guard. The callhome key is imported from
#: :mod:`~red_teaming.tools.zap.process` so the exact key cannot drift between
#: the offline smoke and the bounded run.
LAUNCH_HARDENING_PAIRS: tuple[tuple[str, str], ...] = (
    ("start.checkForUpdates", "false"),
    ("start.downloadNewRelease", "false"),
    ("start.checkAddonUpdates", "false"),
    ("start.installAddonUpdates", "false"),
    ("start.installScannerRules", "false"),
    (OFFLINE_CONFIG_CALLHOME_TEL_ENABLED, "false"),
)

#: Fixed loopback OAST callback containment, mirroring the Stage 1 smoke so any
#: locally started callback listener stays on 127.0.0.1:18081 and can be
#: verified closed after shutdown. These keys and their semantics were
#: established read-only from the installed OAST 0.24.0 add-on.
OAST_CALLBACK_PORT = 18081
OAST_CONTAINMENT_PAIRS: tuple[tuple[str, str], ...] = (
    ("oast.callback.localaddr", "127.0.0.1"),
    ("oast.callback.remoteaddr", "127.0.0.1"),
    ("oast.callback.port", str(OAST_CALLBACK_PORT)),
)

#: Fixed endpoint of the project-owned exact-host CONNECT egress guard.
GUARD_HOST = "127.0.0.1"
GUARD_PORT = 18082

#: Deterministic ``-config`` pairs that point ZAP's own outbound HTTP(S) proxy
#: at the exact-host CONNECT egress guard. The proxy is the only outbound path,
#: so all target DNS resolution and every outbound connection happen inside the
#: guard. No target URL or external hostname is ever included here.
PROXY_CONFIG_PAIRS: tuple[tuple[str, str], ...] = (
    ("network.connection.httpProxy.enabled", "true"),
    ("network.connection.httpProxy.host", GUARD_HOST),
    ("network.connection.httpProxy.port", str(GUARD_PORT)),
)

#: Bounded evidence limits: never persist unbounded inspection or connection
#: data.
_MAX_INSPECTIONS = 64
_MAX_INSPECTION_RECORDS = 8
_MAX_GUARD_RECORDS = 16

STAGE2_STATE_FILENAME = "stage2-state.json"
STAGE2_JSON_FILENAME = "stage2-spider.json"
STAGE2_MARKDOWN_FILENAME = "STAGE2_SPIDER.md"
PREFLIGHT_FILENAME = "stage2-preflight.json"
PRELAUNCH_FILENAME = "stage2-prelaunch.json"

_DEFAULT_API_PORT = 18080
_EXACT_LOOPBACK_HOST = "127.0.0.1"


class Stage2Error(ZapError):
    """Base class for bounded Stage 2 failures."""


class Stage2ProfileError(Stage2Error, ValueError):
    """The requested run does not match the one authorized Stage 2 profile."""


class Stage2AllowlistError(Stage2Error):
    """A request was rejected by the Stage 2 API allowlist before sending."""


class Stage2PreflightError(Stage2Error):
    """A required control could not be proven; the target Spider is refused."""


def _validate_positive(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Stage2Error(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise Stage2Error(f"{name} must be a positive finite number")
    return float(value)


# ---------------------------------------------------------------------------
# Target containment policy
# ---------------------------------------------------------------------------


class Stage2TargetPolicy:
    """Exact-host https/443 policy for the single authorized seed."""

    def __init__(self, seed_url: str = STAGE2_SEED) -> None:
        if seed_url != STAGE2_SEED:
            raise Stage2ProfileError(
                f"seed URL must be exactly {STAGE2_SEED!r}"
            )
        self._seed = seed_url

    @property
    def seed(self) -> str:
        return self._seed

    def is_allowed_url(self, url: Any) -> bool:
        """Return True only for an in-host ``https`` URL on default port 443."""

        if not isinstance(url, str) or not url or url != url.strip():
            return False
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
            return False
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme.lower() != STAGE2_SCHEME:
            return False
        if parts.username is not None or parts.password is not None:
            return False
        if parts.hostname != STAGE2_HOST:
            return False
        try:
            port = parts.port
        except ValueError:
            return False
        if port not in (None, STAGE2_PORT):
            return False
        return True

    def require_allowed_url(self, url: Any) -> str:
        if not self.is_allowed_url(url):
            raise Stage2ProfileError(
                "refusing out-of-scope target URL; only "
                f"https://{STAGE2_HOST}/ on default port 443 is allowed"
            )
        return str(url)

    def result_violations(self, results: Iterable[Any]) -> list[str]:
        """Return the out-of-host URLs discovered in Spider results.

        This is the wrapper-side containment gate: any result URL that is not
        the exact host is reported so the run fails closed instead of treating
        the crawl as contained.
        """

        violations: list[str] = []
        for entry in results:
            url: Any = None
            if isinstance(entry, Mapping):
                url = entry.get("url")
            elif isinstance(entry, str):
                url = entry
            if url is None:
                continue
            if not self.is_allowed_url(url):
                violations.append(str(url))
        return violations


# ---------------------------------------------------------------------------
# Secret-free API call recording + allowlist transport
# ---------------------------------------------------------------------------


class ApiCallRecorder:
    """Ordered, secret-free record of every attempted Stage 2 API call."""

    def __init__(self, now: Callable[[], str]) -> None:
        self._now = now
        self.calls: list[dict] = []

    def record(
        self,
        attempt: Mapping[str, Any],
        *,
        status: Optional[int],
        error: Optional[str],
    ) -> None:
        entry: dict[str, Any] = {
            "timestamp": self._now(),
            "component": attempt.get("component"),
            "operation": attempt.get("operation"),
            "kind": attempt.get("kind"),
            # Path only: the query string (which carries request parameters) is
            # never recorded. The API is keyless, so no secret is ever present.
            "path": attempt.get("path"),
            "allowed": bool(attempt.get("allowed")),
            "status": status,
            "error": error,
        }
        if not entry["allowed"] and attempt.get("reason"):
            entry["reason"] = attempt["reason"]
        self.calls.append(entry)


class Stage2AllowlistedTransport:
    """Transport wrapper enforcing the Stage 2 API operation allowlist.

    A request is classified from its URL *before* the inner transport is
    touched. Only the explicit allowlist triples on exactly ``127.0.0.1`` and
    the configured port are allowed. Every attempt -- allowed or rejected -- is
    recorded with its path only; the query string (request parameters) is
    never persisted. The API is keyless, so no secret ever exists to redact.
    """

    def __init__(
        self,
        inner: Any,
        *,
        endpoint: ZapEndpoint,
        recorder: ApiCallRecorder,
        allowed_operations: Iterable[tuple[str, str, str]] = ALLOWED_OPERATIONS,
    ) -> None:
        if not isinstance(endpoint, ZapEndpoint):
            raise Stage2Error("endpoint must be a ZapEndpoint")
        if endpoint.host != _EXACT_LOOPBACK_HOST:
            raise Stage2Error(
                "the Stage 2 allowlist requires the exact 127.0.0.1 endpoint"
            )
        if not hasattr(inner, "request"):
            raise Stage2Error("inner transport must expose request()")
        if not isinstance(recorder, ApiCallRecorder):
            raise Stage2Error("recorder must be an ApiCallRecorder")
        self._inner = inner
        self._endpoint = endpoint
        self._recorder = recorder
        self._allowed = frozenset(allowed_operations)

    @property
    def endpoint(self) -> ZapEndpoint:
        return self._endpoint

    def _classify(self, url: str) -> dict:
        info: dict[str, Any] = {
            "component": None,
            "operation": None,
            "kind": None,
            "path": None,
            "allowed": False,
            "reason": None,
        }
        try:
            parts = urlsplit(url)
        except ValueError:
            info["reason"] = "malformed URL"
            return info

        info["path"] = parts.path or None

        if parts.scheme.lower() not in ("http", "https"):
            info["reason"] = "unsupported scheme"
            return info
        if parts.hostname != _EXACT_LOOPBACK_HOST:
            info["reason"] = "endpoint host is not exactly 127.0.0.1"
            return info
        try:
            port = parts.port
        except ValueError:
            info["reason"] = "invalid endpoint port"
            return info
        if port != self._endpoint.port:
            info["reason"] = "endpoint port does not match the Stage 2 endpoint"
            return info

        segments = [segment for segment in (parts.path or "").split("/") if segment]
        if len(segments) != 4 or segments[0].upper() != "JSON":
            info["reason"] = "path is not a ZAP JSON API path"
            return info

        component, kind, operation = segments[1], segments[2], segments[3]
        info["component"] = component
        info["kind"] = kind
        info["operation"] = operation

        if (component, kind, operation) not in self._allowed:
            info["reason"] = "API operation is not allowlisted for Stage 2"
            return info

        info["allowed"] = True
        return info

    def request(self, method: str, url: str, timeout: float):
        attempt = self._classify(url)
        if not attempt["allowed"]:
            self._recorder.record(attempt, status=None, error=str(attempt["reason"]))
            raise Stage2AllowlistError(
                f"refusing non-allowlisted ZAP API request: {attempt['reason']}"
            )
        try:
            response = self._inner.request(method, url, timeout)
        except Exception as exc:
            self._recorder.record(
                attempt,
                status=None,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise
        self._recorder.record(
            attempt, status=getattr(response, "status", None), error=None
        )
        return response


# ---------------------------------------------------------------------------
# API client facade (no accessUrl / AJAX path)
# ---------------------------------------------------------------------------


class Stage2ApiClient:
    """Narrow facade over :class:`ZapApiClient` exposing only Stage 2 operations.

    The facade pins every context operation to the run's own context and pins
    the traditional Spider seed to the exact authorized URL, so no out-of-host
    URL can reach the wire.
    """

    def __init__(self, client: Any, profile: "Stage2Profile") -> None:
        if client is None:
            raise Stage2Error("client must be provided")
        self._client = client
        self._profile = profile

    def get_version(self) -> str:
        return self._client.get_version()

    def create_context(self) -> int:
        return self._client.create_context(self._profile.context_name)

    def include_in_context(self) -> None:
        self._client.include_in_context(
            self._profile.context_name, self._profile.scope_regex
        )

    def start_spider(
        self,
        url: str,
        *,
        context_name: Optional[str] = None,
        subtree_only: bool = True,
        recurse: bool = True,
    ) -> int:
        self._profile.target_policy.require_allowed_url(url)
        if context_name is not None and context_name != self._profile.context_name:
            raise Stage2ProfileError("refusing to start a Spider for another context")
        return self._client.start_spider(
            url,
            context_name=self._profile.context_name,
            subtree_only=True,
            recurse=True,
        )

    def spider_status(self, scan_id: int) -> int:
        return self._client.spider_status(scan_id)

    def spider_results(self, scan_id: int) -> list:
        return self._client.spider_results(scan_id)

    def stop_spider(self, scan_id: int) -> None:
        self._client.stop_spider(scan_id)

    def shutdown(self) -> None:
        self._client.shutdown()


# ---------------------------------------------------------------------------
# Control proofs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ControlCheck:
    """One mandatory Stage 2 control and whether it is proven active."""

    name: str
    active: bool
    enforcement: str
    detail: str
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_evidence(self) -> dict:
        return {
            "name": self.name,
            "active": bool(self.active),
            "enforcement": self.enforcement,
            "detail": self.detail,
            "evidence": dict(self.evidence),
        }


def _is_global_ip(value: Any) -> bool:
    """Return True only for a globally routable unicast IP literal."""

    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def _config_text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def _as_bool(value: Any) -> bool:
    return _config_text(value) in ("true", "1", "yes", "on")


def _read_config_root(zap_home: Path | str) -> Optional[ET.Element]:
    config_path = Path(zap_home) / "config.xml"
    if not config_path.is_file():
        raise Stage2PreflightError(
            "zap-home/config.xml is absent; the deterministic controls cannot "
            "be read back"
        )
    try:
        tree = ET.parse(str(config_path))
    except (ET.ParseError, OSError) as exc:
        raise Stage2PreflightError(
            f"could not read back zap-home/config.xml: {type(exc).__name__}"
        ) from exc
    return tree.getroot()


def _section_options(
    root: Optional[ET.Element], tags: Sequence[str]
) -> dict[str, str]:
    node = root
    for tag in tags:
        if node is None:
            break
        node = node.find(tag)
    if node is None:
        raise Stage2PreflightError(
            "zap-home/config.xml has no " + "/".join(tags) + " section"
        )
    options: dict[str, str] = {}
    for child in node:
        if not isinstance(child.tag, str):
            continue
        options[child.tag] = _config_text(child.text)
    return options


def read_spider_config(zap_home: Path | str) -> dict[str, str]:
    """Return the persisted ``spider`` option values from ``config.xml``.

    Only the direct scalar children of the ``spider`` element are returned;
    any unrelated configuration is never surfaced.
    """

    return _section_options(_read_config_root(zap_home), ("spider",))


def read_proxy_config(zap_home: Path | str) -> dict[str, str]:
    """Return the persisted ZAP outbound HTTP(S) proxy settings.

    The values come from the deterministic ``network.connection.httpProxy``
    ``-config`` tree written to the project-local ``zap-home/config.xml``.
    """

    return _section_options(
        _read_config_root(zap_home), ("network", "connection", "httpProxy")
    )


def read_callhome_config(zap_home: Path | str) -> dict[str, str]:
    """Return the persisted ``callhome.tel`` option values from ``config.xml``.

    The callhome add-on attempted telemetry through the outbound proxy at both
    startup and shutdown (qualification run ``20261003T121208Z-79bdb0``). The
    deterministic ``callhome.tel.enabled=false`` launch pair must be read back
    from the project-local config before any target request. Only the direct
    scalar children of the ``callhome/tel`` element are returned; an absent
    element (telemetry not proven disabled) is a fail-closed preflight error.
    """

    return _section_options(_read_config_root(zap_home), ("callhome", "tel"))


def _static_controls(profile: "Stage2Profile") -> list[ControlCheck]:
    """Deterministic, fail-closed profile/launch controls.

    Every control here is derived from the fixed authorized profile or the
    deterministic keyless/guard launch plan; none can be weakened by a caller.
    """

    target = profile.target
    seed_exact = (
        target.scheme == STAGE2_SCHEME
        and target.host == STAGE2_HOST
        and target.port == STAGE2_PORT
        and target.url == STAGE2_SEED
    )
    return [
        ControlCheck(
            name="exact_project",
            active=profile.domain == STAGE2_DOMAIN,
            enforcement="deterministic_profile",
            detail="project must be exactly acme.example",
            evidence={"domain": profile.domain},
        ),
        ControlCheck(
            name="exact_seed",
            active=seed_exact,
            enforcement="deterministic_profile",
            detail="seed must be exactly https://acme.example/ (https, default 443, no subdomain)",
            evidence={"url": target.url, "host": target.host, "port": target.port},
        ),
        ControlCheck(
            name="traditional_spider_only",
            active=profile.mode == STAGE2_MODE,
            enforcement="deterministic_profile",
            detail="only the traditional Spider mode is permitted",
            evidence={"mode": profile.mode},
        ),
        ControlCheck(
            name="output_routing",
            active=profile.artifact_route_ok,
            enforcement="deterministic_path_check",
            detail="output must be a new canonical run directory under projects/acme.example",
            evidence={"scan_dir": str(profile.scan_path.scan_dir)},
        ),
        ControlCheck(
            name="scope_regex_exact",
            active=profile.scope_regex_is_exact,
            enforcement="deterministic_scope_regex",
            detail=(
                "the context include regex pins the exact https scheme/host and "
                "rejects subdomains; activation is recorded separately after the "
                "allowlisted context calls succeed"
            ),
            evidence={"scope_regex": profile.scope_regex},
        ),
        ControlCheck(
            name="deterministic_spider_controls_configured",
            active=True,
            enforcement="deterministic_launch_config_planned",
            detail=(
                "the bounded spider -config pairs are supplied at launch and read "
                "back from project-local zap-home/config.xml after startup"
            ),
            evidence={"pairs": [f"{k}={v}" for k, v in SPIDER_CONFIG_PAIRS]},
        ),
        ControlCheck(
            name="forms_disabled_configured",
            active=True,
            enforcement="deterministic_launch_config_planned",
            detail="spider.processform=false and spider.postform=false are supplied at launch",
        ),
        ControlCheck(
            name="get_head_only",
            active=profile.mode == STAGE2_MODE,
            enforcement="derived_traditional_spider",
            detail=(
                "traditional Spider with form processing/submission disabled; "
                "ZAP exposes no method allowlist under the permitted API set, so "
                "this is derived assurance, not an independent runtime probe"
            ),
        ),
        ControlCheck(
            name="api_allowlist_only",
            active=True,
            enforcement="wrapper_transport_allowlist",
            detail="only the explicit Stage 2 operation allowlist may reach the local transport",
            evidence={"allowed_operations": sorted("/".join(op) for op in ALLOWED_OPERATIONS)},
        ),
        ControlCheck(
            name="no_forbidden_workflow",
            active=(
                ("core", "action", "accessUrl") not in ALLOWED_OPERATIONS
                and not any(
                    op[0].lower() in ("ajaxspider", "ascan", "pscan", "import", "reports")
                    for op in ALLOWED_OPERATIONS
                )
            ),
            enforcement="wrapper_transport_allowlist",
            detail="no AJAX/browser, active scan, authentication, import, report, or core/accessUrl",
        ),
        ControlCheck(
            name="oast_callback_loopback_only",
            active=True,
            enforcement="deterministic_launch_config",
            detail=(
                "any locally started OAST callback listener is pinned to "
                "127.0.0.1:18081 and its closure is verified after shutdown"
            ),
            evidence={
                "pairs": [f"{key}={value}" for key, value in OAST_CONTAINMENT_PAIRS],
                "callback_port": OAST_CALLBACK_PORT,
            },
        ),
        ControlCheck(
            name="keyless_api_configured",
            active=True,
            enforcement="deterministic_launch_plan",
            detail=(
                "the local ZAP API runs keyless on the exact 127.0.0.1 endpoint; "
                "no API key or other secret is generated, accepted, logged, "
                "persisted, or retained"
            ),
            evidence={
                "keyless": True,
                "host": _EXACT_LOOPBACK_HOST,
                "port": _DEFAULT_API_PORT,
            },
        ),
        ControlCheck(
            name="egress_guard_configured",
            active=True,
            enforcement="deterministic_launch_plan",
            detail=(
                "ZAP outbound HTTP(S) proxy is pinned to the exact-host CONNECT "
                "egress guard on 127.0.0.1:18082; the guard is the only target "
                "DNS point and connects only to the pinned public IP set on 443"
            ),
            evidence={
                "guard_endpoint": f"{GUARD_HOST}:{GUARD_PORT}",
                "proxy_pairs": [f"{key}={value}" for key, value in PROXY_CONFIG_PAIRS],
            },
        ),
        ControlCheck(
            name="silent_launch_configured",
            active=True,
            enforcement="deterministic_launch_plan",
            detail=(
                "the daemon is launched with the ZAP -silent switch so every "
                "ZAP-initiated unsolicited request (auto-update/news fetch to "
                "news.zaproxy.org) is suppressed at the process level, "
                "independently of start.checkForUpdates"
            ),
            evidence={"flag": SILENT_FLAG},
        ),
    ]


def evaluate_prelaunch_controls(profile: "Stage2Profile") -> list[ControlCheck]:
    """Static controls evaluated before any guard/manager/transport/API work."""

    return _static_controls(profile)


def evaluate_runtime_controls(
    profile: "Stage2Profile",
    *,
    version: Any,
    spider_config: Mapping[str, str],
    proxy_config: Mapping[str, str],
    callhome_config: Mapping[str, str],
    guard: Mapping[str, Any],
    listener_ok: bool,
    listener_detail: str,
    identity_verified: bool,
    zap_direct_egress_ok: bool,
    guard_egress_ok: bool,
    guard_records_clean: bool,
    guard_listener_ok: bool,
    scope_activated: bool,
    include_scope_control: bool = True,
) -> list[ControlCheck]:
    """Static controls plus post-startup guard/config read-back controls.

    ``scope_activated`` reflects successful allowlisted context/inclusion calls
    made *before* any target request. The pre-activation call uses
    ``include_scope_control=False`` so the not-yet-run activation is not counted
    as a blocker.
    """

    def config_matches(section: Mapping[str, str], key: str, expected: str) -> bool:
        return _config_text(section.get(key)) == expected

    def spider_note(key: str, expected: str) -> dict:
        return {
            "key": f"spider.{key}",
            "expected": expected,
            "observed": spider_config.get(key),
        }

    def proxy_note(key: str, expected: str) -> dict:
        return {
            "key": f"network.connection.httpProxy.{key}",
            "expected": expected,
            "observed": proxy_config.get(key),
        }

    def config_false(key: str) -> bool:
        # The key must be present *and* explicitly false; absent configuration
        # is never treated as "disabled".
        return key in spider_config and not _as_bool(spider_config.get(key))

    guard_target = guard.get("target") or {}
    pinned = list(guard.get("pinned_ips") or [])
    guard_endpoint_ok = (
        guard.get("bind_host") == GUARD_HOST and guard.get("bind_port") == GUARD_PORT
    )
    guard_target_ok = (
        isinstance(guard_target, Mapping)
        and guard_target.get("host") == STAGE2_HOST
        and guard_target.get("port") == STAGE2_PORT
    )
    guard_pinned_ok = bool(pinned) and all(_is_global_ip(ip) for ip in pinned)

    checks = _static_controls(profile)
    checks.extend(
        [
            ControlCheck(
                name="zap_version_exact",
                active=str(version) == EXPECTED_ZAP_VERSION,
                enforcement="api_readback_allowed_operation",
                detail=f"ZAP version must be exactly {EXPECTED_ZAP_VERSION}",
                evidence={"observed": version},
            ),
            ControlCheck(
                name="api_loopback_only",
                active=bool(listener_ok),
                enforcement="read_only_local_inspection",
                detail=listener_detail,
                evidence={"endpoint": profile.endpoint.base_url},
            ),
            ControlCheck(
                name="daemon_identity_unambiguous",
                active=bool(identity_verified),
                enforcement="read_only_local_inspection",
                detail="exactly one identity-verified ZAP daemon must own the API port",
            ),
            ControlCheck(
                name="proxy_config_exact",
                active=(
                    config_matches(proxy_config, "enabled", "true")
                    and config_matches(proxy_config, "host", GUARD_HOST)
                    and config_matches(proxy_config, "port", str(GUARD_PORT))
                ),
                enforcement="deterministic_config_readback",
                detail=(
                    "network.connection.httpProxy must be enabled and point to "
                    f"{GUARD_HOST}:{GUARD_PORT}"
                ),
                evidence={
                    "enabled": proxy_note("enabled", "true"),
                    "host": proxy_note("host", GUARD_HOST),
                    "port": proxy_note("port", str(GUARD_PORT)),
                },
            ),
            ControlCheck(
                name="callhome_telemetry_disabled",
                active=(
                    "enabled" in callhome_config
                    and _config_text(callhome_config.get("enabled")) == "false"
                ),
                enforcement="deterministic_config_readback",
                detail=(
                    "callhome.tel.enabled must be present and explicitly false so "
                    "the callhome add-on cannot attempt startup/shutdown telemetry "
                    "egress off-host or over plain HTTP"
                ),
                evidence={
                    "key": OFFLINE_CONFIG_CALLHOME_TEL_ENABLED,
                    "expected": "false",
                    "observed": callhome_config.get("enabled"),
                },
            ),
            ControlCheck(
                name="guard_endpoint_exact",
                active=guard_endpoint_ok,
                enforcement="guard_runtime_status",
                detail=f"egress guard must listen only on {GUARD_HOST}:{GUARD_PORT}",
                evidence={
                    "host": guard.get("bind_host"),
                    "port": guard.get("bind_port"),
                },
            ),
            ControlCheck(
                name="guard_target_exact",
                active=guard_target_ok,
                enforcement="guard_runtime_status",
                detail=(
                    "egress guard target must be exactly "
                    f"{STAGE2_HOST}:{STAGE2_PORT}"
                ),
                evidence={"target": dict(guard_target)},
            ),
            ControlCheck(
                name="guard_pinned_ips_global",
                active=guard_pinned_ok,
                enforcement="guard_runtime_status",
                detail=(
                    "egress guard must pin a non-empty globally routable public "
                    "IP set"
                ),
                evidence={"pinned_ips": pinned},
            ),
            ControlCheck(
                name="guard_running",
                active=bool(guard.get("prepared")) and bool(guard.get("running")),
                enforcement="guard_runtime_status",
                detail=(
                    "egress guard must be prepared and running before any target "
                    "request"
                ),
                evidence={
                    "prepared": guard.get("prepared"),
                    "running": guard.get("running"),
                },
            ),
            ControlCheck(
                name="guard_listener_exact",
                active=bool(guard_listener_ok),
                enforcement="read_only_local_inspection",
                detail=(
                    "the local snapshot must show exactly one listener on "
                    f"{GUARD_HOST}:{GUARD_PORT} owned by the guard PID with a "
                    "loopback bind address"
                ),
            ),
            ControlCheck(
                name="depth_le_3",
                active=config_matches(spider_config, "maxDepth", "3"),
                enforcement="deterministic_config_readback",
                detail="spider.maxDepth must be 3",
                evidence=spider_note("maxDepth", "3"),
            ),
            ControlCheck(
                name="concurrency_exactly_1",
                active=config_matches(spider_config, "thread", "1"),
                enforcement="deterministic_config_readback",
                detail="spider.thread must be 1",
                evidence=spider_note("thread", "1"),
            ),
            ControlCheck(
                name="duration_le_300s",
                active=config_matches(spider_config, "maxDuration", "5")
                and profile.spider_timeout <= MAX_DURATION_SECONDS,
                enforcement="deterministic_config_readback+wrapper_bound",
                detail="spider.maxDuration must be 5 minutes and the wrapper bound <= 300 s",
                evidence={
                    **spider_note("maxDuration", "5"),
                    "wrapper_spider_timeout": profile.spider_timeout,
                },
            ),
            ControlCheck(
                name="request_rate_le_1_per_second",
                active=config_matches(spider_config, "requestwait", "1000"),
                enforcement="deterministic_config_readback",
                detail="spider.requestwait must be 1000 ms (<= 1 request/s)",
                evidence=spider_note("requestwait", "1000"),
            ),
            ControlCheck(
                name="no_form_processing_or_submission",
                active=config_false("processform") and config_false("postform"),
                enforcement="deterministic_config_readback",
                detail="spider.processform and spider.postform must both be explicitly false",
                evidence={
                    "processform": spider_config.get("processform"),
                    "postform": spider_config.get("postform"),
                },
            ),
            ControlCheck(
                name="zap_no_direct_egress_established",
                active=bool(zap_direct_egress_ok),
                enforcement="runtime_connection_inspection",
                detail="ZAP must own no non-loopback ESTABLISHED connection",
            ),
            ControlCheck(
                name="guard_egress_within_pinned_set",
                active=bool(guard_egress_ok),
                enforcement="runtime_connection_inspection",
                detail=(
                    "the guard must own no non-loopback ESTABLISHED connection "
                    "other than to a pinned target IP on port 443"
                ),
            ),
            ControlCheck(
                name="guard_no_denied_or_error_records",
                active=bool(guard_records_clean),
                enforcement="guard_record_inspection",
                detail="the guard must record no denied or error connection attempt",
            ),
        ]
    )
    if include_scope_control:
        checks.append(
            ControlCheck(
                name="scope_activated",
                active=bool(scope_activated),
                enforcement="allowlisted_api_call",
                detail=(
                    "the exact-host context was created and the include-URL regex "
                    "applied by successful allowlisted API calls before any target "
                    "request"
                ),
            )
        )
    return checks


def _blockers(checks: Iterable[ControlCheck]) -> list[str]:
    return [check.name for check in checks if not check.active]


# ---------------------------------------------------------------------------
# Runtime connection inspection helpers (bounded, request-data-free)
# ---------------------------------------------------------------------------


def _is_established_state(state: Any) -> bool:
    normalized = "".join(ch for ch in str(state or "").lower() if ch.isalpha())
    return normalized == "established"


def _parse_ip(value: Any) -> Any:
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _connection_evidence(connection: Any) -> dict:
    return {
        "local_port": connection.local_port,
        "remote_address": str(connection.remote_address),
        "remote_port": connection.remote_port,
        "state": connection.state,
        "pid": connection.pid,
    }


def _bounded_connection_records(records: Iterable[Any]) -> list[dict]:
    return [_connection_evidence(record) for record in list(records)[:_MAX_INSPECTION_RECORDS]]


def _is_loopback_address(value: Any) -> bool:
    """Return True only for an explicitly parsed loopback remote address."""

    address = _parse_ip(value)
    return address is not None and address.is_loopback


def _non_loopback_established(connections: Iterable[Any]) -> list[Any]:
    """Return ESTABLISHED connections that are not explicitly loopback.

    Fail closed: an ESTABLISHED record whose remote address is unparseable or
    unspecified (for example ``0.0.0.0``) is offending, never exempt.
    """

    offending: list[Any] = []
    for connection in connections:
        if not _is_established_state(connection.state):
            continue
        if _is_loopback_address(connection.remote_address):
            continue
        offending.append(connection)
    return offending


def _guard_off_pinned(
    connections: Iterable[Any], pinned_ips: Any, target_port: int
) -> list[Any]:
    """Return guard ESTABLISHED connections outside loopback/pinned-IP:443.

    Only an explicitly parsed loopback endpoint or an explicitly parsed pinned
    target IP on the target port is allowed. Unparseable or unspecified remote
    addresses are offending (fail closed).
    """

    pinned = {str(ip) for ip in (pinned_ips or ())}
    offending: list[Any] = []
    for connection in connections:
        if not _is_established_state(connection.state):
            continue
        if _is_loopback_address(connection.remote_address):
            continue
        address = _parse_ip(connection.remote_address)
        if (
            address is not None
            and str(address) in pinned
            and connection.remote_port == target_port
        ):
            continue
        offending.append(connection)
    return offending


def _guard_listener_proof(
    connections: Iterable[Any], guard_pid: Any, observation_available: bool
) -> dict:
    """Prove one listener on exactly 127.0.0.1:18082 owned by the guard PID.

    The proof is derived from the local snapshot, never from ``guard.running``.
    It fails when observation is absent, when no listener on the exact port is
    present, when the bound address is wildcard/non-loopback, or when the
    listener owner is missing, wrong, or ambiguous.
    """

    proof: dict[str, Any] = {
        "observed": bool(observation_available),
        "present": False,
        "exact": False,
        "owner_pids": [],
        "local_addresses": [],
        "port": GUARD_PORT,
    }
    if not observation_available:
        return proof
    listeners = [
        connection
        for connection in connections
        if connection.is_listening and connection.local_port == GUARD_PORT
    ]
    proof["present"] = bool(listeners)
    proof["local_addresses"] = sorted(
        {str(connection.local_address) for connection in listeners}
    )
    owners: set[int] = set()
    for connection in listeners:
        pid = connection.pid
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            owners.add(pid)
    proof["owner_pids"] = sorted(owners)
    expected_owner = (
        int(guard_pid)
        if isinstance(guard_pid, int) and not isinstance(guard_pid, bool)
        else None
    )
    proof["exact"] = bool(
        listeners
        and proof["local_addresses"] == [GUARD_HOST]
        and expected_owner is not None
        and proof["owner_pids"] == [expected_owner]
    )
    return proof


def _bounded_field(value: Any, limit: int = 128) -> Any:
    if value is None:
        return None
    return str(value)[:limit]


def _bounded_int(value: Any) -> Any:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bounded_guard_record(record: Mapping[str, Any]) -> dict:
    return {
        "timestamp": _bounded_field(record.get("timestamp")),
        "decision": _bounded_field(record.get("decision")),
        "reason": _bounded_field(record.get("reason")),
        "host": _bounded_field(record.get("host")),
        "port": _bounded_int(record.get("port")),
        "status": _bounded_int(record.get("status")),
        "connected_ip": _bounded_field(record.get("connected_ip")),
        "bytes_to_upstream": _bounded_int(record.get("bytes_to_upstream")) or 0,
        "bytes_to_client": _bounded_int(record.get("bytes_to_client")) or 0,
    }


def _bounded_guard_evidence(guard: Any) -> dict:
    """Return a sanitized, bounded snapshot of the guard's evidence.

    Counters and at most ``_MAX_GUARD_RECORDS`` request-data-free records are
    retained. The guard never records headers, bodies, cookies, or credentials,
    and only the fixed scalar record fields are surfaced here.
    """

    if guard is None:
        return {"available": False}
    try:
        raw = guard.evidence()
    except Exception:
        return {"available": False}
    if not isinstance(raw, Mapping):
        return {"available": False}

    counters: dict[str, Any] = {}
    counters_raw = raw.get("counters")
    if isinstance(counters_raw, Mapping):
        for key in (
            "connections",
            "allowed",
            "denied",
            "errors",
            "bytes_to_upstream",
            "bytes_to_client",
        ):
            counters[key] = _bounded_int(counters_raw.get(key, 0))

    records_raw = raw.get("records")
    records: list[dict] = []
    if isinstance(records_raw, list):
        for record in records_raw[:_MAX_GUARD_RECORDS]:
            if isinstance(record, Mapping):
                records.append(_bounded_guard_record(record))

    target = raw.get("target")
    pinned_raw = raw.get("pinned_ips")
    return {
        "available": True,
        "guard": _bounded_field(raw.get("guard")),
        "running": bool(raw.get("running")),
        "prepared": bool(raw.get("prepared")),
        "bind_endpoint": _bounded_field(raw.get("bind_endpoint")),
        "target": dict(target) if isinstance(target, Mapping) else None,
        "pinned_ips": (
            [_bounded_field(ip) for ip in list(pinned_raw)[:_MAX_GUARD_RECORDS]]
            if isinstance(pinned_raw, list)
            else None
        ),
        "counters": counters,
        "record_count": len(records_raw) if isinstance(records_raw, list) else None,
        "records": records,
    }


def _evaluate_manager_shutdown(lifecycle: Any) -> tuple[bool, list[str], dict]:
    """Validate clean ZAP shutdown from the manager's lifecycle evidence.

    Fails closed when evidence is missing/unavailable or when it does not prove
    a graceful, API-initiated shutdown with the daemon gone, both fixed ports
    closed, and no control errors or terminate/kill fallbacks.
    """

    if not isinstance(lifecycle, Mapping):
        return False, ["manager lifecycle evidence is unavailable"], {"available": False}
    shutdown = lifecycle.get("shutdown")
    if not isinstance(shutdown, Mapping):
        return (
            False,
            ["manager shutdown evidence is unavailable"],
            {"available": False, "daemon_running": lifecycle.get("daemon_running")},
        )

    reasons: list[str] = []
    if shutdown.get("mode") != "identities_verified":
        reasons.append("manager shutdown mode is not identities_verified")
    if shutdown.get("api_attempted") is not True:
        reasons.append("API shutdown was not attempted")
    if shutdown.get("api_result") != "sent":
        reasons.append("API shutdown was not sent successfully")
    if shutdown.get("result") != "graceful":
        reasons.append("manager shutdown result is not graceful")
    if shutdown.get("daemon_running_after") is not False:
        reasons.append("ZAP daemon is still running after shutdown")
    if shutdown.get("api_port_closed") is not True:
        reasons.append("ZAP API port was not verified closed")
    if shutdown.get("callback_port_closed") is not True:
        reasons.append("OAST callback port was not verified closed")
    if shutdown.get("both_ports_closed") is not True:
        reasons.append("ZAP API and OAST ports were not both verified closed")
    if list(shutdown.get("control_errors") or []):
        reasons.append("process control errors occurred during shutdown")
    if list(shutdown.get("fallbacks") or []):
        reasons.append("terminate/kill fallback was required during shutdown")

    evidence = {
        "available": True,
        "mode": shutdown.get("mode"),
        "api_attempted": shutdown.get("api_attempted"),
        "api_result": shutdown.get("api_result"),
        "api_error": _bounded_field(shutdown.get("api_error")),
        "result": shutdown.get("result"),
        "daemon_running_after": shutdown.get("daemon_running_after"),
        "api_port_closed": shutdown.get("api_port_closed"),
        "callback_port_closed": shutdown.get("callback_port_closed"),
        "both_ports_closed": shutdown.get("both_ports_closed"),
        "fallbacks": [str(item) for item in (shutdown.get("fallbacks") or [])],
        "control_errors": [str(item) for item in (shutdown.get("control_errors") or [])],
        "process_exited": shutdown.get("process_exited"),
        "launcher_exit_code": _bounded_int(shutdown.get("launcher_exit_code")),
        "reasons": list(reasons),
    }
    return (not reasons), reasons, evidence


def _runtime_violations(inspection: Mapping[str, Any]) -> list[str]:
    """Return the fail-closed runtime violations for one inspection snapshot."""

    violations: list[str] = []
    if not inspection.get("observation_available"):
        violations.append("runtime connection observation is unavailable")
    if inspection.get("zap_non_loopback_established"):
        violations.append("ZAP owns a non-loopback ESTABLISHED connection")
    if inspection.get("guard_off_pinned"):
        violations.append(
            "guard owns a non-loopback ESTABLISHED connection off the pinned "
            "target set"
        )
    if inspection.get("observation_available"):
        guard_listener = inspection.get("guard_listener") or {}
        if not guard_listener.get("exact"):
            violations.append(
                f"guard listener is not exactly {GUARD_HOST}:{GUARD_PORT} owned "
                "by the guard PID"
            )
    if not inspection.get("guard_records_available"):
        violations.append("guard records are unavailable")
    elif inspection.get("guard_denied_or_error"):
        violations.append("guard recorded a denied or error connection attempt")
    return violations


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Stage2Profile:
    """A validated, side-effect-free description of the one Stage 2 run."""

    workspace_root: Path
    output_dir: Path
    executable: Path
    project: ProjectDomain
    target: Target
    scan_path: ScanPath
    endpoint: ZapEndpoint
    request_timeout: float
    startup_timeout: float
    spider_timeout: float
    poll_interval: float
    graceful_timeout: float
    terminate_timeout: float
    kill_timeout: float

    @property
    def domain(self) -> str:
        return self.project.name

    @property
    def mode(self) -> str:
        return STAGE2_MODE

    @property
    def context_name(self) -> str:
        return f"stage2-{self.scan_path.scan_id}"

    @property
    def target_policy(self) -> Stage2TargetPolicy:
        return Stage2TargetPolicy(self.target.url)

    @property
    def scope_regex(self) -> str:
        from .scanner import build_scope_regex

        return build_scope_regex(self.target)

    @property
    def scope_regex_is_exact(self) -> bool:
        # build_scope_regex escapes the exact host and pins the scheme; verify
        # it rejects a lookalike subdomain/sibling before trusting it.
        import re

        pattern = re.compile(self.scope_regex)
        return bool(pattern.match(STAGE2_SEED)) and not pattern.match(
            f"{STAGE2_SCHEME}://sub.{STAGE2_HOST}/"
        ) and not pattern.match(
            f"{STAGE2_SCHEME}://{STAGE2_HOST}.evil.test/"
        )

    @property
    def artifact_route_ok(self) -> bool:
        expected_project = self.workspace_root / "projects" / STAGE2_DOMAIN
        expected_target = expected_project / "targets" / STAGE2_HOST
        expected_zap = expected_target / "scans" / "zap"
        if self.project.name != STAGE2_DOMAIN or self.target.host != STAGE2_HOST:
            return False
        if not is_within(self.scan_path.scan_dir, expected_zap):
            return False
        return self.scan_path.scan_dir.name == self.scan_path.scan_id


def build_stage2_profile(
    *,
    workspace_root: Any,
    output_dir: Any,
    zap_executable: Any,
    zap_host: str = _EXACT_LOOPBACK_HOST,
    zap_port: int = _DEFAULT_API_PORT,
    request_timeout: float = DEFAULT_API_TIMEOUT,
    startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
    spider_timeout: float = MAX_DURATION_SECONDS,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    graceful_timeout: float = DEFAULT_GRACEFUL_TIMEOUT,
    terminate_timeout: float = DEFAULT_TERMINATE_TIMEOUT,
    kill_timeout: float = DEFAULT_KILL_TIMEOUT,
    expected_root: Any = None,
) -> Stage2Profile:
    """Validate the fixed Stage 2 profile without side effects."""

    from ...cli.scan_target import CliValidationError, build_plan

    args = SimpleNamespace(
        workspace_root=workspace_root,
        output_dir=output_dir,
        zap_executable=zap_executable,
        project=STAGE2_DOMAIN,
        target=STAGE2_SEED,
        mode=STAGE2_MODE,
        zap_host=zap_host,
        zap_port=zap_port,
        request_timeout=request_timeout,
        startup_timeout=startup_timeout,
        spider_timeout=spider_timeout,
        ajax_timeout=MAX_DURATION_SECONDS,
        poll_interval=poll_interval,
        graceful_timeout=graceful_timeout,
        terminate_timeout=terminate_timeout,
        kill_timeout=kill_timeout,
    )
    try:
        plan = build_plan(args, expected_root=expected_root)
    except CliValidationError as exc:
        raise Stage2ProfileError(str(exc)) from exc

    target = plan.target
    if plan.project.name != STAGE2_DOMAIN:
        raise Stage2ProfileError("project must be exactly acme.example")
    if (
        target.scheme != STAGE2_SCHEME
        or target.host != STAGE2_HOST
        or target.port != STAGE2_PORT
        or target.url != STAGE2_SEED
    ):
        raise Stage2ProfileError(
            f"target must be exactly {STAGE2_SEED!r} (https, host acme.example, port 443)"
        )
    if plan.mode != STAGE2_MODE:
        raise Stage2ProfileError("mode must be the traditional spider only")
    if plan.spider_timeout > MAX_DURATION_SECONDS:
        raise Stage2ProfileError(
            f"spider timeout must not exceed {MAX_DURATION_SECONDS:.0f} seconds"
        )

    return Stage2Profile(
        workspace_root=plan.workspace_root,
        output_dir=plan.output_dir,
        executable=plan.zap_executable,
        project=plan.project,
        target=target,
        scan_path=plan.scan_path,
        endpoint=plan.endpoint,
        request_timeout=plan.request_timeout,
        startup_timeout=plan.startup_timeout,
        spider_timeout=plan.spider_timeout,
        poll_interval=plan.poll_interval,
        graceful_timeout=plan.graceful_timeout,
        terminate_timeout=plan.terminate_timeout,
        kill_timeout=plan.kill_timeout,
    )


# ---------------------------------------------------------------------------
# Stage 2 runner
# ---------------------------------------------------------------------------


class Stage2SpiderRunner:
    """Run one bounded, exact-host traditional Spider and persist evidence.

    The runner never raises for an in-band failure: a failed or blocked run is
    reported through the returned evidence, and final JSON + Markdown evidence
    is always written. A failure to persist evidence is the only propagated
    error.
    """

    def __init__(
        self,
        *,
        profile: Stage2Profile,
        system: Optional[LifecycleSystem] = None,
        manager_factory: Optional[Callable[..., Any]] = None,
        client_factory: Optional[Callable[..., Any]] = None,
        transport_factory: Optional[Callable[..., Any]] = None,
        guard_factory: Optional[Callable[[], Any]] = None,
        spider_runner_factory: Optional[Callable[..., Any]] = None,
        now: Optional[Callable[[], str]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(profile, Stage2Profile):
            raise Stage2Error("profile must be a Stage2Profile")
        # No API key and no capability override are accepted: the production
        # runner is keyless and guarded by construction.
        self._profile = profile
        self._system = system
        self._now = now or (
            lambda: datetime.now(timezone.utc).isoformat()
        )
        self._clock = clock
        self._sleep = sleep

        self._recorder = ApiCallRecorder(self._now)
        self._transport = None
        self._client = None
        self._manager = None
        self._guard = None
        self._guard_stop_attempted = False
        self._spider_runner_factory = spider_runner_factory or self._default_spider_runner

        if client_factory is None:
            client_factory = self._default_client_factory
        if manager_factory is None:
            manager_factory = self._default_manager_factory
        if transport_factory is None:
            transport_factory = self._default_transport_factory
        if guard_factory is None:
            guard_factory = self._default_guard_factory

        self._client_factory = client_factory
        self._manager_factory = manager_factory
        self._transport_factory = transport_factory
        self._guard_factory = guard_factory

        self._state: dict[str, Any] = {}
        self._errors: list[dict] = []
        self._blocked = False
        self._stop_attempted = False
        self._stop_error: Optional[BaseException] = None

    # -- introspection ------------------------------------------------------

    @property
    def state(self) -> dict:
        return self._state

    @property
    def api_calls(self) -> list[dict]:
        return list(self._recorder.calls)

    # -- default components -------------------------------------------------

    def _default_transport_factory(self, inner: Any) -> Stage2AllowlistedTransport:
        return Stage2AllowlistedTransport(
            inner,
            endpoint=self._profile.endpoint,
            recorder=self._recorder,
        )

    def _default_client_factory(self, endpoint: ZapEndpoint, transport: Any) -> Stage2ApiClient:
        from .client import ZapApiClient

        # Keyless: no API key argument exists, so no secret can be created or
        # sent.
        raw = ZapApiClient(
            endpoint,
            None,
            keyless=True,
            transport=transport,
            timeout=self._profile.request_timeout,
        )
        return Stage2ApiClient(raw, self._profile)

    def _default_manager_factory(self, **kwargs: Any) -> ZapProcessManager:
        return ZapProcessManager(**kwargs)

    def _default_guard_factory(self) -> Any:
        from .egress import ConnectEgressGuard

        # Construction is fully inert: no socket, DNS, or filesystem activity.
        return ConnectEgressGuard()

    def _default_spider_runner(self) -> SpiderRunner:
        return SpiderRunner(
            self._client,
            timeout=self._profile.spider_timeout,
            poll_interval=self._profile.poll_interval,
            process_exited=self._process_exited,
            observer=self._runtime_observer,
            clock=self._clock,
            sleep=self._sleep,
        )

    def _process_exited(self) -> bool:
        running = getattr(self._manager, "running", None)
        return running is False

    # -- execution ----------------------------------------------------------

    def run(self) -> dict:
        self._state = self._initial_state()
        self._errors = []
        try:
            self._execute()
        except Exception as exc:
            self._record_error(exc)
        finally:
            # Shutdown order is fixed: stop ZAP first, then the guard. Both are
            # attempted exactly once even when an earlier step failed.
            self._stop_manager()
            self._stop_guard()
        self._finalize()
        return self._state

    def _execute(self) -> None:
        profile = self._profile
        profile.scan_path.create()
        self._persist()

        # ---- Static pre-launch gate: no guard/manager/transport/API call. ----
        prelaunch_checks = evaluate_prelaunch_controls(profile)
        prelaunch = {
            "ready_to_launch": all(check.active for check in prelaunch_checks),
            "blockers": _blockers(prelaunch_checks),
            "controls": [check.to_evidence() for check in prelaunch_checks],
        }
        self._state["prelaunch"] = prelaunch
        self._state["phase"] = "prelaunch-gate"
        self._persist()
        self._write_prelaunch_artifact(prelaunch)

        if not prelaunch["ready_to_launch"]:
            self._blocked = True
            self._state["status"] = "blocked"
            self._state["blocked_reason"] = (
                "refusing any ZAP launch: failed pre-launch controls: "
                + ", ".join(prelaunch["blockers"])
            )
            self._persist()
            return

        # Resolve the single lifecycle inspector before guard/ZAP start so the
        # guard-closure verification can use it even on an early failure.
        if self._system is None:
            from .smoke import PowerShellLocalInspector

            self._system = PowerShellLocalInspector()

        # ---- Egress guard: the only target DNS point, before ZAP start. ----
        self._start_guard()

        self._state["phase"] = "starting"
        self._persist()

        from .client import UrllibTransport

        inner = UrllibTransport()
        self._transport = self._transport_factory(inner)
        self._client = self._client_factory(profile.endpoint, self._transport)

        manager = self._manager_factory(
            executable=profile.executable,
            scan_path=profile.scan_path,
            keyless=True,
            silent=True,
            host=profile.endpoint.host,
            port=profile.endpoint.port,
            client=self._client,
            startup_timeout=profile.startup_timeout,
            graceful_timeout=profile.graceful_timeout,
            terminate_timeout=profile.terminate_timeout,
            kill_timeout=profile.kill_timeout,
            poll_interval=profile.poll_interval,
            extra_config=(
                LAUNCH_HARDENING_PAIRS
                + SPIDER_CONFIG_PAIRS
                + OAST_CONTAINMENT_PAIRS
                + PROXY_CONFIG_PAIRS
            ),
            callback_port=OAST_CALLBACK_PORT,
            system=self._system,
        )
        self._manager = manager
        safe_command = getattr(manager, "safe_command", None)
        self._state["safe_command"] = list(safe_command()) if callable(safe_command) else []
        self._persist()

        manager.start()
        version = manager.wait_until_ready()
        self._state["zap_version"] = version
        self._persist()

        # Post-startup read-back controls, before scope activation. The
        # not-yet-run scope activation is excluded from this first check and is
        # recorded separately once its allowlisted calls succeed.
        checks = self._runtime_preflight_checks(
            version, scope_activated=False, include_scope_control=False
        )
        preflight = {
            "ready_to_spider": all(check.active for check in checks),
            "blockers": _blockers(checks),
            "controls": [check.to_evidence() for check in checks],
        }
        self._state["preflight"] = preflight
        self._state["phase"] = "preflight"
        self._persist()
        self._write_preflight_artifact(preflight)
        if not preflight["ready_to_spider"]:
            raise Stage2PreflightError(
                "refusing to activate scope or start the target Spider; "
                "unproven controls: " + ", ".join(preflight["blockers"])
            )

        # ---- Scope activation: allowlisted context calls, no target request. --
        self._state["phase"] = "scope-activation"
        self._persist()
        try:
            self._client.create_context()
            self._client.include_in_context()
        except Exception as exc:
            raise Stage2PreflightError(
                "exact-host context activation failed; refusing to start the "
                f"target Spider ({type(exc).__name__})"
            ) from exc
        self._state["scope_activated"] = True
        self._persist()

        final_checks = self._runtime_preflight_checks(version, scope_activated=True)
        preflight = {
            "ready_to_spider": all(check.active for check in final_checks),
            "blockers": _blockers(final_checks),
            "controls": [check.to_evidence() for check in final_checks],
        }
        self._state["preflight"] = preflight
        self._state["phase"] = "preflight"
        self._persist()
        self._write_preflight_artifact(preflight)
        if not preflight["ready_to_spider"]:
            raise Stage2PreflightError(
                "refusing to start the target Spider; unproven controls: "
                + ", ".join(preflight["blockers"])
            )

        self._state["phase"] = "spider"
        self._persist()
        self._run_spider()
        self._state["status"] = "succeeded"
        self._state["phase"] = "done"
        self._persist()

    # -- egress guard -------------------------------------------------------

    def _start_guard(self) -> None:
        """Prepare, validate, and start the exact-host CONNECT egress guard.

        This is the only place target DNS resolution happens for the run. The
        guard is constructed inert, prepared (resolving and pinning the exact
        target host once), validated against the fixed endpoint/target, and
        finally started on ``127.0.0.1:18082`` before any ZAP process exists.
        """

        self._state["phase"] = "guard-prepare"
        self._persist()
        guard = self._guard_factory()
        self._guard = guard
        # The only target DNS point in the entire run.
        guard.prepare()
        self._validate_guard_config(guard)
        guard.start()
        status = self._guard_status()
        if not status["running"]:
            raise Stage2PreflightError(
                "egress guard did not start on the exact loopback endpoint"
            )
        self._state["egress_guard"] = status
        self._persist()

    def _validate_guard_config(self, guard: Any) -> None:
        host = getattr(guard, "bind_host", None)
        port = getattr(guard, "bind_port", None)
        if host != GUARD_HOST or port != GUARD_PORT:
            raise Stage2PreflightError(
                "egress guard is not configured for the exact loopback endpoint "
                f"{GUARD_HOST}:{GUARD_PORT}"
            )
        endpoint = getattr(guard, "target_endpoint", None)
        if not (
            isinstance(endpoint, (tuple, list))
            and len(endpoint) == 2
            and endpoint[0] == STAGE2_HOST
            and endpoint[1] == STAGE2_PORT
        ):
            raise Stage2PreflightError(
                f"egress guard target must be exactly {STAGE2_HOST}:{STAGE2_PORT}"
            )
        pinned = list(getattr(guard, "pinned_ips", ()) or ())
        if not pinned:
            raise Stage2PreflightError("egress guard pinned no target addresses")
        if not all(_is_global_ip(ip) for ip in pinned):
            raise Stage2PreflightError(
                "egress guard pinned a non-global target address"
            )

    def _guard_status(self) -> dict:
        guard = self._guard
        if guard is None:
            return {
                "configured": False,
                "bind_host": None,
                "bind_port": None,
                "target": None,
                "pinned_ips": [],
                "prepared": False,
                "running": False,
                "pid": None,
            }
        endpoint = getattr(guard, "target_endpoint", None)
        target = (
            {"host": endpoint[0], "port": endpoint[1]}
            if isinstance(endpoint, (tuple, list)) and len(endpoint) == 2
            else None
        )
        try:
            pinned = [str(ip) for ip in (getattr(guard, "pinned_ips", ()) or ())]
        except Exception:
            pinned = []
        return {
            "configured": True,
            "bind_host": getattr(guard, "bind_host", None),
            "bind_port": getattr(guard, "bind_port", None),
            "target": target,
            "pinned_ips": pinned,
            "prepared": bool(getattr(guard, "prepared", False)),
            "running": bool(getattr(guard, "running", False)),
            "pid": getattr(guard, "pid", None),
        }

    def _runtime_preflight_checks(
        self, version: Any, *, scope_activated: bool, include_scope_control: bool = True
    ) -> list[ControlCheck]:
        manager = self._manager
        inspection = self._runtime_inspection()
        listener_ok = bool(
            inspection.get("observation_available")
            and inspection.get("api_listener_loopback_only")
            and inspection.get("all_listener_loopback_only")
        )

        spider_config: dict[str, str] = {}
        try:
            spider_config = read_spider_config(manager.zap_home)
        except Stage2PreflightError:
            spider_config = {}
        else:
            self._state["spider_config_readback"] = dict(spider_config)

        proxy_config: dict[str, str] = {}
        try:
            proxy_config = read_proxy_config(manager.zap_home)
        except Stage2PreflightError:
            proxy_config = {}
        else:
            self._state["proxy_config_readback"] = dict(proxy_config)

        callhome_config: dict[str, str] = {}
        try:
            callhome_config = read_callhome_config(manager.zap_home)
        except Stage2PreflightError:
            callhome_config = {}
        else:
            self._state["callhome_config_readback"] = dict(callhome_config)

        guard_status = self._guard_status()
        self._state["egress_guard"] = guard_status
        guard_listener = inspection.get("guard_listener") or {}
        guard_listener_ok = bool(
            inspection.get("observation_available") and guard_listener.get("exact")
        )
        observed = bool(inspection.get("observation_available"))
        checks = evaluate_runtime_controls(
            self._profile,
            version=version,
            spider_config=spider_config,
            proxy_config=proxy_config,
            callhome_config=callhome_config,
            guard=guard_status,
            listener_ok=listener_ok,
            listener_detail=(
                "every observed daemon listener must be exactly 127.0.0.1"
                if listener_ok
                else "daemon listener observation is unavailable or non-loopback"
            ),
            identity_verified=getattr(manager, "daemon_pid", None) is not None,
            zap_direct_egress_ok=observed
            and not inspection.get("zap_non_loopback_established"),
            guard_egress_ok=observed and not inspection.get("guard_off_pinned"),
            guard_records_clean=bool(
                inspection.get("guard_records_available")
                and not inspection.get("guard_denied_or_error")
            ),
            guard_listener_ok=guard_listener_ok,
            scope_activated=scope_activated,
            include_scope_control=include_scope_control,
        )
        # Capture a bounded guard evidence snapshot alongside the runtime checks.
        self._capture_guard_evidence("guard_evidence")
        return checks

    def _collect_snapshot(self) -> Any:
        system = self._system
        if system is None:
            return None
        try:
            return system.snapshot()
        except Exception:
            return None

    def _runtime_inspection(self) -> dict:
        """Return a bounded, request-data-free runtime egress snapshot.

        The snapshot is derived from a read-only local process/TCP observation
        scoped to the ZAP/guard PIDs and the fixed API/OAST/guard ports. It
        records counters and a bounded list of offending endpoints only; no
        command lines, bodies, headers, cookies, or credentials are retained.
        """

        profile = self._profile
        manager = self._manager
        guard = self._guard
        zap_pid = None
        if manager is not None:
            zap_pid = getattr(manager, "daemon_pid", None)
            if zap_pid is None:
                zap_pid = getattr(manager, "pid", None)
        guard_pid = getattr(guard, "pid", None) if guard is not None else None
        pinned = set(self._guard_status().get("pinned_ips") or [])

        result: dict[str, Any] = {
            "timestamp": self._now(),
            "observation_available": False,
            "process_observation_available": False,
            "zap_pid": zap_pid,
            "guard_pid": guard_pid,
            "api_listener_loopback_only": False,
            "all_listener_loopback_only": False,
            "listener_local_addresses": [],
            "zap_non_loopback_established": [],
            "guard_off_pinned": [],
            "guard_listener": _guard_listener_proof((), guard_pid, False),
        }

        snapshot = self._collect_snapshot()
        if snapshot is not None and snapshot.observation_available:
            result["observation_available"] = True
            result["process_observation_available"] = bool(
                snapshot.process_observation_available
            )
            scoped = scope_snapshot(
                snapshot,
                api_port=profile.endpoint.port,
                callback_port=OAST_CALLBACK_PORT,
                extra_pids=(zap_pid, guard_pid),
            )
            raw = snapshot_to_inspection_raw(
                scoped,
                port=profile.endpoint.port,
                callback_port=OAST_CALLBACK_PORT,
            )
            analysis = analyze_inspection(raw)
            result["api_listener_loopback_only"] = bool(
                analysis.get("api_listener_loopback_only")
            )
            result["all_listener_loopback_only"] = bool(
                analysis.get("all_listener_loopback_only")
            )
            result["listener_local_addresses"] = list(
                analysis.get("all_listener_local_addresses") or []
            )
            result["zap_non_loopback_established"] = _bounded_connection_records(
                _non_loopback_established(scoped.connections_for_pid(zap_pid))
            )
            result["guard_off_pinned"] = _bounded_connection_records(
                _guard_off_pinned(
                    scoped.connections_for_pid(guard_pid),
                    pinned,
                    profile.target.port,
                )
            )
            result["guard_listener"] = _guard_listener_proof(
                scoped.connections, guard_pid, True
            )

        records = self._guard_records_status()
        result["guard_records_available"] = records["available"]
        result["guard_denied_or_error"] = records["denied_or_error"]
        self._record_inspection(result)
        return result

    def _guard_records_status(self) -> dict:
        guard = self._guard
        if guard is None:
            return {"available": False, "denied_or_error": False}
        available = False
        denied_or_error = False
        try:
            records = guard.get_records()
        except Exception:
            records = None
        if isinstance(records, list):
            available = True
            for record in records:
                if isinstance(record, Mapping) and str(record.get("decision")) in (
                    "denied",
                    "error",
                ):
                    denied_or_error = True
                    break
        try:
            evidence = guard.evidence()
        except Exception:
            evidence = None
        if isinstance(evidence, Mapping):
            available = True
            counters = evidence.get("counters")
            if isinstance(counters, Mapping):
                try:
                    if int(counters.get("denied", 0)) > 0 or int(
                        counters.get("errors", 0)
                    ) > 0:
                        denied_or_error = True
                except (TypeError, ValueError):
                    pass
        return {"available": available, "denied_or_error": denied_or_error}

    def _record_inspection(self, inspection: Mapping[str, Any]) -> None:
        inspections = self._state.setdefault("runtime_inspections", [])
        inspections.append(dict(inspection))
        if len(inspections) > _MAX_INSPECTIONS:
            del inspections[: len(inspections) - _MAX_INSPECTIONS]

    def _capture_guard_evidence(self, key: str) -> None:
        self._state[key] = _bounded_guard_evidence(self._guard)

    def _inspect_runtime_or_fail(self, *, context: str) -> None:
        inspection = self._runtime_inspection()
        self._capture_guard_evidence("guard_evidence")
        violations = _runtime_violations(inspection)
        if violations:
            raise Stage2PreflightError(
                f"runtime egress inspection failed during {context}: "
                + "; ".join(violations)
            )

    def _runtime_observer(self) -> None:
        """Fail-closed observer invoked after Spider start and on every poll."""

        self._inspect_runtime_or_fail(context="spider-poll")

    def _run_spider(self) -> None:
        # Context/scope activation already happened, and only after that did the
        # final preflight pass. This method issues the first target request.
        self._begin_step("spider")
        runner = self._spider_runner_factory()
        result = runner.run(
            self._profile.target.url,
            context_name=self._profile.context_name,
            subtree_only=True,
        )
        # The same fail-closed inspection runs again at completion, before the
        # results are treated as successful.
        self._inspect_runtime_or_fail(context="spider-complete")
        violations = self._profile.target_policy.result_violations(result.results)
        if violations:
            try:
                self._client.stop_spider(result.scan_id)
            except Exception:
                pass
            raise Stage2PreflightError(
                "Spider results contained out-of-host URLs; refusing to treat the "
                f"crawl as contained: {violations[:5]}"
            )
        self._write_artifact(
            "raw/spider.json",
            {
                "mode": "spider",
                "scan_id": result.scan_id,
                "results": result.results,
            },
        )
        self._finish_step("spider")

    # -- shutdown -----------------------------------------------------------

    def _stop_manager(self) -> None:
        manager = self._manager
        if manager is None or self._stop_attempted:
            return
        self._stop_attempted = True
        self._state["phase"] = "stopping"
        try:
            self._persist()
        except Exception:
            pass
        try:
            # The manager performs and verifies the API/OAST shutdown and
            # raises on failure (including after a terminate/kill fallback).
            manager.stop()
        except Exception as exc:
            self._stop_error = exc
            self._record_error(exc, phase="shutdown")
        # Independently prove the shutdown was clean from bounded lifecycle
        # evidence: API shutdown attempted and sent, graceful result, daemon
        # gone, both fixed ports closed, and no control errors/fallbacks.
        lifecycle = None
        getter = getattr(manager, "lifecycle_evidence", None)
        if callable(getter):
            try:
                lifecycle = getter()
            except Exception as exc:
                self._record_error(exc, phase="shutdown")
                lifecycle = None
        clean, reasons, evidence = _evaluate_manager_shutdown(lifecycle)
        self._state["manager_shutdown"] = evidence
        if not clean:
            self._record_error(
                Stage2PreflightError(
                    "ZAP shutdown was not verified clean: " + "; ".join(reasons)
                ),
                phase="shutdown",
            )
        try:
            self._persist()
        except Exception:
            pass

    def _stop_guard(self) -> None:
        """Stop the guard once and verify it and its exact port are closed."""

        guard = self._guard
        if guard is None or self._guard_stop_attempted:
            return
        self._guard_stop_attempted = True
        try:
            self._persist()
        except Exception:
            pass
        try:
            guard.stop()
        except Exception as exc:
            self._record_error(exc, phase="guard_shutdown")
        # Final inspection of the retained guard records/counters after ZAP
        # shutdown and guard stop. This is the last point at which the in-process
        # guard still retains its records, so a shutdown-time off-host/plain-HTTP
        # egress attempt (for example callhome telemetry) cannot slip past the
        # final Spider observer.
        self._final_guard_records_check()
        closure = self._verify_guard_closed(guard)
        self._state["guard_shutdown"] = closure
        if not closure.get("stopped"):
            self._record_error(
                Stage2PreflightError("egress guard did not report stopped"),
                phase="guard_shutdown",
            )
        elif not closure.get("port_closed"):
            self._record_error(
                Stage2PreflightError(
                    f"egress guard port {GUARD_PORT} was not verified closed after "
                    "shutdown"
                ),
                phase="guard_shutdown",
            )
        try:
            self._persist()
        except Exception:
            pass

    def _final_guard_records_check(self) -> None:
        """Inspect the retained guard records/counters one final time.

        Called after ZAP shutdown and guard stop. Unavailable records or any
        denied/error attempt -- for example a callhome telemetry egress attempted
        through the guard during ZAP shutdown -- marks the run failed, closing
        the gap where such an attempt could occur after the final Spider
        observer.
        """

        self._capture_guard_evidence("guard_shutdown_evidence")
        records = self._guard_records_status()
        self._state["guard_shutdown_records"] = {
            "available": bool(records["available"]),
            "denied_or_error": bool(records["denied_or_error"]),
        }
        if not records["available"]:
            self._record_error(
                Stage2PreflightError(
                    "guard records were unavailable after shutdown; refusing to "
                    "treat the run as clean"
                ),
                phase="guard_shutdown",
            )
        elif records["denied_or_error"]:
            self._record_error(
                Stage2PreflightError(
                    "guard recorded a denied or error connection attempt during "
                    "shutdown"
                ),
                phase="guard_shutdown",
            )

    def _verify_guard_closed(self, guard: Any) -> dict:
        result: dict[str, Any] = {
            "endpoint": f"{GUARD_HOST}:{GUARD_PORT}",
            "guard_running": True,
            "stopped": False,
            "port": GUARD_PORT,
            "port_closed": False,
            "observation_available": False,
        }
        try:
            running = bool(getattr(guard, "running", False))
        except Exception:
            running = True
        result["guard_running"] = running
        if running:
            return result
        result["stopped"] = True
        snapshot = self._collect_snapshot()
        if snapshot is not None and snapshot.observation_available:
            result["observation_available"] = True
            result["port_closed"] = not snapshot.has_listener_on(GUARD_PORT)
        return result

    # -- state / evidence ---------------------------------------------------

    def _initial_state(self) -> dict:
        timestamp = self._now()
        profile = self._profile
        return {
            "schema_version": 1,
            "status": "planned",
            "phase": "plan",
            "created_at": timestamp,
            "updated_at": timestamp,
            "domain": profile.domain,
            "target_url": profile.target.url,
            "mode": profile.mode,
            "scan_id": profile.scan_path.scan_id,
            "workspace_root": str(profile.workspace_root),
            "run_dir": str(profile.scan_path.scan_dir),
            "endpoint": profile.endpoint.base_url,
            "expected_version": EXPECTED_ZAP_VERSION,
            "zap_version": None,
            "scope_regex": profile.scope_regex,
            "context_name": profile.context_name,
            "controls": {
                "max_depth": MAX_DEPTH,
                "max_duration_seconds": MAX_DURATION_SECONDS,
                "max_duration_minutes": MAX_DURATION_MINUTES,
                "concurrency": CONCURRENCY,
                "max_requests_per_second": MAX_REQUESTS_PER_SECOND,
                "allowed_methods": list(ALLOWED_METHODS),
                "form_processing": False,
                "form_submission": False,
                "external_redirects": False,
                "third_party_resources": False,
            },
            "keyless_api": True,
            "guard_endpoint": f"{GUARD_HOST}:{GUARD_PORT}",
            "spider_config_pairs": [f"{key}={value}" for key, value in SPIDER_CONFIG_PAIRS],
            "launch_hardening_pairs": [f"{key}={value}" for key, value in LAUNCH_HARDENING_PAIRS],
            "oast_containment_pairs": [f"{key}={value}" for key, value in OAST_CONTAINMENT_PAIRS],
            "proxy_config_pairs": [f"{key}={value}" for key, value in PROXY_CONFIG_PAIRS],
            "safe_command": [],
            "spider_config_readback": None,
            "proxy_config_readback": None,
            "callhome_config_readback": None,
            "egress_guard": None,
            "guard_evidence": None,
            "guard_shutdown_evidence": None,
            "guard_shutdown_records": None,
            "runtime_inspections": [],
            "guard_shutdown": None,
            "manager_shutdown": None,
            "allowed_operations": sorted("/".join(op) for op in ALLOWED_OPERATIONS),
            "prelaunch": None,
            "preflight": None,
            "scope_activated": None,
            "blocked_reason": None,
            "steps": {},
            "artifacts": {},
            "errors": [],
        }

    def _begin_step(self, name: str) -> None:
        step = self._state["steps"].setdefault(name, {})
        step["status"] = "running"
        step["started_at"] = self._now()
        self._persist()

    def _finish_step(self, name: str) -> None:
        step = self._state["steps"].setdefault(name, {})
        step["status"] = "succeeded"
        step["finished_at"] = self._now()
        self._persist()

    def _record_error(self, exc: BaseException, *, phase: Optional[str] = None) -> None:
        if not self._state:
            self._state = self._initial_state()
        message = str(exc).strip() or type(exc).__name__
        self._errors.append(
            {
                "type": type(exc).__name__,
                "message": message,
                "phase": phase or self._state.get("phase"),
            }
        )

    def _persist(self) -> Path:
        self._state["updated_at"] = self._now()
        self._state["errors"] = list(self._errors)
        target = self._profile.scan_path.state_file_path(STAGE2_STATE_FILENAME)
        return atomic_write_json(
            target, self._state, scan_dir=self._profile.scan_path.scan_dir
        )

    def _write_prelaunch_artifact(self, prelaunch: Mapping[str, Any]) -> None:
        target = self._profile.scan_path.state_file_path(PRELAUNCH_FILENAME)
        atomic_write_json(
            target, dict(prelaunch), scan_dir=self._profile.scan_path.scan_dir
        )
        self._state["artifacts"]["prelaunch"] = target.name

    def _write_preflight_artifact(self, preflight: Mapping[str, Any]) -> None:
        target = self._profile.scan_path.state_file_path(PREFLIGHT_FILENAME)
        atomic_write_json(
            target, dict(preflight), scan_dir=self._profile.scan_path.scan_dir
        )
        self._state["artifacts"]["preflight"] = target.name

    def _write_artifact(self, relative: str, payload: Mapping[str, Any]) -> Path:
        raw_dir = self._profile.scan_path.scan_dir / Path(relative).parent
        if not is_within(raw_dir, self._profile.scan_path.scan_dir):
            raise Stage2Error("refusing to write artifacts outside the scan directory")
        raw_dir.mkdir(parents=True, exist_ok=True)
        target = raw_dir / Path(relative).name
        if not is_within(target, raw_dir):
            raise Stage2Error("refusing to write an artifact outside the run directory")
        atomic_write_json(
            target, dict(payload), scan_dir=self._profile.scan_path.scan_dir
        )
        self._state["artifacts"][Path(relative).stem] = relative
        return target

    def _finalize(self) -> None:
        self._state["api_calls"] = list(self._recorder.calls)
        self._state["errors"] = list(self._errors)
        # The keyless launch command contains no API key, so it is already safe
        # to retain verbatim.
        self._state["command_summary"] = list(self._state.get("safe_command") or [])

        if self._blocked and not self._errors:
            # A blocked run is a distinct, non-error outcome: no guard, manager,
            # transport, client, or API call was ever made.
            self._state["status"] = "blocked"
            self._state["phase"] = "prelaunch-gate"
        else:
            if self._state.get("status") != "succeeded" or self._errors:
                self._state["status"] = "failed"
            if self._state["status"] == "succeeded":
                self._state["phase"] = "done"

        self._state["finished_at"] = self._now()
        self._state["updated_at"] = self._state["finished_at"]
        self._state["errors"] = list(self._errors)
        self._write_evidence()

    def _write_evidence(self) -> None:
        self._persist()
        json_path = self._profile.scan_path.state_file_path(STAGE2_JSON_FILENAME)
        atomic_write_json(
            json_path, self._state, scan_dir=self._profile.scan_path.scan_dir
        )
        markdown_path = self._profile.scan_path.state_file_path(
            STAGE2_MARKDOWN_FILENAME
        )
        markdown_path.write_text(
            render_markdown(self._state), encoding="utf-8", newline="\n"
        )


# ---------------------------------------------------------------------------
# Markdown evidence
# ---------------------------------------------------------------------------


def _md(value: Any) -> str:
    import json

    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def render_markdown(evidence: Mapping[str, Any]) -> str:
    """Render the Stage 2 evidence object as human-readable Markdown."""

    import json

    lines: list[str] = []
    lines.append("# OWASP ZAP bounded Stage 2 traditional Spider")
    lines.append("")
    lines.append(
        "Single unauthenticated traditional Spider against exactly "
        "`https://acme.example/`. Keyless loopback ZAP API; exact-host "
        "CONNECT egress guard; GET/HEAD only; no forms; no AJAX/browser; no "
        "active scan; no authentication; no API import; no report API. No target "
        "launch is authorized unless every control below is proven active."
    )
    lines.append("")

    lines.append("## Outcome")
    lines.append("")
    for key in (
        "status",
        "phase",
        "schema_version",
        "created_at",
        "finished_at",
        "blocked_reason",
    ):
        lines.append(f"- {key}: {_md(evidence.get(key))}")
    lines.append(f"- keyless_api: {_md(evidence.get('keyless_api'))}")
    lines.append(f"- guard_endpoint: {_md(evidence.get('guard_endpoint'))}")
    lines.append("")

    lines.append("## Run identity")
    lines.append("")
    for key in (
        "domain",
        "target_url",
        "mode",
        "scan_id",
        "workspace_root",
        "run_dir",
        "endpoint",
        "context_name",
        "scope_regex",
    ):
        lines.append(f"- {key}: {_md(evidence.get(key))}")
    lines.append("")

    lines.append("## Fixed controls")
    lines.append("")
    for key, value in (evidence.get("controls") or {}).items():
        lines.append(f"- {key}: {_md(value)}")
    lines.append("")

    lines.append("## Launch configuration")
    lines.append("")
    lines.append(f"- safe_command: {_md(evidence.get('command_summary'))}")
    lines.append(f"- spider_config_pairs: {_md(evidence.get('spider_config_pairs'))}")
    lines.append(f"- launch_hardening_pairs: {_md(evidence.get('launch_hardening_pairs'))}")
    lines.append(f"- oast_containment_pairs: {_md(evidence.get('oast_containment_pairs'))}")
    lines.append(f"- proxy_config_pairs: {_md(evidence.get('proxy_config_pairs'))}")
    lines.append(f"- spider_config_readback: {_md(evidence.get('spider_config_readback'))}")
    lines.append(f"- proxy_config_readback: {_md(evidence.get('proxy_config_readback'))}")
    lines.append(
        f"- callhome_config_readback: "
        f"{_md(evidence.get('callhome_config_readback'))}"
    )
    lines.append(f"- allowed_operations: {_md(evidence.get('allowed_operations'))}")
    lines.append(f"- expected_version: {_md(evidence.get('expected_version'))}")
    lines.append(f"- observed_version: {_md(evidence.get('zap_version'))}")
    lines.append("")

    lines.append("## Egress guard")
    lines.append("")
    lines.append(f"- egress_guard: {_md(evidence.get('egress_guard'))}")
    lines.append(f"- guard_evidence: {_md(evidence.get('guard_evidence'))}")
    lines.append(f"- guard_shutdown: {_md(evidence.get('guard_shutdown'))}")
    lines.append(
        f"- guard_shutdown_evidence: {_md(evidence.get('guard_shutdown_evidence'))}"
    )
    lines.append(
        f"- guard_shutdown_records: {_md(evidence.get('guard_shutdown_records'))}"
    )
    lines.append("")

    lines.append("## ZAP shutdown proof")
    lines.append("")
    lines.append(f"- manager_shutdown: {_md(evidence.get('manager_shutdown'))}")
    lines.append("")

    lines.append("## Pre-launch gate (before any guard/manager/transport/API)")
    lines.append("")
    prelaunch = evidence.get("prelaunch") or {}
    lines.append(f"- ready_to_launch: {_md(prelaunch.get('ready_to_launch'))}")
    lines.append(f"- blockers: {_md(prelaunch.get('blockers'))}")
    for check in prelaunch.get("controls") or []:
        lines.append(
            f"- {check.get('name')}: active={_md(check.get('active'))} "
            f"enforcement={_md(check.get('enforcement'))} detail={_md(check.get('detail'))}"
        )
    lines.append("")

    lines.append("## Post-startup preflight controls")
    lines.append("")
    preflight = evidence.get("preflight") or {}
    lines.append(f"- ready_to_spider: {_md(preflight.get('ready_to_spider'))}")
    lines.append(f"- blockers: {_md(preflight.get('blockers'))}")
    for check in preflight.get("controls") or []:
        lines.append(
            f"- {check.get('name')}: active={_md(check.get('active'))} "
            f"enforcement={_md(check.get('enforcement'))} detail={_md(check.get('detail'))}"
        )
    lines.append("")

    lines.append("## Runtime egress inspections")
    lines.append("")
    inspections = evidence.get("runtime_inspections") or []
    if not inspections:
        lines.append("_No runtime inspection snapshots were recorded._")
    else:
        for snapshot in inspections:
            lines.append(f"- {_md(snapshot)}")
    lines.append("")

    lines.append("## API calls")
    lines.append("")
    calls = evidence.get("api_calls") or []
    if not calls:
        lines.append("_No API calls were attempted._")
    else:
        for call in calls:
            lines.append(
                "- "
                f"{call.get('timestamp')} {call.get('kind')}/{call.get('operation')} "
                f"path={call.get('path')} allowed={call.get('allowed')} "
                f"status={call.get('status')} error={call.get('error')}"
            )
    lines.append("")

    lines.append("## Steps")
    lines.append("")
    for name, step in (evidence.get("steps") or {}).items():
        lines.append(f"- {name}: {_md(step)}")
    lines.append("")

    lines.append("## Errors")
    lines.append("")
    for error in evidence.get("errors") or []:
        lines.append(
            f"- {error.get('type')} ({error.get('phase')}): {error.get('message')}"
        )
    lines.append("")
    return "\n".join(lines)
