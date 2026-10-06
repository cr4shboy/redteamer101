"""RECON-003 evidence: network-policy document, launch ledger, failure record.

All artifacts here are **domain-routed** and rewritten only inside an already
created run directory. The document deliberately contains no full URL, query
string, or secret: broker events record only hostnames, ports, DNS names/types,
and a fixed decision token.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Optional

from ..orchestration.state import ScanStateError, atomic_write_json
from .netpolicy import RECON_002_POLICY, ReconNetworkPolicy
from .paths import ReconPath
from .storage import ensure_evidence_dir

__all__ = [
    "AUTHORIZED_INPUT_FILENAME",
    "LAUNCH_MARKER_FILENAME",
    "NETWORK_POLICY_FILENAME",
    "PACKAGE_NAME",
    "EvidenceProvider",
    "build_launch_marker",
    "build_network_policy_document",
    "prior_recon_entries",
    "write_launch_marker",
    "write_network_policy",
    "write_run_failure",
]

PACKAGE_NAME = "RECON-003"
HISTORICAL_PACKAGE_NAME = "RECON-002"
HISTORICAL_RUN_ID = "20261004T110717Z-94fa0e"
NETWORK_POLICY_FILENAME = "network-policy.json"
LAUNCH_MARKER_FILENAME = "launch-marker.json"
FAILURE_FILENAME = "run.json"

#: The single regular, non-symlink input file permitted to sit at the recon
#: root without consuming the one-run budget.
AUTHORIZED_INPUT_FILENAME = "domains.txt"


class EvidenceError(ValueError):
    """Evidence could not be built or written safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _assert_no_query_or_secret(value: object, *, path: str = "$") -> None:
    if isinstance(value, str):
        if "?" in value:
            raise EvidenceError(f"evidence at {path} would persist a query string")
        lowered = value.lower()
        for fragment in ("token=", "secret=", "password=", "api_key=", "apikey="):
            if fragment in lowered:
                raise EvidenceError(f"evidence at {path} would persist a secret")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _assert_no_query_or_secret(item, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_no_query_or_secret(item, path=f"{path}[{index}]")


def _endpoint_for_event(event: Mapping) -> str | None:
    """Return the explicit ``host:port`` destination of an allowed event, if any.

    CONNECT events name the CT authority in ``host``/``port``; allowed DNS and
    bootstrap-resolve events name the resolver in ``upstream_host``/
    ``upstream_port``. Results never include a URL or query string.
    """

    action = event.get("action")
    if action == "connect":
        host, port = event.get("host"), event.get("port")
    elif action in ("dns", "resolve"):
        host, port = event.get("upstream_host"), event.get("upstream_port")
    else:
        return None
    if not isinstance(host, str) or not host:
        return None
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    return f"{host}:{port}"


def _external_destinations(invocations: Iterable[Mapping]) -> dict:
    """Summarize external destinations from bounded broker events (no URLs)."""

    allow = deny = error = 0
    hosts: dict[str, int] = {}
    endpoints: dict[str, int] = {}
    for invocation in invocations:
        for event in invocation.get("broker_events", []) or ():
            decision = event.get("decision")
            if decision == "allowed":
                allow += 1
                endpoint = _endpoint_for_event(event)
                if endpoint is not None:
                    endpoints[endpoint] = endpoints.get(endpoint, 0) + 1
            elif decision == "denied":
                deny += 1
            elif decision == "error":
                error += 1
            host = event.get("host") or event.get("qname")
            if isinstance(host, str) and host:
                hosts[host] = hosts.get(host, 0) + 1
    return {
        "allowed": allow,
        "denied": deny,
        "errors": error,
        "hosts": [{"host": host, "events": hosts[host]} for host in sorted(hosts)],
        "endpoints": [
            {"endpoint": endpoint, "events": endpoints[endpoint]}
            for endpoint in sorted(endpoints)
        ],
    }


def build_network_policy_document(
    *,
    run_id: str,
    root: str,
    runtime: Optional[Mapping] = None,
    installs: Optional[Iterable[Mapping]] = None,
    invocations: Optional[Iterable[Mapping]] = None,
    policy=RECON_002_POLICY,
    generated_utc: Optional[str] = None,
    status: str = "completed",
) -> dict:
    """Build the ``network-policy.json`` document (no I/O)."""

    invocation_list = [dict(item) for item in (invocations or ())]
    document = {
        "schema_version": 1,
        "package": PACKAGE_NAME,
        "root_domain": root,
        "run_id": run_id,
        "status": status,
        "generated_utc": generated_utc or _utc_now(),
        "policy": {
            "root_domain": policy.root_domain,
            "https_host": policy.https_host,
            "https_port": policy.https_port,
            "upstream_dns_host": policy.upstream_dns_host,
            "upstream_dns_port": policy.upstream_dns_port,
            "dns_qps": policy.dns_qps,
            "dns_max_concurrent": policy.dns_max_concurrent,
            "discovery_source": "crt.sh",
            "record_types": ["A", "AAAA", "CNAME"],
        },
        "runtime": dict(runtime) if runtime is not None else None,
        "pinned_installs": [dict(item) for item in (installs or ())],
        "invocations": invocation_list,
        "external_destinations": _external_destinations(invocation_list),
    }
    _assert_no_query_or_secret(document)
    return document


def write_network_policy(recon_path: ReconPath, document: dict) -> Path:
    """Atomically write ``evidence/network-policy.json`` inside an existing run."""

    if not isinstance(document, dict):
        raise EvidenceError("network policy document must be a JSON object")
    _assert_no_query_or_secret(document)
    _require_run(recon_path)
    directory = ensure_evidence_dir(recon_path)
    target = directory / NETWORK_POLICY_FILENAME
    try:
        return atomic_write_json(target, document, scan_dir=recon_path.run_dir)
    except (ScanStateError,) as exc:  # pragma: no cover - defensive
        raise EvidenceError(str(exc)) from exc


@dataclass
class EvidenceProvider:
    """Builds the run's ``network-policy.json`` from validated runtime facts.

    ``invocations`` is the shared, live list appended to by the sandbox runners,
    so the evidence document reflects exactly what each tool stage did.
    """

    root: str
    runtime: object = None
    installs: tuple = ()
    invocations: list = None
    #: Injected network policy (a real dataclass field so it is constructor-
    #: settable; a bare ``policy=...`` annotation-less class attribute would be
    #: invisible to ``dataclasses`` and rejected as an ``__init__`` kwarg).
    policy: ReconNetworkPolicy = RECON_002_POLICY

    def document(self, *, run_id: str, root: str, status: str = "completed") -> dict:
        runtime_document = None
        if self.runtime is not None and hasattr(self.runtime, "to_dict"):
            runtime_document = self.runtime.to_dict()
        installs = [
            report.to_dict() if hasattr(report, "to_dict") else dict(report)
            for report in (self.installs or ())
        ]
        return build_network_policy_document(
            run_id=run_id,
            root=root,
            runtime=runtime_document,
            installs=installs,
            invocations=list(self.invocations or []),
            policy=self.policy,
            status=status,
        )


def _require_run(recon_path: ReconPath) -> ReconPath:
    if not isinstance(recon_path, ReconPath):
        raise EvidenceError("expected a ReconPath")
    if not recon_path.run_dir.is_dir():
        raise EvidenceError("run directory must already exist")
    return recon_path


# ---------------------------------------------------------------------------
# One-run ledger
# ---------------------------------------------------------------------------


def prior_recon_entries(workspace_root, root: str) -> tuple[Path, ...]:
    """Return blocking entries under ``projects/<root>/recon/`` (fail closed).

    The regular, non-symlink input file ``domains.txt`` is ignored. The one exact
    immutable RECON-002 run is also ignored only when its two ledger documents
    are regular, non-symlink files with matching canonical identity fields.
    Every other entry blocks the RECON-003 one-run budget.
    """

    recon_root = Path(workspace_root) / "projects" / root / "recon"
    if not recon_root.exists():
        return ()
    if recon_root.is_symlink() or not recon_root.is_dir():
        return (recon_root,)
    blocking: list[Path] = []
    for entry in sorted(recon_root.iterdir(), key=lambda item: item.name):
        if (
            entry.name == AUTHORIZED_INPUT_FILENAME
            and entry.is_file()
            and not entry.is_symlink()
        ):
            continue
        if entry.name == HISTORICAL_RUN_ID and _valid_historical_run(entry, root):
            continue
        blocking.append(entry)
    return tuple(blocking)


def _valid_historical_run(run_dir: Path, root: str) -> bool:
    """Validate only the identity ledger needed to exempt the immutable run."""

    if root != "acme.example" or run_dir.is_symlink() or not run_dir.is_dir():
        return False
    expected = {
        "package": HISTORICAL_PACKAGE_NAME,
        "root_domain": root,
        "run_id": HISTORICAL_RUN_ID,
        "launch_budget_consumed": True,
    }
    for filename in (FAILURE_FILENAME, LAUNCH_MARKER_FILENAME):
        path = run_dir / filename
        if path.is_symlink() or not path.is_file():
            return False
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False
        if not isinstance(document, dict):
            return False
        if any(
            document.get(key) != value
            for key, value in expected.items()
            if key != "launch_budget_consumed"
        ) or document.get("launch_budget_consumed") is not True:
            return False
    return True


def build_launch_marker(
    *,
    run_id: str,
    root: str,
    generated_utc: Optional[str] = None,
) -> dict:
    """Build the contained run-local launch marker written before any tool stage."""

    return {
        "schema_version": 1,
        "package": PACKAGE_NAME,
        "root_domain": root,
        "run_id": run_id,
        "state": "launched",
        "launch_budget_consumed": True,
        "generated_utc": generated_utc or _utc_now(),
    }


def write_launch_marker(recon_path: ReconPath, *, mark: Optional[dict] = None) -> Path:
    """Atomically write the launch marker at the run root before any tool stage."""

    _require_run(recon_path)
    document = mark if mark is not None else build_launch_marker(
        run_id=recon_path.run_id, root=recon_path.root
    )
    if not isinstance(document, dict):
        raise EvidenceError("launch marker must be a JSON object")
    target = recon_path.run_dir / LAUNCH_MARKER_FILENAME
    try:
        return atomic_write_json(target, document, scan_dir=recon_path.run_dir)
    except (ScanStateError,) as exc:  # pragma: no cover - defensive
        raise EvidenceError(str(exc)) from exc


@dataclass(frozen=True)
class RunFailure:
    """Bounded, secret-free failure record for a consumed live run."""

    root: str
    run_id: str
    package: str = PACKAGE_NAME
    status: str = "failed"
    error: str | None = None
    generated_utc: str = ""
    detail: Mapping | None = None

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "package": self.package,
            "root_domain": self.root,
            "run_id": self.run_id,
            "status": self.status,
            "launch_budget_consumed": True,
            "error": self.error,
            "generated_utc": self.generated_utc or _utc_now(),
            "detail": dict(self.detail) if self.detail else None,
        }


def write_run_failure(
    recon_path: ReconPath,
    *,
    error: str,
    detail: Optional[Mapping] = None,
    status: str = "failed",
) -> Path:
    """Write ``run.json`` (failed) inside an existing run directory and never retry."""

    _require_run(recon_path)
    failure = RunFailure(
        root=recon_path.root,
        run_id=recon_path.run_id,
        status=status,
        error=str(error).replace("?", " ")[:512],
        detail=detail,
    )
    document = failure.to_dict()
    _assert_no_query_or_secret(document)
    target = recon_path.run_dir / FAILURE_FILENAME
    try:
        return atomic_write_json(target, document, scan_dir=recon_path.run_dir)
    except (ScanStateError,) as exc:  # pragma: no cover - defensive
        raise EvidenceError(str(exc)) from exc
