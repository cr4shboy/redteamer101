"""Containment-checked, atomic JSON storage for recon runs.

These helpers are thin wrappers over the existing
:func:`red_teaming.orchestration.state.atomic_write_json`. The run directory
must already exist (created explicitly via :meth:`ReconPath.create`); no helper
here creates directories or writes outside the run directory.
"""

from __future__ import annotations

from pathlib import Path

from ..orchestration.state import ScanStateError, atomic_write_json, read_json_object
from ..projects.models import ProjectDomain, ValidationError, normalize_dns_name
from ..projects.paths import is_within
from .models import SCHEMA_VERSION, Asset
from .paths import ReconPath
from .scope import DomainScope

__all__ = [
    "ASSETS_FILENAME",
    "EVIDENCE_DIRNAME",
    "SCOPE_FILENAME",
    "ReconStorageError",
    "asset_document",
    "ensure_evidence_dir",
    "evidence_dir",
    "read_recon_json",
    "write_assets",
    "write_evidence_json",
    "write_recon_json",
    "write_scope",
]

SCOPE_FILENAME = "scope.json"
ASSETS_FILENAME = "assets.json"
EVIDENCE_DIRNAME = "evidence"


class ReconStorageError(ValueError):
    """Raised when recon JSON cannot be written or read safely."""


def _require_run_dir(recon_path: ReconPath) -> ReconPath:
    if not isinstance(recon_path, ReconPath):
        raise TypeError("expected a ReconPath instance")
    if not recon_path.run_dir.is_dir():
        raise ReconStorageError(
            "recon run directory must already exist before writing "
            "(call ReconPath.create first)"
        )
    return recon_path


def _simple_name(name: object, label: str = "file name") -> str:
    if not isinstance(name, str) or not name:
        raise ReconStorageError(f"{label} must be a non-empty string")
    if (
        name in {".", ".."}
        or "/" in name
        or "\\" in name
        or ":" in name
    ):
        raise ReconStorageError(f"{label} must be a simple name: {name!r}")
    return name


def asset_document(asset: Asset) -> dict:
    """Return the tool-neutral canonical asset object for ``assets.json``.

    Deliberately avoids nesting a ``schema_version`` inside every asset/DNS
    object; the schema version lives once at the document level.
    """

    if not isinstance(asset, Asset):
        raise TypeError("expected an Asset instance")
    return {
        "hostname": asset.hostname,
        "kind": asset.kind.value,
        "sources": list(asset.sources),
        "dns": {
            "a": list(asset.dns.a),
            "aaaa": list(asset.dns.aaaa),
            "cname": list(asset.dns.cname),
        },
        "resolution_status": asset.resolution_status.value,
    }


def write_recon_json(recon_path: ReconPath, payload: dict, filename: str) -> Path:
    """Atomically write *payload* as *filename* inside an existing run directory."""

    run = _require_run_dir(recon_path)
    if not isinstance(payload, dict):
        raise ReconStorageError("recon payload must be a JSON object")
    try:
        target = run.file_path(filename)
    except ValidationError as exc:
        raise ReconStorageError(str(exc)) from exc
    try:
        return atomic_write_json(target, payload, scan_dir=run.run_dir)
    except (ValidationError, ScanStateError) as exc:
        raise ReconStorageError(str(exc)) from exc


def read_recon_json(recon_path: ReconPath, filename: str) -> dict:
    """Read a JSON object from *filename* inside an existing run directory."""

    run = _require_run_dir(recon_path)
    try:
        target = run.file_path(filename)
    except ValidationError as exc:
        raise ReconStorageError(str(exc)) from exc
    try:
        return read_json_object(target)
    except ScanStateError as exc:
        raise ReconStorageError(str(exc)) from exc


def write_scope(recon_path: ReconPath, scope: DomainScope) -> Path:
    """Write a scope document to ``scope.json``."""

    if not isinstance(scope, DomainScope):
        raise TypeError("expected a DomainScope instance")
    return write_recon_json(recon_path, scope.to_dict(), SCOPE_FILENAME)


def write_assets(recon_path: ReconPath, root_domain, assets) -> Path:
    """Write a per-domain asset document to ``assets.json``.

    The document shape is ``{schema_version, root_domain, assets}``. Assets are
    validated to be contained by *root_domain* (the root itself or one of its
    subdomains) and emitted in deterministic hostname order, so mixed-domain
    output cannot be produced by accident.
    """

    try:
        if isinstance(root_domain, ProjectDomain):
            root = root_domain.name
        else:
            root = normalize_dns_name(root_domain)
    except ValidationError as exc:
        raise ReconStorageError(str(exc)) from exc

    items = list(assets)
    for asset in items:
        if not isinstance(asset, Asset):
            raise TypeError("assets must contain Asset instances")
        if asset.hostname != root and not asset.hostname.endswith("." + root):
            raise ReconStorageError(
                f"asset {asset.hostname!r} is not contained by root domain {root!r}"
            )

    ordered = sorted(items, key=lambda asset: asset.hostname)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "root_domain": root,
        "assets": [asset_document(asset) for asset in ordered],
    }
    return write_recon_json(recon_path, payload, ASSETS_FILENAME)


def evidence_dir(recon_path: ReconPath):
    """Return the containment-checked evidence directory without creating it."""

    if not isinstance(recon_path, ReconPath):
        raise TypeError("expected a ReconPath instance")
    directory = recon_path.run_dir / EVIDENCE_DIRNAME
    if not is_within(directory, recon_path.run_dir):  # pragma: no cover - defensive
        raise ReconStorageError("evidence directory escapes the run directory")
    return directory


def ensure_evidence_dir(recon_path: ReconPath):
    """Create (and return) the run-local evidence directory."""

    run = _require_run_dir(recon_path)
    directory = run.run_dir / EVIDENCE_DIRNAME
    if not is_within(directory, run.run_dir):  # pragma: no cover - defensive
        raise ReconStorageError("evidence directory escapes the run directory")
    directory.mkdir(parents=False, exist_ok=True)
    return directory


def write_evidence_json(recon_path: ReconPath, tool: str, payload: dict) -> Path:
    """Atomically write ``evidence/<tool>.json`` inside an existing run."""

    run = _require_run_dir(recon_path)
    _simple_name(tool, "tool evidence name")
    if not isinstance(payload, dict):
        raise ReconStorageError("evidence payload must be a JSON object")
    directory = ensure_evidence_dir(recon_path)
    target = directory / f"{tool}.json"
    if not is_within(target, run.run_dir):  # pragma: no cover - defensive
        raise ReconStorageError("evidence path escapes the run directory")
    try:
        return atomic_write_json(target, payload, scan_dir=run.run_dir)
    except (ValidationError, ScanStateError) as exc:
        raise ReconStorageError(str(exc)) from exc
