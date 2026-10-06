"""Per-root recon pipeline and multi-root batch orchestration.

Each root is processed independently through exactly one single-root scope
projection and its own ``projects/<root>/recon/<run-id>/`` run directory. No
evidence is mixed between roots. The batch preflights every per-root run
directory *before* creating anything, so an existing directory aborts the batch
with no partial new run directories.

Nothing here invokes a real discovery tool on its own: adapters (and their
subprocess layers) are injected. Production factories construct the current
adapters with per-tool, run-local work directories.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..projects.paths import (
    ensure_within,
    generate_scan_id,
    is_within,
    require_absolute_root,
    resolve_path,
)
from .aggregate import DiscoveryAggregate, aggregate_discovery, build_assets
from .evidence import write_launch_marker, write_network_policy, write_run_failure
from .models import SCHEMA_VERSION, ObservationState, ToolResult, ToolRunStatus
from .paths import ReconPath, validate_run_id
from .scope import DomainScope
from .storage import (
    ensure_evidence_dir,
    write_assets,
    write_evidence_json,
    write_recon_json,
    write_scope,
)

__all__ = [
    "EVIDENCE_TOOLS",
    "PLANNED_STAGES",
    "WORK_DIRNAME",
    "AdapterFactories",
    "BatchPreflightError",
    "PipelineError",
    "RootRunResult",
    "default_factories",
    "run_batch",
    "run_root_pipeline",
]

EVIDENCE_TOOLS = ("subfinder", "amass", "dnsx")
PLANNED_STAGES = ("scope", "subfinder", "amass", "dnsx", "assets")
WORK_DIRNAME = "work"

AdapterFactory = Callable[[DomainScope, Path], object]


class PipelineError(ValueError):
    """Raised when the recon pipeline is misconfigured or misused."""


class BatchPreflightError(PipelineError):
    """Raised when a batch cannot start without colliding with existing runs."""


@dataclass(frozen=True)
class AdapterFactories:
    """Injectable per-tool adapter factories ``(scope, work_dir) -> adapter``."""

    subfinder: AdapterFactory
    amass: AdapterFactory
    dnsx: AdapterFactory


@dataclass(frozen=True)
class RootRunResult:
    """Outcome of one per-root pipeline run."""

    root: str
    run_id: str
    run_dir: Path
    status: str
    asset_count: int
    candidate_count: int
    tools: tuple[tuple[str, str], ...]


def default_factories(*_args, **_kwargs) -> AdapterFactories:
    """Fail closed: production factories require the pinned runtime wiring.

    Bare-name production adapters are no longer constructed implicitly. A real
    run must pass ``ProductionRuntime.factories()`` (bound to the exact pinned
    WSL binaries and the sandbox runner); offline tests must inject explicit fake
    factories. This function exists only so old call sites fail loudly rather
    than silently running an unpinned tool.
    """

    raise PipelineError(
        "production factories must be constructed by ProductionRuntime with a "
        "verified pinned runtime; inject fake factories for offline tests"
    )


def _tool_work_dir(recon: ReconPath, tool: str) -> Path:
    path = recon.run_dir / WORK_DIRNAME / tool
    ensure_within(path, recon.run_dir)
    return path


def _failure_result(tool: str, exc: Exception) -> ToolResult:
    """Convert an adapter/runtime exception into a bounded, secret-free result."""

    return ToolResult(
        tool=tool,
        status=ToolRunStatus.TOOL_FAILED,
        errors=[type(exc).__name__],
    )


def _require_success(tool: str, result: ToolResult) -> None:
    """Fail closed when a production/package stage did not succeed.

    RECON-002 package mode must stop immediately rather than continue to the
    next tool or report the run as completed.
    """

    if not isinstance(result, ToolResult) or result.status is not ToolRunStatus.SUCCEEDED:
        status = result.status.value if isinstance(result, ToolResult) else "invalid"
        raise PipelineError(f"stage {tool} did not succeed: {status}")


def _preserve_failure_evidence(
    recon: ReconPath,
    root_name: str,
    results: dict,
    exc: Exception,
    evidence_provider,
) -> None:
    """Write available tool evidence and failed run/network-policy records.

    Every step is best-effort so it can never mask the original failure.
    """

    for tool, result in results.items():
        try:
            write_evidence_json(recon, tool, _result_dict(result))
        except Exception:  # noqa: BLE001 - never mask the original failure
            pass
    if evidence_provider is not None:
        try:
            document = evidence_provider.document(
                run_id=recon.run_id, root=root_name, status="failed"
            )
            write_network_policy(recon, document)
        except Exception:  # noqa: BLE001 - never mask the original failure
            pass
    try:
        write_run_failure(recon, error=f"{type(exc).__name__}: {exc}")
    except Exception:  # noqa: BLE001 - never mask the original failure
        pass


def _run_stage(
    tool: str, factory: AdapterFactory, scope: DomainScope, work_dir: Path, *run_args
) -> ToolResult:
    """Build the adapter and run one stage, converting exceptions to failures."""

    try:
        adapter = factory(scope, work_dir)
    except Exception as exc:  # noqa: BLE001 - explicit boundary conversion
        return _failure_result(tool, exc)
    try:
        result = adapter.run(*run_args)
    except Exception as exc:  # noqa: BLE001 - explicit boundary conversion
        return _failure_result(tool, exc)
    if not isinstance(result, ToolResult):
        return _failure_result(tool, TypeError("adapter did not return a ToolResult"))
    return result


def _cleanup_work(work_root: Path, run_dir: Path) -> None:
    """Best-effort removal of only this run's contained ``work/`` tree."""

    if work_root.name != WORK_DIRNAME:
        return
    if not is_within(work_root, run_dir):
        return
    try:
        resolved_run = resolve_path(run_dir)
        resolved_work = resolve_path(work_root)
    except OSError:  # pragma: no cover - defensive
        return
    if resolved_work == resolved_run or not is_within(resolved_work, resolved_run):
        return
    if work_root.is_dir() and not work_root.is_symlink():
        shutil.rmtree(work_root, ignore_errors=True)


def _result_dict(result: ToolResult) -> dict:
    if not isinstance(result, ToolResult):
        raise PipelineError("adapter did not return a ToolResult")
    return result.to_dict()


def _tool_summary(result: ToolResult) -> dict:
    return {
        "status": result.status.value,
        "executable": result.executable,
        "version": result.version,
        "exit_code": result.exit_code,
        "timeout": result.timeout,
        "observations": len(result.observations),
        "resolutions": len(result.resolutions),
        "errors": len(result.errors),
    }


def _run_document(
    root: str,
    run_id: str,
    aggregate: DiscoveryAggregate,
    results: dict,
    asset_count: int,
    *,
    package: str | None = None,
) -> dict:
    by_state = {state.value: 0 for state in ObservationState}
    for observation in aggregate.observations:
        by_state[observation.state.value] += 1
    document = {
        "schema_version": SCHEMA_VERSION,
        "root_domain": root,
        "run_id": run_id,
        "status": "completed",
        "stages": list(PLANNED_STAGES),
        "tools": {tool: _tool_summary(results[tool]) for tool in EVIDENCE_TOOLS},
        "counts": {
            "assets": asset_count,
            "dns_candidates": len(aggregate.candidates),
            "observations": len(aggregate.observations),
            "by_state": by_state,
        },
    }
    if package is not None:
        document["package"] = package
        document["launch_budget_consumed"] = True
    return document


def run_root_pipeline(
    workspace_root,
    scope: DomainScope,
    root,
    run_id,
    factories: AdapterFactories,
    *,
    now=None,
    suffix=None,
    evidence_provider=None,
    launch_marker: dict | None = None,
    package: str | None = None,
) -> RootRunResult:
    """Run exactly one root through discovery -> aggregation -> dnsx -> assets."""

    if not isinstance(scope, DomainScope):
        raise PipelineError("scope must be a DomainScope")
    if not isinstance(factories, AdapterFactories):
        raise PipelineError("factories must be an AdapterFactories instance")

    workspace = require_absolute_root(workspace_root)
    root_scope = scope.for_root(root)
    recon = ReconPath.build(workspace, root_scope.roots[0].name, run_id, now=now, suffix=suffix)

    if recon.run_dir.exists():
        raise BatchPreflightError(
            f"recon run directory already exists and must not be reused: {recon.run_dir}"
        )
    recon.create()
    ensure_evidence_dir(recon)
    if launch_marker is not None:
        # The marker is written before any tool stage so a started live run
        # consumes the one-run budget even if it later fails.
        write_launch_marker(recon, mark=launch_marker)
    work_root = recon.run_dir / WORK_DIRNAME
    root_name = root_scope.roots[0].name
    # RECON-002 package mode is strict: any non-succeeded stage stops the run
    # before the next stage rather than continuing or reporting completion.
    strict = package is not None
    results: dict[str, ToolResult] = {}
    try:
        try:
            work_dirs: dict[str, Path] = {}
            for tool in EVIDENCE_TOOLS:
                path = _tool_work_dir(recon, tool)
                path.mkdir(parents=True, exist_ok=True)
                work_dirs[tool] = path

            results["subfinder"] = _run_stage(
                "subfinder", factories.subfinder, root_scope, work_dirs["subfinder"]
            )
            if strict:
                _require_success("subfinder", results["subfinder"])
            results["amass"] = _run_stage(
                "amass", factories.amass, root_scope, work_dirs["amass"]
            )
            if strict:
                _require_success("amass", results["amass"])

            aggregate = aggregate_discovery(
                root_scope,
                {"subfinder": results["subfinder"], "amass": results["amass"]},
            )

            results["dnsx"] = _run_stage(
                "dnsx", factories.dnsx, root_scope, work_dirs["dnsx"], aggregate.candidates
            )
            if strict:
                _require_success("dnsx", results["dnsx"])

            assets = build_assets(root_scope, aggregate, results["dnsx"])

            write_scope(recon, root_scope)
            write_assets(recon, root_name, assets)
            for tool in EVIDENCE_TOOLS:
                write_evidence_json(recon, tool, _result_dict(results[tool]))
            write_recon_json(
                recon,
                _run_document(
                    root_name,
                    recon.run_id,
                    aggregate,
                    results,
                    len(assets),
                    package=package,
                ),
                "run.json",
            )
            if evidence_provider is not None:
                document = evidence_provider.document(
                    run_id=recon.run_id, root=root_name, status="completed"
                )
                write_network_policy(recon, document)
        except Exception as exc:
            if package is not None or evidence_provider is not None or launch_marker is not None:
                _preserve_failure_evidence(
                    recon, root_name, results, exc, evidence_provider
                )
            raise

        return RootRunResult(
            root=root_name,
            run_id=recon.run_id,
            run_dir=recon.run_dir,
            status="completed",
            asset_count=len(assets),
            candidate_count=len(aggregate.candidates),
            tools=tuple((tool, results[tool].status.value) for tool in EVIDENCE_TOOLS),
        )
    finally:
        _cleanup_work(work_root, recon.run_dir)


def run_batch(
    workspace_root,
    scope: DomainScope,
    run_id=None,
    factories: AdapterFactories | None = None,
    *,
    now=None,
    suffix=None,
    evidence_provider=None,
    launch_marker: dict | None = None,
    package: str | None = None,
) -> tuple[RootRunResult, ...]:
    """Run every authorized root independently under one shared run id."""

    if not isinstance(scope, DomainScope):
        raise PipelineError("scope must be a DomainScope")
    if factories is None:
        factories = default_factories()

    workspace = require_absolute_root(workspace_root)
    if run_id is None:
        run_id = generate_scan_id(now=now, suffix=suffix)
    else:
        run_id = validate_run_id(run_id)

    paths = tuple(
        ReconPath.build(workspace, root.name, run_id) for root in scope.roots
    )

    collisions = [str(path.run_dir) for path in paths if path.run_dir.exists()]
    if collisions:
        raise BatchPreflightError(
            "refusing to start batch: run directories already exist: "
            + ", ".join(collisions)
        )

    results = []
    for path in paths:
        results.append(
            run_root_pipeline(
                workspace,
                scope,
                path.root,
                run_id,
                factories,
                evidence_provider=evidence_provider,
                launch_marker=launch_marker,
                package=package,
            )
        )
    return tuple(results)
