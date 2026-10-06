"""Thin CLI for bounded passive reconnaissance runs.

Argument parsing is side-effect free: nothing is created and no tool is
inspected until :func:`main` is asked to act.

Three runtime modes:

* **Production (default on Linux/WSL)** is fail-closed. Requires pinned
  binaries under ``.tools/wsl/``, a network-namespace sandbox, and the exact
  RECON-002/003 root domain.
* **Native (``--native``, default on macOS)** uses PATH-available tool
  binaries via ``subprocess.run`` with no sandbox. Supports any authorized
  root domain.
* **Fixture (injected factories)** is retained for offline unit tests only.

There are deliberately no target-URL, tool-flag, credential, or key options.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence, TextIO

from ..projects.models import ValidationError
from ..projects.paths import (
    generate_scan_id,
    is_within,
    require_workspace_root,
    resolve_path,
)
from ..recon.evidence import (
    PACKAGE_NAME,
    build_launch_marker,
    prior_recon_entries,
)
from ..recon.input import InputError, read_entries
from ..recon.models import ToolRunStatus
from ..recon.netpolicy import ROOT_DOMAIN
from ..recon.netns_selftest import run_self_test
from ..recon.paths import ReconPath, ReconPathError, validate_run_id
from ..recon.pinned import (
    InstallReport,
    RuntimeReport,
    host_runtime_report,
    verify_all_installs,
)
from ..recon.pipeline import (
    PLANNED_STAGES,
    AdapterFactories,
    BatchPreflightError,
    PipelineError,
    run_batch,
)
from ..recon.production import ProductionRuntime, transient_preflight_work_dir
from ..recon.scope import DomainScope

__all__ = [
    "EXIT_OK",
    "EXIT_RUNTIME",
    "EXIT_VALIDATION",
    "CliValidationError",
    "ProductionPreflightReport",
    "ReconAssetsPlan",
    "build_parser",
    "build_plan",
    "main",
    "production_preflight",
]

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_RUNTIME = 3

_TOOLS = ("subfinder", "amass", "dnsx")


def _src_path() -> str:
    """Return this checkout's ``src`` directory (never the cwd)."""

    # .../src/red_teaming/cli/recon_assets.py -> .../src
    return str(Path(__file__).resolve().parents[2])


class CliValidationError(ValueError):
    """The supplied CLI arguments do not describe a valid recon plan."""


@dataclass(frozen=True)
class ReconAssetsPlan:
    """A validated, side-effect-free description of one recon batch."""

    workspace_root: Path
    scope: DomainScope
    run_id: str
    recon_paths: tuple[ReconPath, ...]
    domains_file: Path
    exclude_file: Path | None
    inspect_work_dir: Path


#: Maximum length of a bounded inspection reason emitted in preflight output.
_INSPECTION_REASON_MAX = 256


def _bounded_reason(reason: object) -> str:
    """Return a single-line, length-bounded inspection reason.

    The reason is a locally-constructed diagnostic (never raw help output); it is
    collapsed to one line and capped so preflight output stays bounded and
    secret-free.
    """

    if not isinstance(reason, str) or not reason.strip():
        return ""
    return " ".join(reason.split())[:_INSPECTION_REASON_MAX]


@dataclass(frozen=True)
class ProductionPreflightReport:
    """Structured outcome of the fail-closed production preflight."""

    ok: bool
    blocked_reason: str | None = None
    runtime: RuntimeReport | None = None
    installs: tuple[InstallReport, ...] = ()
    selftest: object | None = None
    inspections: tuple[tuple[str, str], ...] = ()
    inspection_reasons: tuple[tuple[str, str], ...] = ()
    runtime_obj: ProductionRuntime | None = field(default=None, compare=False)

    def to_lines(self) -> list[str]:
        lines = ["RECON-003 production preflight"]
        if self.runtime is not None:
            lines.append(
                f"runtime: ok={self.runtime.ok} detail={self.runtime.detail}"
            )
        for report in self.installs:
            lines.append(
                f"pinned[{report.tool}]: ok={report.ok} version={report.version} "
                f"reason={report.reason or '-'}"
            )
        if self.selftest is not None:
            passed = getattr(self.selftest, "passed", None)
            lines.append(f"namespace-selftest: passed={passed}")
        reasons = dict(self.inspection_reasons)
        for tool, status in self.inspections:
            line = f"tool[{tool}]: {status}"
            reason = _bounded_reason(reasons.get(tool))
            if reason:
                line += f" reason={reason}"
            lines.append(line)
        if self.blocked_reason:
            lines.append(f"blocked: {self.blocked_reason}")
        return lines


def _assert_exact_root(scope: DomainScope) -> None:
    if not isinstance(scope, DomainScope):
        raise CliValidationError("scope must be a DomainScope")
    if scope.authorized_domains != (ROOT_DOMAIN,):
        raise CliValidationError(
            f"production mode is fixed to the single root {ROOT_DOMAIN!r}"
        )


def production_preflight(
    *,
    workspace_root: Path,
    scope: DomainScope,
    src_path: str | None = None,
    runtime_probe: Callable[[], RuntimeReport] = host_runtime_report,
    install_verifier: Callable[..., tuple[InstallReport, ...]] = verify_all_installs,
    selftest_runner: Callable[..., object] = run_self_test,
    inspect_tools: bool = True,
    broker_factory=None,
    helper_runner=None,
    port_factory=None,
    amass_launcher_check=None,
) -> ProductionPreflightReport:
    """Run the local-only production preflight (no run dir, no target traffic)."""

    try:
        _assert_exact_root(scope)
    except CliValidationError as exc:
        return ProductionPreflightReport(ok=False, blocked_reason=str(exc))

    runtime = runtime_probe()
    if not runtime.ok:
        return ProductionPreflightReport(
            ok=False, blocked_reason=f"runtime:{runtime.detail}", runtime=runtime
        )

    installs = tuple(install_verifier(workspace_root))
    if any(not report.ok for report in installs) or len(installs) != len(_TOOLS):
        bad = [report.tool for report in installs if not report.ok]
        return ProductionPreflightReport(
            ok=False,
            blocked_reason="pinned-installs:" + ",".join(bad or ["count"]),
            runtime=runtime,
            installs=installs,
        )

    try:
        selftest = selftest_runner(src_path=src_path) if src_path else selftest_runner()
    except Exception as exc:  # noqa: BLE001 - fail closed with a reason
        return ProductionPreflightReport(
            ok=False,
            blocked_reason=f"namespace-selftest:{type(exc).__name__}",
            runtime=runtime,
            installs=installs,
        )
    if not getattr(selftest, "passed", False):
        reason = getattr(selftest, "reason", None) or "not_passed"
        return ProductionPreflightReport(
            ok=False,
            blocked_reason=f"namespace-selftest:{reason}",
            runtime=runtime,
            installs=installs,
            selftest=selftest,
        )

    runtime_obj = ProductionRuntime(
        workspace_root=workspace_root,
        root=ROOT_DOMAIN,
        installs=installs,
        runtime=runtime,
        src_path=src_path,
        broker_factory=broker_factory,
        helper_runner=helper_runner,
        port_factory=port_factory,
        amass_launcher_check=amass_launcher_check,
    )

    inspections: list[tuple[str, str]] = []
    inspection_reasons: list[tuple[str, str]] = []
    if inspect_tools:
        try:
            # The transient work dir lives under projects/<root>/ (never the
            # project root and never a run-id directory) and is removed in a
            # finally block so no preflight _sandbox files survive.
            with transient_preflight_work_dir(workspace_root, ROOT_DOMAIN) as work:
                factories = runtime_obj.factories()
                root_scope = scope.for_root(ROOT_DOMAIN)
                for tool in _TOOLS:
                    adapter = getattr(factories, tool)(root_scope, work)
                    inspection = adapter.inspect()
                    inspections.append((tool, inspection.status.value))
                    inspection_reasons.append(
                        (tool, _bounded_reason(inspection.reason))
                    )
                    if inspection.status is ToolRunStatus.SUCCEEDED:
                        # Cache the successful inspection for the live adapter so
                        # the actual stage never repeats version/help inspection.
                        runtime_obj.inspections[tool] = inspection
        except Exception as exc:  # noqa: BLE001 - fail closed with a reason
            return ProductionPreflightReport(
                ok=False,
                blocked_reason=f"capability-inspection:{type(exc).__name__}",
                runtime=runtime,
                installs=installs,
                selftest=selftest,
                inspections=tuple(inspections),
                inspection_reasons=tuple(inspection_reasons),
                runtime_obj=runtime_obj,
            )
        failing = [
            tool
            for tool, status in inspections
            if status != ToolRunStatus.SUCCEEDED.value
        ]
        if failing:
            return ProductionPreflightReport(
                ok=False,
                blocked_reason="capability-inspection:" + ",".join(failing),
                runtime=runtime,
                installs=installs,
                selftest=selftest,
                inspections=tuple(inspections),
                inspection_reasons=tuple(inspection_reasons),
                runtime_obj=runtime_obj,
            )

    return ProductionPreflightReport(
        ok=True,
        runtime=runtime,
        installs=installs,
        selftest=selftest,
        inspections=tuple(inspections),
        inspection_reasons=tuple(inspection_reasons),
        runtime_obj=runtime_obj,
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the side-effect-free argument parser."""

    parser = argparse.ArgumentParser(
        prog="recon_assets.py",
        description=(
            "Plan and (only when separately authorized) execute the bounded "
            "RECON-003 passive recon run for acme.example. Validate-only "
            "performs local runtime/pinned/namespace/version checks only; no "
            "target or network traffic is involved."
        ),
    )
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument(
        "--domains",
        required=True,
        help="absolute path to a UTF-8 file with one authorized root domain per line",
    )
    parser.add_argument(
        "--exclude",
        default=None,
        help="optional absolute path to a file with one exact excluded host per line",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="optional pre-validated run id shared across every root",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        dest="validate_only",
        help=(
            "validate the plan and inspect local tools without creating recon "
            "run artifacts"
        ),
    )
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        dest="confirm_authorized",
        help=(
            "required for an actual live run; a safety interlock, not legal "
            "authorization"
        ),
    )
    parser.add_argument(
        "--native",
        action="store_true",
        help=(
            "use native (non-sandboxed) runtime with PATH-available tool "
            "binaries instead of pinned WSL binaries. Default on macOS"
        ),
    )
    return parser


def _contained_input_file(workspace_root: Path, value: str, label: str) -> Path:
    """Return *value* resolved and contained in *workspace_root*, else raise.

    Containment is validated **before** any file is read, so the CLI can never
    read an arbitrary file outside the verified project (no-secret rule).
    """

    candidate = Path(value)
    if not candidate.is_absolute():
        raise CliValidationError(f"{label} must be an absolute path")
    try:
        resolved = resolve_path(candidate)
        root = resolve_path(workspace_root)
    except OSError as exc:  # pragma: no cover - defensive
        raise CliValidationError(f"cannot resolve {label}: {exc}") from exc
    if not is_within(resolved, root):
        raise CliValidationError(
            f"{label} resolves outside the workspace root and must not be read"
        )
    if not resolved.is_file():
        raise CliValidationError(f"{label} must be an existing regular file")
    return resolved


def build_plan(
    args: argparse.Namespace, *, expected_root=None
) -> ReconAssetsPlan:
    """Validate *args* into a plan without creating directories or files."""

    try:
        workspace_root = require_workspace_root(
            args.workspace_root, expected_root=expected_root
        )
        domains_file = _contained_input_file(
            workspace_root, args.domains, "--domains"
        )
        exclude_file = (
            _contained_input_file(workspace_root, args.exclude, "--exclude")
            if args.exclude
            else None
        )
        domains = read_entries(domains_file)
        exclusions = read_entries(exclude_file) if exclude_file else ()
        scope = DomainScope.parse(domains, exclusions)
        if args.run_id is not None:
            run_id = validate_run_id(args.run_id)
        else:
            run_id = generate_scan_id()
        recon_paths = tuple(
            ReconPath.build(workspace_root, root.name, run_id) for root in scope.roots
        )
    except (ValidationError, InputError, ReconPathError) as exc:
        raise CliValidationError(str(exc)) from exc

    collisions = [str(path.run_dir) for path in recon_paths if path.run_dir.exists()]
    if collisions:
        raise CliValidationError(
            "run directories already exist and must not be reused: "
            + ", ".join(collisions)
        )

    return ReconAssetsPlan(
        workspace_root=workspace_root,
        scope=scope,
        run_id=run_id,
        recon_paths=recon_paths,
        domains_file=domains_file,
        exclude_file=exclude_file,
        inspect_work_dir=workspace_root,
    )


def _format_plan(plan: ReconAssetsPlan) -> str:
    lines = [
        "RECON-003 recon plan",
        f"workspace-root: {plan.workspace_root}",
        f"domains-file: {plan.domains_file}",
        f"exclude-file: {plan.exclude_file if plan.exclude_file else '(none)'}",
        f"run-id: {plan.run_id}",
        f"authorized-roots: {len(plan.recon_paths)}",
        f"stages: {', '.join(PLANNED_STAGES)}",
        "targets: none (scope intake + asset discovery only)",
    ]
    for path in plan.recon_paths:
        lines.append(f"root: {path.root}")
        lines.append(f"  run-dir: {path.run_dir}")
    return "\n".join(lines)


def _tool_inspection_lines(
    plan: ReconAssetsPlan, factories: AdapterFactories
) -> list[str]:
    """Inspect each global tool once (not once per root), using one projection."""

    if not plan.recon_paths:
        return []
    root_scope = plan.scope.for_root(plan.recon_paths[0].root)
    lines = ["tools:"]
    for tool in _TOOLS:
        factory = getattr(factories, tool)
        adapter = factory(root_scope, plan.inspect_work_dir)
        inspection = adapter.inspect()
        capabilities = ",".join(inspection.capabilities) or "none"
        detail = (
            f"  {tool}: status={inspection.status.value} "
            f"version={inspection.version or 'unknown'} capabilities={capabilities}"
        )
        if inspection.warnings:
            detail += " warnings=" + "; ".join(inspection.warnings)
        if inspection.reason:
            detail += f" reason={inspection.reason}"
        lines.append(detail)
    return lines


def _print_results(results, out: TextIO) -> None:
    for result in results:
        tools = ", ".join(f"{tool}={status}" for tool, status in result.tools)
        print(f"root: {result.root}", file=out)
        print(f"  run-dir: {result.run_dir}", file=out)
        print(f"  status: {result.status}", file=out)
        print(
            f"  assets: {result.asset_count}  candidates: {result.candidate_count}",
            file=out,
        )
        print(f"  tools: {tools}", file=out)


def _run_fixture(args, plan, out, err, factories) -> int:
    """Offline fixture path: injected fake factories only (tests)."""

    if args.validate_only:
        print(_format_plan(plan), file=out)
        print("mode: validate-only", file=out)
        for line in _tool_inspection_lines(plan, factories):
            print(line, file=out)
        print("authorization: not run (validate-only)", file=out)
        return EXIT_OK

    if not args.confirm_authorized:
        print(
            "error: an actual run requires --confirm-authorized",
            file=err,
        )
        return EXIT_VALIDATION

    if args.run_id is None:
        print("error: an actual run requires an explicit --run-id", file=err)
        return EXIT_VALIDATION

    print(_format_plan(plan), file=out)
    print("mode: actual", file=out)
    try:
        results = run_batch(plan.workspace_root, plan.scope, plan.run_id, factories)
    except BatchPreflightError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_VALIDATION
    except (PipelineError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME
    _print_results(results, out)
    return EXIT_OK


def _run_production(args, plan, out, err, preflight_fn) -> int:
    """Fail-closed production path: pinned binary + namespace + policy."""

    if args.validate_only:
        report = preflight_fn(
            workspace_root=plan.workspace_root,
            scope=plan.scope,
            src_path=_src_path(),
        )
        print(_format_plan(plan), file=out)
        print("mode: validate-only", file=out)
        for line in report.to_lines():
            print(line, file=out)
        print("authorization: not run (validate-only)", file=out)
        return EXIT_OK if report.ok else EXIT_VALIDATION

    if not args.confirm_authorized:
        print("error: an actual run requires --confirm-authorized", file=err)
        return EXIT_VALIDATION

    if args.run_id is None:
        print("error: an actual run requires an explicit --run-id", file=err)
        return EXIT_VALIDATION

    report = preflight_fn(
        workspace_root=plan.workspace_root,
        scope=plan.scope,
        src_path=_src_path(),
    )

    if not report.ok:
        for line in report.to_lines():
            print(line, file=err)
        print(f"error: production preflight failed: {report.blocked_reason}", file=err)
        return EXIT_VALIDATION

    runtime_obj = report.runtime_obj
    if runtime_obj is None:
        print("error: production runtime was not constructed", file=err)
        return EXIT_VALIDATION

    prior = prior_recon_entries(plan.workspace_root, ROOT_DOMAIN)
    if prior:
        print(
            "error: RECON-003 one-run ledger is blocked; the run budget is "
            "consumed or prior evidence is invalid, so no new run is permitted",
            file=err,
        )
        return EXIT_VALIDATION

    print(_format_plan(plan), file=out)
    print("mode: actual", file=out)
    try:
        results = run_batch(
            plan.workspace_root,
            plan.scope,
            plan.run_id,
            runtime_obj.factories(),
            evidence_provider=runtime_obj.evidence_provider(),
            launch_marker=build_launch_marker(
                run_id=plan.run_id, root=ROOT_DOMAIN
            ),
            package=PACKAGE_NAME,
        )
    except BatchPreflightError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_VALIDATION
    except Exception as exc:  # noqa: BLE001 - explicit CLI boundary
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME
    _print_results(results, out)
    return EXIT_OK


def _run_native(args, plan, out, err) -> int:
    """Native (non-sandboxed) path: PATH-available binaries, no namespace."""

    from ..recon.native import NativeRuntime, NativeRuntimeError

    root = plan.scope.roots[0].name if plan.scope.roots else None
    if root is None:
        print("error: no authorized root domain", file=err)
        return EXIT_VALIDATION

    runtime = NativeRuntime(
        root=root,
        workspace_root=plan.workspace_root,
    )

    try:
        runtime.preflight()
    except NativeRuntimeError as exc:
        print(f"error: native preflight failed: {exc}", file=err)
        return EXIT_VALIDATION

    if args.validate_only:
        print(_format_plan(plan), file=out)
        print("mode: validate-only (native)", file=out)
        for tool, version in runtime.versions.items():
            print(f"  {tool}: {version} ({runtime.binaries[tool]})", file=out)
        print("authorization: not run (validate-only)", file=out)
        return EXIT_OK

    if not args.confirm_authorized:
        print("error: an actual run requires --confirm-authorized", file=err)
        return EXIT_VALIDATION

    if args.run_id is None:
        print("error: an actual run requires an explicit --run-id", file=err)
        return EXIT_VALIDATION

    print(_format_plan(plan), file=out)
    print("mode: actual (native)", file=out)
    try:
        results = run_batch(
            plan.workspace_root,
            plan.scope,
            plan.run_id,
            runtime.factories(),
        )
    except BatchPreflightError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_VALIDATION
    except Exception as exc:  # noqa: BLE001 - explicit CLI boundary
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME
    _print_results(results, out)
    return EXIT_OK


def _use_native(args) -> bool:
    """Decide whether to use native runtime."""
    if getattr(args, "native", False):
        return True
    return sys.platform == "darwin"


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    factories: AdapterFactories | None = None,
    expected_root=None,
    production_preflight_fn: Optional[Callable[..., ProductionPreflightReport]] = None,
) -> int:
    """Parse, validate, and (only when confirmed) execute a recon batch.

    When *factories* is provided the CLI runs the offline fixture path (tests
    only). When ``--native`` is set or platform is macOS, uses the native
    runtime. Otherwise runs the fail-closed production path bound to the exact
    pinned WSL binaries and the namespace/broker layer.
    """

    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        plan = build_plan(args, expected_root=expected_root)
    except CliValidationError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_VALIDATION

    if factories is not None:
        return _run_fixture(args, plan, out, err, factories)

    if _use_native(args):
        return _run_native(args, plan, out, err)

    return _run_production(
        args,
        plan,
        out,
        err,
        production_preflight_fn or production_preflight,
    )


if __name__ == "__main__":  # pragma: no cover - exercised via the wrapper
    raise SystemExit(main())
