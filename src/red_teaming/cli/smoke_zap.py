"""Thin CLI for the local-only OWASP ZAP daemon health smoke.

Argument parsing is side-effect free: nothing is created and no process/API
activity happens until :func:`main` is asked to *run*. ``--validate-only``
validates the whole plan and prints a redacted summary without creating a
directory, starting a process, or making an API call.

An actual run additionally requires ``--confirm-local-smoke``, a safety latch
for this narrow loopback-only tool-health check. This CLI deliberately exposes
no target URL and no scan mode: there is no target interaction to authorize.
"""

from __future__ import annotations

import argparse
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, TextIO

from ..projects.models import ProjectDomain, ValidationError
from ..projects.paths import ScanPath, is_within, require_workspace_root, resolve_path
from ..tools.zap.models import DEFAULT_API_TIMEOUT, ZapConfigError, ZapEndpoint, ZapError
from ..tools.zap.process import (
    DEFAULT_GRACEFUL_TIMEOUT,
    DEFAULT_KILL_TIMEOUT,
    DEFAULT_OFFLINE_GUARD_HOST,
    DEFAULT_OFFLINE_GUARD_PORT,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_STARTUP_TIMEOUT,
    DEFAULT_TERMINATE_TIMEOUT,
)
from ..tools.zap.smoke import (
    EXACT_BIND_HOST,
    SMOKE_JSON_FILENAME,
    ZapSmokeRunner,
)

__all__ = [
    "DEFAULT_SMOKE_PORT",
    "DEFAULT_SMOKE_STARTUP_TIMEOUT",
    "EXIT_OK",
    "EXIT_RUNTIME",
    "EXIT_VALIDATION",
    "CliValidationError",
    "SmokePlan",
    "build_parser",
    "build_plan",
    "main",
]

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_RUNTIME = 3

DEFAULT_SMOKE_PORT = 18080
#: First ZAP (Java) start can be slow; the bound stays explicit and finite.
DEFAULT_SMOKE_STARTUP_TIMEOUT = 180.0
DEFAULT_SMOKE_REQUEST_TIMEOUT = DEFAULT_API_TIMEOUT


class CliValidationError(ValueError):
    """The supplied CLI arguments do not describe a valid smoke plan."""


@dataclass(frozen=True)
class SmokePlan:
    """A fully validated, side-effect-free description of one smoke run."""

    workspace_root: Path
    output_dir: Path
    zap_executable: Path
    project: ProjectDomain
    scan_path: ScanPath
    bind_host: str
    bind_port: int
    guard_host: str
    guard_port: int
    expected_version: str
    min_version: str
    request_timeout: float
    startup_timeout: float
    graceful_timeout: float
    terminate_timeout: float
    kill_timeout: float
    poll_interval: float


def _validate_positive(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CliValidationError(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise CliValidationError(f"{name} must be a positive finite number")
    return float(value)


def build_parser() -> argparse.ArgumentParser:
    """Construct the side-effect-free argument parser.

    There is intentionally no ``--target``, ``--url``, ``--mode``, or any other
    scan-input option.
    """

    parser = argparse.ArgumentParser(
        prog="smoke_zap.py",
        description=(
            "Run exactly one local-only OWASP ZAP daemon health smoke: start "
            "ZAP headless on 127.0.0.1, read the version over its loopback "
            "API, shut it down gracefully, and write Markdown + JSON evidence. "
            "No target, scan, or external traffic is involved."
        ),
    )
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--zap-executable", required=True)
    parser.add_argument(
        "--project",
        required=True,
        help="the routed project/domain this local smoke is recorded under",
    )
    parser.add_argument("--zap-host", default=EXACT_BIND_HOST)
    parser.add_argument("--zap-port", type=int, default=DEFAULT_SMOKE_PORT)
    parser.add_argument("--guard-host", default=DEFAULT_OFFLINE_GUARD_HOST)
    parser.add_argument("--guard-port", type=int, default=DEFAULT_OFFLINE_GUARD_PORT)
    parser.add_argument("--expected-version", default="2.17.0")
    parser.add_argument("--min-version", default="2.17.0")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        dest="validate_only",
        help="validate and print a redacted plan without any side effects",
    )
    parser.add_argument(
        "--confirm-local-smoke",
        action="store_true",
        dest="confirm_local_smoke",
        help=(
            "required for an actual run; confirms the operator intends this "
            "single loopback-only tool-health smoke"
        ),
    )
    parser.add_argument(
        "--startup-timeout", type=float, default=DEFAULT_SMOKE_STARTUP_TIMEOUT
    )
    parser.add_argument(
        "--request-timeout", type=float, default=DEFAULT_SMOKE_REQUEST_TIMEOUT
    )
    parser.add_argument("--graceful-timeout", type=float, default=DEFAULT_GRACEFUL_TIMEOUT)
    parser.add_argument(
        "--terminate-timeout", type=float, default=DEFAULT_TERMINATE_TIMEOUT
    )
    parser.add_argument("--kill-timeout", type=float, default=DEFAULT_KILL_TIMEOUT)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    return parser


def build_plan(
    args: argparse.Namespace, *, expected_root: os.PathLike | str | None = None
) -> SmokePlan:
    """Validate *args* into a :class:`SmokePlan` without touching the filesystem.

    Only read-only ``Path`` checks are performed; no directory is created and
    no process/API call is made.
    """

    try:
        workspace_root = require_workspace_root(
            args.workspace_root, expected_root=expected_root
        )
        project = ProjectDomain.parse(args.project)
    except ValidationError as exc:
        raise CliValidationError(str(exc)) from exc

    raw_output = Path(args.output_dir)
    if not raw_output.is_absolute():
        raise CliValidationError("--output-dir must be an absolute path")
    output_dir = Path(os.path.normpath(str(raw_output)))

    # The smoke target is the project domain itself: there is no separate
    # target URL input, and no network resolution is ever performed.
    try:
        scan_path = ScanPath.build(
            workspace_root, project, project.name, scan_id=output_dir.name
        )
    except ValidationError as exc:
        raise CliValidationError(f"invalid --output-dir: {exc}") from exc

    if os.path.normcase(str(scan_path.scan_dir)) != os.path.normcase(str(output_dir)):
        raise CliValidationError(
            "--output-dir does not match the canonical "
            "<workspace>/projects/<domain>/targets/<host>/scans/zap/<scan-id> layout"
        )

    resolved_workspace = resolve_path(workspace_root)
    resolved_output = resolve_path(output_dir)
    resolved_project = resolve_path(scan_path.project_dir)
    resolved_canonical = resolve_path(scan_path.scan_dir)
    if not is_within(resolved_output, resolved_workspace):
        raise CliValidationError(
            "--output-dir resolves outside the workspace root "
            "(symlink/junction escape)"
        )
    if not is_within(resolved_output, resolved_project):
        raise CliValidationError(
            "--output-dir resolves outside the project directory "
            "(symlink/junction escape)"
        )
    if os.path.normcase(str(resolved_output)) != os.path.normcase(
        str(resolved_canonical)
    ):
        raise CliValidationError(
            "--output-dir resolves outside the canonical smoke layout "
            "(symlink/junction escape)"
        )

    executable = Path(args.zap_executable)
    if not executable.is_absolute():
        raise CliValidationError("--zap-executable must be an absolute path")
    if not executable.is_file():
        raise CliValidationError("--zap-executable must be an existing regular file")

    if args.zap_host != EXACT_BIND_HOST:
        raise CliValidationError("--zap-host must be exactly 127.0.0.1")
    try:
        ZapEndpoint.from_host_port(args.zap_host, args.zap_port)
    except ZapConfigError as exc:
        raise CliValidationError(f"invalid --zap-host/--zap-port: {exc}") from exc

    try:
        ZapEndpoint.from_host_port(args.guard_host, args.guard_port)
    except ZapConfigError as exc:
        raise CliValidationError(f"invalid --guard-host/--guard-port: {exc}") from exc

    if not isinstance(args.expected_version, str) or not args.expected_version:
        raise CliValidationError("--expected-version must be a non-blank string")
    if not isinstance(args.min_version, str) or not args.min_version:
        raise CliValidationError("--min-version must be a non-blank string")

    if output_dir.exists():
        raise CliValidationError(
            "--output-dir already exists; refusing to overwrite or reuse a run directory"
        )

    return SmokePlan(
        workspace_root=workspace_root,
        output_dir=output_dir,
        zap_executable=executable,
        project=project,
        scan_path=scan_path,
        bind_host=args.zap_host,
        bind_port=args.zap_port,
        guard_host=args.guard_host,
        guard_port=args.guard_port,
        expected_version=args.expected_version,
        min_version=args.min_version,
        request_timeout=_validate_positive("--request-timeout", args.request_timeout),
        startup_timeout=_validate_positive("--startup-timeout", args.startup_timeout),
        graceful_timeout=_validate_positive("--graceful-timeout", args.graceful_timeout),
        terminate_timeout=_validate_positive(
            "--terminate-timeout", args.terminate_timeout
        ),
        kill_timeout=_validate_positive("--kill-timeout", args.kill_timeout),
        poll_interval=_validate_positive("--poll-interval", args.poll_interval),
    )


def _format_summary(plan: SmokePlan, *, validate_only: bool) -> str:
    lines = [
        "ZAP daemon smoke plan",
        f"workspace-root: {plan.workspace_root}",
        f"project: {plan.project.name}",
        f"target: none (local tool-health smoke)",
        f"scan-id: {plan.scan_path.scan_id}",
        f"output-dir: {plan.output_dir}",
        f"zap-executable: {plan.zap_executable}",
        f"bind-endpoint: http://{plan.bind_host}:{plan.bind_port}",
        f"guard-endpoint: http://{plan.guard_host}:{plan.guard_port}",
        f"expected-version: {plan.expected_version}",
        "keyless: true",
        "offline-smoke: true",
    ]
    if validate_only:
        lines.append("authorization: not run (validate-only)")
    else:
        lines.append("authorization: operator-confirmed (local smoke latch)")
    return "\n".join(lines)


def _default_runner_factory(plan: SmokePlan) -> ZapSmokeRunner:
    return ZapSmokeRunner(
        scan_path=plan.scan_path,
        executable=plan.zap_executable,
        bind_host=plan.bind_host,
        bind_port=plan.bind_port,
        guard_host=plan.guard_host,
        guard_port=plan.guard_port,
        expected_version=plan.expected_version,
        min_version=plan.min_version,
        startup_timeout=plan.startup_timeout,
        graceful_timeout=plan.graceful_timeout,
        terminate_timeout=plan.terminate_timeout,
        kill_timeout=plan.kill_timeout,
        poll_interval=plan.poll_interval,
        request_timeout=plan.request_timeout,
    )


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    runner_factory: Optional[Callable[[SmokePlan], Any]] = None,
    expected_root: os.PathLike | str | None = None,
) -> int:
    """Parse, validate, and (only when confirmed) execute one smoke run."""

    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        plan = build_plan(args, expected_root=expected_root)
    except CliValidationError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_VALIDATION

    if args.validate_only:
        print(_format_summary(plan, validate_only=True), file=out)
        return EXIT_OK

    if not args.confirm_local_smoke:
        print(
            "error: an actual run requires --confirm-local-smoke",
            file=err,
        )
        return EXIT_VALIDATION

    try:
        runner = (runner_factory or _default_runner_factory)(plan)
        evidence = runner.run()
    except ZapError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME
    except OSError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME
    except ValueError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME

    print(_format_summary(plan, validate_only=False), file=out)
    print(f"status: {evidence.get('status')}", file=out)
    print(f"observed-version: {evidence.get('observed_version')}", file=out)
    print(
        f"evidence: {plan.scan_path.scan_dir / SMOKE_JSON_FILENAME}",
        file=out,
    )
    if evidence.get("status") == "succeeded":
        return EXIT_OK

    print("error: smoke did not meet all acceptance checks", file=err)
    return EXIT_RUNTIME


if __name__ == "__main__":  # pragma: no cover - exercised via the wrapper
    raise SystemExit(main())
