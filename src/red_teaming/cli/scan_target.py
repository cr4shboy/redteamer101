"""Thin CLI for one bounded OWASP ZAP Spider/AJAX Spider run.

Argument parsing is side-effect free: nothing is created and no API/process
activity happens until :func:`main` is asked to *run*. ``--validate-only``
validates the whole plan and prints a redacted summary without ever creating a
directory, starting a process, or making an API call.

An actual run additionally requires ``--confirm-authorized``. That flag is a
safety latch only: it does not itself confer legal authorization for a target.
"""

from __future__ import annotations

import argparse
import math
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, TextIO

from ..projects.models import ProjectDomain, Target, ValidationError
from ..projects.paths import (
    ScanPath,
    is_within,
    require_workspace_root,
    resolve_path,
)
from ..tools.zap.client import ZapApiClient
from ..tools.zap.discovery import (
    DEFAULT_AJAX_TIMEOUT,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_SPIDER_TIMEOUT,
)
from ..tools.zap.models import (
    DEFAULT_API_TIMEOUT,
    ZapConfigError,
    ZapEndpoint,
    ZapError,
    redact_secret,
)
from ..tools.zap.process import (
    DEFAULT_GRACEFUL_TIMEOUT,
    DEFAULT_KILL_TIMEOUT,
    DEFAULT_STARTUP_TIMEOUT,
    DEFAULT_TERMINATE_TIMEOUT,
    ZapProcessManager,
)
from ..tools.zap.scanner import VALID_MODES, ZapScanner

__all__ = [
    "EXIT_OK",
    "EXIT_RUNTIME",
    "EXIT_VALIDATION",
    "CliValidationError",
    "ScanPlan",
    "build_parser",
    "main",
]

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_RUNTIME = 3

DEFAULT_ZAP_HOST = "127.0.0.1"
DEFAULT_ZAP_PORT = 8080


class CliValidationError(ValueError):
    """The supplied CLI arguments do not describe a valid scan plan."""


@dataclass(frozen=True)
class ScanPlan:
    """A fully validated, side-effect-free description of one scan run."""

    workspace_root: Path
    output_dir: Path
    zap_executable: Path
    project: ProjectDomain
    target: Target
    mode: str
    scan_path: ScanPath
    endpoint: ZapEndpoint
    request_timeout: float
    startup_timeout: float
    spider_timeout: float
    ajax_timeout: float
    poll_interval: float
    graceful_timeout: float
    terminate_timeout: float
    kill_timeout: float


def _validate_positive(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CliValidationError(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise CliValidationError(f"{name} must be a positive finite number")
    return float(value)


def build_parser() -> argparse.ArgumentParser:
    """Construct the side-effect-free argument parser."""

    parser = argparse.ArgumentParser(
        prog="scan_target.py",
        description=(
            "Run one bounded OWASP ZAP Spider and/or AJAX Spider scan for an "
            "explicitly authorized target. No directory is created and no "
            "process/API call is made unless an actual run is requested."
        ),
    )
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--zap-executable", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", required=True, choices=list(VALID_MODES))
    parser.add_argument(
        "--validate-only",
        action="store_true",
        dest="validate_only",
        help="validate and print a redacted plan without any side effects",
    )
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        dest="confirm_authorized",
        help=(
            "required for an actual run; this latch does not itself confer "
            "legal authorization for the target"
        ),
    )
    parser.add_argument("--zap-host", default=DEFAULT_ZAP_HOST)
    parser.add_argument("--zap-port", type=int, default=DEFAULT_ZAP_PORT)
    parser.add_argument("--startup-timeout", type=float, default=DEFAULT_STARTUP_TIMEOUT)
    parser.add_argument("--spider-timeout", type=float, default=DEFAULT_SPIDER_TIMEOUT)
    parser.add_argument("--ajax-timeout", type=float, default=DEFAULT_AJAX_TIMEOUT)
    parser.add_argument("--request-timeout", type=float, default=DEFAULT_API_TIMEOUT)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--graceful-timeout", type=float, default=DEFAULT_GRACEFUL_TIMEOUT)
    parser.add_argument(
        "--terminate-timeout", type=float, default=DEFAULT_TERMINATE_TIMEOUT
    )
    parser.add_argument("--kill-timeout", type=float, default=DEFAULT_KILL_TIMEOUT)
    return parser


def build_plan(
    args: argparse.Namespace, *, expected_root: os.PathLike | str | None = None
) -> ScanPlan:
    """Validate *args* into a :class:`ScanPlan` without touching the filesystem.

    Only read-only ``Path`` checks (existence, ``is_dir``/``is_file``, and
    non-strict ``realpath``) are performed; no directory is created and no
    process/API call is made. ``expected_root`` allows tests to inject the
    approved checkout root; when omitted it is resolved from the source file.
    """

    try:
        workspace_root = require_workspace_root(
            args.workspace_root, expected_root=expected_root
        )
        project = ProjectDomain.parse(args.project)
        target = Target.parse(args.target, project)
    except ValidationError as exc:
        raise CliValidationError(str(exc)) from exc

    raw_output = Path(args.output_dir)
    if not raw_output.is_absolute():
        raise CliValidationError("--output-dir must be an absolute path")
    output_dir = Path(os.path.normpath(str(raw_output)))

    try:
        scan_path = ScanPath.build(
            workspace_root, project, target, scan_id=output_dir.name
        )
    except ValidationError as exc:
        raise CliValidationError(f"invalid --output-dir: {exc}") from exc

    if os.path.normcase(str(scan_path.scan_dir)) != os.path.normcase(str(output_dir)):
        raise CliValidationError(
            "--output-dir does not match the canonical "
            "<workspace>/projects/<domain>/targets/<host>/scans/zap/<scan-id> layout"
        )

    # Symlink/junction hardening: resolve existing components (strict=False)
    # and re-verify containment plus agreement with the derived canonical path.
    resolved_workspace = resolve_path(workspace_root)
    resolved_output = resolve_path(output_dir)
    resolved_project = resolve_path(scan_path.project_dir)
    resolved_zap_root = resolve_path(scan_path.zap_dir)
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
    if not is_within(resolved_output, resolved_zap_root):
        raise CliValidationError(
            "--output-dir resolves outside the canonical ZAP scan root "
            "(symlink/junction escape)"
        )
    if os.path.normcase(str(resolved_output)) != os.path.normcase(
        str(resolved_canonical)
    ):
        raise CliValidationError(
            "--output-dir resolves outside the canonical scan layout "
            "(symlink/junction escape)"
        )

    executable = Path(args.zap_executable)
    if not executable.is_absolute():
        raise CliValidationError("--zap-executable must be an absolute path")
    if not executable.is_file():
        raise CliValidationError(
            "--zap-executable must be an existing regular file"
        )

    if args.mode not in VALID_MODES:
        raise CliValidationError(f"--mode must be one of {', '.join(VALID_MODES)}")

    try:
        endpoint = ZapEndpoint.from_host_port(args.zap_host, args.zap_port)
    except ZapConfigError as exc:
        raise CliValidationError(str(exc)) from exc

    if output_dir.exists():
        raise CliValidationError(
            "--output-dir already exists; refusing to overwrite or reuse a scan directory"
        )

    return ScanPlan(
        workspace_root=workspace_root,
        output_dir=output_dir,
        zap_executable=executable,
        project=project,
        target=target,
        mode=args.mode,
        scan_path=scan_path,
        endpoint=endpoint,
        request_timeout=_validate_positive("--request-timeout", args.request_timeout),
        startup_timeout=_validate_positive("--startup-timeout", args.startup_timeout),
        spider_timeout=_validate_positive("--spider-timeout", args.spider_timeout),
        ajax_timeout=_validate_positive("--ajax-timeout", args.ajax_timeout),
        poll_interval=_validate_positive("--poll-interval", args.poll_interval),
        graceful_timeout=_validate_positive("--graceful-timeout", args.graceful_timeout),
        terminate_timeout=_validate_positive(
            "--terminate-timeout", args.terminate_timeout
        ),
        kill_timeout=_validate_positive("--kill-timeout", args.kill_timeout),
    )


def _format_summary(plan: ScanPlan, *, validate_only: bool) -> str:
    lines = [
        "ZAP Spider/AJAX scan plan",
        f"workspace-root: {plan.workspace_root}",
        f"project: {plan.project.name}",
        f"target: {plan.target.url}",
        f"mode: {plan.mode}",
        f"scan-id: {plan.scan_path.scan_id}",
        f"output-dir: {plan.output_dir}",
        f"zap-executable: {plan.zap_executable}",
        f"zap-endpoint: {plan.endpoint.base_url}",
    ]
    if validate_only:
        lines.append("authorization: not run (validate-only)")
        lines.append("API key: not generated")
    else:
        lines.append("authorization: operator-confirmed (not legal authorization)")
    return "\n".join(lines)


def _default_key_factory() -> str:
    return secrets.token_hex(32)


def _default_client_factory(
    endpoint: ZapEndpoint, api_key: str, *, timeout: float
) -> ZapApiClient:
    return ZapApiClient(endpoint, api_key, timeout=timeout)


def _default_manager_factory(**kwargs: Any) -> ZapProcessManager:
    return ZapProcessManager(**kwargs)


def _default_scanner_factory(**kwargs: Any) -> ZapScanner:
    return ZapScanner(**kwargs)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    client_factory: Optional[Callable[..., Any]] = None,
    manager_factory: Optional[Callable[..., Any]] = None,
    scanner_factory: Optional[Callable[..., Any]] = None,
    key_factory: Optional[Callable[[], str]] = None,
    expected_root: os.PathLike | str | None = None,
) -> int:
    """Parse, validate, and (only when requested) execute one scan run.

    ``expected_root`` is an optional test seam for the approved checkout root;
    production callers omit it so the root is derived from the source location.
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

    if args.validate_only:
        print(_format_summary(plan, validate_only=True), file=out)
        return EXIT_OK

    if not args.confirm_authorized:
        print(
            "error: an actual run requires --confirm-authorized; this safety "
            "latch does not itself confer legal authorization",
            file=err,
        )
        return EXIT_VALIDATION

    api_key = (key_factory or _default_key_factory)()

    def redact(text: str) -> str:
        return redact_secret(str(text), api_key)

    try:
        client = (client_factory or _default_client_factory)(
            plan.endpoint, api_key, timeout=plan.request_timeout
        )
        manager = (manager_factory or _default_manager_factory)(
            executable=plan.zap_executable,
            scan_path=plan.scan_path,
            api_key=api_key,
            host=plan.endpoint.host,
            port=plan.endpoint.port,
            client=client,
            startup_timeout=plan.startup_timeout,
            graceful_timeout=plan.graceful_timeout,
            terminate_timeout=plan.terminate_timeout,
            kill_timeout=plan.kill_timeout,
            poll_interval=plan.poll_interval,
        )
        scanner = (scanner_factory or _default_scanner_factory)(
            scan_path=plan.scan_path,
            target=plan.target,
            project=plan.project.name,
            mode=plan.mode,
            manager=manager,
            client=client,
            spider_timeout=plan.spider_timeout,
            ajax_timeout=plan.ajax_timeout,
            poll_interval=plan.poll_interval,
            secret_redactor=redact,
        )
        scanner.run()
    except ZapError as exc:
        print(f"error: {redact(str(exc))}", file=err)
        return EXIT_RUNTIME
    except OSError as exc:
        print(f"error: {redact(str(exc))}", file=err)
        return EXIT_RUNTIME
    except ValueError as exc:
        print(f"error: {redact(str(exc))}", file=err)
        return EXIT_RUNTIME

    print(_format_summary(plan, validate_only=False), file=out)
    print("status: succeeded", file=out)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised via the wrapper
    raise SystemExit(main())
