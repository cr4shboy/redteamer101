"""Dedicated CLI for the bounded Stage 2 traditional Spider.

This is deliberately *not* the generic ``scan_target.py`` Spider/AJAX CLI. The
project, seed, and mode are fixed to the single work package authorized by
``CURRENT_TASK.md`` and are not exposed as options, so a caller cannot widen the
profile by argument. An actual run additionally requires
``--confirm-authorized``; that latch does not itself confer legal authorization.

The production runner is keyless and guarded; no API key is generated and no
CLI option can weaken the guard/control checks. Argument parsing is side-effect
free. ``--validate-only`` validates the whole profile and prints a summary
without creating a directory, resolving DNS, opening a socket, or starting a
process.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Callable, Optional, Sequence, TextIO

from ..tools.zap.bounded import (
    EXPECTED_ZAP_VERSION,
    STAGE2_SEED,
    Stage2PreflightError,
    Stage2Profile,
    Stage2ProfileError,
    Stage2SpiderRunner,
    build_stage2_profile,
)
from ..tools.zap.models import DEFAULT_API_TIMEOUT, ZapError
from ..tools.zap.process import (
    DEFAULT_GRACEFUL_TIMEOUT,
    DEFAULT_KILL_TIMEOUT,
    DEFAULT_STARTUP_TIMEOUT,
    DEFAULT_TERMINATE_TIMEOUT,
)
from ..tools.zap.discovery import DEFAULT_POLL_INTERVAL

__all__ = ["EXIT_OK", "EXIT_RUNTIME", "EXIT_VALIDATION", "build_parser", "main"]

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_RUNTIME = 3

DEFAULT_ZAP_HOST = "127.0.0.1"
DEFAULT_ZAP_PORT = 18080
DEFAULT_SPIDER_TIMEOUT = 300.0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stage2_spider.py",
        description=(
            "Run the one authorized bounded traditional Spider against "
            "https://acme.example/. The project, seed, and mode are fixed."
        ),
    )
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--zap-executable", required=True)
    parser.add_argument("--validate-only", action="store_true", dest="validate_only")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        dest="confirm_authorized",
        help=(
            "required for an actual run; this latch does not itself confer "
            "legal authorization"
        ),
    )
    parser.add_argument("--zap-host", default=DEFAULT_ZAP_HOST)
    parser.add_argument("--zap-port", type=int, default=DEFAULT_ZAP_PORT)
    parser.add_argument("--startup-timeout", type=float, default=DEFAULT_STARTUP_TIMEOUT)
    parser.add_argument("--spider-timeout", type=float, default=DEFAULT_SPIDER_TIMEOUT)
    parser.add_argument("--request-timeout", type=float, default=DEFAULT_API_TIMEOUT)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--graceful-timeout", type=float, default=DEFAULT_GRACEFUL_TIMEOUT)
    parser.add_argument("--terminate-timeout", type=float, default=DEFAULT_TERMINATE_TIMEOUT)
    parser.add_argument("--kill-timeout", type=float, default=DEFAULT_KILL_TIMEOUT)
    return parser


def _format_summary(plan: Stage2Profile, *, validate_only: bool) -> str:
    lines = [
        "bounded Stage 2 traditional Spider plan",
        f"workspace-root: {plan.workspace_root}",
        f"project: {plan.domain}",
        f"target: {plan.target.url}",
        f"mode: {plan.mode}",
        f"scan-id: {plan.scan_path.scan_id}",
        f"output-dir: {plan.output_dir}",
        f"zap-executable: {plan.executable}",
        f"zap-endpoint: {plan.endpoint.base_url}",
        f"expected-version: {EXPECTED_ZAP_VERSION}",
    ]
    if validate_only:
        lines.append("authorization: not run (validate-only)")
        lines.append("API authentication: keyless (no key generated)")
    else:
        lines.append("authorization: operator-confirmed (not legal authorization)")
        lines.append("API authentication: keyless (no key generated)")
    return "\n".join(lines)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    runner_factory: Optional[Callable[..., Any]] = None,
    expected_root: Any = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        plan = build_stage2_profile(
            workspace_root=args.workspace_root,
            output_dir=args.output_dir,
            zap_executable=args.zap_executable,
            zap_host=args.zap_host,
            zap_port=args.zap_port,
            request_timeout=args.request_timeout,
            startup_timeout=args.startup_timeout,
            spider_timeout=args.spider_timeout,
            poll_interval=args.poll_interval,
            graceful_timeout=args.graceful_timeout,
            terminate_timeout=args.terminate_timeout,
            kill_timeout=args.kill_timeout,
            expected_root=expected_root,
        )
    except (Stage2ProfileError, ZapError) as exc:
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

    # The runner receives the profile only: it is keyless and guarded, and no
    # CLI option may supply an API key, capability proof, or guard override.
    runner_kwargs = {"profile": plan}
    runner = (
        runner_factory(**runner_kwargs)
        if runner_factory is not None
        else Stage2SpiderRunner(**runner_kwargs)
    )

    try:
        state = runner.run()
    except (Stage2PreflightError, ZapError) as exc:
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME
    except OSError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_RUNTIME

    print(_format_summary(plan, validate_only=False), file=out)
    status = state.get("status") if isinstance(state, dict) else None
    if status == "succeeded":
        print("status: succeeded", file=out)
        return EXIT_OK
    prelaunch = (state or {}).get("prelaunch") or {}
    preflight = (state or {}).get("preflight") or {}
    blockers = prelaunch.get("blockers") or preflight.get("blockers") or []
    print(f"status: {status or 'failed'} (blockers: {blockers})", file=out)
    return EXIT_RUNTIME


if __name__ == "__main__":  # pragma: no cover - exercised via the wrapper
    raise SystemExit(main())
