"""Thin CLI for the deterministic, fact-driven recon planner.

Given a single root domain, this prints the control-plane plan derived from the
current knowledge base: the facts and one decision per stage
(eligible/blocked/needs_build/awaiting_authorization). It is the entry point a
caller runs with their own authorized domain as a parameter.

``--validate-only`` (the default) is side-effect free: it builds the scope and
prints the plan on the current knowledge base without creating anything,
resolving DNS, opening a socket, or starting a process. From scratch (an empty
knowledge base) only the passive discovery stage is eligible; web-only stages
report ``blocked: no_web_services`` exactly because no live web is known yet.

``--confirm-authorized`` is wired but fail-closed: a live end-to-end run of the
passive-to-active chain requires an owner-authorized live package in
``CURRENT_TASK.md`` (exact domain, allowlist, limits, preflight/stop/acceptance).
None is active, so this CLI refuses to execute any tool and exits nonzero.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence, TextIO

from ..intel import (
    KnowledgeBase,
    derive_findings,
    plan,
    render_json,
    render_markdown,
    render_sarif,
    summary,
)
from ..intel.plan import STATUS_ELIGIBLE
from ..projects.models import ValidationError
from ..recon.scope import DomainScope

__all__ = ["EXIT_OK", "EXIT_RUNTIME", "EXIT_VALIDATION", "build_parser", "main"]

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_RUNTIME = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon_plan.py",
        description=(
            "Print the deterministic recon plan for a root domain: derived facts "
            "and one decision per stage. Passive-to-active chaining is gated by "
            "facts; a live run requires an authorized CURRENT_TASK.md package."
        ),
    )
    parser.add_argument("--domain", required=True, help="the single in-scope root domain")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="HOST",
        help="an exact hostname to exclude from scope (repeatable)",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="wordlist path for the active ffuf stage (informational only here)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the plan as JSON instead of text"
    )
    parser.add_argument(
        "--report",
        choices=("md", "json", "sarif"),
        default=None,
        help="emit a findings report in the given format instead of the plan",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--validate-only",
        action="store_true",
        help="default: print the plan without executing anything (no network)",
    )
    mode.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="request a live run (fail-closed without an authorized package)",
    )
    return parser


def _render_text(kb: KnowledgeBase, decisions, out: TextIO) -> None:
    facts = summary(kb)
    print(f"domain: {facts['domain']}", file=out)
    print(
        "facts: "
        f"hosts={facts['hosts']} "
        f"resolvable={len(facts['resolvable'])} "
        f"web_hosts={len(facts['web_hosts'])} "
        f"has_web={facts['has_web']}",
        file=out,
    )
    print("plan:", file=out)
    width = max(len(d.stage) for d in decisions)
    for decision in decisions:
        reason = f"  ({decision.reason})" if decision.reason else ""
        print(
            f"  {decision.stage.ljust(width)}  {decision.tier:<7}  "
            f"{decision.status}{reason}",
            file=out,
        )
    eligible = [d.stage for d in decisions if d.status == STATUS_ELIGIBLE]
    print(f"eligible now: {', '.join(eligible) if eligible else '(none)'}", file=out)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)

    try:
        scope = DomainScope.parse([args.domain], args.exclude)
    except ValidationError as exc:
        print(f"recon_plan.py: invalid scope: {exc}", file=err)
        return EXIT_VALIDATION

    # From scratch: an empty knowledge base. A live run would ingest tool
    # results into this base and re-plan; that path is gated below.
    kb = KnowledgeBase.empty(scope.roots[0].name)
    decisions = plan(kb, authorized=args.confirm_authorized)

    if args.confirm_authorized:
        print(
            "recon_plan.py: live execution refused. A passive-to-active live run "
            "requires an owner-authorized live package in CURRENT_TASK.md (exact "
            "domain, network allowlist, per-tool limits, preflight/stop/acceptance "
            "criteria). No active package is present, so no tool was run.",
            file=err,
        )
        return EXIT_RUNTIME

    if args.report is not None:
        findings = derive_findings(kb)
        if args.report == "md":
            print(render_markdown(kb, decisions, findings), file=out)
        elif args.report == "sarif":
            print(render_sarif(findings, domain=kb.domain), file=out)
        else:
            print(render_json(kb, decisions, findings), file=out)
        return EXIT_OK

    if args.json:
        payload = {
            "domain": kb.domain,
            "facts": summary(kb),
            "plan": [decision.to_dict() for decision in decisions],
        }
        print(json.dumps(payload, indent=2), file=out)
    else:
        _render_text(kb, decisions, out)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
