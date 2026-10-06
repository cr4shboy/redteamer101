"""Deterministic recon orchestrator: the ``reduce -> plan -> drive`` loop.

The orchestrator is a pure driver. It holds accumulated per-tool results and
supplied offline fingerprint facts, asks the planner which stage is eligible,
runs exactly one eligible stage via an injected runner, folds the result into
the knowledge base (``reduce``), and re-plans -- repeating until no eligible
stage has a runner (fixpoint) or the step budget is exhausted. The fingerprint
stage alone accepts a ``FetchResult`` and folds its fact only for a known live
web endpoint. Stage selection and folding are deterministic; the only
non-deterministic element is an injected runner.

Safety: the orchestrator performs no network or process activity itself. Active
stages are eligible only when ``authorized`` is set *and* their capability is
available, so an unauthorized run can only ever drive passive stages whose
runners the caller supplied. No real adapter or egress transport is wired here;
live wiring is a separate, authorization-gated step. In tests, runners are fakes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

from ..recon.models import ToolResult, ToolRunStatus
from ..recon.scope import DomainScope
from ..tools.http_fetch import FetchResult
from .findings import Finding, derive_findings
from .fingerprint import WebServerFingerprint
from .model import KnowledgeBase
from .plan import STATUS_ELIGIBLE, Decision, plan

__all__ = ["StepLog", "OrchestratorReport", "reduce", "Orchestrator"]

#: Only the fingerprint stage may return FetchResult; other stages return ToolResult.
StageRunner = Callable[[KnowledgeBase], ToolResult | FetchResult]


@dataclass(frozen=True)
class StepLog:
    """One executed step in the drive loop."""

    stage: str
    tool: str
    status: str

    def to_dict(self) -> dict:
        return {"stage": self.stage, "tool": self.tool, "status": self.status}


@dataclass(frozen=True)
class OrchestratorReport:
    """The deterministic result of a full drive to fixpoint."""

    domain: str
    knowledge: KnowledgeBase
    decisions: tuple[Decision, ...]
    findings: tuple[Finding, ...]
    steps: tuple[StepLog, ...]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "knowledge": self.knowledge.to_dict(),
            "plan": [decision.to_dict() for decision in self.decisions],
            "findings": [finding.to_dict() for finding in self.findings],
            "steps": [step.to_dict() for step in self.steps],
        }


def reduce(
    scope: DomainScope,
    results: Mapping[str, ToolResult],
    *,
    fingerprints: Iterable[WebServerFingerprint] = (),
) -> KnowledgeBase:
    """Fold accumulated per-tool results into a fresh knowledge base.

    Rebuilding from the full result set keeps the fold pure and order-independent
    (the underlying aggregation is deterministic), so ``reduce`` is a true
    reducer: the same results always yield the same knowledge base.
    """

    return KnowledgeBase.build(scope, results, fingerprints=fingerprints)


class Orchestrator:
    """Drive eligible stages to fixpoint, deterministically."""

    def __init__(
        self,
        scope: DomainScope,
        *,
        runners: Mapping[str, StageRunner],
        capabilities: Mapping[str, str] | None = None,
        fingerprints: Iterable[WebServerFingerprint] = (),
        authorized: bool = False,
        max_steps: int = 32,
    ) -> None:
        if not isinstance(scope, DomainScope):
            raise ValueError("scope must be a DomainScope")
        if len(scope.roots) != 1:
            raise ValueError("orchestrator requires a single-root scope")
        if max_steps <= 0:
            raise ValueError("max_steps must be positive")
        self._scope = scope
        self._runners = dict(runners)
        self._capabilities = (
            dict(capabilities) if capabilities is not None else None
        )
        # Validate scope and duplicates before any injected runner is called.
        self._fingerprints = KnowledgeBase.build(
            scope, {}, fingerprints=fingerprints
        ).fingerprints
        self._authorized = bool(authorized)
        self._max_steps = int(max_steps)

    def _plan(self, kb: KnowledgeBase) -> tuple[Decision, ...]:
        return plan(
            kb, capabilities=self._capabilities, authorized=self._authorized
        )

    def run(self) -> OrchestratorReport:
        domain = self._scope.roots[0].name
        results: dict[str, ToolResult] = {}
        fingerprints = list(self._fingerprints)
        ran: set[str] = set()
        steps: list[StepLog] = []
        kb = KnowledgeBase(domain=domain, fingerprints=self._fingerprints)

        for _ in range(self._max_steps):
            decisions = self._plan(kb)
            eligible = [d.stage for d in decisions if d.status == STATUS_ELIGIBLE]
            nxt = next(
                (s for s in eligible if s in self._runners and s not in ran), None
            )
            if nxt is None:
                break
            ran.add(nxt)
            result = self._runners[nxt](kb)
            if nxt == "fingerprint_web_server":
                if not isinstance(result, FetchResult):
                    raise ValueError("fingerprint runner did not return a FetchResult")
                fact = result.fingerprint
                if not any(
                    service.alive
                    and (service.host, service.scheme, service.port)
                    == (fact.host, fact.scheme, fact.port)
                    for service in kb.web
                ):
                    raise ValueError("fingerprint endpoint is not a known live web service")
                # Validate scope and duplicate identity before committing the fact.
                next_fingerprints = (*fingerprints, fact)
                next_kb = reduce(self._scope, results, fingerprints=next_fingerprints)
                fingerprints.append(fact)
                kb = next_kb
                steps.append(StepLog(
                    stage=nxt, tool="http_fetch", status=ToolRunStatus.SUCCEEDED.value,
                ))
                continue
            if not isinstance(result, ToolResult):
                raise ValueError(
                    f"runner for stage {nxt!r} did not return a ToolResult"
                )
            results[result.tool] = result
            kb = reduce(self._scope, results, fingerprints=fingerprints)
            steps.append(
                StepLog(stage=nxt, tool=result.tool, status=result.status.value)
            )

        decisions = self._plan(kb)
        findings = derive_findings(kb)
        return OrchestratorReport(
            domain=domain,
            knowledge=kb,
            decisions=decisions,
            findings=findings,
            steps=tuple(steps),
        )
