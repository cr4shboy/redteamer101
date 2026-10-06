"""Deterministic findings derived from the knowledge base.

Findings are the defensive output of the pipeline: each is a pure function of the
knowledge base, so the same recon state always yields the same findings in the
same order. Rules are small, honest, and additive -- today they describe the
attack surface (what is exposed / unresolved); richer rules (missing security
headers, weak TLS, expiring certificates) slot in here unchanged once the active
probes that supply that evidence land.

Nothing here performs network or process activity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .facts import resolvable_hosts, web_hosts
from .model import KnowledgeBase

__all__ = ["Severity", "Finding", "RULES", "derive_findings"]


class Severity(Enum):
    """Ordered finding severities (``rank`` sorts most-severe first)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order[self.value]


@dataclass(frozen=True)
class Finding:
    """One deterministic, host-scoped observation about the attack surface."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    host: str | None
    evidence: str

    @property
    def _sort_key(self) -> tuple:
        # Most-severe first, then stable by rule and host.
        return (-self.severity.rank, self.rule_id, self.host or "")

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "host": self.host,
            "evidence": self.evidence,
        }


def _rule_web_service_exposed(kb: KnowledgeBase) -> list[Finding]:
    return [
        Finding(
            rule_id="web-service-exposed",
            title="Live web service exposed",
            severity=Severity.INFO,
            category="surface",
            host=host,
            evidence=f"https://{host}/ responded to an in-scope probe",
        )
        for host in web_hosts(kb)
    ]


def _rule_host_unresolved(kb: KnowledgeBase) -> list[Finding]:
    resolvable = set(resolvable_hosts(kb))
    return [
        Finding(
            rule_id="host-unresolved",
            title="In-scope host did not resolve",
            severity=Severity.INFO,
            category="dns",
            host=host,
            evidence="no A/AAAA record observed for this in-scope host",
        )
        for host in kb.hostnames
        if host not in resolvable
    ]


#: The active rule set. Each rule is a pure ``KnowledgeBase -> list[Finding]``.
RULES: tuple[Callable[[KnowledgeBase], list[Finding]], ...] = (
    _rule_web_service_exposed,
    _rule_host_unresolved,
)


def derive_findings(kb: KnowledgeBase) -> tuple[Finding, ...]:
    """Return all findings for *kb*, deduplicated and deterministically ordered."""

    seen: dict[tuple[str, str | None], Finding] = {}
    for rule in RULES:
        for finding in rule(kb):
            seen[(finding.rule_id, finding.host)] = finding
    return tuple(sorted(seen.values(), key=lambda f: f._sort_key))
