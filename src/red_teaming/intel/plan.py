"""Control plane: a deterministic, fact-driven stage planner.

Each stage declares its tool, tier (passive/active), the registry capability it
needs (if any), and a precondition expressed over derived facts. Given a
knowledge base, the planner emits one deterministic :class:`Decision` per stage:

* ``blocked`` -- the fact precondition is not met (for example a web-only stage
  with no live web service); the reason names the missing fact;
* ``needs_build`` -- the precondition is met but the capability is not
  ``available`` in the registry (route to a build handoff);
* ``awaiting_authorization`` -- an active stage whose precondition and
  capability are satisfied but which has not been authorized for a live run;
* ``eligible`` -- ready to run now.

The planner is pure: the same knowledge base, capability map, and authorization
flag always produce the same decisions. It never runs a tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .facts import has_hosts, has_scope, has_web
from .model import KnowledgeBase

__all__ = [
    "ACTIVE",
    "PASSIVE",
    "STAGES",
    "STATUS_AWAITING_AUTHORIZATION",
    "STATUS_BLOCKED",
    "STATUS_ELIGIBLE",
    "STATUS_NEEDS_BUILD",
    "Decision",
    "Stage",
    "eligible_stages",
    "load_capability_statuses",
    "plan",
]

PASSIVE = "passive"
ACTIVE = "active"

STATUS_ELIGIBLE = "eligible"
STATUS_BLOCKED = "blocked"
STATUS_NEEDS_BUILD = "needs_build"
STATUS_AWAITING_AUTHORIZATION = "awaiting_authorization"

_REGISTRY_PATH = Path(__file__).resolve().parents[3] / "capabilities" / "registry.yaml"


@dataclass(frozen=True)
class Stage:
    """A declarative recon stage with a fact-based precondition."""

    name: str
    tool: str
    tier: str
    capability: str | None
    check: Callable[[KnowledgeBase], tuple[bool, str | None]]
    produces: str


@dataclass(frozen=True)
class Decision:
    """The planner's deterministic verdict for one stage."""

    stage: str
    tool: str
    tier: str
    status: str
    reason: str | None
    capability: str | None
    produces: str

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "tool": self.tool,
            "tier": self.tier,
            "status": self.status,
            "reason": self.reason,
            "capability": self.capability,
            "produces": self.produces,
        }


def _check_scope(kb: KnowledgeBase) -> tuple[bool, str | None]:
    return (has_scope(kb), None if has_scope(kb) else "no_scope")


def _check_hosts(kb: KnowledgeBase) -> tuple[bool, str | None]:
    return (has_hosts(kb), None if has_hosts(kb) else "no_hosts_to_resolve")


def _check_web(kb: KnowledgeBase) -> tuple[bool, str | None]:
    return (has_web(kb), None if has_web(kb) else "no_web_services")


#: The fixed stage order: passive discovery, resolution, then active stages,
#: each gated by the facts the previous stages can produce.
STAGES: tuple[Stage, ...] = (
    Stage(
        "passive_subdomains", "amass", PASSIVE, None, _check_scope,
        "in-scope subdomain candidates",
    ),
    Stage(
        "resolve", "dnsx", PASSIVE, None, _check_hosts,
        "A/AAAA/CNAME records for known hosts",
    ),
    Stage(
        "active_subdomains", "ffuf", ACTIVE, None, _check_scope,
        "active subdomain candidates and web liveness",
    ),
    Stage(
        "fingerprint_web_server", "http_fetch", ACTIVE, "fingerprint_web_server", _check_web,
        "Server header claims for live web hosts",
    ),
    Stage(
        "zap_spider", "zap", ACTIVE, "zap_spider", _check_web,
        "spidered endpoints for live web hosts",
    ),
    Stage(
        "nuclei_scan", "nuclei", ACTIVE, "nuclei_scan", _check_web,
        "template findings for live web hosts",
    ),
)


def load_capability_statuses(path: Path = _REGISTRY_PATH) -> dict[str, str]:
    """Read ``name -> status`` from the capability registry (fail-open to empty).

    Uses the same tiny nested-mapping shape as ``capability.py``; an unreadable
    registry yields an empty map so every capability-gated stage then reports
    ``needs_build`` rather than silently appearing available.
    """

    statuses: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return statuses
    current: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] not in (" ", "\t"):
            current = line.strip().rstrip(":").strip() or None
            continue
        key, sep, value = line.strip().partition(":")
        if current and sep and key.strip() == "status":
            statuses[current] = value.strip()
    return statuses


def plan(
    kb: KnowledgeBase,
    *,
    capabilities: Mapping[str, str] | None = None,
    authorized: bool = False,
) -> tuple[Decision, ...]:
    """Return one deterministic :class:`Decision` per stage for *kb*.

    *capabilities* maps a registry capability name to its status; when omitted
    it is loaded from the capability registry. *authorized* reflects an explicit
    live-run authorization (active stages stay ``awaiting_authorization`` until
    it is set).
    """

    caps = dict(capabilities) if capabilities is not None else load_capability_statuses()
    decisions: list[Decision] = []
    for stage in STAGES:
        ok, reason = stage.check(kb)
        if not ok:
            status, rsn = STATUS_BLOCKED, reason
        elif stage.capability is not None and caps.get(stage.capability) != "available":
            status = STATUS_NEEDS_BUILD
            rsn = f"capability_{caps.get(stage.capability, 'unknown')}"
        elif stage.tier == ACTIVE and not authorized:
            status = STATUS_AWAITING_AUTHORIZATION
            rsn = "requires_authorized_live_run"
        else:
            status, rsn = STATUS_ELIGIBLE, None
        decisions.append(
            Decision(
                stage=stage.name,
                tool=stage.tool,
                tier=stage.tier,
                status=status,
                reason=rsn,
                capability=stage.capability,
                produces=stage.produces,
            )
        )
    return tuple(decisions)


def eligible_stages(decisions: tuple[Decision, ...]) -> tuple[str, ...]:
    """Return the names of the stages that are eligible to run now."""

    return tuple(d.stage for d in decisions if d.status == STATUS_ELIGIBLE)
