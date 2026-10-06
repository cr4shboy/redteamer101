"""Derived intel: pure predicates over the knowledge base.

Facts are the only thing the planner reads when deciding which stages are
eligible. Each function is pure and deterministic, so the full decision chain is
reproducible and offline-testable.
"""

from __future__ import annotations

from .model import KnowledgeBase

__all__ = [
    "has_scope",
    "has_hosts",
    "resolvable_hosts",
    "unresolved_hosts",
    "web_hosts",
    "has_web",
    "summary",
]


def has_scope(kb: KnowledgeBase) -> bool:
    """True when a root domain is defined (the minimum to start passively)."""

    return bool(kb.domain)


def has_hosts(kb: KnowledgeBase) -> bool:
    """True when at least one candidate host is known (resolution has input)."""

    return bool(kb.assets)


def resolvable_hosts(kb: KnowledgeBase) -> tuple[str, ...]:
    """Sorted hostnames that resolved to at least one A/AAAA address."""

    return tuple(sorted(asset.hostname for asset in kb.resolvable_assets()))


def unresolved_hosts(kb: KnowledgeBase) -> tuple[str, ...]:
    """Sorted in-scope hostnames without an A/AAAA resolution yet."""

    resolvable = set(resolvable_hosts(kb))
    return tuple(sorted(host for host in kb.hostnames if host not in resolvable))


def web_hosts(kb: KnowledgeBase) -> tuple[str, ...]:
    """Sorted hostnames with at least one live web service."""

    return kb.web_hosts()


def has_web(kb: KnowledgeBase) -> bool:
    """True when any in-scope host exposes a live web service.

    This is the gate for web-only active stages (for example ZAP spidering):
    with no live web service, those stages can never become eligible.
    """

    return bool(web_hosts(kb))


def summary(kb: KnowledgeBase) -> dict:
    """Return a compact, deterministic snapshot of the derived facts."""

    return {
        "domain": kb.domain,
        "has_scope": has_scope(kb),
        "hosts": len(kb.hostnames),
        "resolvable": list(resolvable_hosts(kb)),
        "unresolved": list(unresolved_hosts(kb)),
        "web_hosts": list(web_hosts(kb)),
        "has_web": has_web(kb),
    }
