"""Objectified data plane: a deterministic knowledge base of recon entities.

The knowledge base consolidates per-tool :class:`ToolResult` outputs into
canonical, linked entities so the control plane can derive intel from *objects*
rather than raw tool output. It reuses the existing passive objectification
(:func:`aggregate_discovery` / :func:`build_assets` produce canonical
:class:`~red_teaming.recon.models.Asset` records with DNS evidence) and adds a
minimal :class:`WebService` layer derived from active, web-touching tools.

Everything here is pure and deterministic: the same tool results and supplied
fingerprint facts always yield the same knowledge base (assets sorted by
hostname, web services by ``(host, scheme, port)``, fingerprint facts by source
identity). Nothing performs network or process activity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from ..recon.aggregate import aggregate_discovery, build_assets
from ..recon.models import Asset, ResolutionStatus, ToolResult
from ..recon.scope import DomainScope
from ..projects.models import ProjectDomain, ValidationError
from ..tools.acceptance import accepted_hosts_from_result
from .fingerprint import WebServerFingerprint

__all__ = [
    "DNS_RESOLVER_TOOL",
    "WEB_SOURCE_TOOLS",
    "KnowledgeBase",
    "WebService",
    "derive_web_services",
]

#: Tool name whose result carries DNS resolutions (kept separate from the
#: candidate-discovery tools during aggregation).
DNS_RESOLVER_TOOL = "dnsx"

#: Tools whose successful, in-scope discovered hosts imply a live web service.
#: ffuf subdomain fuzzing over ``https://FUZZ.<root>/`` only reports a host when
#: it actually answered over HTTPS, so a discovered host is treated as a live
#: ``https`` web service.
WEB_SOURCE_TOOLS = ("ffuf",)


@dataclass(frozen=True)
class WebService:
    """A live web endpoint discovered on an in-scope host."""

    host: str
    scheme: str = "https"
    port: int = 443
    alive: bool = True
    status_code: int | None = None

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.host, self.scheme, self.port)


def derive_web_services(
    results: Mapping[str, ToolResult],
    *,
    web_source_tools: tuple[str, ...] = WEB_SOURCE_TOOLS,
) -> tuple[WebService, ...]:
    """Derive deterministic live web services from active discovery results.

    Only successful results from *web_source_tools* contribute, and only their
    accepted (in-scope, DISCOVERED) hosts. The result is deduplicated by
    ``(host, scheme, port)`` and sorted.
    """

    services: dict[tuple[str, str, int], WebService] = {}
    for tool in sorted(results):
        if tool not in web_source_tools:
            continue
        for host in accepted_hosts_from_result(results[tool]):
            service = WebService(host=host, scheme="https", port=443, alive=True)
            services[service.key] = service
    return tuple(services[key] for key in sorted(services))


@dataclass(frozen=True)
class KnowledgeBase:
    """Consolidated, linked recon entities for one in-scope root domain."""

    domain: str
    assets: tuple[Asset, ...] = ()
    web: tuple[WebService, ...] = ()
    fingerprints: tuple[WebServerFingerprint, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.fingerprints, (str, bytes)):
            raise ValidationError("fingerprints must be a collection of fingerprint facts")
        try:
            items = tuple(self.fingerprints)
        except TypeError as exc:
            raise ValidationError("fingerprints must be iterable") from exc
        if not all(isinstance(item, WebServerFingerprint) for item in items):
            raise ValidationError("fingerprints must contain WebServerFingerprint values")
        if items:
            root = ProjectDomain.parse(self.domain)
            if any(not root.contains(item.host) for item in items):
                raise ValidationError("fingerprint host is outside the knowledge domain")
        by_identity: dict[tuple[str, str, int, str], WebServerFingerprint] = {}
        for item in items:
            previous = by_identity.get(item.identity)
            if previous is not None and previous != item:
                raise ValidationError("conflicting duplicate fingerprint identity")
            by_identity[item.identity] = item
        object.__setattr__(
            self,
            "fingerprints",
            tuple(by_identity[key] for key in sorted(by_identity)),
        )

    @classmethod
    def empty(cls, domain: str) -> "KnowledgeBase":
        """Return an empty knowledge base for *domain* (no collection yet)."""

        return cls(domain=domain, assets=(), web=())

    @classmethod
    def build(
        cls,
        scope: DomainScope,
        results: Mapping[str, ToolResult],
        *,
        fingerprints: Iterable[WebServerFingerprint] = (),
    ) -> "KnowledgeBase":
        """Build a knowledge base from accumulated per-tool results.

        *results* maps a tool-level name to its :class:`ToolResult`. The
        ``dnsx`` result (if any) supplies resolutions; every other result is a
        candidate-discovery source; web-touching tools additionally yield web
        services. Aggregation and asset building reuse the existing
        deterministic, single-root pipeline helpers.
        """

        discovery = {
            tool: result
            for tool, result in results.items()
            if tool != DNS_RESOLVER_TOOL
        }
        dnsx_result = results.get(DNS_RESOLVER_TOOL)
        aggregate = aggregate_discovery(scope, discovery)
        assets = build_assets(scope, aggregate, dnsx_result)
        web = derive_web_services(results)
        items: list[WebServerFingerprint] = []
        for fingerprint in fingerprints:
            if not isinstance(fingerprint, WebServerFingerprint):
                raise ValidationError("fingerprints must contain WebServerFingerprint values")
            if not scope.contains(fingerprint.host):
                raise ValidationError("fingerprint host is outside the domain scope")
            items.append(fingerprint)
        return cls(domain=scope.roots[0].name, assets=assets, web=web, fingerprints=tuple(items))

    # -- views --------------------------------------------------------------

    @property
    def hostnames(self) -> tuple[str, ...]:
        return tuple(asset.hostname for asset in self.assets)

    def resolvable_assets(self) -> tuple[Asset, ...]:
        return tuple(
            asset
            for asset in self.assets
            if asset.resolution_status is ResolutionStatus.RESOLVED
            or asset.dns.a
            or asset.dns.aaaa
        )

    def web_hosts(self) -> tuple[str, ...]:
        return tuple(sorted({service.host for service in self.web if service.alive}))

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "assets": [asset.to_dict() for asset in self.assets],
            "web": [
                {
                    "host": service.host,
                    "scheme": service.scheme,
                    "port": service.port,
                    "alive": service.alive,
                    "status_code": service.status_code,
                }
                for service in self.web
            ],
            "fingerprints": [item.to_dict() for item in self.fingerprints],
        }
