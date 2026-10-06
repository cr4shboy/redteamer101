"""Deterministic, domain-neutral scope intake.

A :class:`DomainScope` holds one or more authorized root DNS domains plus exact
hostname exclusions. All normalization is delegated to the canonical
:func:`red_teaming.projects.models.normalize_dns_name` / ``ProjectDomain`` logic,
so no alternate DNS validation exists here. No DNS, socket, subprocess, or
filesystem activity is performed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from ..projects.models import ProjectDomain, ValidationError, normalize_dns_name
from .models import SCHEMA_VERSION

__all__ = [
    "Classification",
    "DomainScope",
    "EXCLUDED",
    "IN_SCOPE",
    "OUT_OF_SCOPE",
]

IN_SCOPE = "in_scope"
EXCLUDED = "excluded"
OUT_OF_SCOPE = "out_of_scope"

Classification = Literal["in_scope", "excluded", "out_of_scope"]


def _iter_values(values: object, label: str) -> tuple:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValidationError(
            f"{label} must be an iterable of strings, not a single string"
        )
    try:
        return tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValidationError(f"{label} must be an iterable of strings") from exc


def _as_root(value: object) -> ProjectDomain:
    if isinstance(value, ProjectDomain):
        return value
    return ProjectDomain.parse(value)  # type: ignore[arg-type]


def _normalize_roots(values: object) -> tuple[ProjectDomain, ...]:
    items = _iter_values(values, "roots")
    if not items:
        raise ValidationError(
            "scope must contain at least one authorized root domain"
        )
    unique: dict[str, ProjectDomain] = {}
    for value in items:
        root = _as_root(value)
        unique[root.name] = root
    return tuple(unique[name] for name in sorted(unique))


def _normalize_exclusions(
    values: object, roots: tuple[ProjectDomain, ...]
) -> tuple[str, ...]:
    items = _iter_values(values, "excluded_hosts")
    unique: set[str] = set()
    for value in items:
        host = normalize_dns_name(value)  # type: ignore[arg-type]
        if not any(root.contains(host) for root in roots):
            raise ValidationError(
                f"excluded host is not within any authorized root: {host}"
            )
        unique.add(host)
    return tuple(sorted(unique))


@dataclass(frozen=True)
class DomainScope:
    """Authorized root domains with exact hostname exclusions.

    Construction normalizes, validates, deduplicates, and deterministically
    orders both collections. Exclusions apply only to the exact hostname and
    must be contained by at least one authorized root.
    """

    roots: tuple[ProjectDomain, ...]
    excluded_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        roots = _normalize_roots(self.roots)
        exclusions = _normalize_exclusions(self.excluded_hosts, roots)
        object.__setattr__(self, "roots", roots)
        object.__setattr__(self, "excluded_hosts", exclusions)

    @classmethod
    def parse(
        cls,
        roots: Iterable[str | ProjectDomain],
        excluded_hosts: Iterable[str] = (),
    ) -> "DomainScope":
        """Build a scope from root domains and exact hostname exclusions."""

        return cls(roots=roots, excluded_hosts=excluded_hosts)  # type: ignore[arg-type]

    @property
    def authorized_domains(self) -> tuple[str, ...]:
        return tuple(root.name for root in self.roots)

    def _exclusion_set(self) -> frozenset[str]:
        return frozenset(self.excluded_hosts)

    def classify(
        self, host: str, root: ProjectDomain | str | None = None
    ) -> Classification:
        """Classify a candidate host as ``in_scope``, ``excluded``, or ``out_of_scope``.

        The candidate is normalized with canonical DNS validation. When *root*
        is supplied, containment is tested against that single authorized root
        only; otherwise any authorized root qualifies.
        """

        normalized = normalize_dns_name(host)
        if normalized in self._exclusion_set():
            return EXCLUDED

        if root is not None:
            root_domain = _as_root(root)
            if root_domain.name not in {candidate.name for candidate in self.roots}:
                raise ValidationError(
                    f"root is not part of this scope: {root_domain.name}"
                )
            return IN_SCOPE if root_domain.contains(normalized) else OUT_OF_SCOPE

        if any(candidate.contains(normalized) for candidate in self.roots):
            return IN_SCOPE
        return OUT_OF_SCOPE

    def contains(self, host: str, root: ProjectDomain | str | None = None) -> bool:
        """Return True when *host* is in scope (and not excluded)."""

        return self.classify(host, root) == IN_SCOPE

    def is_excluded(self, host: str) -> bool:
        """Return True when *host* is an exact excluded hostname."""

        return self.classify(host) == EXCLUDED

    def for_root(self, root: ProjectDomain | str) -> "DomainScope":
        """Return the single-root projection of this scope."""

        root_domain = _as_root(root)
        if root_domain.name not in {candidate.name for candidate in self.roots}:
            raise ValidationError(
                f"root is not part of this scope: {root_domain.name}"
            )
        exclusions = tuple(
            host for host in self.excluded_hosts if root_domain.contains(host)
        )
        return DomainScope(roots=(root_domain,), excluded_hosts=exclusions)

    def to_dict(self) -> dict:
        """Return a schema-v1 dictionary independent of file serialization."""

        return {
            "schema_version": SCHEMA_VERSION,
            "authorized_domains": list(self.authorized_domains),
            "excluded_hosts": list(self.excluded_hosts),
        }
