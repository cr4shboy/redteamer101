"""Immutable RECON-002 network policy for the egress/sandbox layer.

This module is the single source of truth for the two and only two egress paths
authorized by ``CURRENT_TASK.md``:

1. HTTPS to the Certificate Transparency source ``crt.sh`` on TCP port 443; and
2. DNS to Cloudflare resolver ``1.1.1.1`` on port 53 (UDP with a bounded TCP
   fallback), used to resolve ``crt.sh`` for the broker and to query A/AAAA/CNAME
   for the authorized root domain ``acme.example`` and its normalized
   subdomains only.

Everything here is pure data and pure validation: no sockets, no DNS, no
subprocess, no filesystem access. Importing this module performs no I/O.

The policy deliberately separates three namespaces so they can never be
confused:

* the *target* root (``acme.example`` and its subdomains), queryable only
  for A/AAAA/CNAME and never contacted over HTTP/HTTPS;
* the *CT source* (``crt.sh``), resolvable only for A/AAAA bootstrap by the
  outer broker and reachable only through the loopback enforcing proxy; and
* the *upstream resolver* (``1.1.1.1``), used by the broker only.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Final

from ..projects.models import ValidationError, normalize_dns_name

__all__ = [
    "DNS_MAX_CONCURRENT",
    "DNS_PROTO_TCP",
    "DNS_PROTO_UDP",
    "DNS_QPS",
    "DNS_SCOPE_BOOTSTRAP",
    "DNS_SCOPE_TARGET",
    "DNS_TYPE_A",
    "DNS_TYPE_AAAA",
    "DNS_TYPE_CNAME",
    "DNS_TYPE_NAMES",
    "HTTPS_HOST",
    "HTTPS_PORT",
    "MAX_DNS_MESSAGE",
    "MAX_IPC_FRAME",
    "RECON_002_POLICY",
    "ROOT_DOMAIN",
    "UPSTREAM_DNS_HOST",
    "UPSTREAM_DNS_PORT",
    "PolicyError",
    "ReconNetworkPolicy",
    "describe_dns_type",
    "is_global_literal",
    "normalize_policy_name",
    "validate_upstream_ip",
]

# ---------------------------------------------------------------------------
# Canonical RECON-002 constants (CURRENT_TASK.md)
# ---------------------------------------------------------------------------

#: Authorized root domain. The root itself and normalized subdomains only.
ROOT_DOMAIN: Final[str] = "acme.example"

#: The only permitted HTTPS authority (passive Certificate Transparency source).
HTTPS_HOST: Final[str] = "crt.sh"
HTTPS_PORT: Final[int] = 443

#: The only permitted upstream DNS resolver endpoint.
UPSTREAM_DNS_HOST: Final[str] = "1.1.1.1"
UPSTREAM_DNS_PORT: Final[int] = 53

#: DNS broker rate/concurrency bounds (dnsx: 5 qps, 2 threads).
DNS_QPS: Final[int] = 5
DNS_MAX_CONCURRENT: Final[int] = 2

#: Bounded protocol sizes.
MAX_IPC_FRAME: Final[int] = 8192
MAX_DNS_MESSAGE: Final[int] = 4096

#: Bounded socket/operation timeouts (seconds).
DNS_UDP_TIMEOUT: Final[float] = 5.0
DNS_TCP_TIMEOUT: Final[float] = 5.0
CONNECT_TIMEOUT: Final[float] = 10.0
IPC_POLL_INTERVAL: Final[float] = 0.2
RELAY_IDLE_TIMEOUT: Final[float] = 30.0
RELAY_MAX_SECONDS: Final[float] = 300.0

#: DNS record type numbers (RFC 1035 / RFC 3596).
DNS_TYPE_A: Final[int] = 1
DNS_TYPE_CNAME: Final[int] = 5
DNS_TYPE_AAAA: Final[int] = 28

DNS_TYPE_NAMES: Final[dict[int, str]] = {
    DNS_TYPE_A: "A",
    DNS_TYPE_CNAME: "CNAME",
    DNS_TYPE_AAAA: "AAAA",
}

#: DNS transport tags used by the loopback relay / broker IPC frames.
DNS_PROTO_UDP: Final[int] = 0
DNS_PROTO_TCP: Final[int] = 1

#: Policy classification of an allowed DNS question.
DNS_SCOPE_TARGET: Final[str] = "target"
DNS_SCOPE_BOOTSTRAP: Final[str] = "bootstrap"


class PolicyError(ValueError):
    """Raised when a value would violate the RECON-002 network policy."""


def describe_dns_type(qtype: object) -> str:
    """Return the canonical textual form of a DNS record type number."""

    if isinstance(qtype, bool) or not isinstance(qtype, int):
        return f"TYPE{int(qtype) if isinstance(qtype, (int, float)) else 0}"
    return DNS_TYPE_NAMES.get(qtype, f"TYPE{qtype}")


def normalize_policy_name(value: object) -> str:
    """Normalize a DNS name with the project's canonical normalizer.

    Raises :class:`PolicyError` (never the underlying ``ValidationError``) so
    policy enforcement points can fail closed with a stable error type.
    """

    try:
        return normalize_dns_name(value)  # type: ignore[arg-type]
    except ValidationError as exc:
        raise PolicyError("malformed DNS name") from exc


def is_global_literal(ip: object) -> bool:
    """Return True when *ip* is a global-unicast IP literal.

    Loopback, private, link-local, multicast, unspecified, reserved, and
    IPv4-mapped addresses are all rejected so a resolver answer can never point
    the broker at a local or non-routable destination.
    """

    if not isinstance(ip, str) or not ip or ip != ip.strip():
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        return False
    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
    )


def validate_upstream_ip(ip: object) -> str:
    """Return the canonical text of a permitted upstream IP literal.

    Raises :class:`PolicyError` for anything that is not a global-unicast IP
    literal. Used to validate every resolver answer before a socket is created.
    """

    if not is_global_literal(ip):
        raise PolicyError("resolver answer is not a global unicast IP literal")
    return str(ipaddress.ip_address(ip))  # type: ignore[arg-type]


def _is_root_or_subdomain(name: str, root: str) -> bool:
    return name == root or name.endswith("." + root)


@dataclass(frozen=True)
class ReconNetworkPolicy:
    """Immutable RECON-002 policy configuration.

    The defaults are the only authorized values for the live run. The type is a
    frozen dataclass so later adapter integration can inject a narrowed policy
    (for example a different root in a different domain package) without editing
    enforcement code, while still failing closed on invalid configuration.
    """

    root_domain: str = ROOT_DOMAIN
    https_host: str = HTTPS_HOST
    https_port: int = HTTPS_PORT
    upstream_dns_host: str = UPSTREAM_DNS_HOST
    upstream_dns_port: int = UPSTREAM_DNS_PORT
    dns_qps: int = DNS_QPS
    dns_max_concurrent: int = DNS_MAX_CONCURRENT
    dns_udp_timeout: float = DNS_UDP_TIMEOUT
    dns_tcp_timeout: float = DNS_TCP_TIMEOUT
    connect_timeout: float = CONNECT_TIMEOUT
    max_ipc_frame: int = MAX_IPC_FRAME
    max_dns_message: int = MAX_DNS_MESSAGE
    ipc_poll_interval: float = IPC_POLL_INTERVAL
    relay_idle_timeout: float = RELAY_IDLE_TIMEOUT
    relay_max_seconds: float = RELAY_MAX_SECONDS

    def __post_init__(self) -> None:
        root = normalize_policy_name(self.root_domain)
        https = normalize_policy_name(self.https_host)
        object.__setattr__(self, "root_domain", root)
        object.__setattr__(self, "https_host", https)

        try:
            upstream = ipaddress.ip_address(self.upstream_dns_host)
        except ValueError as exc:
            raise PolicyError("upstream DNS host must be an IP literal") from exc
        if not is_global_literal(str(upstream)):
            raise PolicyError("upstream DNS host must be a global unicast literal")
        object.__setattr__(self, "upstream_dns_host", str(upstream))

        for name, value, low, high in (
            ("https_port", self.https_port, 1, 65535),
            ("upstream_dns_port", self.upstream_dns_port, 1, 65535),
            ("dns_qps", self.dns_qps, 1, 10_000),
            ("dns_max_concurrent", self.dns_max_concurrent, 1, 1024),
            ("max_ipc_frame", self.max_ipc_frame, 512, 1_048_576),
            ("max_dns_message", self.max_dns_message, 512, 65_535),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise PolicyError(f"{name} must be an integer")
            if not low <= value <= high:
                raise PolicyError(f"{name} is out of range")

        for name, value in (
            ("dns_udp_timeout", self.dns_udp_timeout),
            ("dns_tcp_timeout", self.dns_tcp_timeout),
            ("connect_timeout", self.connect_timeout),
            ("ipc_poll_interval", self.ipc_poll_interval),
            ("relay_idle_timeout", self.relay_idle_timeout),
            ("relay_max_seconds", self.relay_max_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not float(value) > 0
                or float(value) != float(value)
                or float(value) in (float("inf"), float("-inf"))
            ):
                raise PolicyError(f"{name} must be a positive finite number")
            object.__setattr__(self, name, float(value))

        if self.max_dns_message > self.max_ipc_frame:
            raise PolicyError("max_dns_message must not exceed max_ipc_frame")

    # -- name classification ------------------------------------------------

    def is_target_name(self, name: object) -> bool:
        """Return True when *name* is the root or one of its subdomains."""

        try:
            canon = normalize_policy_name(name)
        except PolicyError:
            return False
        return _is_root_or_subdomain(canon, self.root_domain)

    def is_bootstrap_name(self, name: object) -> bool:
        """Return True only for the exact CT source host ``crt.sh``."""

        try:
            canon = normalize_policy_name(name)
        except PolicyError:
            return False
        return canon == self.https_host

    def classify_dns_question(self, name: object, qtype: object) -> str | None:
        """Return ``"target"``, ``"bootstrap"``, or ``None`` when disallowed.

        Target questions allow A/AAAA/CNAME. Bootstrap questions allow only
        A/AAAA for the exact ``crt.sh`` host.
        """

        if isinstance(qtype, bool) or not isinstance(qtype, int):
            return None
        try:
            canon = normalize_policy_name(name)
        except PolicyError:
            return None
        if _is_root_or_subdomain(canon, self.root_domain):
            if qtype in (DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME):
                return DNS_SCOPE_TARGET
            return None
        if canon == self.https_host:
            if qtype in (DNS_TYPE_A, DNS_TYPE_AAAA):
                return DNS_SCOPE_BOOTSTRAP
            return None
        return None

    # -- authority / destination classification -----------------------------

    def is_allowed_connect_authority(self, host: object, port: object) -> bool:
        """Return True only for the exact literal authority ``crt.sh:443``."""

        if isinstance(port, bool) or not isinstance(port, int):
            return False
        if port != self.https_port:
            return False
        try:
            canon = normalize_policy_name(host)
        except PolicyError:
            return False
        return canon == self.https_host

    def is_allowed_upstream_endpoint(self, host: object, port: object) -> bool:
        """Return True only for the exact upstream DNS endpoint ``1.1.1.1:53``."""

        if isinstance(port, bool) or not isinstance(port, int):
            return False
        if port != self.upstream_dns_port:
            return False
        return host == self.upstream_dns_host

    def validate_target_address(self, ip: object) -> str:
        """Validate a resolved target IP; return its canonical literal text."""

        return validate_upstream_ip(ip)


#: The single canonical RECON-002 policy instance.
RECON_002_POLICY: Final[ReconNetworkPolicy] = ReconNetworkPolicy()
