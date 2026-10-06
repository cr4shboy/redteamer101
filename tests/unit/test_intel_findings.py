"""Unit tests for deterministic finding derivation (offline)."""

import unittest

from red_teaming.intel import KnowledgeBase, Severity, derive_findings
from red_teaming.recon.models import (
    DiscoveryObservation,
    DnsRecords,
    DnsResolution,
    ObservationState,
    ResolutionStatus,
    ToolResult,
    ToolRunStatus,
)
from red_teaming.recon.scope import DomainScope


def _discovered(host, source):
    return DiscoveryObservation(
        raw=host, source=source, state=ObservationState.DISCOVERED,
        normalized=host, reason="in_scope",
    )


def _ffuf(*hosts):
    return ToolResult(
        tool="ffuf", status=ToolRunStatus.SUCCEEDED,
        observations=tuple(_discovered(h, "ffuf") for h in hosts),
    )


def _amass(*hosts):
    return ToolResult(
        tool="amass", status=ToolRunStatus.SUCCEEDED,
        observations=tuple(_discovered(h, "amass") for h in hosts),
    )


def _dnsx(host, a):
    return ToolResult(
        tool="dnsx", status=ToolRunStatus.SUCCEEDED,
        resolutions=(
            DnsResolution(hostname=host, status=ResolutionStatus.RESOLVED,
                          dns=DnsRecords(a=a)),
        ),
    )


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"])

    def test_empty_kb_has_no_findings(self):
        self.assertEqual(derive_findings(KnowledgeBase.empty("example.com")), ())

    def test_web_service_exposed_finding(self):
        kb = KnowledgeBase.build(self.scope, {"ffuf": _ffuf("www.example.com")})
        findings = derive_findings(kb)
        web = [f for f in findings if f.rule_id == "web-service-exposed"]
        self.assertEqual(len(web), 1)
        self.assertEqual(web[0].host, "www.example.com")
        self.assertEqual(web[0].severity, Severity.INFO)
        self.assertEqual(web[0].category, "surface")

    def test_unresolved_host_finding(self):
        kb = KnowledgeBase.build(self.scope, {"amass": _amass("a.example.com")})
        rule_hosts = {
            (f.rule_id, f.host) for f in derive_findings(kb)
        }
        # Root and the discovered host both lack A/AAAA -> unresolved findings.
        self.assertIn(("host-unresolved", "a.example.com"), rule_hosts)
        self.assertIn(("host-unresolved", "example.com"), rule_hosts)

    def test_resolved_host_has_no_unresolved_finding(self):
        kb = KnowledgeBase.build(
            self.scope,
            {"amass": _amass("a.example.com"), "dnsx": _dnsx("a.example.com", ("192.0.2.1",))},
        )
        unresolved = {
            f.host for f in derive_findings(kb) if f.rule_id == "host-unresolved"
        }
        self.assertNotIn("a.example.com", unresolved)

    def test_findings_are_deterministic_and_sorted(self):
        kb = KnowledgeBase.build(
            self.scope, {"ffuf": _ffuf("b.example.com", "a.example.com")}
        )
        a = derive_findings(kb)
        b = derive_findings(kb)
        self.assertEqual([f.to_dict() for f in a], [f.to_dict() for f in b])
        # Most-severe first; equal severity stable by rule then host.
        ranks = [f.severity.rank for f in a]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
