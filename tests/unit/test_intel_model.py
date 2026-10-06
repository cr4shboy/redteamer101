"""Unit tests for the intel knowledge base and web derivation (offline)."""

import unittest

from red_teaming.intel import KnowledgeBase, WebService, derive_web_services
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


def discovered(host, source):
    return DiscoveryObservation(
        raw=host, source=source, state=ObservationState.DISCOVERED,
        normalized=host, reason="in_scope",
    )


def amass_result(*hosts):
    return ToolResult(
        tool="amass",
        status=ToolRunStatus.SUCCEEDED,
        observations=tuple(discovered(h, "amass") for h in hosts),
    )


def ffuf_result(*hosts):
    return ToolResult(
        tool="ffuf",
        status=ToolRunStatus.SUCCEEDED,
        observations=tuple(discovered(h, "ffuf") for h in hosts),
    )


def dnsx_result(host, a):
    return ToolResult(
        tool="dnsx",
        status=ToolRunStatus.SUCCEEDED,
        resolutions=(
            DnsResolution(
                hostname=host, status=ResolutionStatus.RESOLVED, dns=DnsRecords(a=a)
            ),
        ),
    )


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"])

    def test_empty(self):
        kb = KnowledgeBase.empty("example.com")
        self.assertEqual(kb.assets, ())
        self.assertEqual(kb.web, ())
        self.assertEqual(kb.web_hosts(), ())

    def test_build_merges_sources_dns_and_web(self):
        results = {
            "amass": amass_result("a.example.com"),
            "ffuf": ffuf_result("www.example.com"),
            "dnsx": dnsx_result("www.example.com", ("192.0.2.1",)),
        }
        kb = KnowledgeBase.build(self.scope, results)
        hostnames = set(kb.hostnames)
        # Root seed plus both discovered hosts become canonical assets.
        self.assertIn("example.com", hostnames)
        self.assertIn("a.example.com", hostnames)
        self.assertIn("www.example.com", hostnames)
        # dnsx resolution is applied to the matching candidate.
        self.assertIn("www.example.com", kb.web_hosts())
        resolvable = {a.hostname for a in kb.resolvable_assets()}
        self.assertIn("www.example.com", resolvable)

    def test_web_only_from_ffuf_not_amass(self):
        results = {
            "amass": amass_result("passive.example.com"),
            "ffuf": ffuf_result("live.example.com"),
        }
        kb = KnowledgeBase.build(self.scope, results)
        self.assertEqual(kb.web_hosts(), ("live.example.com",))

    def test_failed_tool_contributes_no_hosts(self):
        failed = ToolResult(
            tool="ffuf",
            status=ToolRunStatus.TOOL_FAILED,
            observations=(discovered("nope.example.com", "ffuf"),),
        )
        self.assertEqual(derive_web_services({"ffuf": failed}), ())

    def test_derive_web_services_is_sorted_and_deduped(self):
        services = derive_web_services(
            {"ffuf": ffuf_result("b.example.com", "a.example.com", "a.example.com")}
        )
        self.assertEqual([s.host for s in services], ["a.example.com", "b.example.com"])
        self.assertTrue(all(isinstance(s, WebService) and s.alive for s in services))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
