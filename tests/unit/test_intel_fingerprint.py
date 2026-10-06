"""Offline WSTG-INFO-02A facts and integration, using synthetic headers only."""

import json
import unittest
from dataclasses import FrozenInstanceError

from red_teaming.intel import (
    KnowledgeBase,
    Orchestrator,
    WebServerFingerprint,
    fingerprint_server_header,
    plan,
    render_json,
    render_markdown,
    render_sarif,
)
from red_teaming.projects.models import ValidationError
from red_teaming.recon.models import ToolResult, ToolRunStatus
from red_teaming.recon.scope import DomainScope


def observation(host="www.example.com", source_id="response-1", header="Apache/2.4.41 (Unix)"):
    return fingerprint_server_header(
        host=host,
        scheme="https",
        port=443,
        source_id=source_id,
        server_header=header,
    )


class FingerprintParsingTests(unittest.TestCase):
    def test_reported_banner_is_a_claim_and_raw_header_is_not_retained(self):
        item = observation()
        self.assertEqual(item.status, "reported")
        self.assertEqual(item.claimed_product, "Apache")
        self.assertEqual(item.claimed_version, "2.4.41")
        self.assertEqual(item.host, "www.example.com")
        self.assertNotIn("Unix", repr(item))
        self.assertNotIn("Unix", json.dumps(item.to_dict()))
        with self.assertRaises(FrozenInstanceError):
            item.status = "unknown"

    def test_absent_or_malformed_banner_is_unknown(self):
        for header in (None, "", " Apache/2.4.41", "Apache/2.4.41\r\nSet-Cookie: x", "A" * 257):
            with self.subTest(header=header):
                item = observation(header=header)
                self.assertEqual(item.status, "unknown")
                self.assertIsNone(item.claimed_product)
                self.assertIsNone(item.claimed_version)

    def test_unrecognized_product_is_only_reported_not_verified(self):
        item = observation(header="Website.com")
        self.assertEqual(item.status, "reported")
        self.assertEqual(item.claimed_product, "Website.com")
        self.assertIsNone(item.claimed_version)

    def test_invalid_contract_values_are_rejected(self):
        with self.assertRaises(ValidationError):
            observation(source_id="../outside")
        with self.assertRaises(ValidationError):
            fingerprint_server_header(
                host="example.com", scheme="ftp", port=21,
                source_id="response-1", server_header="nginx/1.2",
            )
        with self.assertRaises(ValidationError):
            fingerprint_server_header(
                host="example.com", scheme="https", port=443,
                source_id="response-1", server_header=123,
            )
        with self.assertRaises(ValidationError):
            WebServerFingerprint(
                host="example.com", scheme="https", port=443,
                source_id="response-1", status="unknown", claimed_product="nginx",
            )


class FingerprintIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])

    def test_build_is_sorted_idempotent_and_does_not_discover_a_host(self):
        second = observation(host="b.example.com", source_id="response-2", header="nginx/1.25")
        first = observation(host="a.example.com", source_id="response-1")
        kb = KnowledgeBase.build(self.scope, {}, fingerprints=(second, first, first))
        self.assertEqual(kb.fingerprints, (first, second))
        self.assertNotIn("a.example.com", kb.hostnames)
        self.assertNotIn("a.example.com", kb.web_hosts())
        self.assertEqual(kb.to_dict()["fingerprints"][0]["source_id"], "response-1")
        self.assertEqual(kb.fingerprints, KnowledgeBase.build(
            self.scope, {}, fingerprints=(first, second)
        ).fingerprints)

    def test_scope_exclusions_and_conflicting_duplicates_fail_closed(self):
        for host in ("other.example.org", "excluded.example.com"):
            with self.subTest(host=host), self.assertRaises(ValidationError):
                KnowledgeBase.build(self.scope, {}, fingerprints=(observation(host=host),))
        with self.assertRaises(ValidationError):
            KnowledgeBase.build(self.scope, {}, fingerprints=(
                observation(header="Apache/2.4.41"), observation(header="nginx/1.25"),
            ))
        with self.assertRaises(ValidationError):
            KnowledgeBase(
                domain="example.com",
                fingerprints=(observation(host="outside.example.org"),),
            )

    def test_direct_knowledge_construction_canonicalizes_facts(self):
        second = observation(host="b.example.com", source_id="response-2", header=None)
        first = observation(host="a.example.com", source_id="response-1")
        kb = KnowledgeBase(domain="example.com", fingerprints=[second, first, first])
        self.assertEqual(kb.fingerprints, (first, second))
        with self.assertRaises(ValidationError):
            KnowledgeBase(domain="example.com", fingerprints=[
                first, observation(host="a.example.com", source_id="response-1", header="nginx"),
            ])

    def test_orchestrator_and_reports_keep_fact_separate_from_findings(self):
        item = observation()
        report = Orchestrator(
            self.scope, runners={}, capabilities={}, fingerprints=(item,),
        ).run()
        self.assertEqual(report.knowledge.fingerprints, (item,))
        self.assertEqual(report.steps, ())
        self.assertEqual(report.findings, ())
        decisions = plan(report.knowledge, capabilities={}, authorized=False)
        json_text = render_json(report.knowledge, decisions, report.findings)
        markdown = render_markdown(report.knowledge, decisions, report.findings)
        self.assertEqual(json.loads(json_text)["fingerprints"], [item.to_dict()])
        self.assertIn("## Web server fingerprints", markdown)
        self.assertIn("Apache", markdown)
        self.assertEqual(json_text, render_json(report.knowledge, decisions, report.findings))
        self.assertEqual(json.loads(render_sarif(report.findings))["runs"][0]["results"], [])

    def test_orchestrator_preserves_fact_after_a_tool_result(self):
        item = observation()
        report = Orchestrator(
            self.scope,
            runners={"passive_subdomains": lambda kb: ToolResult(
                tool="amass", status=ToolRunStatus.SUCCEEDED,
            )},
            fingerprints=(item,),
        ).run()
        self.assertEqual(report.knowledge.fingerprints, (item,))
        self.assertEqual(len(report.steps), 1)

    def test_invalid_fingerprints_are_rejected_before_runner_execution(self):
        calls = []
        with self.assertRaises(ValidationError):
            Orchestrator(
                self.scope,
                runners={"passive_subdomains": lambda kb: calls.append(kb)},
                fingerprints=(observation(host="outside.example.org"),),
            )
        self.assertEqual(calls, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
