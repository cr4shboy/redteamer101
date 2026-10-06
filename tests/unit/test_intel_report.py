"""Unit tests for deterministic report rendering (offline)."""

import json
import unittest

from red_teaming.intel import (
    KnowledgeBase,
    derive_findings,
    plan,
    render_json,
    render_markdown,
    render_sarif,
)
from red_teaming.recon.models import (
    DiscoveryObservation,
    ObservationState,
    ToolResult,
    ToolRunStatus,
)
from red_teaming.recon.scope import DomainScope


def _web_kb(scope):
    ffuf = ToolResult(
        tool="ffuf", status=ToolRunStatus.SUCCEEDED,
        observations=(
            DiscoveryObservation(
                raw="www.example.com", source="ffuf",
                state=ObservationState.DISCOVERED, normalized="www.example.com",
                reason="in_scope",
            ),
        ),
    )
    return KnowledgeBase.build(scope, {"ffuf": ffuf})


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"])
        self.kb = _web_kb(self.scope)
        self.decisions = plan(self.kb, capabilities={}, authorized=False)
        self.findings = derive_findings(self.kb)

    def test_json_report_structure(self):
        payload = json.loads(render_json(self.kb, self.decisions, self.findings))
        self.assertEqual(payload["domain"], "example.com")
        self.assertIn("facts", payload)
        self.assertIn("plan", payload)
        self.assertTrue(
            any(f["rule_id"] == "web-service-exposed" for f in payload["findings"])
        )

    def test_markdown_report_sections(self):
        md = render_markdown(self.kb, self.decisions, self.findings)
        self.assertIn("# Recon report: example.com", md)
        self.assertIn("## Plan", md)
        self.assertIn("## Findings", md)
        self.assertIn("web-service-exposed", md)

    def test_sarif_is_valid_2_1_0(self):
        doc = json.loads(render_sarif(self.findings, domain="example.com"))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "redteamer101")
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertIn("web-service-exposed", rule_ids)
        result = next(
            r for r in run["results"] if r["ruleId"] == "web-service-exposed"
        )
        self.assertEqual(result["level"], "note")  # INFO -> note
        self.assertEqual(
            result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
            "www.example.com",
        )

    def test_renderers_are_deterministic(self):
        self.assertEqual(
            render_sarif(self.findings, domain="example.com"),
            render_sarif(self.findings, domain="example.com"),
        )
        self.assertEqual(
            render_json(self.kb, self.decisions, self.findings),
            render_json(self.kb, self.decisions, self.findings),
        )

    def test_empty_findings_render_cleanly(self):
        empty = KnowledgeBase.empty("example.com")
        decisions = plan(empty, capabilities={}, authorized=False)
        self.assertIn("No findings", render_markdown(empty, decisions, ()))
        doc = json.loads(render_sarif(()))
        self.assertEqual(doc["runs"][0]["results"], [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
