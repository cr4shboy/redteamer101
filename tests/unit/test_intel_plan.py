"""Unit tests for the fact-driven recon planner (offline).

The central property: a web-only stage (ZAP spider) can never be eligible while
no live web service is known -- even if its capability is available and the run
is authorized.
"""

import unittest

from red_teaming.intel import (
    STATUS_AWAITING_AUTHORIZATION,
    STATUS_BLOCKED,
    STATUS_ELIGIBLE,
    STATUS_NEEDS_BUILD,
    KnowledgeBase,
    eligible_stages,
    load_capability_statuses,
    plan,
)
from red_teaming.recon.models import (
    DiscoveryObservation,
    ObservationState,
    ToolResult,
    ToolRunStatus,
)
from red_teaming.recon.scope import DomainScope

CAPS_MISSING = {
    "fingerprint_web_server": "missing", "zap_spider": "missing", "nuclei_scan": "missing",
}
CAPS_ZAP_AVAILABLE = {
    "fingerprint_web_server": "missing", "zap_spider": "available", "nuclei_scan": "missing",
}


def web_kb(scope):
    ffuf = ToolResult(
        tool="ffuf",
        status=ToolRunStatus.SUCCEEDED,
        observations=(
            DiscoveryObservation(
                raw="www.example.com", source="ffuf",
                state=ObservationState.DISCOVERED, normalized="www.example.com",
                reason="in_scope",
            ),
        ),
    )
    return KnowledgeBase.build(scope, {"ffuf": ffuf})


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"])
        self.empty = KnowledgeBase.empty("example.com")

    def by_stage(self, decisions):
        return {d.stage: d for d in decisions}

    def test_from_scratch_only_passive_is_eligible(self):
        decisions = plan(self.empty, capabilities=CAPS_MISSING, authorized=False)
        by = self.by_stage(decisions)
        self.assertEqual(by["passive_subdomains"].status, STATUS_ELIGIBLE)
        self.assertEqual(by["resolve"].status, STATUS_BLOCKED)
        self.assertEqual(by["resolve"].reason, "no_hosts_to_resolve")
        self.assertEqual(
            by["active_subdomains"].status, STATUS_AWAITING_AUTHORIZATION
        )
        self.assertEqual(eligible_stages(decisions), ("passive_subdomains",))

    def test_no_web_blocks_zap_even_if_available_and_authorized(self):
        decisions = plan(
            self.empty, capabilities=CAPS_ZAP_AVAILABLE, authorized=True
        )
        zap = self.by_stage(decisions)["zap_spider"]
        self.assertEqual(zap.status, STATUS_BLOCKED)
        self.assertEqual(zap.reason, "no_web_services")
        self.assertNotIn("zap_spider", eligible_stages(decisions))

    def test_fingerprint_stage_requires_web_and_a_real_capability(self):
        caps = {**CAPS_MISSING, "fingerprint_web_server": "available"}
        for authorized in (False, True):
            stage = self.by_stage(plan(
                self.empty, capabilities=caps, authorized=authorized,
            ))["fingerprint_web_server"]
            self.assertEqual(stage.status, STATUS_BLOCKED)
            self.assertEqual(stage.reason, "no_web_services")
        stage = self.by_stage(plan(
            web_kb(self.scope), capabilities=CAPS_MISSING, authorized=False,
        ))["fingerprint_web_server"]
        self.assertEqual(stage.status, STATUS_NEEDS_BUILD)
        self.assertEqual(stage.reason, "capability_missing")
        stage = self.by_stage(plan(
            web_kb(self.scope), capabilities=caps, authorized=False,
        ))["fingerprint_web_server"]
        self.assertEqual(stage.status, STATUS_AWAITING_AUTHORIZATION)
        self.assertEqual(stage.reason, "requires_authorized_live_run")
        stage = self.by_stage(plan(
            web_kb(self.scope), capabilities=caps, authorized=True,
        ))["fingerprint_web_server"]
        self.assertEqual(stage.status, STATUS_ELIGIBLE)

    def test_default_registry_keeps_unwired_fingerprint_stage_missing(self):
        self.assertEqual(load_capability_statuses()["fingerprint_web_server"], "missing")
        stage = self.by_stage(plan(web_kb(self.scope)))["fingerprint_web_server"]
        self.assertEqual(stage.status, STATUS_NEEDS_BUILD)
        self.assertEqual(stage.reason, "capability_missing")

    def test_web_present_zap_needs_build_when_capability_missing(self):
        decisions = plan(web_kb(self.scope), capabilities=CAPS_MISSING, authorized=True)
        zap = self.by_stage(decisions)["zap_spider"]
        self.assertEqual(zap.status, STATUS_NEEDS_BUILD)
        self.assertEqual(zap.reason, "capability_missing")

    def test_web_present_zap_eligible_when_available_and_authorized(self):
        decisions = plan(
            web_kb(self.scope), capabilities=CAPS_ZAP_AVAILABLE, authorized=True
        )
        by = self.by_stage(decisions)
        self.assertEqual(by["zap_spider"].status, STATUS_ELIGIBLE)
        self.assertEqual(by["nuclei_scan"].status, STATUS_NEEDS_BUILD)

    def test_active_requires_authorization(self):
        decisions = plan(self.empty, capabilities=CAPS_MISSING, authorized=False)
        self.assertEqual(
            self.by_stage(decisions)["active_subdomains"].status,
            STATUS_AWAITING_AUTHORIZATION,
        )
        authorized = plan(self.empty, capabilities=CAPS_MISSING, authorized=True)
        self.assertEqual(
            self.by_stage(authorized)["active_subdomains"].status, STATUS_ELIGIBLE
        )

    def test_plan_is_deterministic(self):
        a = plan(self.empty, capabilities=CAPS_MISSING, authorized=False)
        b = plan(self.empty, capabilities=CAPS_MISSING, authorized=False)
        self.assertEqual([d.to_dict() for d in a], [d.to_dict() for d in b])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
