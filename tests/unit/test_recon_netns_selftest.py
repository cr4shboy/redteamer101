"""Tests for the local-only namespace self-test harness.

On non-Linux platforms the self-test must fail closed with an *unsupported*
report and do nothing. On Linux/WSL it runs the full local-only namespace
self-test (no external host is ever contacted).
"""

import sys
import unittest

from red_teaming.recon.netns_selftest import SelfTestReport, run_self_test


class ReportShapeTests(unittest.TestCase):
    def test_to_dict(self):
        report = SelfTestReport(supported=False, passed=False, reason="x", checks={"a": 1})
        document = report.to_dict()
        self.assertEqual(document["supported"], False)
        self.assertEqual(document["passed"], False)
        self.assertEqual(document["reason"], "x")
        self.assertEqual(document["checks"], {"a": 1})
        self.assertEqual(document["broker"], {})


class UnsupportedPlatformTests(unittest.TestCase):
    @unittest.skipIf(sys.platform.startswith("linux"), "Linux host")
    def test_fails_closed_off_linux(self):
        report = run_self_test()
        self.assertFalse(report.supported)
        self.assertFalse(report.passed)
        self.assertEqual(report.reason, "unsupported_platform")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux/WSL only")
class NamespaceSelfTestTests(unittest.TestCase):
    def test_local_only_namespace_self_test_passes(self):
        report = run_self_test(deadline=45.0)
        self.assertTrue(report.supported, report.to_dict())
        self.assertIsNone(report.reason, report.to_dict())
        self.assertTrue(report.checks.get("route_isolated"), report.to_dict())
        self.assertTrue(report.checks.get("direct_tcp_blocked"), report.to_dict())
        self.assertTrue(report.checks.get("direct_udp_blocked"), report.to_dict())
        self.assertTrue(report.checks.get("connect_denied"), report.to_dict())
        self.assertTrue(report.checks.get("connect_allowed"), report.to_dict())
        self.assertTrue(report.checks.get("dns_allowed_udp"), report.to_dict())
        self.assertTrue(report.checks.get("dns_allowed_tcp"), report.to_dict())
        self.assertTrue(report.checks.get("dns_denied"), report.to_dict())
        # The denied CONNECT must never reach the broker; only the allowed DNS
        # queries may count as upstream calls.
        self.assertEqual(report.broker.get("connect_requests"), 1, report.to_dict())
        self.assertEqual(report.broker.get("upstream_calls"), 2, report.to_dict())
        self.assertEqual(report.broker.get("denied_dns"), 1, report.to_dict())
        self.assertTrue(report.passed, report.to_dict())


if __name__ == "__main__":
    unittest.main()
