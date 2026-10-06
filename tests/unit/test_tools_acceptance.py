"""Unit tests for success-gated pipeline acceptance helpers."""

import unittest

from red_teaming.recon.models import (
    DiscoveryObservation,
    DnsResolution,
    ToolResult,
)
from red_teaming.tools.acceptance import (
    accepted_hosts_from_result,
    accepted_resolutions_from_result,
)


def discovered(host):
    return DiscoveryObservation(
        raw=host, source="subfinder", state="discovered", normalized=host, reason="in_scope"
    )


class AcceptedHostsTests(unittest.TestCase):
    def test_succeeded_result_promotes_discovered_hosts(self):
        result = ToolResult(
            tool="subfinder",
            status="succeeded",
            observations=[discovered("b.example.com"), discovered("a.example.com")],
        )
        self.assertEqual(
            accepted_hosts_from_result(result), ("a.example.com", "b.example.com")
        )

    def test_non_succeeded_status_promotes_nothing(self):
        for status in ["tool_not_available", "tool_failed", "timeout", "unsupported"]:
            with self.subTest(status=status):
                result = ToolResult(
                    tool="subfinder",
                    status=status,
                    observations=[discovered("a.example.com")],
                )
                self.assertEqual(accepted_hosts_from_result(result), ())

    def test_non_discovered_observations_are_not_promoted(self):
        excluded = DiscoveryObservation(
            raw="x.example.com",
            source="subfinder",
            state="excluded",
            normalized="x.example.com",
            reason="excluded",
        )
        result = ToolResult(
            tool="subfinder", status="succeeded", observations=[excluded]
        )
        self.assertEqual(accepted_hosts_from_result(result), ())

    def test_non_result_inputs_return_empty(self):
        self.assertEqual(accepted_hosts_from_result(None), ())
        self.assertEqual(accepted_hosts_from_result({"status": "succeeded"}), ())


class AcceptedResolutionsTests(unittest.TestCase):
    def test_succeeded_result_promotes_sorted_resolutions(self):
        result = ToolResult(
            tool="dnsx",
            status="succeeded",
            resolutions=[
                DnsResolution(hostname="b.example.com", status="resolved"),
                DnsResolution(hostname="a.example.com", status="unresolved"),
            ],
        )
        self.assertEqual(
            [r.hostname for r in accepted_resolutions_from_result(result)],
            ["a.example.com", "b.example.com"],
        )

    def test_non_succeeded_status_promotes_nothing(self):
        result = ToolResult(
            tool="dnsx",
            status="timeout",
            resolutions=[DnsResolution(hostname="a.example.com", status="resolved")],
        )
        self.assertEqual(accepted_resolutions_from_result(result), ())

    def test_non_result_inputs_return_empty(self):
        self.assertEqual(accepted_resolutions_from_result(None), ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
