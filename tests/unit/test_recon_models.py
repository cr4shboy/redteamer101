"""Unit tests for canonical recon models.

All names use reserved example domains. No test performs DNS, socket,
subprocess, or filesystem activity.
"""

import unittest

from red_teaming.projects.models import ValidationError
from red_teaming.recon.models import (
    MAX_TOOL_OUTPUT_CHARS,
    SCHEMA_VERSION,
    Asset,
    AssetKind,
    DiscoveryObservation,
    DnsRecords,
    DnsResolution,
    ResolutionStatus,
    ToolResult,
    ToolRunStatus,
)


class DnsRecordsTests(unittest.TestCase):
    def test_a_records_dedup_and_numeric_order(self):
        dns = DnsRecords(a=["192.0.2.1", "10.0.0.1", "9.0.0.1", "10.0.0.1"])
        self.assertEqual(dns.a, ("9.0.0.1", "10.0.0.1", "192.0.2.1"))

    def test_aaaa_records_dedup_and_order(self):
        dns = DnsRecords(aaaa=["2001:db8::2", "2001:db8::1", "2001:db8::1"])
        self.assertEqual(dns.aaaa, ("2001:db8::1", "2001:db8::2"))

    def test_rejects_invalid_and_wrong_family(self):
        for kwargs in [
            {"a": ["999.999.999.999"]},
            {"a": ["not-an-ip"]},
            {"a": ["2001:db8::1"]},
            {"aaaa": ["192.0.2.1"]},
            {"a": "192.0.2.1"},
            {"a": 123},
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValidationError):
                    DnsRecords(**kwargs)

    def test_cname_records_dedup_and_order(self):
        dns = DnsRecords(
            cname=["CDN.Other.Example.", "a.example", "cdn.other.example"]
        )
        self.assertEqual(dns.cname, ("a.example", "cdn.other.example"))
        self.assertTrue(dns.has_cname)

    def test_cname_default_is_empty_tuple(self):
        dns = DnsRecords()
        self.assertEqual(dns.cname, ())
        self.assertFalse(dns.has_cname)

    def test_cname_invalid_rejected(self):
        for value in ["", "*.example.com", "http://example.com", "not a host"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    DnsRecords(cname=[value])

    def test_cname_requires_iterable_not_bare_string(self):
        with self.assertRaises(ValidationError):
            DnsRecords(cname="cdn.example")

    def test_external_cname_is_data_only(self):
        # A CNAME target outside the scope must remain inert data.
        external = DnsRecords(cname=["cdn.third-party.example"]).cname
        self.assertEqual(external, ("cdn.third-party.example",))

    def test_to_dict(self):
        dns = DnsRecords(
            a=["192.0.2.1"], aaaa=["2001:db8::1"], cname=["c.example", "c.example"]
        )
        self.assertEqual(
            dns.to_dict(),
            {
                "schema_version": SCHEMA_VERSION,
                "a": ["192.0.2.1"],
                "aaaa": ["2001:db8::1"],
                "cname": ["c.example"],
            },
        )


class AssetTests(unittest.TestCase):
    def test_normalizes_hostname_sources_and_enums(self):
        asset = Asset(
            hostname="WWW.Example.COM.",
            kind="subdomain",
            sources=["z", "a", "a"],
            resolution_status="resolved",
        )
        self.assertEqual(asset.hostname, "www.example.com")
        self.assertIs(asset.kind, AssetKind.SUBDOMAIN)
        self.assertIs(asset.resolution_status, ResolutionStatus.RESOLVED)
        self.assertEqual(asset.sources, ("a", "z"))

    def test_root_kind(self):
        asset = Asset(hostname="example.com", kind="root_domain")
        self.assertIs(asset.kind, AssetKind.ROOT_DOMAIN)

    def test_rejects_invalid_hostname_and_kind(self):
        with self.assertRaises(ValidationError):
            Asset(hostname="192.0.2.1", kind="subdomain")
        with self.assertRaises(ValidationError):
            Asset(hostname="example.com", kind="bogus")

    def test_to_dict(self):
        asset = Asset(
            hostname="example.com",
            kind="root_domain",
            sources=["seed"],
            dns=DnsRecords(a=["192.0.2.1"]),
            resolution_status="resolved",
        )
        payload = asset.to_dict()
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["hostname"], "example.com")
        self.assertEqual(payload["kind"], "root_domain")
        self.assertEqual(payload["sources"], ["seed"])
        self.assertEqual(payload["resolution_status"], "resolved")
        self.assertNotIn("resolution", payload)
        self.assertEqual(payload["dns"]["a"], ["192.0.2.1"])


class DnsResolutionTests(unittest.TestCase):
    def test_normalizes_hostname_and_status(self):
        resolution = DnsResolution(
            hostname="WWW.Example.COM.",
            status="resolved",
            dns=DnsRecords(a=["192.0.2.1"]),
        )
        self.assertEqual(resolution.hostname, "www.example.com")
        self.assertIs(resolution.status, ResolutionStatus.RESOLVED)

    def test_nxdomain_status(self):
        resolution = DnsResolution(hostname="example.com", status="nxdomain")
        self.assertIs(resolution.status, ResolutionStatus.NXDOMAIN)

    def test_to_dict(self):
        resolution = DnsResolution(hostname="example.com", status="unresolved")
        self.assertEqual(
            resolution.to_dict(),
            {
                "schema_version": SCHEMA_VERSION,
                "hostname": "example.com",
                "status": "unresolved",
                "dns": {
                    "schema_version": SCHEMA_VERSION,
                    "a": [],
                    "aaaa": [],
                    "cname": [],
                },
            },
        )


class ObservationTests(unittest.TestCase):
    def test_all_states_parse(self):
        for state in ["seed", "discovered", "excluded", "out_of_scope", "rejected"]:
            with self.subTest(state=state):
                obs = DiscoveryObservation(raw="x.example", source="seed", state=state)
                self.assertEqual(obs.state.value, state)

    def test_normalized_is_optional_and_canonical(self):
        obs = DiscoveryObservation(
            raw="WWW.Example.COM.",
            source="seed",
            state="seed",
            normalized="WWW.Example.COM.",
        )
        self.assertEqual(obs.normalized, "www.example.com")

    def test_invalid_state_rejected(self):
        with self.assertRaises(ValidationError):
            DiscoveryObservation(raw="x.example", source="seed", state="bogus")

    def test_to_dict(self):
        obs = DiscoveryObservation(
            raw="x.example", source="dnsx", state="out_of_scope", reason="not in scope"
        )
        self.assertEqual(
            obs.to_dict(),
            {
                "schema_version": SCHEMA_VERSION,
                "raw": "x.example",
                "source": "dnsx",
                "state": "out_of_scope",
                "normalized": None,
                "reason": "not in scope",
            },
        )


class ToolResultTests(unittest.TestCase):
    def test_all_statuses_parse(self):
        for status in [
            "succeeded",
            "tool_not_available",
            "tool_failed",
            "timeout",
            "unsupported",
        ]:
            with self.subTest(status=status):
                result = ToolResult(tool="subfinder", status=status)
                self.assertEqual(result.status.value, status)

    def test_argv_order_preserved(self):
        result = ToolResult(
            tool="dnsx", status="succeeded", argv=["dnsx", "-a", "-resp"]
        )
        self.assertEqual(result.argv, ("dnsx", "-a", "-resp"))

    def test_bounded_output(self):
        long_output = "x" * (MAX_TOOL_OUTPUT_CHARS + 10)
        result = ToolResult(tool="subfinder", status="tool_failed", stdout=long_output)
        self.assertEqual(len(result.stdout), MAX_TOOL_OUTPUT_CHARS)
        self.assertTrue(result.stdout_truncated)
        self.assertFalse(result.stderr_truncated)

    def test_rejects_bad_exit_code(self):
        with self.assertRaises(ValidationError):
            ToolResult(tool="subfinder", status="tool_failed", exit_code=True)

    def test_success_property(self):
        self.assertTrue(ToolResult(tool="subfinder", status="succeeded").succeeded)
        self.assertFalse(
            ToolResult(tool="subfinder", status="tool_not_available").succeeded
        )

    def test_no_secret_fields(self):
        payload = ToolResult(tool="subfinder", status="succeeded").to_dict()
        self.assertNotIn("secret", payload)
        self.assertNotIn("api_key", payload)

    def test_to_dict_includes_observations_and_errors(self):
        obs = DiscoveryObservation(
            raw="x.example", source="subfinder", state="discovered"
        )
        result = ToolResult(
            tool="subfinder",
            status="succeeded",
            observations=[obs],
            errors=["boom"],
        )
        payload = result.to_dict()
        self.assertEqual(payload["observations"][0]["raw"], "x.example")
        self.assertEqual(payload["resolutions"], [])
        self.assertEqual(payload["errors"], ["boom"])
        self.assertEqual(payload["status"], ToolRunStatus.SUCCEEDED.value)

    def test_timeout_is_recorded(self):
        result = ToolResult(tool="subfinder", status="succeeded", timeout=5)
        self.assertEqual(result.timeout, 5.0)
        self.assertEqual(result.to_dict()["timeout"], 5.0)

    def test_rejects_bad_timeout(self):
        for bad in [0, -1, True, "5"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    ToolResult(tool="subfinder", status="succeeded", timeout=bad)

    def test_carries_dns_resolutions(self):
        resolution = DnsResolution(hostname="example.com", status="resolved")
        result = ToolResult(
            tool="dnsx", status="succeeded", resolutions=[resolution]
        )
        self.assertEqual(result.resolutions, (resolution,))
        self.assertEqual(
            result.to_dict()["resolutions"][0]["hostname"], "example.com"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
