"""Unit tests for deterministic per-root aggregation (offline)."""

import unittest

from red_teaming.recon.aggregate import (
    SEED_SOURCE,
    AggregateError,
    DiscoveryAggregate,
    aggregate_discovery,
    build_assets,
    seed_observation,
)
from red_teaming.recon.models import AssetKind, ObservationState, ResolutionStatus
from red_teaming.recon.scope import DomainScope
from tests.unit.recon_fakes import amass_result, dnsx_result, missing, subfinder_result


class AggregateExampleTests(unittest.TestCase):
    """The documented RECON-001 aggregation example."""

    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])
        self.subfinder = subfinder_result(
            self.scope,
            [
                {"host": "www.example.com"},
                {"host": "api.example.com"},
                {"host": "excluded.example.com"},
                {"host": "external.example.net"},
            ],
        )
        self.amass = amass_result(
            self.scope,
            [
                {"name": "api.example.com", "sources": ["crtsh"]},
                {"name": "mail.example.com"},
                {"name": "external.example.net"},
            ],
        )
        self.aggregate = aggregate_discovery(
            self.scope, {"subfinder": self.subfinder, "amass": self.amass}
        )

    def test_candidates_are_seed_plus_in_scope_hosts(self):
        self.assertEqual(
            self.aggregate.candidates,
            (
                "api.example.com",
                "example.com",
                "mail.example.com",
                "www.example.com",
            ),
        )

    def test_seed_observation(self):
        observation = seed_observation(self.scope)
        self.assertEqual(observation.source, SEED_SOURCE)
        self.assertEqual(observation.state, ObservationState.SEED)
        self.assertEqual(observation.normalized, "example.com")

    def test_tool_level_provenance_is_sorted(self):
        self.assertEqual(
            dict(self.aggregate.provenance),
            {
                "api.example.com": ("amass", "subfinder"),
                "example.com": ("scope",),
                "mail.example.com": ("amass",),
                "www.example.com": ("subfinder",),
            },
        )

    def test_excluded_and_out_of_scope_retained_but_not_candidates(self):
        states = {o.normalized: o.state for o in self.aggregate.observations}
        self.assertEqual(
            states.get("excluded.example.com"), ObservationState.EXCLUDED
        )
        self.assertEqual(
            states.get("external.example.net"), ObservationState.OUT_OF_SCOPE
        )
        self.assertNotIn("excluded.example.com", self.aggregate.candidates)
        self.assertNotIn("external.example.net", self.aggregate.candidates)

    def test_build_assets_applies_successful_dns_and_keeps_external_cname(self):
        dns_result = dnsx_result(
            self.scope,
            [
                {
                    "host": "api.example.com",
                    "a": ["192.0.2.1"],
                    "cname": ["cdn.third.example"],
                    "status_code": "NOERROR",
                },
                {"host": "example.com", "a": ["192.0.2.10"], "status_code": "NOERROR"},
                {"host": "mail.example.com", "a": ["192.0.2.20"], "status_code": "NOERROR"},
                {"host": "www.example.com", "a": ["192.0.2.30"], "status_code": "NOERROR"},
                {"host": "external.example.net", "a": ["203.0.113.1"], "status_code": "NOERROR"},
            ],
        )
        assets = build_assets(self.scope, self.aggregate, dns_result)
        self.assertEqual(
            [asset.hostname for asset in assets],
            ["api.example.com", "example.com", "mail.example.com", "www.example.com"],
        )
        by_host = {asset.hostname: asset for asset in assets}
        self.assertEqual(by_host["example.com"].kind, AssetKind.ROOT_DOMAIN)
        self.assertEqual(by_host["api.example.com"].kind, AssetKind.SUBDOMAIN)
        self.assertEqual(by_host["api.example.com"].sources, ("amass", "subfinder"))
        self.assertEqual(by_host["api.example.com"].dns.a, ("192.0.2.1",))
        self.assertEqual(
            by_host["api.example.com"].dns.cname, ("cdn.third.example",)
        )
        self.assertEqual(
            by_host["api.example.com"].resolution_status, ResolutionStatus.RESOLVED
        )
        # External CNAME target is never promoted to an asset.
        self.assertNotIn("cdn.third.example", by_host)
        self.assertNotIn("external.example.net", by_host)


class AggregateGatingTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"])

    def test_failed_result_is_not_promoted_but_evidence_retained(self):
        subfinder = subfinder_result(
            self.scope, [{"host": "www.example.com"}, {"host": "api.example.com"}]
        )
        failed = type(subfinder)(
            tool="subfinder",
            status="timeout",
            observations=subfinder.observations,
        )
        aggregate = aggregate_discovery(
            self.scope, {"subfinder": failed, "amass": missing("amass")}
        )
        self.assertEqual(aggregate.candidates, ("example.com",))
        discovered = {
            o.normalized for o in aggregate.observations if o.state is ObservationState.DISCOVERED
        }
        self.assertIn("www.example.com", discovered)

    def test_missing_all_tools_yields_seed_only(self):
        aggregate = aggregate_discovery(
            self.scope,
            {"subfinder": missing("subfinder"), "amass": missing("amass")},
        )
        assets = build_assets(self.scope, aggregate, missing("dnsx"))
        self.assertEqual([asset.hostname for asset in assets], ["example.com"])
        self.assertEqual(assets[0].resolution_status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(assets[0].dns.a, ())

    def test_failed_dns_result_not_applied(self):
        subfinder = subfinder_result(self.scope, [{"host": "www.example.com"}])
        aggregate = aggregate_discovery(
            self.scope, {"subfinder": subfinder, "amass": missing("amass")}
        )
        failed_dns = type(missing("dnsx"))(tool="dnsx", status="tool_failed")
        assets = build_assets(self.scope, aggregate, failed_dns)
        self.assertTrue(
            all(asset.resolution_status == ResolutionStatus.UNRESOLVED for asset in assets)
        )


class BuildAssetInvariantTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])

    def test_rejects_mismatched_root(self):
        aggregate = DiscoveryAggregate(
            root="other.example",
            provenance=(("example.com", ("scope",)),),
            observations=(),
            candidates=("example.com",),
        )
        with self.assertRaises(AggregateError):
            build_assets(self.scope, aggregate)

    def test_rejects_out_of_scope_provenance(self):
        aggregate = DiscoveryAggregate(
            root="example.com",
            provenance=(
                ("example.com", ("scope",)),
                ("evil.example.net", ("scope",)),
            ),
            observations=(),
            candidates=("example.com",),
        )
        with self.assertRaises(AggregateError):
            build_assets(self.scope, aggregate)

    def test_rejects_excluded_provenance(self):
        aggregate = DiscoveryAggregate(
            root="example.com",
            provenance=(
                ("example.com", ("scope",)),
                ("excluded.example.com", ("subfinder",)),
            ),
            observations=(),
            candidates=("example.com",),
        )
        with self.assertRaises(AggregateError):
            build_assets(self.scope, aggregate)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
