"""Unit tests for the deterministic orchestrator drive loop (offline)."""

import unittest

from red_teaming.intel import Orchestrator, fingerprint_server_header, reduce
from red_teaming.projects.models import ValidationError
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
from red_teaming.tools.http_fetch import FetchResult


def _obs(host, source):
    return DiscoveryObservation(
        raw=host, source=source, state=ObservationState.DISCOVERED,
        normalized=host, reason="in_scope",
    )


def _amass(*hosts):
    return lambda kb: ToolResult(
        tool="amass", status=ToolRunStatus.SUCCEEDED,
        observations=tuple(_obs(h, "amass") for h in hosts),
    )


def _ffuf(*hosts):
    return lambda kb: ToolResult(
        tool="ffuf", status=ToolRunStatus.SUCCEEDED,
        observations=tuple(_obs(h, "ffuf") for h in hosts),
    )


def _dnsx(host, a):
    return lambda kb: ToolResult(
        tool="dnsx", status=ToolRunStatus.SUCCEEDED,
        resolutions=(
            DnsResolution(hostname=host, status=ResolutionStatus.RESOLVED,
                          dns=DnsRecords(a=a)),
        ),
    )


def _fetch(host="www.example.com", source_id="response-1", header="nginx/1.25"):
    return FetchResult(
        status_code=200,
        fingerprint=fingerprint_server_header(
            host=host, scheme="https", port=443,
            source_id=source_id, server_header=header,
        ),
    )


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"])

    def test_no_runners_runs_nothing(self):
        report = Orchestrator(self.scope, runners={}, capabilities={}).run()
        self.assertEqual(report.steps, ())
        self.assertEqual(report.findings, ())
        self.assertEqual(report.domain, "example.com")

    def test_passive_then_resolve_chain(self):
        report = Orchestrator(
            self.scope,
            runners={
                "passive_subdomains": _amass("a.example.com"),
                "resolve": _dnsx("a.example.com", ("192.0.2.1",)),
                # active runner present but authorization withheld -> never runs
                "active_subdomains": _ffuf("live.example.com"),
            },
            capabilities={},
            authorized=False,
        ).run()
        stages = [s.stage for s in report.steps]
        self.assertEqual(stages, ["passive_subdomains", "resolve"])
        self.assertIn("a.example.com", report.knowledge.hostnames)
        resolvable = {asset.hostname for asset in report.knowledge.resolvable_assets()}
        self.assertIn("a.example.com", resolvable)

    def test_active_runs_only_when_authorized_and_yields_web_finding(self):
        report = Orchestrator(
            self.scope,
            runners={"active_subdomains": _ffuf("www.example.com")},
            capabilities={},
            authorized=True,
        ).run()
        self.assertEqual([s.stage for s in report.steps], ["active_subdomains"])
        self.assertIn("www.example.com", report.knowledge.web_hosts())
        self.assertTrue(
            any(f.rule_id == "web-service-exposed" for f in report.findings)
        )

    def test_active_withheld_without_authorization(self):
        report = Orchestrator(
            self.scope,
            runners={"active_subdomains": _ffuf("www.example.com")},
            capabilities={},
            authorized=False,
        ).run()
        self.assertEqual(report.steps, ())
        self.assertEqual(report.knowledge.web_hosts(), ())

    def test_run_is_deterministic(self):
        def build():
            return Orchestrator(
                self.scope,
                runners={
                    "passive_subdomains": _amass("b.example.com", "a.example.com"),
                    "resolve": _dnsx("a.example.com", ("192.0.2.1",)),
                },
                capabilities={},
            ).run()

        self.assertEqual(build().to_dict(), build().to_dict())

    def test_runner_must_return_toolresult(self):
        orch = Orchestrator(
            self.scope,
            runners={"passive_subdomains": lambda kb: "not-a-result"},
            capabilities={},
        )
        with self.assertRaises(ValueError):
            orch.run()

    def test_fingerprint_result_is_ingested_after_known_web_service(self):
        calls = []
        def fingerprint_runner(kb):
            calls.append(kb.web_hosts())
            return _fetch()

        report = Orchestrator(
            self.scope,
            runners={
                "active_subdomains": _ffuf("www.example.com"),
                "fingerprint_web_server": fingerprint_runner,
            },
            capabilities={"fingerprint_web_server": "available"},
            authorized=True,
        ).run()
        self.assertEqual(calls, [("www.example.com",)])
        self.assertEqual(
            [step.stage for step in report.steps],
            ["active_subdomains", "fingerprint_web_server"],
        )
        self.assertEqual(report.steps[-1].status, "succeeded")
        self.assertEqual(report.knowledge.fingerprints, (_fetch().fingerprint,))
        self.assertEqual(report.knowledge.fingerprints[0].claimed_product, "nginx")

    def test_fingerprint_runner_is_gated_by_capability_and_authorization(self):
        for caps, authorized in (({}, True), ({"fingerprint_web_server": "available"}, False)):
            with self.subTest(caps=caps, authorized=authorized):
                calls = []
                report = Orchestrator(
                    self.scope,
                    runners={
                        "active_subdomains": _ffuf("www.example.com"),
                        "fingerprint_web_server": lambda kb: calls.append(kb) or _fetch(),
                    },
                    capabilities=caps,
                    authorized=authorized,
                ).run()
                self.assertEqual(calls, [])
                self.assertEqual(report.knowledge.fingerprints, ())

    def test_fingerprint_result_must_match_known_live_web_endpoint(self):
        for host in ("other.example.com", "elsewhere.test"):
            with self.subTest(host=host):
                orch = Orchestrator(
                    self.scope,
                    runners={
                        "active_subdomains": _ffuf("www.example.com"),
                        "fingerprint_web_server": lambda kb: _fetch(host=host),
                    },
                    capabilities={"fingerprint_web_server": "available"},
                    authorized=True,
                )
                with self.assertRaisesRegex(ValueError, "not a known live web service"):
                    orch.run()

    def test_fingerprint_conflicting_source_identity_fails_closed(self):
        orch = Orchestrator(
            self.scope,
            runners={
                "active_subdomains": _ffuf("www.example.com"),
                "fingerprint_web_server": lambda kb: _fetch(header="Apache/2.4"),
            },
            capabilities={"fingerprint_web_server": "available"},
            fingerprints=(_fetch().fingerprint,),
            authorized=True,
        )
        with self.assertRaisesRegex(ValidationError, "conflicting duplicate"):
            orch.run()

    def test_fingerprint_matching_source_identity_is_idempotent(self):
        item = _fetch().fingerprint
        report = Orchestrator(
            self.scope,
            runners={
                "active_subdomains": _ffuf("www.example.com"),
                "fingerprint_web_server": lambda kb: _fetch(),
            },
            capabilities={"fingerprint_web_server": "available"},
            fingerprints=(item,),
            authorized=True,
        ).run()
        self.assertEqual(report.knowledge.fingerprints, (item,))

    def test_other_stage_cannot_return_fetch_result(self):
        orch = Orchestrator(
            self.scope,
            runners={"passive_subdomains": lambda kb: _fetch()},
            capabilities={},
        )
        with self.assertRaisesRegex(ValueError, "did not return a ToolResult"):
            orch.run()

    def test_fingerprint_runner_requires_fetch_result(self):
        orch = Orchestrator(
            self.scope,
            runners={
                "active_subdomains": _ffuf("www.example.com"),
                "fingerprint_web_server": lambda kb: _ffuf("www.example.com")(kb),
            },
            capabilities={"fingerprint_web_server": "available"},
            authorized=True,
        )
        with self.assertRaisesRegex(ValueError, "did not return a FetchResult"):
            orch.run()

    def test_reduce_is_order_independent(self):
        amass = _amass("a.example.com")(None)
        dnsx = _dnsx("a.example.com", ("192.0.2.1",))(None)
        kb1 = reduce(self.scope, {"amass": amass, "dnsx": dnsx})
        kb2 = reduce(self.scope, {"dnsx": dnsx, "amass": amass})
        self.assertEqual(kb1.to_dict(), kb2.to_dict())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
