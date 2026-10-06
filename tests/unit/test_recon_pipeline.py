"""Unit tests for the per-root recon pipeline and multi-root batch (offline)."""

import json
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.models import ResolutionStatus
from red_teaming.recon.evidence import PACKAGE_NAME
from red_teaming.recon.pipeline import (
    BatchPreflightError,
    PipelineError,
    run_batch,
    run_root_pipeline,
)
from red_teaming.recon.scope import DomainScope
from tests.unit import recon_fakes
from tests.unit.recon_fakes import (
    DnsAdapter,
    ExplodingAdapter,
    ResultAdapter,
    amass_result,
    dnsx_result,
    factories,
    missing,
    subfinder_result,
)


class SingleRootPipelineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])
        self.run_id = "20260101T000000Z-abc123"

    def tearDown(self):
        self._tmp.cleanup()

    def build_factories(self):
        scope = self.scope
        subfinder = ResultAdapter(
            subfinder_result(
                scope,
                [
                    {"host": "www.example.com"},
                    {"host": "api.example.com"},
                    {"host": "excluded.example.com"},
                    {"host": "external.example.net"},
                ],
            )
        )
        amass = ResultAdapter(
            amass_result(
                scope,
                [
                    {"name": "api.example.com", "sources": ["crtsh"]},
                    {"name": "mail.example.com"},
                    {"name": "external.example.net"},
                ],
            )
        )

        def resolver(candidates):
            return dnsx_result(
                scope,
                [
                    {"host": host, "a": ["192.0.2.1"], "status_code": "NOERROR"}
                    for host in candidates
                ],
            )

        dnsx = DnsAdapter(resolver)
        return factories(lambda s, w: subfinder, lambda s, w: amass, lambda s, w: dnsx), (
            subfinder,
            amass,
            dnsx,
        )

    def run_once(self):
        fac, (subfinder, amass, dnsx) = self.build_factories()
        results = run_batch(self.root, self.scope, self.run_id, fac)
        return results, (subfinder, amass, dnsx)

    def test_layout_and_artifacts(self):
        results, _ = self.run_once()
        run_dir = self.root / "projects" / "example.com" / "recon" / self.run_id
        self.assertEqual(results[0].run_dir, run_dir)
        for name in ("scope.json", "assets.json", "run.json"):
            self.assertTrue((run_dir / name).is_file(), name)
        for tool in ("subfinder", "amass", "dnsx"):
            self.assertTrue((run_dir / "evidence" / f"{tool}.json").is_file(), tool)
        # No temporary work tree survives into final artifacts.
        self.assertFalse((run_dir / "work").exists())
        self.assertEqual(
            sorted(p.name for p in run_dir.iterdir()),
            ["assets.json", "evidence", "run.json", "scope.json"],
        )

    def test_assets_document_is_tool_neutral(self):
        self.run_once()
        run_dir = self.root / "projects" / "example.com" / "recon" / self.run_id
        document = json.loads((run_dir / "assets.json").read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["root_domain"], "example.com")
        self.assertEqual(
            [asset["hostname"] for asset in document["assets"]],
            ["api.example.com", "example.com", "mail.example.com", "www.example.com"],
        )
        for asset in document["assets"]:
            self.assertNotIn("schema_version", asset)
            self.assertNotIn("schema_version", asset["dns"])
            self.assertEqual(
                sorted(asset.keys()),
                ["dns", "hostname", "kind", "resolution_status", "sources"],
            )

    def test_dns_receives_only_in_scope_candidates(self):
        _, (_, _, dnsx) = self.run_once()
        self.assertEqual(
            dnsx.run_calls[0],
            ("api.example.com", "example.com", "mail.example.com", "www.example.com"),
        )

    def test_run_document_and_evidence(self):
        self.run_once()
        run_dir = self.root / "projects" / "example.com" / "recon" / self.run_id
        run_doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_doc["schema_version"], 1)
        self.assertEqual(run_doc["root_domain"], "example.com")
        self.assertEqual(run_doc["status"], "completed")
        self.assertEqual(
            run_doc["stages"], ["scope", "subfinder", "amass", "dnsx", "assets"]
        )
        self.assertEqual(run_doc["tools"]["subfinder"]["status"], "succeeded")
        self.assertEqual(run_doc["counts"]["assets"], 4)
        self.assertGreaterEqual(run_doc["counts"]["by_state"]["out_of_scope"], 1)

        evidence = json.loads(
            (run_dir / "evidence" / "subfinder.json").read_text(encoding="utf-8")
        )
        self.assertEqual(evidence["tool"], "subfinder")
        self.assertEqual(evidence["status"], "succeeded")
        self.assertNotIn("input", evidence)
        self.assertNotIn("stdin", evidence)

    def test_deterministic_json(self):
        self.run_once()
        first = (
            self.root / "projects" / "example.com" / "recon" / self.run_id / "assets.json"
        ).read_text(encoding="utf-8")
        expected = json.dumps(
            {
                "schema_version": 1,
                "root_domain": "example.com",
                "assets": [
                    {
                        "hostname": "api.example.com",
                        "kind": "subdomain",
                        "sources": ["amass", "subfinder"],
                        "dns": {"a": ["192.0.2.1"], "aaaa": [], "cname": []},
                        "resolution_status": "resolved",
                    },
                    {
                        "hostname": "example.com",
                        "kind": "root_domain",
                        "sources": ["scope"],
                        "dns": {"a": ["192.0.2.1"], "aaaa": [], "cname": []},
                        "resolution_status": "resolved",
                    },
                    {
                        "hostname": "mail.example.com",
                        "kind": "subdomain",
                        "sources": ["amass"],
                        "dns": {"a": ["192.0.2.1"], "aaaa": [], "cname": []},
                        "resolution_status": "resolved",
                    },
                    {
                        "hostname": "www.example.com",
                        "kind": "subdomain",
                        "sources": ["subfinder"],
                        "dns": {"a": ["192.0.2.1"], "aaaa": [], "cname": []},
                        "resolution_status": "resolved",
                    },
                ],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        self.assertEqual(first, expected)

    def test_missing_all_tools_writes_seed_only(self):
        fac = factories(
            lambda s, w: ResultAdapter(missing("subfinder")),
            lambda s, w: ResultAdapter(missing("amass")),
            lambda s, w: DnsAdapter(lambda candidates: missing("dnsx")),
        )
        results = run_batch(self.root, self.scope, self.run_id, fac)
        self.assertEqual(results[0].asset_count, 1)
        run_dir = results[0].run_dir
        document = json.loads((run_dir / "assets.json").read_text(encoding="utf-8"))
        self.assertEqual([a["hostname"] for a in document["assets"]], ["example.com"])
        self.assertEqual(document["assets"][0]["resolution_status"], "unresolved")
        run_doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_doc["tools"]["subfinder"]["status"], "tool_not_available")
        self.assertEqual(run_doc["tools"]["dnsx"]["status"], "tool_not_available")
        self.assertFalse((run_dir / "work").exists())

    def test_failed_discovery_not_promoted(self):
        scope = self.scope
        raw = subfinder_result(
            scope, [{"host": "www.example.com"}, {"host": "api.example.com"}]
        )
        failed = type(raw)(tool="subfinder", status="timeout", observations=raw.observations)
        fac = factories(
            lambda s, w: ResultAdapter(failed),
            lambda s, w: ResultAdapter(missing("amass")),
            lambda s, w: DnsAdapter(lambda candidates: missing("dnsx")),
        )
        results = run_batch(self.root, self.scope, self.run_id, fac)
        document = json.loads(
            (results[0].run_dir / "assets.json").read_text(encoding="utf-8")
        )
        self.assertEqual([a["hostname"] for a in document["assets"]], ["example.com"])

    def test_existing_run_is_refused(self):
        self.run_once()
        fac, _ = self.build_factories()
        with self.assertRaises(BatchPreflightError):
            run_batch(self.root, self.scope, self.run_id, fac)

    def test_implicit_production_factories_fail_closed(self):
        # Bare-name production adapters must never be constructed implicitly.
        with self.assertRaises(PipelineError):
            run_batch(self.root, self.scope, self.run_id, None)

    def test_discovery_exception_is_structured(self):
        fac = factories(
            lambda s, w: ExplodingAdapter(),
            lambda s, w: ResultAdapter(missing("amass")),
            lambda s, w: DnsAdapter(lambda candidates: missing("dnsx")),
        )
        results = run_batch(self.root, self.scope, self.run_id, fac)
        run_dir = results[0].run_dir
        run_doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_doc["tools"]["subfinder"]["status"], "tool_failed")
        evidence = json.loads(
            (run_dir / "evidence" / "subfinder.json").read_text(encoding="utf-8")
        )
        self.assertEqual(evidence["status"], "tool_failed")
        self.assertEqual(evidence["errors"], ["RuntimeError"])
        self.assertFalse((run_dir / "work").exists())

    def test_factory_exception_is_structured(self):
        def boom(scope, work_dir):
            raise ValueError("bad factory")

        fac = factories(
            boom,
            lambda s, w: ResultAdapter(missing("amass")),
            lambda s, w: DnsAdapter(lambda candidates: missing("dnsx")),
        )
        results = run_batch(self.root, self.scope, self.run_id, fac)
        self.assertIn(("subfinder", "tool_failed"), results[0].tools)

    def test_dnsx_exception_is_structured(self):
        scope = self.scope
        fac = factories(
            lambda s, w: ResultAdapter(
                subfinder_result(scope, [{"host": "www.example.com"}])
            ),
            lambda s, w: ResultAdapter(missing("amass")),
            lambda s, w: ExplodingAdapter(),
        )
        results = run_batch(self.root, self.scope, self.run_id, fac)
        run_dir = results[0].run_dir
        run_doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_doc["tools"]["dnsx"]["status"], "tool_failed")
        document = json.loads((run_dir / "assets.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [asset["hostname"] for asset in document["assets"]],
            ["example.com", "www.example.com"],
        )
        # Failed dnsx output is never promoted.
        self.assertTrue(
            all(a["resolution_status"] == "unresolved" for a in document["assets"])
        )


class StrictPackageTests(unittest.TestCase):
    """RECON-002 package mode must stop immediately on any stage failure."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scope = DomainScope.parse(["acme.example"])
        self.run_id = "20260101T000000Z-abc123"

    def tearDown(self):
        self._tmp.cleanup()

    class Provider:
        def __init__(self):
            self.statuses = []

        def document(self, *, run_id, root, status="completed"):
            self.statuses.append(status)
            return {
                "schema_version": 1,
                "package": PACKAGE_NAME,
                "root_domain": root,
                "run_id": run_id,
                "status": status,
            }

    def _run(self, sub, am, dx):
        provider = self.Provider()
        fac = factories(lambda s, w: sub, lambda s, w: am, lambda s, w: dx)
        with self.assertRaises(PipelineError):
            run_batch(
                self.root,
                self.scope,
                self.run_id,
                fac,
                package=PACKAGE_NAME,
                evidence_provider=provider,
                launch_marker={"state": "launched"},
            )
        run_dir = self.root / "projects" / "acme.example" / "recon" / self.run_id
        return run_dir, provider

    def test_stops_after_subfinder_failure(self):
        sub = ResultAdapter(missing("subfinder"))
        am = ExplodingAdapter()
        dx = ExplodingAdapter()
        run_dir, provider = self._run(sub, am, dx)
        self.assertEqual(am.run_calls, 0)
        self.assertEqual(dx.run_calls, 0)
        run_doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_doc["status"], "failed")
        evidence_doc = json.loads(
            (run_dir / "evidence" / "subfinder.json").read_text(encoding="utf-8")
        )
        self.assertEqual(evidence_doc["status"], "tool_not_available")
        policy = json.loads(
            (run_dir / "evidence" / "network-policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(policy["status"], "failed")
        self.assertIn("failed", provider.statuses)

    def test_stops_after_amass_failure(self):
        sub = ResultAdapter(
            subfinder_result(self.scope, [{"host": "www.acme.example"}])
        )
        am = ResultAdapter(missing("amass"))
        dx = ExplodingAdapter()
        run_dir, _provider = self._run(sub, am, dx)
        self.assertEqual(dx.run_calls, 0)
        run_doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_doc["status"], "failed")
        self.assertTrue((run_dir / "evidence" / "amass.json").is_file())
        self.assertFalse((run_dir / "evidence" / "dnsx.json").exists())

    def test_stops_after_dnsx_failure(self):
        sub = ResultAdapter(
            subfinder_result(self.scope, [{"host": "www.acme.example"}])
        )
        am = ResultAdapter(
            amass_result(self.scope, [{"name": "api.acme.example"}])
        )
        dx = DnsAdapter(lambda candidates: missing("dnsx"))
        run_dir, _provider = self._run(sub, am, dx)
        run_doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_doc["status"], "failed")
        policy = json.loads(
            (run_dir / "evidence" / "network-policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(policy["status"], "failed")


class MultiRootBatchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scope = DomainScope.parse(["a.example.com", "b.example.com"])
        self.run_id = "20260101T000000Z-abc123"

    def tearDown(self):
        self._tmp.cleanup()

    def root_factory(self, tool):
        def build(scope, work_dir):
            host = scope.roots[0].name
            if tool == "subfinder":
                return ResultAdapter(
                    subfinder_result(scope, [{"host": f"www.{host}"}])
                )
            if tool == "amass":
                return ResultAdapter(
                    amass_result(scope, [{"name": f"api.{host}"}])
                )
            return DnsAdapter(
                lambda candidates: dnsx_result(
                    scope,
                    [
                        {"host": h, "a": ["192.0.2.1"], "status_code": "NOERROR"}
                        for h in candidates
                    ],
                )
            )

        return build

    def test_separate_trees_never_mix(self):
        fac = factories(
            self.root_factory("subfinder"),
            self.root_factory("amass"),
            self.root_factory("dnsx"),
        )
        results = run_batch(self.root, self.scope, self.run_id, fac)
        self.assertEqual([r.root for r in results], ["a.example.com", "b.example.com"])

        for root in ("a.example.com", "b.example.com"):
            run_dir = self.root / "projects" / root / "recon" / self.run_id
            self.assertTrue(run_dir.is_dir())
            document = json.loads((run_dir / "assets.json").read_text(encoding="utf-8"))
            self.assertEqual(document["root_domain"], root)
            for asset in document["assets"]:
                self.assertTrue(
                    asset["hostname"] == root or asset["hostname"].endswith("." + root),
                    asset["hostname"],
                )
        a_doc = json.loads(
            (
                self.root / "projects" / "a.example.com" / "recon" / self.run_id / "assets.json"
            ).read_text(encoding="utf-8")
        )
        self.assertNotIn(
            "www.b.example.com", [asset["hostname"] for asset in a_doc["assets"]]
        )

    def test_preflight_collision_creates_nothing(self):
        a_run = self.root / "projects" / "a.example.com" / "recon" / self.run_id
        a_run.mkdir(parents=True)
        fac = factories(
            self.root_factory("subfinder"),
            self.root_factory("amass"),
            self.root_factory("dnsx"),
        )
        with self.assertRaises(BatchPreflightError):
            run_batch(self.root, self.scope, self.run_id, fac)
        b_run = self.root / "projects" / "b.example.com" / "recon" / self.run_id
        self.assertFalse(b_run.exists())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
