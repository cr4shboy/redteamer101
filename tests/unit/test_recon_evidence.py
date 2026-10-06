"""Offline tests for RECON-003 network-policy evidence and the one-run ledger."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from red_teaming.recon import evidence
from red_teaming.recon.netpolicy import ROOT_DOMAIN, ReconNetworkPolicy
from red_teaming.recon.paths import ReconPath
from red_teaming.recon.pinned import PINNED_TOOLS, install_dir_for
from red_teaming.recon.production import ProductionRuntime


class DocumentTests(unittest.TestCase):
    def test_document_shape_and_summary(self):
        invocations = [
            {
                "tool": "subfinder",
                "invocation": "live",
                "broker_events": [
                    {
                        "action": "connect",
                        "decision": "allowed",
                        "host": "crt.sh",
                        "port": 443,
                        "upstream_ip": "8.8.8.8",
                    },
                    {"decision": "denied", "host": "evil.example"},
                ],
            },
            {
                "tool": "dnsx",
                "invocation": "live",
                "broker_events": [
                    {
                        "action": "dns",
                        "decision": "allowed",
                        "qname": "www.acme.example",
                        "qtype": "A",
                        "upstream_host": "1.1.1.1",
                        "upstream_port": 53,
                    },
                ],
            },
        ]
        doc = evidence.build_network_policy_document(
            run_id="20260101T000000Z-abc123",
            root="acme.example",
            runtime={"ok": True},
            installs=[{"tool": "subfinder", "ok": True, "reason": None}],
            invocations=invocations,
        )
        self.assertEqual(doc["package"], "RECON-003")
        self.assertEqual(doc["policy"]["https_host"], "crt.sh")
        self.assertEqual(doc["policy"]["record_types"], ["A", "AAAA", "CNAME"])
        dest = doc["external_destinations"]
        self.assertEqual(dest["allowed"], 2)
        self.assertEqual(dest["denied"], 1)
        hosts = {entry["host"] for entry in dest["hosts"]}
        self.assertEqual(hosts, {"crt.sh", "evil.example", "www.acme.example"})
        # The auditor-visible external destinations are exactly the two paths.
        endpoints = {entry["endpoint"] for entry in dest["endpoints"]}
        self.assertEqual(endpoints, {"crt.sh:443", "1.1.1.1:53"})
        # A qname is never misreported as an external endpoint.
        self.assertNotIn("www.acme.example:53", endpoints)

    def test_bootstrap_resolve_events_show_resolver(self):
        invocations = [
            {
                "tool": "subfinder",
                "invocation": "live",
                "broker_events": [
                    {
                        "action": "resolve",
                        "decision": "allowed",
                        "qname": "crt.sh",
                        "qtype": "A",
                        "upstream_host": "1.1.1.1",
                        "upstream_port": 53,
                    }
                ],
            }
        ]
        doc = evidence.build_network_policy_document(
            run_id="x", root="acme.example", invocations=invocations
        )
        endpoints = {entry["endpoint"] for entry in doc["external_destinations"]["endpoints"]}
        self.assertEqual(endpoints, {"1.1.1.1:53"})

    def test_query_strings_and_secrets_rejected(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.build_network_policy_document(
                run_id="x",
                root="acme.example",
                invocations=[{"tool": "x", "note": "https://x/?a=1"}],
            )
        with self.assertRaises(evidence.EvidenceError):
            evidence.build_network_policy_document(
                run_id="x",
                root="acme.example",
                invocations=[{"tool": "x", "note": "token=abc"}],
            )


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "projects").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _recon(self, run_id="20260101T000000Z-abc123"):
        recon = ReconPath.build(self.root, "acme.example", run_id)
        recon.create()
        return recon

    def _recon_root(self):
        return self.root / "projects" / "acme.example" / "recon"

    def _historical_run(self, **overrides):
        run_dir = self._recon_root() / evidence.HISTORICAL_RUN_ID
        run_dir.mkdir(parents=True)
        document = {
            "package": "RECON-002",
            "root_domain": "acme.example",
            "run_id": evidence.HISTORICAL_RUN_ID,
            "launch_budget_consumed": True,
        }
        document.update(overrides)
        for filename in ("run.json", "launch-marker.json"):
            (run_dir / filename).write_text(json.dumps(document), encoding="utf-8")
        return run_dir

    def test_clean_root_has_no_prior_entries(self):
        self.assertEqual(evidence.prior_recon_entries(self.root, "acme.example"), ())

    def test_only_authorized_domains_file_is_allowed(self):
        recon_root = self._recon_root()
        recon_root.mkdir(parents=True)
        (recon_root / "domains.txt").write_text("acme.example\n", encoding="utf-8")
        self.assertEqual(evidence.prior_recon_entries(self.root, "acme.example"), ())

    def test_recon_003_run_directory_blocks(self):
        recon = self._recon()
        entries = evidence.prior_recon_entries(self.root, "acme.example")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0], recon.run_dir)

    def test_valid_historical_run_and_domains_file_are_ignored(self):
        self._historical_run()
        (self._recon_root() / "domains.txt").write_text(
            "acme.example\n", encoding="utf-8"
        )
        self.assertEqual(evidence.prior_recon_entries(self.root, "acme.example"), ())

    def test_historical_missing_or_malformed_evidence_blocks(self):
        for case in ("missing", "malformed"):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    run_dir = root / "projects" / "acme.example" / "recon" / evidence.HISTORICAL_RUN_ID
                    run_dir.mkdir(parents=True)
                    (run_dir / "run.json").write_text("{" if case == "malformed" else "{}", encoding="utf-8")
                    if case == "malformed":
                        (run_dir / "launch-marker.json").write_text("{}", encoding="utf-8")
                    self.assertEqual(evidence.prior_recon_entries(root, "acme.example"), (run_dir,))

    def test_historical_mismatched_evidence_blocks(self):
        run_dir = self._historical_run(package="RECON-003")
        self.assertEqual(
            evidence.prior_recon_entries(self.root, "acme.example"), (run_dir,)
        )

    def test_historical_consumed_flag_must_be_json_true(self):
        run_dir = self._historical_run(launch_budget_consumed=1)
        self.assertEqual(
            evidence.prior_recon_entries(self.root, "acme.example"), (run_dir,)
        )

    def test_symlinked_historical_evidence_blocks(self):
        run_dir = self._historical_run()
        marker = run_dir / "launch-marker.json"
        real = run_dir / "real-marker.json"
        marker.replace(real)
        try:
            marker.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(
            evidence.prior_recon_entries(self.root, "acme.example"), (run_dir,)
        )

    def test_reported_symlinked_historical_evidence_blocks_on_all_platforms(self):
        run_dir = self._historical_run()
        marker = run_dir / "launch-marker.json"
        original = Path.is_symlink

        def reported_symlink(path):
            return path == marker or original(path)

        with mock.patch.object(Path, "is_symlink", reported_symlink):
            self.assertEqual(
                evidence.prior_recon_entries(self.root, "acme.example"),
                (run_dir,),
            )

    def test_domains_file_and_run_directory_blocks(self):
        recon_root = self._recon_root()
        recon_root.mkdir(parents=True)
        (recon_root / "domains.txt").write_text("acme.example\n", encoding="utf-8")
        recon = self._recon()
        entries = evidence.prior_recon_entries(self.root, "acme.example")
        self.assertEqual(entries, (recon.run_dir,))

    def test_unexpected_file_blocks(self):
        recon_root = self._recon_root()
        recon_root.mkdir(parents=True)
        (recon_root / "domains.txt").write_text("acme.example\n", encoding="utf-8")
        (recon_root / "surprise.txt").write_text("x", encoding="utf-8")
        entries = evidence.prior_recon_entries(self.root, "acme.example")
        self.assertEqual([entry.name for entry in entries], ["surprise.txt"])

    def test_symlinked_domains_file_blocks(self):
        recon_root = self._recon_root()
        recon_root.mkdir(parents=True)
        real = recon_root / "real.txt"
        real.write_text("acme.example\n", encoding="utf-8")
        link = recon_root / "domains.txt"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        entries = evidence.prior_recon_entries(self.root, "acme.example")
        self.assertIn(link, entries)

    def test_launch_marker_and_failure_written_contained(self):
        recon = self._recon()
        marker = evidence.write_launch_marker(
            recon, mark=evidence.build_launch_marker(run_id=recon.run_id, root="acme.example")
        )
        self.assertTrue(marker.is_file())
        document = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(document["package"], "RECON-003")
        self.assertTrue(document["launch_budget_consumed"])

        failure = evidence.write_run_failure(recon, error="RuntimeError: boom")
        self.assertTrue(failure.is_file())
        fail_doc = json.loads(failure.read_text(encoding="utf-8"))
        self.assertEqual(fail_doc["status"], "failed")
        self.assertEqual(fail_doc["package"], "RECON-003")
        self.assertEqual(fail_doc["error"], "RuntimeError: boom")
        # Marker and failure remain inside the run directory.
        self.assertEqual(marker.parent, recon.run_dir)

    def test_run_failure_rejects_secret_like_error(self):
        recon = self._recon()
        with self.assertRaises(evidence.EvidenceError):
            evidence.write_run_failure(recon, error="token=abc")


class ProviderTests(unittest.TestCase):
    def test_provider_document_uses_install_summaries(self):
        installs = []
        for spec in PINNED_TOOLS.values():
            installs.append(
                type(
                    "R",
                    (),
                    {
                        "to_dict": lambda self, spec=spec: {
                            "tool": spec.tool,
                            "version": spec.version,
                            "ok": True,
                            "reason": None,
                        }
                    },
                )()
            )
        provider = evidence.EvidenceProvider(
            root="acme.example",
            runtime=None,
            installs=tuple(installs),
            invocations=[{"tool": "dnsx", "invocation": "live", "broker_events": []}],
        )
        doc = provider.document(run_id="r", root="acme.example")
        self.assertEqual(len(doc["pinned_installs"]), 3)
        self.assertEqual(doc["invocations"][0]["tool"], "dnsx")

    def test_production_evidence_provider_accepts_and_uses_injected_policy(self):
        policy = ReconNetworkPolicy(dns_qps=9, dns_max_concurrent=3)
        with tempfile.TemporaryDirectory() as tmp:
            runtime = ProductionRuntime(
                workspace_root=Path(tmp),
                root=ROOT_DOMAIN,
                installs=(),
                policy=policy,
            )
            provider = runtime.evidence_provider()
            doc = provider.document(
                run_id="20260101T000000Z-abc123", root=ROOT_DOMAIN
            )
        self.assertEqual(doc["policy"]["root_domain"], ROOT_DOMAIN)
        self.assertEqual(doc["policy"]["https_host"], "crt.sh")
        # The injected policy (not the module default) is reflected in output.
        self.assertEqual(doc["policy"]["dns_qps"], 9)
        self.assertEqual(doc["policy"]["dns_max_concurrent"], 3)

    def test_provider_document_rejects_query_string_and_secret(self):
        for note in ("https://x.example/?a=1", "token=abc", "password=hunter2"):
            with self.subTest(note=note):
                provider = evidence.EvidenceProvider(
                    root="acme.example",
                    invocations=[{"tool": "x", "note": note}],
                )
                with self.assertRaises(evidence.EvidenceError):
                    provider.document(run_id="r", root="acme.example")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
