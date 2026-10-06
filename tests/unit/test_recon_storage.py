"""Unit tests for containment-checked atomic recon JSON storage."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from red_teaming.recon.models import Asset, DnsRecords
from red_teaming.recon.paths import ReconPath
from red_teaming.recon.scope import DomainScope
from red_teaming.recon.storage import (
    ASSETS_FILENAME,
    EVIDENCE_DIRNAME,
    SCOPE_FILENAME,
    ReconStorageError,
    asset_document,
    ensure_evidence_dir,
    evidence_dir,
    read_recon_json,
    write_assets,
    write_evidence_json,
    write_recon_json,
    write_scope,
)


class ReconStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.recon = ReconPath.build(
            self.root,
            "example.com",
            now=datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc),
            suffix="abc123",
        )
        self.scope = DomainScope.parse(["Example.com"], ["www.example.com"])

    def tearDown(self):
        self._tmp.cleanup()

    def test_requires_existing_run_dir(self):
        with self.assertRaises(ReconStorageError):
            write_scope(self.recon, self.scope)
        self.assertFalse(self.recon.run_dir.exists())

    def test_write_then_read_scope(self):
        self.recon.create()
        path = write_scope(self.recon, self.scope)
        self.assertEqual(path, self.recon.run_dir / SCOPE_FILENAME)
        self.assertEqual(
            read_recon_json(self.recon, SCOPE_FILENAME), self.scope.to_dict()
        )

    def test_write_assets_payload_is_per_domain(self):
        self.recon.create()
        asset = Asset(hostname="www.example.com", kind="subdomain", sources=["seed"])
        write_assets(self.recon, "example.com", [asset])
        payload = read_recon_json(self.recon, ASSETS_FILENAME)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["root_domain"], "example.com")
        self.assertEqual(payload["assets"][0]["hostname"], "www.example.com")

    def test_write_assets_orders_by_hostname(self):
        self.recon.create()
        assets = [
            Asset(hostname="z.example.com", kind="subdomain"),
            Asset(hostname="example.com", kind="root_domain"),
            Asset(hostname="a.example.com", kind="subdomain"),
        ]
        write_assets(self.recon, "example.com", assets)
        payload = read_recon_json(self.recon, ASSETS_FILENAME)
        self.assertEqual(
            [asset["hostname"] for asset in payload["assets"]],
            ["a.example.com", "example.com", "z.example.com"],
        )

    def test_write_assets_normalizes_root(self):
        self.recon.create()
        write_assets(self.recon, "Example.COM.", [Asset(hostname="a.example.com", kind="subdomain")])
        payload = read_recon_json(self.recon, ASSETS_FILENAME)
        self.assertEqual(payload["root_domain"], "example.com")

    def test_write_assets_rejects_mixed_domain(self):
        self.recon.create()
        with self.assertRaises(ReconStorageError):
            write_assets(
                self.recon, "example.com", [Asset(hostname="other.example", kind="subdomain")]
            )

    def test_write_assets_rejects_invalid_root(self):
        self.recon.create()
        for bad_root in ["", "not a host", "192.0.2.1", "*.example.com", "http://example.com"]:
            with self.subTest(bad_root=bad_root):
                with self.assertRaises(ReconStorageError):
                    write_assets(self.recon, bad_root, [])

    def test_formatting_is_stable(self):
        self.recon.create()
        write_recon_json(self.recon, {"b": 1, "a": {"z": 2}}, "custom.json")
        raw = (self.recon.run_dir / "custom.json").read_text(encoding="utf-8")
        self.assertEqual(raw, '{\n  "a": {\n    "z": 2\n  },\n  "b": 1\n}\n')

    def test_rejects_traversal_filename(self):
        self.recon.create()
        with self.assertRaises(ReconStorageError):
            write_recon_json(self.recon, {"x": 1}, "../evil.json")
        self.assertFalse((self.recon.run_dir.parent / "evil.json").exists())

    def test_rejects_non_object_payload(self):
        self.recon.create()
        with self.assertRaises(ReconStorageError):
            write_recon_json(self.recon, [1, 2], "list.json")

    def test_no_temporary_files_remain(self):
        self.recon.create()
        write_scope(self.recon, self.scope)
        leftovers = [p.name for p in self.recon.run_dir.iterdir()]
        self.assertEqual(leftovers, [SCOPE_FILENAME])

    def test_type_checking(self):
        with self.assertRaises(TypeError):
            write_scope(self.recon, {"not": "a scope"})
        self.recon.create()
        with self.assertRaises(TypeError):
            write_assets(self.recon, "example.com", ["not-an-asset"])


class AssetDocumentTests(unittest.TestCase):
    def test_tool_neutral_shape(self):
        asset = Asset(
            hostname="api.example.com",
            kind="subdomain",
            sources=["scope", "subfinder"],
            dns=DnsRecords(a=["192.0.2.1"], cname=["cdn.third.example"]),
            resolution_status="resolved",
        )
        self.assertEqual(
            asset_document(asset),
            {
                "hostname": "api.example.com",
                "kind": "subdomain",
                "sources": ["scope", "subfinder"],
                "dns": {"a": ["192.0.2.1"], "aaaa": [], "cname": ["cdn.third.example"]},
                "resolution_status": "resolved",
            },
        )

    def test_write_assets_has_no_nested_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            recon = ReconPath.build(
                Path(tmp),
                "example.com",
                now=datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc),
                suffix="abc123",
            )
            recon.create()
            write_assets(recon, "example.com", [Asset(hostname="example.com", kind="root_domain")])
            payload = read_recon_json(recon, ASSETS_FILENAME)
            self.assertEqual(payload["schema_version"], 1)
            self.assertNotIn("schema_version", payload["assets"][0])
            self.assertNotIn("schema_version", payload["assets"][0]["dns"])


class EvidenceStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.recon = ReconPath.build(
            Path(self._tmp.name),
            "example.com",
            now=datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc),
            suffix="abc123",
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_requires_existing_run_dir(self):
        with self.assertRaises(ReconStorageError):
            write_evidence_json(self.recon, "subfinder", {"tool": "subfinder"})
        self.assertEqual(evidence_dir(self.recon), self.recon.run_dir / EVIDENCE_DIRNAME)

    def test_writes_contained_evidence(self):
        self.recon.create()
        path = write_evidence_json(self.recon, "subfinder", {"tool": "subfinder"})
        self.assertEqual(path, self.recon.run_dir / EVIDENCE_DIRNAME / "subfinder.json")
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8")), {"tool": "subfinder"}
        )
        self.assertEqual(ensure_evidence_dir(self.recon).name, EVIDENCE_DIRNAME)

    def test_rejects_unsafe_tool_name(self):
        self.recon.create()
        for bad in ("../evil", "sub/dir", "..", "sub:name"):
            with self.subTest(bad=bad):
                with self.assertRaises(ReconStorageError):
                    write_evidence_json(self.recon, bad, {"x": 1})

    def test_rejects_non_object_payload(self):
        self.recon.create()
        with self.assertRaises(ReconStorageError):
            write_evidence_json(self.recon, "subfinder", ["not", "an", "object"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
