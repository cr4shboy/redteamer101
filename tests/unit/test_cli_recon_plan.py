"""Unit tests for the recon planner CLI (offline, no network)."""

import io
import json
import unittest

from red_teaming.cli.recon_plan import EXIT_OK, EXIT_RUNTIME, EXIT_VALIDATION, main


class ReconPlanCliTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        code = main(argv, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_validate_only_prints_plan_with_no_web_block(self):
        code, out, _ = self.run_cli(["--domain", "example.com", "--validate-only"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("passive_subdomains", out)
        self.assertIn("zap_spider", out)
        self.assertIn("no_web_services", out)
        self.assertIn("eligible now: passive_subdomains", out)

    def test_default_mode_is_validate_only(self):
        code, out, _ = self.run_cli(["--domain", "example.com"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("plan:", out)

    def test_json_output_is_structured(self):
        code, out, _ = self.run_cli(["--domain", "example.com", "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["domain"], "example.com")
        self.assertIn("plan", payload)
        stages = {entry["stage"]: entry for entry in payload["plan"]}
        self.assertEqual(stages["zap_spider"]["status"], "blocked")
        self.assertEqual(stages["zap_spider"]["reason"], "no_web_services")

    def test_confirm_authorized_fails_closed_without_live_package(self):
        code, out, err = self.run_cli(
            ["--domain", "example.com", "--confirm-authorized"]
        )
        self.assertEqual(code, EXIT_RUNTIME)
        self.assertEqual(out, "")
        self.assertIn("live execution refused", err)
        self.assertIn("CURRENT_TASK.md", err)

    def test_invalid_domain_is_validation_error(self):
        code, out, err = self.run_cli(["--domain", "bad host", "--validate-only"])
        self.assertEqual(code, EXIT_VALIDATION)
        self.assertEqual(out, "")
        self.assertIn("invalid scope", err)

    def test_report_sarif_is_valid_json(self):
        code, out, _ = self.run_cli(["--domain", "example.com", "--report", "sarif"])
        self.assertEqual(code, EXIT_OK)
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "redteamer101")

    def test_report_markdown(self):
        code, out, _ = self.run_cli(["--domain", "example.com", "--report", "md"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("# Recon report: example.com", out)

    def test_report_json(self):
        code, out, _ = self.run_cli(["--domain", "example.com", "--report", "json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["domain"], "example.com")
        self.assertIn("findings", payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
