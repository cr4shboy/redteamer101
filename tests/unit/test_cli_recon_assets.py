"""Unit tests for the RECON-001 CLI (offline, no real tools)."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from red_teaming.cli import recon_assets as cli
from red_teaming.recon.scope import DomainScope
from tests.unit import recon_fakes
from tests.unit.recon_fakes import (
    DnsAdapter,
    InspectOnlyAdapter,
    ResultAdapter,
    amass_result,
    dnsx_result,
    factories,
    subfinder_result,
)

RUN_ID = "20260101T000000Z-abc123"


def make_workspace(tmp: str) -> Path:
    root = Path(tmp)
    (root / "projects").mkdir()
    for marker in ("AGENTS.md", "PROJECT.md", "CURRENT_TASK.md"):
        (root / marker).write_text("marker\n", encoding="utf-8")
    return root


class CliPlanTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_workspace(self._tmp.name)
        self.domains = self.root / "domains.txt"
        self.domains.write_text("# scope\nexample.com\n\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, argv, *, fac=None):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(
            argv, stdout=out, stderr=err, factories=fac, expected_root=self.root
        )
        return code, out.getvalue(), err.getvalue()

    def inspect_factories(self, status="succeeded"):
        created = []

        def build(scope, work_dir):
            adapter = InspectOnlyAdapter(
                recon_fakes.inspection(
                    status=status,
                    capabilities=("-d", "-json", "-silent"),
                )
            )
            created.append(adapter)
            return adapter

        return factories(build, build, build), created

    def test_validate_only_has_no_side_effects(self):
        fac, created = self.inspect_factories()
        code, out, err = self.run_cli(
            [
                "--workspace-root",
                str(self.root),
                "--domains",
                str(self.domains),
                "--run-id",
                RUN_ID,
                "--validate-only",
            ],
            fac=fac,
        )
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("mode: validate-only", out)
        self.assertIn(RUN_ID, out)
        self.assertIn("run-dir:", out)
        # Nothing created anywhere.
        self.assertEqual(list((self.root / "projects").iterdir()), [])
        # Inspection only; never run().
        self.assertEqual(sum(a.inspect_calls for a in created), 3)
        self.assertEqual(sum(a.run_calls for a in created), 0)

    def test_validate_only_reports_missing_tools(self):
        fac, _ = self.inspect_factories(status="tool_not_available")
        code, out, _ = self.run_cli(
            [
                "--workspace-root",
                str(self.root),
                "--domains",
                str(self.domains),
                "--validate-only",
            ],
            fac=fac,
        )
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("tool_not_available", out)

    def test_validate_only_inspects_each_tool_once_for_many_roots(self):
        self.domains.write_text("a.example.com\nb.example.com\n", encoding="utf-8")
        fac, created = self.inspect_factories()
        code, out, _ = self.run_cli(
            [
                "--workspace-root",
                str(self.root),
                "--domains",
                str(self.domains),
                "--validate-only",
            ],
            fac=fac,
        )
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(sum(a.inspect_calls for a in created), 3)
        self.assertIn("a.example.com", out)
        self.assertIn("b.example.com", out)
        self.assertIn("tools:", out)

    def test_input_outside_workspace_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as outside_dir:
            outside = Path(outside_dir) / "domains.txt"
            outside.write_bytes(b"\xff\xfe")  # invalid UTF-8; must not be read
            code, _, err = self.run_cli(
                ["--workspace-root", str(self.root), "--domains", str(outside)],
                fac=self.inspect_factories()[0],
            )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("outside the workspace root", err)
        self.assertNotIn("UTF-8", err)

    def test_dotdot_escape_rejected(self):
        escape = self.root / ".." / "escape_domains.txt"
        code, _, err = self.run_cli(
            ["--workspace-root", str(self.root), "--domains", str(escape)],
            fac=self.inspect_factories()[0],
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("outside the workspace root", err)

    def test_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as outside_dir:
            target = Path(outside_dir) / "domains.txt"
            target.write_text("example.com\n", encoding="utf-8")
            link = self.root / "link_domains.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable on this platform")
            code, _, err = self.run_cli(
                ["--workspace-root", str(self.root), "--domains", str(link)],
                fac=self.inspect_factories()[0],
            )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("outside the workspace root", err)

    def test_actual_requires_latch(self):
        fac, _ = self.inspect_factories()
        code, out, err = self.run_cli(
            ["--workspace-root", str(self.root), "--domains", str(self.domains)],
            fac=fac,
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("--confirm-authorized", err)
        self.assertFalse((self.root / "projects" / "example.com").exists())

    def test_actual_runs_with_fake_adapters(self):
        scope_holder = {}

        def sf(scope, work_dir):
            return ResultAdapter(
                subfinder_result(scope, [{"host": f"www.{scope.roots[0].name}"}])
            )

        def am(scope, work_dir):
            return ResultAdapter(
                amass_result(scope, [{"name": f"api.{scope.roots[0].name}"}])
            )

        def dx(scope, work_dir):
            scope_holder["scope"] = scope
            return DnsAdapter(
                lambda candidates: dnsx_result(
                    scope,
                    [
                        {"host": h, "a": ["192.0.2.1"], "status_code": "NOERROR"}
                        for h in candidates
                    ],
                )
            )

        fac = factories(sf, am, dx)
        code, out, err = self.run_cli(
            [
                "--workspace-root",
                str(self.root),
                "--domains",
                str(self.domains),
                "--run-id",
                RUN_ID,
                "--confirm-authorized",
            ],
            fac=fac,
        )
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn("mode: actual", out)
        run_dir = self.root / "projects" / "example.com" / "recon" / RUN_ID
        self.assertTrue((run_dir / "assets.json").is_file())
        document = json.loads((run_dir / "assets.json").read_text(encoding="utf-8"))
        self.assertEqual(document["root_domain"], "example.com")
        self.assertEqual(
            [a["hostname"] for a in document["assets"]],
            ["api.example.com", "example.com", "www.example.com"],
        )

    def test_fixture_actual_requires_explicit_run_id(self):
        fac, _ = self.inspect_factories()
        code, _, err = self.run_cli(
            [
                "--workspace-root",
                str(self.root),
                "--domains",
                str(self.domains),
                "--confirm-authorized",
            ],
            fac=fac,
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("explicit --run-id", err)
        self.assertEqual(list((self.root / "projects").iterdir()), [])

    def test_existing_run_dir_is_validation_error(self):
        run_dir = self.root / "projects" / "example.com" / "recon" / RUN_ID
        run_dir.mkdir(parents=True)
        code, _, err = self.run_cli(
            [
                "--workspace-root",
                str(self.root),
                "--domains",
                str(self.domains),
                "--run-id",
                RUN_ID,
                "--validate-only",
            ],
            fac=self.inspect_factories()[0],
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertIn("already exist", err)

    def test_exclude_file_is_applied(self):
        exclude = self.root / "exclude.txt"
        exclude.write_text("www.example.com\n", encoding="utf-8")
        plan_args = [
            "--workspace-root",
            str(self.root),
            "--domains",
            str(self.domains),
            "--exclude",
            str(exclude),
            "--validate-only",
        ]
        code, out, _ = self.run_cli(plan_args, fac=self.inspect_factories()[0])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("exclude-file:", out)


class CliParserTests(unittest.TestCase):
    def test_rejects_unknown_or_forbidden_options(self):
        parser = cli.build_parser()
        for extra in (["--target", "example.com"], ["--url", "https://x"], ["--api-key", "k"]):
            with self.subTest(extra=extra):
                with self.assertRaises(SystemExit):
                    parser.parse_args(
                        ["--workspace-root", "x", "--domains", "y", *extra]
                    )

    def test_parser_has_no_forbidden_options(self):
        parser = cli.build_parser()
        options = {
            option for action in parser._actions for option in action.option_strings
        }
        for forbidden in (
            "--target",
            "--url",
            "--api-key",
            "--token",
            "--tool",
            "--flags",
            "--dns-server",
            "--provider",
        ):
            self.assertNotIn(forbidden, options)
        self.assertIn("--validate-only", options)
        self.assertIn("--confirm-authorized", options)


class WrapperTests(unittest.TestCase):
    def test_wrapper_exposes_main(self):
        repo_root = Path(__file__).resolve().parents[2]
        source = repo_root / "scripts" / "recon_assets.py"
        namespace = {"__name__": "recon_assets_wrapper_test", "__file__": str(source)}
        exec(compile(source.read_text(encoding="utf-8"), str(source), "exec"), namespace)
        self.assertTrue(callable(namespace["main"]))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
