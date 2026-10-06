"""Linux/WSL-only integration tests for the sandbox runner with a fake tool.

These tests never invoke a pinned tool and never contact the network: they
launch the real unprivileged network namespace with a tiny fake executable that
only prints canned JSON. On non-Linux platforms they are skipped.
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon.runner import SandboxToolRunner
from red_teaming.recon.tool_argv import LIVE, ToolCommandSpec, expected_live_argv

REPO_SRC = str(Path(__file__).resolve().parents[2] / "src")


def _write_script(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux/WSL only")
class SandboxRunnerIntegrationTests(unittest.TestCase):
    def test_live_invocation_executes_fake_tool_in_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            script = _write_script(
                work / "fake-subfinder",
                "#!/bin/sh\nprintf '%s\\n' '{\"host\":\"www.acme.example\"}'\n",
            )
            spec = ToolCommandSpec(
                "subfinder", "2.16.0", str(script), root="acme.example"
            )
            runner = SandboxToolRunner(
                spec=spec, work_dir=work, src_path=REPO_SRC, timeout=30.0
            )
            completed = runner(expected_live_argv(spec))
            self.assertEqual(completed.returncode, 0)
            self.assertIn("www.acme.example", completed.stdout)
            self.assertEqual(runner.evidence[0]["invocation"], LIVE)
            self.assertEqual(runner.evidence[0]["sandbox"]["event"], "ready")

    def test_timeout_kills_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            script = _write_script(work / "fake-slow", "#!/bin/sh\nsleep 60\n")
            spec = ToolCommandSpec(
                "subfinder", "2.16.0", str(script), root="acme.example"
            )
            runner = SandboxToolRunner(
                spec=spec, work_dir=work, src_path=REPO_SRC, timeout=2.0
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                runner(expected_live_argv(spec))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
