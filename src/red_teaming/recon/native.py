"""Native (non-sandboxed) runtime for macOS and other non-WSL platforms.

Discovers tool binaries via ``shutil.which`` or explicit paths, validates
versions, and builds adapter factories that run tools directly via
``subprocess.run`` — no network namespace, no pinned-binary checks, no WSL.

The pipeline itself (``run_root_pipeline`` / ``run_batch``) is unchanged;
only the runtime wiring differs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .pipeline import AdapterFactories
from .scope import DomainScope

__all__ = [
    "NativeRuntime",
    "NativeRuntimeError",
]

EXPECTED_VERSIONS = {
    "subfinder": "2.16.0",
    "amass": "5.1.1",
    "dnsx": "1.3.1",
}


class NativeRuntimeError(ValueError):
    """Native runtime setup failed."""


def _detect_binary(tool: str, which: Callable[[str], str | None] = shutil.which) -> str:
    path = which(tool)
    if path is None:
        raise NativeRuntimeError(f"{tool} not found in PATH")
    return path


def _check_version(tool: str, binary: str, expected: str) -> str:
    try:
        result = subprocess.run(
            [binary, "-version"],
            capture_output=True, text=True, timeout=10,
        )
        combined = result.stdout + result.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NativeRuntimeError(f"{tool}: version check failed: {exc}") from exc
    for line in combined.splitlines():
        if expected in line:
            return expected
    raise NativeRuntimeError(
        f"{tool}: expected version {expected}, got: {combined.strip()[:200]}"
    )


@dataclass
class NativeRuntime:
    """Non-sandboxed runtime using PATH-available tool binaries."""

    root: str
    workspace_root: Path
    timeout: float = 120.0
    which: Callable[[str], str | None] = shutil.which
    binaries: dict[str, str] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)

    def preflight(self) -> None:
        for tool, expected in EXPECTED_VERSIONS.items():
            binary = _detect_binary(tool, self.which)
            _check_version(tool, binary, expected)
            self.binaries[tool] = binary
            self.versions[tool] = expected

    def factories(self) -> AdapterFactories:
        if not self.binaries:
            self.preflight()
        return AdapterFactories(
            subfinder=self._build_factory("subfinder"),
            amass=self._build_factory("amass"),
            dnsx=self._build_factory("dnsx"),
        )

    def _build_factory(self, tool: str):
        binary = self.binaries[tool]
        root = self.root
        timeout = self.timeout

        def factory(scope: DomainScope, work_dir):
            work = Path(work_dir)
            kwargs = dict(
                scope=scope,
                work_dir=work,
                executable=binary,
                runner=subprocess.run,
                timeout=timeout,
            )
            if tool == "subfinder":
                from ..tools.subfinder import SubfinderAdapter
                return SubfinderAdapter(**kwargs)
            if tool == "dnsx":
                from ..tools.dnsx import DnsxAdapter
                return DnsxAdapter(**kwargs)
            if tool == "amass":
                from ..tools.amass import AmassAdapter
                return AmassAdapter(**kwargs)
            raise NativeRuntimeError(f"unsupported tool: {tool}")

        return factory
