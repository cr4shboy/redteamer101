"""Deterministic, offline project code-readiness checks."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO


PROJECT_ROOT = Path(__file__).resolve().parents[3]
REQUIRED_FILES = (
    "AGENTS.md",
    "PROJECT.md",
    "CURRENT_TASK.md",
    "pyproject.toml",
    "capability.py",
    "capabilities/registry.yaml",
)
REQUIRED_DIRECTORIES = ("src", "scripts", "tests")
CLI_WRAPPERS = (
    "scripts/recon_plan.py",
    "scripts/recon_assets.py",
    "scripts/stage2_spider.py",
    "scripts/smoke_zap.py",
    "scripts/scan_target.py",
    "scripts/project_doctor.py",
)
REQUIRED_ENTRY_KEYS = ("type", "status", "path", "description")
VALID_STATUSES = frozenset(("available", "missing"))
MAX_BLOCKERS = 20


def parse_registry(text: str) -> dict[str, dict[str, str]]:
    """Parse the mapping-of-scalar-mappings YAML subset used by the registry."""
    registry: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line[0] not in (" ", "\t"):
            if not line.endswith(":"):
                raise ValueError(f"line {lineno}: expected '<name>:'")
            name = line[:-1].strip()
            if not name:
                raise ValueError(f"line {lineno}: empty name")
            if name in registry:
                raise ValueError(f"line {lineno}: duplicate name '{name}'")
            current = {}
            registry[name] = current
            continue
        if current is None:
            raise ValueError(f"line {lineno}: indented entry before any name")
        key, separator, value = line.strip().partition(":")
        key = key.strip()
        if not separator or not key:
            raise ValueError(f"line {lineno}: expected '<key>: <value>'")
        if key in current:
            raise ValueError(f"line {lineno}: duplicate key '{key}'")
        current[key] = value.strip()
    return registry


def readiness_blockers(
    root: Path = PROJECT_ROOT,
    python_version: tuple[int, ...] | None = None,
) -> list[str]:
    """Return deterministic blockers without changing state or using the network."""
    blockers: list[str] = []
    version = python_version or tuple(sys.version_info)
    if version < (3, 10):
        blockers.append("Python 3.10 or newer is required")

    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            blockers.append(f"missing required file: {relative}")
    for relative in REQUIRED_DIRECTORIES:
        if not (root / relative).is_dir():
            blockers.append(f"missing required directory: {relative}/")
    for relative in CLI_WRAPPERS:
        if not (root / relative).is_file():
            blockers.append(f"missing CLI wrapper: {relative}")

    registry_path = root / "capabilities" / "registry.yaml"
    try:
        registry = parse_registry(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        blockers.append(f"invalid capability registry: {exc}")
        return blockers[:MAX_BLOCKERS]

    resolved_root = root.resolve()
    for name, entry in registry.items():
        missing_keys = [key for key in REQUIRED_ENTRY_KEYS if key not in entry]
        if missing_keys:
            blockers.append(
                f"registry entry '{name}' missing fields: {', '.join(missing_keys)}"
            )
            continue
        status = entry["status"]
        if status not in VALID_STATUSES:
            blockers.append(f"registry entry '{name}' has invalid status: {status}")
            continue
        if status != "available":
            continue
        capability_path = (root / entry["path"]).resolve()
        try:
            capability_path.relative_to(resolved_root)
        except ValueError:
            blockers.append(f"available capability '{name}' path escapes project root")
            continue
        if not capability_path.is_dir():
            blockers.append(f"available capability '{name}' directory is missing")
        elif not (capability_path / "run.py").is_file():
            blockers.append(f"available capability '{name}' is missing run.py")

    return blockers[:MAX_BLOCKERS]


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run the read-only readiness check and print deterministic results."""
    del stderr  # Reserved for the common CLI signature; output is one report.
    if argv:
        print("blocker: project_doctor takes no arguments", file=stdout)
        print("code readiness: blocked", file=stdout)
        print("live execution authorization: not evaluated", file=stdout)
        return 2

    blockers = readiness_blockers()
    if blockers:
        print("code readiness: blocked", file=stdout)
        for blocker in blockers:
            print(f"blocker: {blocker}", file=stdout)
    else:
        print("code readiness: ready", file=stdout)
    print("live execution authorization: not evaluated", file=stdout)
    return 1 if blockers else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
