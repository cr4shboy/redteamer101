"""Pure/local pinned-tool and runtime preflight for RECON-002.

This module answers two fail-closed questions *without* starting a tool,
opening a socket, or changing any system state:

1. **Runtime** — is this the exact authorized runtime (Linux under
   ``Ubuntu 24.04`` WSL2 on x86_64)? The check is derived from
   ``/etc/os-release`` text, the POSIX ``uname`` fields, and the kernel release
   string's Microsoft WSL2 indicators. Every input is injectable so the logic is
   unit-testable on any platform.

2. **Pinned installs** — do the three TOOLING-001 canonical install directories
   under ``<workspace>/.tools/wsl/<tool>/<version>/`` contain exactly the tool
   binary, its official checksum file, and ``install-manifest.json``; is nothing
   a symlink or an escape; and does each manifest describe exactly the pinned
   TOOLING-001 package/version/platform/distro/artifact/SHA and persist no
   redirect URL or query string?

Nothing here is imported for its side effects, and no binary is executed. File
reads and SHA-256 hashing are read-only; the caller decides whether to run the
full check.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

__all__ = [
    "EXPECTED_DISTRO",
    "EXPECTED_PLATFORM",
    "PINNED_TOOLS",
    "PINNED_TOOL_ORDER",
    "InstallReport",
    "ManifestError",
    "PinnedToolSpec",
    "RuntimeReport",
    "binary_is_executable",
    "check_runtime",
    "host_runtime_report",
    "install_dir_for",
    "parse_checksum_file",
    "parse_os_release",
    "verify_all_installs",
    "verify_archive_checksum",
    "verify_install",
]

#: Exact runtime identity authorized by ``CURRENT_TASK.md``.
EXPECTED_DISTRO = "Ubuntu-24.04"
EXPECTED_PLATFORM = "linux_amd64"

#: Canonical TOOLING-001 install layout (order-insensitive, exact set).
CANONICAL_LAYOUT = ("binary", "checksum_file", "install-manifest.json")
MANIFEST_FILENAME = "install-manifest.json"

#: Workspace-relative tool root.
TOOLS_SUBPATH = (".tools", "wsl")


class ManifestError(ValueError):
    """An install manifest or directory failed a pinned-tool check."""


@dataclass(frozen=True)
class PinnedToolSpec:
    """Immutable description of one pinned TOOLING-001 tool."""

    tool: str
    version: str
    binary_name: str
    checksum_file: str
    artifact: str
    sha256: str

    @property
    def layout(self) -> tuple[str, ...]:
        return CANONICAL_LAYOUT


#: The three and only three pinned tools, with the CURRENT_TASK/TOOLING-001
#: SHA-256 values (AGENTS.md and CURRENT_TASK.md agree on these).
PINNED_TOOL_ORDER = ("subfinder", "dnsx", "amass")

PINNED_TOOLS: Mapping[str, PinnedToolSpec] = {
    "subfinder": PinnedToolSpec(
        tool="subfinder",
        version="2.16.0",
        binary_name="subfinder",
        checksum_file="subfinder_2.16.0_checksums.txt",
        artifact="subfinder_2.16.0_linux_amd64.zip",
        sha256="1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60",
    ),
    "dnsx": PinnedToolSpec(
        tool="dnsx",
        version="1.3.1",
        binary_name="dnsx",
        checksum_file="dnsx_1.3.1_checksums.txt",
        artifact="dnsx_1.3.1_linux_amd64.zip",
        sha256="438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533",
    ),
    "amass": PinnedToolSpec(
        tool="amass",
        version="5.1.1",
        binary_name="amass",
        checksum_file="amass_checksums.txt",
        artifact="amass_linux_amd64.tar.gz",
        sha256="5e22b5f0239e7eb79439d60d43d3cd20dca2478588bc2242e91ab0c4f8fa40dd",
    ),
}


def install_dir_for(workspace_root: os.PathLike | str, spec: PinnedToolSpec) -> Path:
    """Return the canonical pinned install directory (no I/O)."""

    root = Path(os.fspath(workspace_root))
    return root.joinpath(*TOOLS_SUBPATH, spec.tool, spec.version)


# ---------------------------------------------------------------------------
# Runtime identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuntimeReport:
    """Structured result of the runtime identity check."""

    ok: bool
    detail: str
    os_id: str | None = None
    version_id: str | None = None
    sysname: str | None = None
    machine: str | None = None
    kernel_release: str | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "detail": self.detail,
            "os_id": self.os_id,
            "version_id": self.version_id,
            "sysname": self.sysname,
            "machine": self.machine,
            "kernel_release": self.kernel_release,
        }


def parse_os_release(text: object) -> dict[str, str]:
    """Parse ``/etc/os-release`` text into a mapping (pure).

    Handles ``KEY=value``, quoted values, comments, and blank lines. Keys and
    values are stripped; a malformed line is skipped rather than trusted.
    """

    if not isinstance(text, str):
        return {}
    parsed: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            parsed[key] = value
    return parsed


def check_runtime(
    *,
    platform: str,
    os_release_text: object,
    sysname: object,
    machine: object,
    kernel_release: object,
) -> RuntimeReport:
    """Validate the exact runtime identity from injected local facts (pure)."""

    fields = parse_os_release(os_release_text)
    os_id = fields.get("ID")
    version_id = fields.get("VERSION_ID")
    sysname_text = sysname if isinstance(sysname, str) else None
    machine_text = machine if isinstance(machine, str) else None
    kernel_text = kernel_release if isinstance(kernel_release, str) else None

    def report(ok: bool, detail: str) -> RuntimeReport:
        return RuntimeReport(
            ok=ok,
            detail=detail,
            os_id=os_id,
            version_id=version_id,
            sysname=sysname_text,
            machine=machine_text,
            kernel_release=kernel_text,
        )

    if not isinstance(platform, str) or not platform.startswith("linux"):
        return report(False, "runtime_platform_not_linux")
    if os_id != "ubuntu":
        return report(False, "runtime_distro_not_ubuntu")
    if version_id != "24.04":
        return report(False, "runtime_version_not_24_04")
    if sysname_text != "Linux":
        return report(False, "runtime_uname_not_linux")
    if machine_text not in ("x86_64", "amd64"):
        return report(False, "runtime_arch_not_x86_64")
    if not kernel_text:
        return report(False, "runtime_kernel_missing")
    lower = kernel_text.lower()
    if "microsoft" not in lower:
        return report(False, "runtime_not_wsl")
    if "wsl2" not in lower:
        return report(False, "runtime_not_wsl2")
    return report(True, "ok")


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def host_runtime_report(
    *,
    platform: str | None = None,
    os_release_path: os.PathLike | str = "/etc/os-release",
    kernel_release_path: os.PathLike | str = "/proc/sys/kernel/osrelease",
    uname: Callable[[], object] | None = None,
) -> RuntimeReport:
    """Collect local runtime facts and validate them (read-only, no subprocess).

    On non-Linux hosts this returns a fail-closed report. ``os.uname`` is used
    where available; no external ``uname`` binary is invoked and no system state
    is modified.
    """

    import sys

    platform_name = sys.platform if platform is None else platform

    sysname: object = None
    machine: object = None
    if uname is None:
        uname_fn = getattr(os, "uname", None)
    else:
        uname_fn = uname
    if uname_fn is not None:
        try:
            info = uname_fn()
            sysname = getattr(info, "sysname", None)
            machine = getattr(info, "machine", None)
        except (OSError, AttributeError):  # pragma: no cover - defensive
            sysname = None
            machine = None

    return check_runtime(
        platform=platform_name,
        os_release_text=_read_text(Path(os.fspath(os_release_path))),
        sysname=sysname,
        machine=machine,
        kernel_release=_read_text(Path(os.fspath(kernel_release_path))),
    )


# ---------------------------------------------------------------------------
# Pinned install directory + manifest verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallReport:
    """Structured result of one pinned-install verification."""

    tool: str
    version: str
    ok: bool
    install_dir: str
    binary_path: str | None = None
    reason: str | None = None
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "version": self.version,
            "ok": self.ok,
            "install_dir": self.install_dir,
            "binary_path": self.binary_path,
            "reason": self.reason,
            "detail": dict(self.detail),
        }


def _reject_symlinks(start: Path, target: Path) -> None:
    """Reject any component between *start* (exclusive) and *target* that is a symlink."""

    chain: list[Path] = []
    current = target
    while current != start and current != current.parent:
        chain.append(current)
        current = current.parent
    for component in reversed(chain):
        try:
            if component.is_symlink():
                raise ManifestError("install path contains a symlink component")
        except OSError as exc:  # pragma: no cover - defensive
            raise ManifestError("install path could not be inspected") from exc


def _assert_within(workspace_root: Path, path: Path) -> None:
    try:
        resolved = Path(os.path.realpath(os.fspath(path)))
        root = Path(os.path.realpath(os.fspath(workspace_root)))
    except OSError as exc:  # pragma: no cover - defensive
        raise ManifestError("install path could not be resolved") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ManifestError("install path escapes the workspace root") from exc


def _iter_string_values(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_string_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_string_values(item)


def _validate_manifest(manifest: object, spec: PinnedToolSpec, workspace_root: Path) -> dict:
    if not isinstance(manifest, dict):
        raise ManifestError("install manifest must be a JSON object")

    expected_fields = {
        "package": "TOOLING-001",
        "tool": spec.tool,
        "version": spec.version,
        "platform": EXPECTED_PLATFORM,
        "distro": EXPECTED_DISTRO,
        "artifact": spec.artifact,
        "sha256": spec.sha256,
        "sha256_expected": spec.sha256,
    }
    for key, expected in expected_fields.items():
        if manifest.get(key) != expected:
            raise ManifestError(f"install manifest field {key!r} is not the pinned value")

    if manifest.get("sha256_verified") is not True:
        raise ManifestError("install manifest does not record a verified SHA-256")

    layout = manifest.get("install_layout")
    if not isinstance(layout, list) or sorted(layout) != sorted(CANONICAL_LAYOUT):
        raise ManifestError("install manifest layout is not canonical")

    if manifest.get("redirect_urls_persisted") is not False:
        raise ManifestError("install manifest must not persist redirect URLs")

    install_dir = manifest.get("install_dir")
    if not isinstance(install_dir, str) or not install_dir:
        raise ManifestError("install manifest install_dir is missing")
    normalized_manifest_dir = install_dir.replace("\\", "/").rstrip("/").lower()
    expected_suffix = f".tools/wsl/{spec.tool}/{spec.version}".lower()
    if not normalized_manifest_dir.endswith(expected_suffix):
        raise ManifestError("install manifest install_dir is not the canonical layout")

    # No redirect URL/query persistence anywhere in the manifest.
    for key in manifest:
        lowered = str(key).lower()
        if lowered in ("redirect_url", "redirect_urls", "redirect_query"):
            raise ManifestError("install manifest persists a redirect URL")
    for text in _iter_string_values(manifest):
        if "?" in text:
            raise ManifestError("install manifest persists a query string")
    # Redirect evidence may only record a status and a hostname.
    redirect_evidence = manifest.get("redirect_evidence", [])
    if not isinstance(redirect_evidence, list):
        raise ManifestError("install manifest redirect_evidence must be a list")
    for entry in redirect_evidence:
        if not isinstance(entry, dict) or set(entry) - {"status", "host"}:
            raise ManifestError("install manifest redirect evidence is not host-only")
        if not isinstance(entry.get("status"), str) or not isinstance(entry.get("host"), str):
            raise ManifestError("install manifest redirect evidence is malformed")
        if "/" in entry["host"] or "?" in entry["host"]:
            raise ManifestError("install manifest redirect evidence persists a URL")
    return manifest


def parse_checksum_file(text: object) -> dict[str, str]:
    """Parse an official ``sha256sum``-style checksum file (pure).

    Returns a mapping of archive filename to lowercase SHA-256 hex. A malformed
    line, a non-SHA-256 digest, an unsafe filename, or a duplicate filename
    raises :class:`ManifestError` (fail closed): the retained TOOLING-001
    checksum files are expected to be exact and unambiguous.
    """

    if not isinstance(text, str):
        raise ManifestError("checksum file must be text")
    entries: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ManifestError("checksum file contains a malformed line")
        digest = parts[0].strip().lower()
        filename = parts[1].strip()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ManifestError("checksum file contains a non-SHA-256 digest")
        if filename.startswith("*"):
            filename = filename[1:]
        if not filename or "/" in filename or "\\" in filename or "?" in filename:
            raise ManifestError("checksum file contains an unsafe filename")
        if filename in entries:
            raise ManifestError("checksum file contains a duplicate entry")
        entries[filename] = digest
    return entries


def verify_archive_checksum(text: object, spec: PinnedToolSpec) -> dict:
    """Require an exact official checksum entry for the pinned release archive.

    This validates the *release archive* checksum recorded by TOOLING-001. It is
    deliberately **not** the extracted binary's hash and must never be reported
    as one. Rejects a missing, duplicate, malformed, or mismatched entry.
    """

    entries = parse_checksum_file(text)
    if spec.artifact not in entries:
        raise ManifestError("official checksum file has no entry for the pinned archive")
    actual = entries[spec.artifact]
    expected = spec.sha256.lower()
    if actual != expected:
        raise ManifestError(
            "official checksum entry does not match the pinned archive SHA-256"
        )
    return {"filename": spec.artifact, "sha256": actual}


def binary_is_executable(path: Path) -> bool:
    """Return True only for a regular, non-symlink, executable file.

    On POSIX the execute bit is required. Windows NTFS does not persist the
    POSIX execute bit for these extensionless Linux binaries, so there the
    authoritative execute check is the WSL (POSIX) run and only a readable
    regular file is required here.
    """

    try:
        if path.is_symlink() or not path.is_file():
            return False
        if os.name == "posix":
            return os.access(path, os.X_OK)
        return os.access(path, os.R_OK)
    except OSError:
        return False


def verify_install(
    workspace_root: os.PathLike | str,
    spec: PinnedToolSpec,
    *,
    digest: Callable[[Path], str] | None = None,
    verify_checksum: bool = True,
    compute_binary_digest: bool = True,
    executable_check: Callable[[Path], bool] | None = None,
) -> InstallReport:
    """Verify one pinned install directory, manifest, and official archive checksum.

    The TOOLING-001 ``sha256``/manifest values are **release archive** hashes, so
    this parses the retained official checksum file and requires an exact,
    unambiguous entry mapping the expected archive filename to the expected
    archive SHA. A binary SHA-256 may be computed as an **observational evidence**
    value but is never compared to the archive SHA and is never labelled
    upstream-verified.

    Every failure is returned as ``ok=False`` with a stable reason token; the
    function never raises for a missing/invalid install and never modifies the
    filesystem.
    """

    workspace = Path(os.fspath(workspace_root))
    install_dir = install_dir_for(workspace, spec)
    base = InstallReport(
        tool=spec.tool,
        version=spec.version,
        ok=False,
        install_dir=str(install_dir),
    )

    try:
        _assert_within(workspace, install_dir)
    except ManifestError as exc:
        base = InstallReport(
            tool=spec.tool,
            version=spec.version,
            ok=False,
            install_dir=str(install_dir),
            reason=str(exc),
        )
        return base

    try:
        if not install_dir.is_dir():
            raise ManifestError("install directory is missing or not a directory")
        _reject_symlinks(workspace, install_dir)

        entries = sorted(entry.name for entry in install_dir.iterdir())
        expected_entries = sorted((spec.binary_name, spec.checksum_file, MANIFEST_FILENAME))
        if entries != expected_entries:
            raise ManifestError("install directory does not contain exactly the canonical files")

        binary_path = install_dir / spec.binary_name
        checksum_path = install_dir / spec.checksum_file
        manifest_path = install_dir / MANIFEST_FILENAME
        for entry in (binary_path, checksum_path, manifest_path):
            if entry.is_symlink() or not entry.is_file():
                raise ManifestError(f"install entry is not a regular file: {entry.name}")

        try:
            raw = manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError("install manifest could not be read as JSON") from exc
        manifest = _validate_manifest(manifest, spec, workspace)

        if not (executable_check or binary_is_executable)(binary_path):
            raise ManifestError(
                "binary is not a regular non-symlink executable file"
            )

        checksum_entry = None
        if verify_checksum:
            try:
                checksum_text = checksum_path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError as exc:
                raise ManifestError("official checksum file could not be read") from exc
            checksum_entry = verify_archive_checksum(checksum_text, spec)

        # Observational only: the extracted binary hash is recorded as evidence
        # and is never compared to the release archive SHA or called verified.
        binary_digest = None
        if compute_binary_digest:
            hasher = digest if digest is not None else _sha256_file
            binary_digest = hasher(binary_path)
    except ManifestError as exc:
        return InstallReport(
            tool=spec.tool,
            version=spec.version,
            ok=False,
            install_dir=str(install_dir),
            reason=str(exc),
        )
    except OSError as exc:  # pragma: no cover - defensive
        return InstallReport(
            tool=spec.tool,
            version=spec.version,
            ok=False,
            install_dir=str(install_dir),
            reason=f"install inspection failed: {type(exc).__name__}",
        )

    return InstallReport(
        tool=spec.tool,
        version=spec.version,
        ok=True,
        install_dir=str(install_dir),
        binary_path=str(binary_path),
        detail={
            "artifact": spec.artifact,
            "archive_sha256": spec.sha256,
            "checksum_entry": checksum_entry,
            "binary_sha256": binary_digest,
            "binary_sha256_verified": False,
            "binary_sha256_source": "observational",
            "layout": list(manifest.get("install_layout", [])),
            "redirect_hosts": sorted(
                {
                    entry["host"]
                    for entry in manifest.get("redirect_evidence", [])
                    if isinstance(entry, dict) and isinstance(entry.get("host"), str)
                }
            ),
            "redirect_statuses": sorted(
                {
                    entry["status"]
                    for entry in manifest.get("redirect_evidence", [])
                    if isinstance(entry, dict) and isinstance(entry.get("status"), str)
                }
            ),
        },
    )


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_all_installs(
    workspace_root: os.PathLike | str,
    *,
    digest: Callable[[Path], str] | None = None,
    verify_checksum: bool = True,
    compute_binary_digest: bool = True,
    executable_check: Callable[[Path], bool] | None = None,
) -> tuple[InstallReport, ...]:
    """Verify every pinned tool in canonical order."""

    return tuple(
        verify_install(
            workspace_root,
            PINNED_TOOLS[tool],
            digest=digest,
            verify_checksum=verify_checksum,
            compute_binary_digest=compute_binary_digest,
            executable_check=executable_check,
        )
        for tool in PINNED_TOOL_ORDER
    )
