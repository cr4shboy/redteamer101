"""Deterministic, workspace-root-relative path resolution.

Every project/target/scan path is derived from an explicitly supplied
*absolute* workspace root. The current working directory is never consulted.
No directory is created by parsing or validating input; callers must invoke
:meth:`ScanPath.create` explicitly.

The resulting layout is::

    <workspace>/projects/<normalized-domain>/targets/<normalized-target>/scans/zap/<scan-id>
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import ProjectDomain, Target, ValidationError, normalize_dns_name

__all__ = [
    "PROJECTS_DIRNAME",
    "PROJECT_ROOT_MARKERS",
    "SCANS_DIRNAME",
    "TARGETS_DIRNAME",
    "ZAP_DIRNAME",
    "ScanPath",
    "ensure_within",
    "generate_scan_id",
    "is_within",
    "project_dir",
    "repository_root",
    "require_workspace_root",
    "resolve_path",
    "scan_dir",
    "target_dir",
    "validate_scan_id",
    "zap_scan_root",
]

PROJECTS_DIRNAME = "projects"
TARGETS_DIRNAME = "targets"
SCANS_DIRNAME = "scans"
ZAP_DIRNAME = "zap"

#: Files/directories that must exist at the root of a valid workspace checkout.
PROJECT_ROOT_MARKERS = ("AGENTS.md", "PROJECT.md", "CURRENT_TASK.md")

_SCAN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]+$")
_SUFFIX_RE = re.compile(r"^[0-9a-f]+$")


def _normalize_path(path: os.PathLike | str) -> Path:
    return Path(os.path.normpath(os.fspath(path)))


def require_absolute_root(workspace_root: os.PathLike | str) -> Path:
    """Return a normalized absolute workspace root or raise ``ValidationError``."""

    root = Path(workspace_root)
    if not root.is_absolute():
        raise ValidationError("workspace root must be an absolute path")
    return _normalize_path(root)


def repository_root() -> Path:
    """Return this checkout's root, resolved from this source file (never cwd).

    ``paths.py`` lives at ``<root>/src/red_teaming/projects/paths.py``, so four
    resolved parents up is the repository root regardless of the current working
    directory.
    """

    return Path(__file__).resolve().parents[3]


def resolve_path(path: os.PathLike | str) -> Path:
    """Return a case-normalized, symlink/junction-resolved absolute path.

    ``strict=False`` semantics are used, so non-existent leaves are fine while
    any *existing* symlink or junction component is resolved. A Windows
    ``\\\\?\\`` extended-length prefix is stripped so the result compares
    cleanly against ordinary paths.
    """

    resolved = os.path.realpath(os.fspath(path))
    if resolved.startswith("\\\\?\\UNC\\"):
        resolved = "\\\\" + resolved[len("\\\\?\\UNC\\") :]
    elif resolved.startswith("\\\\?\\"):
        resolved = resolved[len("\\\\?\\") :]
    return Path(os.path.normcase(os.path.normpath(resolved)))


def _same_path(left: os.PathLike | str, right: os.PathLike | str) -> bool:
    return str(resolve_path(left)) == str(resolve_path(right))


def require_workspace_root(
    workspace_root: os.PathLike | str,
    *,
    expected_root: os.PathLike | str | None = None,
) -> Path:
    """Validate that *workspace_root* is the approved project checkout.

    The supplied root must be absolute, resolve to *expected_root* (which
    defaults to :func:`repository_root` resolved from this source file, not the
    current working directory), exist as a directory, and contain the project
    root markers plus the ``projects/`` directory. The optional ``expected_root``
    exists so unit tests can inject an isolated fixture root.
    """

    root = require_absolute_root(workspace_root)
    expected = (
        Path(expected_root) if expected_root is not None else repository_root()
    )
    if not _same_path(root, expected):
        raise ValidationError(
            "workspace root must resolve to this project checkout "
            f"({resolve_path(expected)})"
        )
    if not root.is_dir():
        raise ValidationError("workspace root must be an existing directory")
    for marker in PROJECT_ROOT_MARKERS:
        if not (root / marker).is_file():
            raise ValidationError(f"workspace root is missing required {marker}")
    if not (root / PROJECTS_DIRNAME).is_dir():
        raise ValidationError(
            f"workspace root is missing required {PROJECTS_DIRNAME}/ directory"
        )
    return root


def is_within(path: os.PathLike | str, base: os.PathLike | str) -> bool:
    """Return True when *path* is lexically contained in *base*."""

    candidate = _normalize_path(path)
    root = _normalize_path(base)
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def ensure_within(path: os.PathLike | str, base: os.PathLike | str) -> Path:
    """Return *path* when contained in *base*, otherwise raise ``ValidationError``."""

    normalized = _normalize_path(path)
    if not is_within(normalized, base):
        raise ValidationError(f"path escapes the approved root: {normalized}")
    return normalized


def _domain_name(domain: ProjectDomain | str) -> str:
    if isinstance(domain, ProjectDomain):
        return domain.name
    return normalize_dns_name(domain)


def _target_host(target: Target | str) -> str:
    if isinstance(target, Target):
        return target.host
    return normalize_dns_name(target)


def validate_scan_id(scan_id: str) -> str:
    """Validate and return a scan/run id (``YYYYMMDDThhmmssZ-<hex>``)."""

    if not isinstance(scan_id, str) or not _SCAN_ID_RE.match(scan_id):
        raise ValidationError(f"invalid scan id: {scan_id!r}")
    return scan_id


def _validate_scan_id(scan_id: str) -> str:
    return validate_scan_id(scan_id)


def generate_scan_id(
    now: datetime | None = None, suffix: str | None = None
) -> str:
    """Create a sortable, collision-resistant UTC scan id.

    The format is ``YYYYMMDDThhmmssZ-<hex>``. Both the timestamp and the short
    random suffix can be injected for deterministic tests.
    """

    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValidationError("scan id timestamp must be timezone-aware")
    now = now.astimezone(timezone.utc)

    if suffix is None:
        suffix = secrets.token_hex(3)
    if not isinstance(suffix, str) or not _SUFFIX_RE.match(suffix):
        raise ValidationError("scan id suffix must be lowercase hexadecimal")

    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{suffix}"


def project_dir(workspace_root: os.PathLike | str, domain: ProjectDomain | str) -> Path:
    return require_absolute_root(workspace_root) / PROJECTS_DIRNAME / _domain_name(domain)


def target_dir(
    workspace_root: os.PathLike | str,
    domain: ProjectDomain | str,
    target: Target | str,
) -> Path:
    return project_dir(workspace_root, domain) / TARGETS_DIRNAME / _target_host(target)


def zap_scan_root(
    workspace_root: os.PathLike | str,
    domain: ProjectDomain | str,
    target: Target | str,
) -> Path:
    return target_dir(workspace_root, domain, target) / SCANS_DIRNAME / ZAP_DIRNAME


def scan_dir(
    workspace_root: os.PathLike | str,
    domain: ProjectDomain | str,
    target: Target | str,
    scan_id: str,
) -> Path:
    return zap_scan_root(workspace_root, domain, target) / _validate_scan_id(scan_id)


@dataclass(frozen=True)
class ScanPath:
    """Resolved, containment-checked paths for one scan directory.

    Construct with :meth:`ScanPath.build`; directory creation only happens when
    :meth:`create` is called explicitly.
    """

    workspace_root: Path
    domain: str
    target: str
    project_dir: Path
    targets_dir: Path
    target_dir: Path
    scans_dir: Path
    zap_dir: Path
    scan_id: str
    scan_dir: Path

    @classmethod
    def build(
        cls,
        workspace_root: os.PathLike | str,
        domain: ProjectDomain | str,
        target: Target | str,
        scan_id: str | None = None,
        *,
        now: datetime | None = None,
        suffix: str | None = None,
    ) -> "ScanPath":
        root = require_absolute_root(workspace_root)
        domain_name = _domain_name(domain)
        target_host = _target_host(target)

        if target_host != domain_name and not target_host.endswith("." + domain_name):
            raise ValidationError("target host is not the project domain or a subdomain")

        if scan_id is None:
            scan_id = generate_scan_id(now=now, suffix=suffix)
        else:
            _validate_scan_id(scan_id)

        pdir = root / PROJECTS_DIRNAME / domain_name
        tdirs = pdir / TARGETS_DIRNAME
        tdir = tdirs / target_host
        scans = tdir / SCANS_DIRNAME
        zap = scans / ZAP_DIRNAME
        sdir = zap / scan_id

        path = cls(
            workspace_root=root,
            domain=domain_name,
            target=target_host,
            project_dir=pdir,
            targets_dir=tdirs,
            target_dir=tdir,
            scans_dir=scans,
            zap_dir=zap,
            scan_id=scan_id,
            scan_dir=sdir,
        )
        return path.validate()

    def validate(self) -> "ScanPath":
        """Verify the scan id and every generated path boundary."""

        _validate_scan_id(self.scan_id)
        require_absolute_root(self.workspace_root)

        ensure_within(self.project_dir, self.workspace_root)
        ensure_within(self.targets_dir, self.project_dir)
        ensure_within(self.target_dir, self.targets_dir)
        ensure_within(self.scans_dir, self.target_dir)
        ensure_within(self.zap_dir, self.scans_dir)
        ensure_within(self.scan_dir, self.zap_dir)

        expected_zap = (
            self.workspace_root
            / PROJECTS_DIRNAME
            / self.domain
            / TARGETS_DIRNAME
            / self.target
            / SCANS_DIRNAME
            / ZAP_DIRNAME
        )
        if self.zap_dir != _normalize_path(expected_zap):
            raise ValidationError("scan root does not match the expected layout")
        return self

    def create(self) -> Path:
        """Explicitly create (and return) the scan directory.

        This is the only method in this class that touches the filesystem.
        """

        self.validate()
        ensure_within(self.scan_dir, self.zap_dir)
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        return self.scan_dir

    def state_file_path(self, filename: str = "scan.json") -> Path:
        """Return a containment-checked file path inside the scan directory."""

        if not isinstance(filename, str) or not filename:
            raise ValidationError("state filename must be a non-empty string")
        if (
            filename in {".", ".."}
            or os.path.isabs(filename)
            or "/" in filename
            or "\\" in filename
            or ":" in filename
        ):
            raise ValidationError(f"state filename must be a simple name: {filename!r}")
        candidate = self.scan_dir / filename
        return ensure_within(candidate, self.scan_dir)
