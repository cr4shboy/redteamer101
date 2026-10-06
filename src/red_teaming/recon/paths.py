"""Immutable, per-domain recon run paths.

Layout::

    <workspace>/projects/<normalized-root>/recon/<run-id>/

Construction is side-effect free. Only :meth:`ReconPath.create` touches the
filesystem, and it refuses to reuse or overwrite an existing run directory so
that every run remains immutable evidence. Run ids reuse the existing
``generate_scan_id`` format and the public ``validate_scan_id`` validator.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..projects.models import ProjectDomain, ValidationError, normalize_dns_name
from ..projects.paths import (
    PROJECTS_DIRNAME,
    ensure_within,
    generate_scan_id,
    is_within,
    require_absolute_root,
    validate_scan_id,
)

__all__ = [
    "RECON_DIRNAME",
    "ReconPath",
    "ReconPathError",
    "recon_dir",
    "recon_run_dir",
    "validate_run_id",
]

RECON_DIRNAME = "recon"


class ReconPathError(ValidationError):
    """Raised when a recon path is invalid, unsafe, or already exists."""


def validate_run_id(run_id: str) -> str:
    """Validate and return a recon run id (same format as a scan id)."""

    try:
        return validate_scan_id(run_id)
    except ValidationError as exc:
        raise ReconPathError(str(exc)) from exc


def _root_name(root: ProjectDomain | str) -> str:
    if isinstance(root, ProjectDomain):
        return root.name
    return normalize_dns_name(root)


def recon_dir(workspace_root: os.PathLike | str, root: ProjectDomain | str) -> Path:
    """Return ``<workspace>/projects/<root>/recon`` without creating it."""

    return (
        require_absolute_root(workspace_root)
        / PROJECTS_DIRNAME
        / _root_name(root)
        / RECON_DIRNAME
    )


def recon_run_dir(
    workspace_root: os.PathLike | str,
    root: ProjectDomain | str,
    run_id: str,
) -> Path:
    """Return the recon run directory path without creating it."""

    return recon_dir(workspace_root, root) / validate_run_id(run_id)


@dataclass(frozen=True)
class ReconPath:
    """Resolved, containment-checked paths for one recon run."""

    workspace_root: Path
    root: str
    project_dir: Path
    recon_dir: Path
    run_id: str
    run_dir: Path

    @classmethod
    def build(
        cls,
        workspace_root: os.PathLike | str,
        root: ProjectDomain | str,
        run_id: str | None = None,
        *,
        now: datetime | None = None,
        suffix: str | None = None,
    ) -> "ReconPath":
        workspace = require_absolute_root(workspace_root)
        root_name = _root_name(root)

        if run_id is None:
            run_id = generate_scan_id(now=now, suffix=suffix)
        else:
            run_id = validate_run_id(run_id)

        project = workspace / PROJECTS_DIRNAME / root_name
        recon = project / RECON_DIRNAME
        run = recon / run_id

        path = cls(
            workspace_root=workspace,
            root=root_name,
            project_dir=project,
            recon_dir=recon,
            run_id=run_id,
            run_dir=run,
        )
        return path.validate()

    def validate(self) -> "ReconPath":
        """Verify the run id and every generated path boundary."""

        validate_run_id(self.run_id)
        require_absolute_root(self.workspace_root)

        ensure_within(self.project_dir, self.workspace_root)
        ensure_within(self.recon_dir, self.project_dir)
        ensure_within(self.run_dir, self.recon_dir)

        expected = (
            self.workspace_root
            / PROJECTS_DIRNAME
            / self.root
            / RECON_DIRNAME
            / self.run_id
        )
        if self.run_dir != expected:
            raise ReconPathError("recon run directory does not match the expected layout")
        return self

    def create(self) -> Path:
        """Explicitly create (and return) the run directory.

        The run directory must not already exist: reuse or overwrite is
        refused so prior runs stay immutable. Parent directories are created
        only inside the canonical project tree, which was validated on build.
        """

        self.validate()
        ensure_within(self.run_dir, self.project_dir)
        if self.run_dir.exists():
            raise ReconPathError(
                f"recon run directory already exists and must not be reused: {self.run_dir}"
            )
        self.run_dir.mkdir(parents=True, exist_ok=False)
        return self.run_dir

    def file_path(self, filename: str = "recon.json") -> Path:
        """Return a containment-checked, single-segment file path in the run dir."""

        if not isinstance(filename, str) or not filename:
            raise ReconPathError("file name must be a non-empty string")
        if (
            filename in {".", ".."}
            or os.path.isabs(filename)
            or "/" in filename
            or "\\" in filename
            or ":" in filename
        ):
            raise ReconPathError(f"file name must be a simple name: {filename!r}")
        candidate = self.run_dir / filename
        try:
            return ensure_within(candidate, self.run_dir)
        except ValidationError as exc:  # pragma: no cover - defensive
            raise ReconPathError(str(exc)) from exc

    # Alias kept for symmetry with ScanPath.state_file_path.
    def state_file_path(self, filename: str = "recon.json") -> Path:
        return self.file_path(filename)

    def contains(self, path: os.PathLike | str) -> bool:
        """Return True when *path* is lexically contained in the run directory."""

        return is_within(path, self.run_dir)
