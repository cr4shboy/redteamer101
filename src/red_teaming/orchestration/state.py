"""Atomic, scan-directory-scoped JSON state persistence.

State files are written as UTF-8 JSON with stable (sorted, indented) keys via
a temporary sibling file followed by :func:`os.replace`, so readers never see
a partially written file. Writes are refused unless the destination path is
lexically contained in the supplied scan directory.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ..projects.models import ValidationError
from ..projects.paths import ScanPath, is_within

__all__ = [
    "STATE_FILENAME",
    "ScanStateError",
    "atomic_write_json",
    "read_json_object",
    "read_state",
    "write_state",
]

STATE_FILENAME = "scan.json"


class ScanStateError(ValueError):
    """Raised when scan state is invalid or would be written unsafely."""


def _normalize(path: os.PathLike | str) -> Path:
    return Path(os.path.normpath(os.fspath(path)))


def atomic_write_json(
    path: os.PathLike | str,
    state: dict,
    *,
    scan_dir: os.PathLike | str,
) -> Path:
    """Atomically write *state* to *path*, bounded by *scan_dir*.

    The parent directory of *path* must already exist; directory creation is
    an explicit caller responsibility (see :meth:`ScanPath.create`).
    """

    if not isinstance(state, dict):
        raise ScanStateError("scan state must be a JSON object")

    target = _normalize(path)
    boundary = _normalize(scan_dir)
    if not is_within(target, boundary):
        raise ScanStateError("refusing to write state outside the scan directory")

    payload = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp), str(target))
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    return target


def read_json_object(path: os.PathLike | str) -> dict:
    """Read *path* as a UTF-8 JSON object, rejecting any other root type."""

    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ScanStateError("root JSON value must be an object")
    return value


def write_state(scan_path: ScanPath, state: dict) -> Path:
    """Create the scan directory (if needed) and atomically write its state."""

    if not isinstance(scan_path, ScanPath):
        raise TypeError("write_state expects a ScanPath instance")
    if not isinstance(state, dict):
        raise ScanStateError("scan state must be a JSON object")

    scan_path.create()
    target = scan_path.state_file_path(STATE_FILENAME)
    try:
        return atomic_write_json(target, state, scan_dir=scan_path.scan_dir)
    except ValidationError as exc:  # pragma: no cover - defensive
        raise ScanStateError(str(exc)) from exc


def read_state(scan_path: ScanPath) -> dict:
    """Read and validate the state object for *scan_path*."""

    if not isinstance(scan_path, ScanPath):
        raise TypeError("read_state expects a ScanPath instance")
    target = scan_path.state_file_path(STATE_FILENAME)
    if not target.is_file():
        raise FileNotFoundError(f"no scan state at {target}")
    return read_json_object(target)
