"""Scan orchestration primitives.

This package currently contains no scanner client. It only provides atomic,
scan-directory-scoped state persistence used by later orchestration steps.
"""

from .state import (
    STATE_FILENAME,
    ScanStateError,
    atomic_write_json,
    read_json_object,
    read_state,
    write_state,
)

__all__ = [
    "STATE_FILENAME",
    "ScanStateError",
    "atomic_write_json",
    "read_json_object",
    "read_state",
    "write_state",
]
