"""Bounded, deterministic parsing of recon scope input files.

Input files are UTF-8 (strict) text with one entry per line. Whitespace is used
*only* to detect blank lines and full-line comments: a line whose stripped form
is empty is blank, and a line whose first non-whitespace character is ``#`` is a
comment. Every other line is returned **verbatim** (leading/trailing whitespace
and control characters preserved) so canonical
:class:`~red_teaming.recon.scope.DomainScope` validation rejects whitespace and
other abuse rather than silently trimming it. Inline ``#`` is *not* a comment
(domains cannot contain ``#``, so this stays unambiguous).
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "MAX_INPUT_BYTES",
    "MAX_INPUT_ENTRIES",
    "InputError",
    "parse_entries",
    "read_entries",
    "read_text",
]

#: Hard bound on a single input file's UTF-8 byte length.
MAX_INPUT_BYTES = 256 * 1024
#: Hard bound on the number of non-blank entries read from one input file.
MAX_INPUT_ENTRIES = 4096


class InputError(ValueError):
    """Raised when a recon input file is missing, oversized, or not valid UTF-8."""


def read_text(path: Path | str, *, max_bytes: int = MAX_INPUT_BYTES) -> str:
    """Read *path* as strict UTF-8 text, bounded to *max_bytes*."""

    candidate = Path(path)
    if not candidate.is_absolute():
        raise InputError("input path must be an absolute path")
    if not candidate.is_file():
        raise InputError(f"input file is missing or not a regular file: {candidate}")
    try:
        size = candidate.stat().st_size
    except OSError as exc:  # pragma: no cover - defensive
        raise InputError(f"cannot stat input file: {candidate}") from exc
    if size > max_bytes:
        raise InputError(
            f"input file exceeds the maximum of {max_bytes} bytes: {candidate}"
        )
    try:
        text = candidate.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"input file must be valid UTF-8: {candidate}") from exc
    except OSError as exc:
        raise InputError(f"cannot read input file: {candidate}") from exc
    if text.startswith("\ufeff"):
        text = text[1:]
    return text


def parse_entries(
    text: object, *, max_entries: int = MAX_INPUT_ENTRIES
) -> tuple[str, ...]:
    """Return non-blank, non-comment entries from *text*, bounded in count."""

    if not isinstance(text, str):
        raise InputError("input text must be a string")
    entries: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        # Preserve the entry exactly (splitlines already dropped the newline).
        entries.append(raw_line)
        if len(entries) > max_entries:
            raise InputError(
                f"input contains more than the maximum of {max_entries} entries"
            )
    return tuple(entries)


def read_entries(
    path: Path | str,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    max_entries: int = MAX_INPUT_ENTRIES,
) -> tuple[str, ...]:
    """Read and parse one bounded UTF-8 entry-per-line input file."""

    return parse_entries(read_text(path, max_bytes=max_bytes), max_entries=max_entries)
