"""Exact option-token matching for untrusted tool help text.

Adapters must never decide a capability is supported from a substring test:
``"-a" in help`` is falsely satisfied by ``-aaaa`` and ``"-d" in help`` by
``-debug``. This module tokenizes short/long option flags exactly (respecting
word-ish boundaries) so a required option is only matched when it appears as a
standalone flag.
"""

from __future__ import annotations

import re
from typing import Iterable

__all__ = ["has_options", "option_tokens", "select_option"]

#: Matches a short or long option token (``-d``, ``--passive``, ``-aaaa``)
#: only when it is not embedded in a longer word/flag.
_OPTION_RE = re.compile(r"(?<![A-Za-z0-9_-])(--?[A-Za-z][A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")


def option_tokens(text: object) -> frozenset[str]:
    """Return the set of exact option tokens present in *text*."""

    if not isinstance(text, str):
        return frozenset()
    return frozenset(_OPTION_RE.findall(text))


def has_options(text: object, required: Iterable[str]) -> bool:
    """Return True only when every option in *required* is an exact token."""

    tokens = option_tokens(text)
    return all(option in tokens for option in required)


def select_option(text: object, options: Iterable[str]) -> str | None:
    """Return the first exact token from *options* present in *text*, else None."""

    tokens = option_tokens(text)
    for option in options:
        if option in tokens:
            return option
    return None
