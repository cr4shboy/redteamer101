#!/usr/bin/env python
"""Directly runnable thin wrapper for the bounded Stage 2 traditional Spider CLI.

The repository ``src`` directory is resolved relative to this file, never the
current working directory, so the wrapper can be invoked from anywhere without
installing the package.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"

if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from red_teaming.cli.stage2_spider import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
