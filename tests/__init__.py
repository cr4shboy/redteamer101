"""Test package bootstrap.

Adds the ``src`` directory to ``sys.path`` so the tests run against the
in-tree package without any installation step.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
