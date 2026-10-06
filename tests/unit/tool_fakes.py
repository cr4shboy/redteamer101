"""Shared offline fakes for discovery-adapter tests.

Nothing here launches a real process or contacts the network: callers inject
:class:`FakeRunner` as the adapter's ``runner`` and a fake executable path (or a
``which`` callable) as the executable lookup.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def completed(argv, *, code: int = 0, stdout: str = "", stderr: str = ""):
    """Build a ``subprocess.CompletedProcess`` for a fake runner."""

    return subprocess.CompletedProcess(list(argv), code, stdout=stdout, stderr=stderr)


def make_fake_executable(directory, name: str) -> Path:
    """Create a small fake executable file and return its absolute path."""

    path = Path(directory) / name
    path.write_text("fake executable\n", encoding="utf-8")
    return path


class FakeRunner:
    """A ``subprocess.run`` stand-in that records calls and dispatches results.

    ``responses`` is a sequence of ``(matcher, response)`` pairs. ``matcher``
    receives the argv list; ``response`` is either a ``CompletedProcess``, an
    exception instance to raise, or a callable taking argv and returning one of
    those.
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], dict]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append((tuple(argv), dict(kwargs)))
        for matcher, response in self._responses:
            if matcher(argv):
                value = response(argv) if callable(response) else response
                if isinstance(value, BaseException):
                    raise value
                return value
        return completed(argv, code=1, stderr="unexpected invocation")
