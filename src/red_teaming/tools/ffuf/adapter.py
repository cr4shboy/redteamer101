"""Bounded, active ffuf subdomain-fuzzing adapter.

ffuf is an *active-stage* discovery tool: unlike the passive Amass/dnsx
adapters, an actual run issues HTTP(S) requests to ``FUZZ.<root>`` candidates
built from a caller-supplied wordlist. The internally generated argv is
deterministic and bounded by construction -- fixed https scheme, a single
``FUZZ.<root>`` URL template (no arbitrary host), a request-rate cap, a thread
cap, a per-request timeout, and an overall ``-maxtime`` wall-clock bound -- and
JSON output is written under the caller-supplied work directory and read with
the same hard parser cap as the other adapters.

Nothing here performs network activity or real tool execution at import or
construction time: executable lookup and the subprocess call are injected, so
the adapter is fully offline-testable. An actual run against any target remains
subject to the project's existing authorization and safety controls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ...recon.models import ToolResult, ToolRunStatus
from ..adapter_base import DiscoveryAdapter
from ..execution import ExecutionError, bound_text
from ..help_text import has_options
from .parsing import REQUIRED_CAPABILITY_MARKERS, TOOL_NAME, parse_ffuf_output

__all__ = ["FfufAdapter"]

#: Fixed request scheme; no downgrade to plain HTTP is ever constructed.
SCHEME = "https"

#: Bounded defaults baked into the deterministic argv so an actual run is always
#: rate-limited and time-bounded regardless of the caller.
DEFAULT_THREADS = 20
DEFAULT_RATE = 50
DEFAULT_HTTP_TIMEOUT = 10
DEFAULT_MAXTIME = 600


class FfufAdapter(DiscoveryAdapter):
    """Run ffuf subdomain fuzzing and parse its JSON output filesystem-side."""

    TOOL_NAME = TOOL_NAME
    OUTPUT_FILENAME = "ffuf-subdomains.json"

    def __init__(
        self,
        *,
        scope,
        work_dir,
        executable=None,
        wordlist=None,
        which=None,
        runner=None,
        timeout=None,
        parse_max=None,
        output_reader: Callable[[Path], str] | None = None,
        required_version=None,
        required_markers=None,
        prevalidated_inspection=None,
    ) -> None:
        kwargs = {}
        if which is not None:
            kwargs["which"] = which
        if runner is not None:
            kwargs["runner"] = runner
        if timeout is not None:
            kwargs["timeout"] = timeout
        if parse_max is not None:
            kwargs["parse_max"] = parse_max
        if required_version is not None:
            kwargs["required_version"] = required_version
        if required_markers is not None:
            kwargs["required_markers"] = required_markers
        if prevalidated_inspection is not None:
            kwargs["prevalidated_inspection"] = prevalidated_inspection
        super().__init__(
            scope=scope,
            work_dir=work_dir,
            executable=executable,
            **kwargs,
        )
        self._wordlist = self._validate_wordlist(wordlist)
        self._output_reader = output_reader

    @staticmethod
    def _validate_wordlist(wordlist) -> str | None:
        if wordlist is None:
            return None
        path = Path(wordlist)
        if not path.is_absolute():
            raise ExecutionError("wordlist path must be absolute")
        if not path.is_file():
            raise ExecutionError("wordlist must be an existing file")
        return str(path)

    @property
    def wordlist(self) -> str | None:
        return self._wordlist

    def output_path(self) -> Path:
        """Return the exact generated JSON file under the work directory."""

        return self.work_dir / self.OUTPUT_FILENAME

    def version_argv(self, executable: str) -> tuple[str, ...]:
        # ffuf prints its version with ``-V`` (``-version`` is not defined).
        return (str(executable), "-V")

    def target_url(self) -> str:
        """Return the single fixed ``FUZZ.<root>`` URL template (no arbitrary host)."""

        return f"{SCHEME}://FUZZ.{self.root.name}/"

    def build_argv(self, executable: str) -> tuple[str, ...]:
        """Return the deterministic, bounded ffuf subdomain-fuzzing argv."""

        if self._wordlist is None:
            raise ExecutionError("ffuf adapter requires a wordlist")
        return (
            str(executable),
            "-w",
            self._wordlist,
            "-u",
            self.target_url(),
            "-o",
            str(self.output_path()),
            "-of",
            "json",
            "-t",
            str(DEFAULT_THREADS),
            "-rate",
            str(DEFAULT_RATE),
            "-timeout",
            str(DEFAULT_HTTP_TIMEOUT),
            "-maxtime",
            str(DEFAULT_MAXTIME),
            "-s",
        )

    def evaluate_capabilities(self, help_text: str):
        required = self.required_markers or REQUIRED_CAPABILITY_MARKERS
        if not has_options(help_text, required):
            missing = [token for token in required if not has_options(help_text, (token,))]
            return (
                False,
                (),
                (),
                "ffuf help did not advertise the required "
                + "/".join(missing)
                + " options",
            )
        return (True, tuple(required), (), None)

    def _read_output(self, outcome) -> tuple[str, bool, bool]:
        """Read the generated JSON bounded to the hard parser cap.

        Returns ``(text, truncated, missing)``. The ``-o`` JSON file is the
        authoritative output; a missing or unreadable file returns
        ``missing=True`` with empty text and process stdout is never substituted.
        An injected ``output_reader`` supplies the text directly for offline tests.
        """

        path = self.output_path()
        if self._output_reader is not None:
            value = self._output_reader(path)
            text, truncated = bound_text(
                value if isinstance(value, str) else "", max_chars=self._parse_max
            )
            return text, truncated, False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                raw = handle.read(self._parse_max + 1)
        except OSError:
            return "", False, True
        if len(raw) > self._parse_max:
            return raw[: self._parse_max], True, False
        return raw, False, False

    def _remove_stale_output(self) -> None:
        """Remove any prior generated JSON so stale output cannot be consumed."""

        try:
            self.output_path().unlink()
        except OSError:
            pass

    def run(self) -> ToolResult:
        inspection = self._resolve_inspection()
        executable = inspection.executable
        if not inspection.supported or executable is None:
            return self._inspection_result(inspection)
        if self._wordlist is None:
            raise ExecutionError("ffuf adapter requires a wordlist")

        self._remove_stale_output()
        outcome = self._run(self.build_argv(executable), env=self.build_env())
        text, file_truncated, output_missing = self._read_output(outcome)
        observations = parse_ffuf_output(text, self.scope)

        errors: list[str] = list(inspection.warnings)
        if outcome.error is not None:
            errors.append(f"execution error: {outcome.error}")
        status_override = None
        if output_missing:
            status_override = ToolRunStatus.TOOL_FAILED
            errors.append("ffuf -o JSON output was not created/readable")
        elif outcome.parse_truncated or file_truncated:
            status_override = ToolRunStatus.TOOL_FAILED
            errors.append(
                "ffuf output exceeded the parser capture cap and was truncated"
            )
        return self._result(
            outcome=outcome,
            executable=executable,
            version=inspection.version,
            observations=observations,
            errors=errors,
            status_override=status_override,
        )
