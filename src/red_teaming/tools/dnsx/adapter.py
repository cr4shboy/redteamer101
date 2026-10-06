"""Bounded dnsx adapter.

Candidates are revalidated against the single-root scope, then fed to dnsx over
stdin (never as arbitrary arguments) as a deterministically sorted
one-host-per-line list. The internally generated argv requests only JSON output
for A, AAAA, and CNAME records -- no brute-force, wildcard, or arbitrary modes.
"""

from __future__ import annotations

from ...recon.models import ToolResult, ToolRunStatus
from ...recon.tool_argv import expected_live_argv
from ..adapter_base import DiscoveryAdapter
from ..help_text import has_options
from ..observations import dedupe_observations
from .parsing import (
    REQUIRED_CAPABILITY_MARKERS,
    TOOL_NAME,
    parse_json_lines,
    prepare_candidates,
)

__all__ = ["DnsxAdapter"]


class DnsxAdapter(DiscoveryAdapter):
    """Resolve already-discovered hosts with dnsx."""

    TOOL_NAME = TOOL_NAME

    def build_argv(self, executable: str) -> tuple[str, ...]:
        """Return the deterministic, internally generated dnsx argv.

        With a production :class:`ToolCommandSpec`, the exact RECON-002 live
        argv (A/AAAA/CNAME only, resolver ``1.1.1.1:53``, 5 qps, 2 threads,
        update-check disabled) is returned.
        """

        if self.command_spec is not None:
            return expected_live_argv(self.command_spec)
        return (str(executable), "-json", "-a", "-aaaa", "-cname", "-silent")

    def build_stdin(self, hosts: tuple[str, ...]) -> str:
        """Return one sorted hostname per line (empty string when none)."""

        return "".join(f"{host}\n" for host in hosts)

    def evaluate_capabilities(self, help_text: str):
        required = self.required_markers or REQUIRED_CAPABILITY_MARKERS
        if not has_options(help_text, required):
            return (
                False,
                (),
                (),
                "dnsx help did not advertise the required "
                + "/".join(required)
                + " options",
            )
        return (True, tuple(required), (), None)

    def run(self, candidates: object) -> ToolResult:
        inspection = self._resolve_inspection()
        executable = inspection.executable
        if not inspection.supported or executable is None:
            return self._inspection_result(inspection)

        hosts, input_observations = prepare_candidates(candidates, self.scope)
        if not hosts:
            return ToolResult(
                tool=TOOL_NAME,
                status=ToolRunStatus.SUCCEEDED,
                executable=executable,
                version=inspection.version,
                argv=(),
                observations=tuple(input_observations),
                errors=tuple(inspection.warnings),
                timeout=self.timeout,
            )

        outcome = self._run(
            self.build_argv(executable),
            env=self.build_env(),
            stdin_text=self.build_stdin(hosts),
        )
        output_observations, resolutions = parse_json_lines(
            outcome.parser_text, self.scope
        )
        observations = dedupe_observations(
            tuple(input_observations) + tuple(output_observations)
        )

        errors: list[str] = list(inspection.warnings)
        if outcome.error is not None:
            errors.append(f"execution error: {outcome.error}")
        status_override = None
        if outcome.parse_truncated:
            status_override = ToolRunStatus.TOOL_FAILED
            errors.append(
                "dnsx output exceeded the parser capture cap and was truncated"
            )
        return self._result(
            outcome=outcome,
            executable=executable,
            version=inspection.version,
            observations=observations,
            resolutions=resolutions,
            errors=errors,
            status_override=status_override,
        )
