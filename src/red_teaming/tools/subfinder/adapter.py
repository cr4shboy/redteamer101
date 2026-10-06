"""Bounded, passive-only Subfinder adapter.

The adapter always builds its own argv (exact domain, JSON Lines, silent), never
accepts caller flags or command fragments, uses ``shell=False``, and runs with a
sanitized environment under the caller-supplied work directory. Tool absence is
a normal ``tool_not_available`` result. No real tool is executed by tests.
"""

from __future__ import annotations

from ...recon.models import ToolResult, ToolRunStatus
from ...recon.tool_argv import expected_live_argv
from ..adapter_base import DiscoveryAdapter
from ..help_text import has_options
from .parsing import (
    REQUIRED_CAPABILITY_MARKERS,
    TOOL_NAME,
    parse_json_lines,
)

__all__ = ["SubfinderAdapter"]


class SubfinderAdapter(DiscoveryAdapter):
    """Run Subfinder's passive, JSON-Lines discovery mode."""

    TOOL_NAME = TOOL_NAME

    def build_argv(self, executable: str) -> tuple[str, ...]:
        """Return the deterministic, internally generated Subfinder argv.

        When a production :class:`~red_teaming.recon.tool_argv.ToolCommandSpec`
        is configured, the exact RECON-002 live argv (crtsh-only, 1 req/s,
        update-check disabled) is returned so the adapter and the independent
        runner validator cannot drift.
        """

        if self.command_spec is not None:
            return expected_live_argv(self.command_spec)
        return (str(executable), "-d", self.root.name, "-json", "-silent")

    def evaluate_capabilities(self, help_text: str):
        required = self.required_markers or REQUIRED_CAPABILITY_MARKERS
        if not has_options(help_text, required):
            return (
                False,
                (),
                (),
                "subfinder help did not advertise the required "
                + "/".join(required)
                + " options",
            )
        return (True, tuple(required), (), None)

    def run(self) -> ToolResult:
        inspection = self._resolve_inspection()
        executable = inspection.executable
        if not inspection.supported or executable is None:
            return self._inspection_result(inspection)

        outcome = self._run(self.build_argv(executable), env=self.build_env())
        observations = parse_json_lines(outcome.parser_text, self.scope)

        errors: list[str] = list(inspection.warnings)
        if outcome.error is not None:
            errors.append(f"execution error: {outcome.error}")
        status_override = None
        if outcome.parse_truncated:
            status_override = ToolRunStatus.TOOL_FAILED
            errors.append(
                "subfinder output exceeded the parser capture cap and was truncated"
            )
        return self._result(
            outcome=outcome,
            executable=executable,
            version=inspection.version,
            observations=observations,
            errors=errors,
            status_override=status_override,
        )
