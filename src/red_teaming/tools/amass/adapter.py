"""Bounded, passive-only Amass ``enum`` adapter.

Only the ``enum`` subcommand in ``-passive`` mode is ever constructed; active,
brute-force, mutation, and DNS-resolution modes are structurally unavailable
(they have no code path). Capability inspection requires positive evidence of
``-passive``, ``-oA`` (the pinned Amass 5.1.1 output-prefix flag, which writes
``<prefix>.json``), and an exact domain option (``-d`` *or* ``-domain``); the
option actually advertised is the one used. The generated JSON output file is
written under the caller-supplied work directory and read with the same hard
parser cap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ...recon.models import ToolResult, ToolRunStatus
from ...recon.tool_argv import AMASS_HELP_FLAG, expected_live_argv
from ..adapter_base import DiscoveryAdapter
from ..execution import ExecutionError, bound_text
from ..help_text import has_options
from .parsing import (
    DOMAIN_OPTIONS,
    TOOL_NAME,
    parse_output,
    select_domain_option,
)

__all__ = ["AmassAdapter"]


class AmassAdapter(DiscoveryAdapter):
    """Run Amass ``enum -passive`` and parse its JSON output filesystem-side."""

    TOOL_NAME = TOOL_NAME
    OUTPUT_BASENAME = "amass-enum"
    JSON_SUFFIX = ".json"
    OUTPUT_FILENAME = OUTPUT_BASENAME + JSON_SUFFIX

    def __init__(
        self,
        *,
        scope,
        work_dir,
        executable=None,
        which=None,
        runner=None,
        timeout=None,
        parse_max=None,
        output_reader: Callable[[Path], str] | None = None,
        required_version=None,
        required_markers=None,
        command_spec=None,
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
        if command_spec is not None:
            kwargs["command_spec"] = command_spec
        if prevalidated_inspection is not None:
            kwargs["prevalidated_inspection"] = prevalidated_inspection
        super().__init__(
            scope=scope,
            work_dir=work_dir,
            executable=executable,
            **kwargs,
        )
        self._output_reader = output_reader

    def output_prefix(self) -> Path:
        """Return the internally controlled ``-oA`` output prefix."""

        if self.command_spec is not None:
            return Path(self.command_spec.output_prefix)
        return self.work_dir / self.OUTPUT_BASENAME

    def output_path(self) -> Path:
        """Return the exact generated JSON file (``<prefix>.json``)."""

        return Path(str(self.output_prefix()) + self.JSON_SUFFIX)

    def help_argv(self, executable: str) -> tuple[str, ...]:
        # Pinned Amass 5.1.1 defines an explicit long help flag for the ``enum``
        # flagset (``-help``) bound to the same usage handler as the short form;
        # the long form is used for a deterministic, self-documenting inspection
        # invocation. The exact argv is mirrored by ``inspection_argvs``.
        return (str(executable), "enum", AMASS_HELP_FLAG)

    def build_argv(self, executable: str, *, domain_option: str) -> tuple[str, ...]:
        """Return the deterministic passive ``enum`` argv (no active modes).

        With a production :class:`ToolCommandSpec`, the exact RECON-002 live
        argv (``enum -passive``, ``crtsh`` source only, JSON output) is
        returned.
        """

        if self.command_spec is not None:
            return expected_live_argv(self.command_spec)
        if domain_option not in DOMAIN_OPTIONS:
            raise ExecutionError(
                f"unsupported amass domain option: {domain_option!r}"
            )
        return (
            str(executable),
            "enum",
            "-passive",
            domain_option,
            self.root.name,
            "-oA",
            str(self.output_prefix()),
        )

    def evaluate_capabilities(self, help_text: str):
        if self.command_spec is not None:
            required = self.required_markers or ("-passive", "-oA")
            domain_option = self.command_spec.domain_option
            checked = tuple(dict.fromkeys(required + (domain_option,)))
            missing = tuple(
                token for token in checked if not has_options(help_text, (token,))
            )
            if missing:
                return (
                    False,
                    (),
                    (),
                    "amass enum help did not advertise: " + "/".join(missing),
                )
            return (
                True,
                ("-passive", "-oA", "-include", domain_option),
                (("domain", domain_option),),
                None,
            )

        domain_option = select_domain_option(help_text)
        missing_tokens = [
            token
            for token in ("-passive", "-oA")
            if not has_options(help_text, (token,))
        ]
        if domain_option is None:
            missing_tokens.append("-d/-domain")
        if missing_tokens:
            return (
                False,
                (),
                (),
                "amass enum help did not advertise: " + "/".join(missing_tokens),
            )
        return (
            True,
            ("-passive", "-oA", domain_option),
            (("domain", domain_option),),
            None,
        )

    def _read_output(self, outcome) -> tuple[str, bool, bool, bool]:
        """Read the generated JSON bounded to the hard parser cap.

        Returns ``(text, truncated, missing, unreadable)``. When a production
        ``command_spec`` is present the exact generated ``<prefix>.json`` is
        authoritative: process stdout is never substituted. An absent file and
        an existing-but-unreadable path are reported separately. The fixture
        adapter (no ``command_spec``) retains the legacy stdout fallback.
        """

        path = self.output_path()
        if self._output_reader is not None:
            value = self._output_reader(path)
            text, truncated = bound_text(
                value if isinstance(value, str) else "", max_chars=self._parse_max
            )
            return text, truncated, False, False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                raw = handle.read(self._parse_max + 1)
        except FileNotFoundError:
            if self.command_spec is not None:
                return "", False, True, False
            return outcome.parser_text, outcome.parse_truncated, False, False
        except OSError:
            if self.command_spec is not None:
                return "", False, False, True
            return outcome.parser_text, outcome.parse_truncated, False, False
        if len(raw) > self._parse_max:
            return raw[: self._parse_max], True, False, False
        return raw, False, False, False

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

        domain_option = inspection.option("domain")
        if domain_option is None:  # pragma: no cover - defensive
            return self._inspection_result(inspection)

        self._remove_stale_output()
        outcome = self._run(
            self.build_argv(executable, domain_option=domain_option),
            env=self.build_env(),
        )
        text, file_truncated, output_missing, output_unreadable = self._read_output(
            outcome
        )
        observations = parse_output(text, self.scope)

        errors: list[str] = list(inspection.warnings)
        if outcome.error is not None:
            errors.append(f"execution error: {outcome.error}")
        status_override = None
        if output_unreadable:
            status_override = ToolRunStatus.TOOL_FAILED
            errors.append("amass -oA JSON output exists but is unreadable")
        elif output_missing and outcome.ok:
            errors.append(
                "amass exited successfully without generated JSON; interpreted as zero findings"
            )
        elif outcome.parse_truncated or file_truncated:
            status_override = ToolRunStatus.TOOL_FAILED
            errors.append(
                "amass output exceeded the parser capture cap and was truncated"
            )
        return self._result(
            outcome=outcome,
            executable=executable,
            version=inspection.version,
            observations=observations,
            errors=errors,
            status_override=status_override,
        )
