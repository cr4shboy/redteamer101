"""Shared offline fakes/builders for recon pipeline and CLI tests.

Nothing here launches a real process or contacts the network.
"""

from __future__ import annotations

import json

from red_teaming.recon.models import ToolResult
from red_teaming.recon.pipeline import AdapterFactories
from red_teaming.tools.adapter_base import Inspection
from red_teaming.tools.amass import parse_output as amass_parse
from red_teaming.tools.dnsx import parse_json_lines as dnsx_parse
from red_teaming.tools.subfinder import parse_json_lines as subfinder_parse


def inspection(
    status: str = "succeeded",
    *,
    version: str | None = "1.0.0",
    capabilities=(),
    options=(),
    warnings=(),
    reason: str | None = None,
    executable: str | None = "/opt/tool",
) -> Inspection:
    return Inspection(
        tool="stub",
        status=status,
        executable=executable,
        version=version,
        capabilities=tuple(capabilities),
        options=tuple(options),
        warnings=tuple(warnings),
        reason=reason,
    )


def subfinder_result(scope, records) -> ToolResult:
    text = "\n".join(
        record if isinstance(record, str) else json.dumps(record) for record in records
    )
    observations = subfinder_parse(text, scope)
    return ToolResult(tool="subfinder", status="succeeded", observations=observations)


def amass_result(scope, records) -> ToolResult:
    text = json.dumps(records)
    observations = amass_parse(text, scope)
    return ToolResult(tool="amass", status="succeeded", observations=observations)


def dnsx_result(scope, records) -> ToolResult:
    text = "\n".join(json.dumps(record) for record in records)
    observations, resolutions = dnsx_parse(text, scope)
    return ToolResult(
        tool="dnsx",
        status="succeeded",
        observations=observations,
        resolutions=resolutions,
    )


def missing(tool: str) -> ToolResult:
    return ToolResult(tool=tool, status="tool_not_available", errors=["not found"])


class ResultAdapter:
    """Adapter returning a fixed ToolResult from ``run()``."""

    def __init__(self, result: ToolResult, inspection_obj: Inspection | None = None):
        self.result = result
        self._inspection = inspection_obj or inspection()
        self.run_calls = []
        self.inspect_calls = 0

    def run(self, *args):
        self.run_calls.append(args)
        return self.result

    def inspect(self):
        self.inspect_calls += 1
        return self._inspection


class DnsAdapter:
    """dnsx-like adapter that derives its ToolResult from the candidates."""

    def __init__(self, resolver, inspection_obj: Inspection | None = None):
        self._resolver = resolver
        self._inspection = inspection_obj or inspection()
        self.run_calls = []
        self.inspect_calls = 0

    def run(self, candidates):
        self.run_calls.append(tuple(candidates))
        return self._resolver(candidates)

    def inspect(self):
        self.inspect_calls += 1
        return self._inspection


class ExplodingAdapter:
    """Adapter whose factory/run boundary raises, for exception-path tests."""

    def __init__(self, exc: Exception | None = None):
        self._exc = exc or RuntimeError("boom")
        self.run_calls = 0
        self.inspect_calls = 0

    def run(self, *args):
        self.run_calls += 1
        raise self._exc

    def inspect(self):
        self.inspect_calls += 1
        return inspection()


class InspectOnlyAdapter:
    """Adapter used by validate-only tests; ``run`` must never be called."""

    def __init__(self, inspection_obj: Inspection):
        self._inspection = inspection_obj
        self.inspect_calls = 0
        self.run_calls = 0

    def inspect(self):
        self.inspect_calls += 1
        return self._inspection

    def run(self, *args):
        self.run_calls += 1
        raise AssertionError("run() must not be called during validate-only")


def factories(subfinder, amass, dnsx) -> AdapterFactories:
    """Wrap three factory callables into :class:`AdapterFactories`."""

    return AdapterFactories(subfinder=subfinder, amass=amass, dnsx=dnsx)
