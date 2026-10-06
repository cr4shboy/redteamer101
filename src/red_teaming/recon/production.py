"""Production wiring: pinned installs -> exact adapters -> sandbox runner.

``ProductionRuntime`` is the only place that constructs the production adapter
factories. It binds each adapter to the exact pinned absolute binary, the exact
permitted argv (via :class:`~red_teaming.recon.tool_argv.ToolCommandSpec`), and a
:class:`~red_teaming.recon.runner.SandboxToolRunner` that independently
re-validates the argv and executes it inside the unprivileged empty network
namespace. The same object accumulates per-invocation network-policy evidence.

Nothing here performs I/O at import time; constructing a runtime does no I/O
beyond what the caller already did during preflight.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional, Sequence

from .evidence import EvidenceProvider  # noqa: F401 - re-exported for callers
from .netpolicy import RECON_002_POLICY, ReconNetworkPolicy
from .pinned import InstallReport, RuntimeReport
from .pipeline import AdapterFactories
from ..projects.paths import is_within, resolve_path
from .runner import SandboxToolRunner
from .tool_argv import ToolCommandSpec

__all__ = [
    "EvidenceProvider",
    "ProductionError",
    "ProductionRuntime",
    "transient_preflight_work_dir",
]


class ProductionError(ValueError):
    """Production wiring is incomplete or violates the pinned runtime contract."""


@contextlib.contextmanager
def transient_preflight_work_dir(
    workspace_root: os.PathLike | str, root: str
) -> Iterator[Path]:
    """Yield a uniquely-created transient work dir under ``projects/<root>/``.

    The directory is created fresh (never a run-id directory, never the project
    root), is rejected if its path is a symlink or already exists, is confirmed
    contained in the domain project directory, and is removed in a ``finally``
    block so no preflight ``_sandbox`` files or transient directories remain.
    """

    workspace = Path(os.fspath(workspace_root))
    project = workspace / "projects" / root
    try:
        project.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProductionError(
            "could not create the domain project directory for preflight"
        ) from exc
    if project.is_symlink():
        raise ProductionError("domain project directory must not be a symlink")
    try:
        resolved_project = resolve_path(project)
        resolved_workspace = resolve_path(workspace)
    except OSError as exc:  # pragma: no cover - defensive
        raise ProductionError("could not resolve the preflight work directory") from exc
    if not is_within(resolved_project, resolved_workspace):
        raise ProductionError("domain project directory escapes the workspace root")

    transient = project / f".preflight-{secrets.token_hex(8)}"
    if transient.exists() or transient.is_symlink():
        raise ProductionError("transient preflight directory collided")
    try:
        transient.mkdir(mode=0o700, exist_ok=False)
    except OSError as exc:
        raise ProductionError("could not create the transient preflight directory") from exc
    if transient.is_symlink():
        raise ProductionError("transient preflight directory is a symlink")
    try:
        yield transient
    finally:
        # Remove only the directory we just created; never follow a symlink.
        try:
            if transient.is_symlink():
                transient.unlink()
            elif transient.is_dir():
                shutil.rmtree(transient, ignore_errors=True)
        except OSError:  # pragma: no cover - defensive
            pass



@dataclass
class ProductionRuntime:
    """Validated pinned runtime plus the machinery to build production factories."""

    workspace_root: Path
    root: str
    installs: tuple[InstallReport, ...]
    runtime: Optional[RuntimeReport] = None
    policy: ReconNetworkPolicy = RECON_002_POLICY
    src_path: Optional[str] = None
    timeout: float = 120.0
    broker_factory: Optional[Callable] = None
    helper_runner: Optional[Callable] = None
    port_factory: Optional[Callable] = None
    #: Injectable Amass launcher-executable predicate (off-platform tests only).
    amass_launcher_check: Optional[Callable] = None
    evidence: list = field(default_factory=list)
    #: Successful preflight inspections keyed by tool, reused by live adapters so
    #: each actual stage makes only its one live invocation.
    inspections: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root)
        if self.root != self.policy.root_domain:
            raise ProductionError("production runtime is fixed to the RECON-002 root")
        if not isinstance(self.installs, tuple):
            self.installs = tuple(self.installs)

    def install_for(self, tool: str) -> InstallReport:
        for report in self.installs:
            if report.tool == tool:
                if not report.ok or not report.binary_path:
                    raise ProductionError(
                        f"pinned install is not usable: {tool} ({report.reason})"
                    )
                return report
        raise ProductionError(f"pinned install is missing: {tool}")

    def factories(self) -> AdapterFactories:
        """Return production factories bound to the exact pinned binaries."""

        return AdapterFactories(
            subfinder=self._build_factory("subfinder"),
            amass=self._build_factory("amass"),
            dnsx=self._build_factory("dnsx"),
        )

    def evidence_provider(self) -> EvidenceProvider:
        return EvidenceProvider(
            root=self.root,
            runtime=self.runtime,
            installs=self.installs,
            invocations=self.evidence,
            policy=self.policy,
        )

    # -- internals ----------------------------------------------------------

    def _build_factory(self, tool: str):
        install = self.install_for(tool)

        def factory(scope, work_dir):
            if len(scope.roots) != 1 or scope.roots[0].name != self.root:
                raise ProductionError("production scope must be the single RECON-002 root")
            work = Path(work_dir)
            output_prefix = None
            if tool == "amass":
                # Pinned Amass 5.1.1 has no ``-json``; ``-oA <prefix>`` writes
                # ``<prefix>.json`` (adapter reads exactly that file).
                output_prefix = str(work / "amass-enum")
            spec = ToolCommandSpec(
                tool=tool,
                version=install.version,
                binary=install.binary_path,
                root=self.root,
                domain_option="-d",
                output_prefix=output_prefix,
            )
            runner = SandboxToolRunner(
                spec=spec,
                work_dir=work,
                src_path=self.src_path,
                timeout=self.timeout,
                policy=self.policy,
                broker_factory=self.broker_factory,
                helper_runner=self.helper_runner,
                port_factory=self.port_factory or self._default_port_factory,
                evidence=self.evidence,
                amass_launcher_check=self.amass_launcher_check,
            )
            return self._build_adapter(
                tool,
                scope,
                work,
                install,
                spec,
                runner,
                timeout=self.timeout,
                cached_inspection=self.inspections.get(tool),
            )

        return factory

    @staticmethod
    def _default_port_factory() -> int:
        from .runner import _free_loopback_port

        return _free_loopback_port()

    @staticmethod
    def _build_adapter(
        tool, scope, work, install, spec, runner, *, timeout, cached_inspection=None
    ):
        kwargs = dict(
            scope=scope,
            work_dir=work,
            executable=install.binary_path,
            runner=runner,
            command_spec=spec,
            timeout=timeout,
            prevalidated_inspection=cached_inspection,
        )
        if tool == "subfinder":
            from ..tools.subfinder import SubfinderAdapter

            return SubfinderAdapter(**kwargs)
        if tool == "dnsx":
            from ..tools.dnsx import DnsxAdapter

            return DnsxAdapter(**kwargs)
        if tool == "amass":
            from ..tools.amass import AmassAdapter

            return AmassAdapter(**kwargs)
        raise ProductionError(f"unsupported tool: {tool}")
