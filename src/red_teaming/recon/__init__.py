"""RECON-003 bounded passive + DNS reconnaissance core.

The package provides canonical scope normalization, discovery/asset/tool-result
models, immutable per-domain run paths, containment-checked JSON storage, the
pinned-tool/runtime preflight, the exact tool-argv specification, the
unprivileged network-namespace sandbox runner, the outer egress broker, and the
run/network-policy evidence.

I/O and execution boundaries:

* importing this package and constructing models/plans performs no I/O;
* input parsing, aggregation, argv validation, and policy checks are pure (no
  filesystem, socket, or subprocess use);
* subprocess execution happens only through the production sandbox runner or an
  explicit pipeline call (``run_root_pipeline``/``run_batch``) with injected
  adapters; importing nothing here starts a process or opens a socket.

RECON-003 is COMPLETED / CLOSED. Its one-run budget is consumed, the completed
run directory ``20261005T202445Z-807db3`` is immutable, and the post-run ledger
blocks another run. Historical RECON-002 evidence remains immutable. There is no
active target; no live run, retry, or target/network activity is authorized.
"""

from .aggregate import (
    DiscoveryAggregate,
    aggregate_discovery,
    build_assets,
    seed_observation,
)
from .egress_broker import BrokerDenied, BrokerEvent, DnsWireClient, EgressBroker
from .evidence import (
    AUTHORIZED_INPUT_FILENAME,
    EvidenceProvider,
    build_network_policy_document,
    prior_recon_entries,
)
from .input import InputError, read_entries
from .models import (
    MAX_TOOL_OUTPUT_CHARS,
    SCHEMA_VERSION,
    Asset,
    AssetKind,
    DiscoveryObservation,
    DnsRecords,
    DnsResolution,
    ObservationState,
    ResolutionStatus,
    ToolResult,
    ToolRunStatus,
)
from .netpolicy import RECON_002_POLICY, PolicyError, ReconNetworkPolicy
from .netns_sandbox import (
    SandboxConfig,
    SandboxError,
    SandboxUnsupported,
    sandbox_supported,
)
from .netns_selftest import SelfTestReport, run_self_test
from .pinned import (
    PINNED_TOOLS,
    InstallReport,
    RuntimeReport,
    host_runtime_report,
    parse_checksum_file,
    verify_all_installs,
    verify_archive_checksum,
    verify_install,
)
from .paths import (
    RECON_DIRNAME,
    ReconPath,
    ReconPathError,
    recon_dir,
    recon_run_dir,
    validate_run_id,
)
from .pipeline import (
    AdapterFactories,
    BatchPreflightError,
    PipelineError,
    RootRunResult,
    default_factories,
    run_batch,
    run_root_pipeline,
)
from .production import (
    ProductionError,
    ProductionRuntime,
    transient_preflight_work_dir,
)
from .runner import (
    SandboxRunnerError,
    SandboxToolRunner,
    ToolScopedBroker,
    allowed_channels_for,
)
from .scope import EXCLUDED, IN_SCOPE, OUT_OF_SCOPE, Classification, DomainScope
from .storage import (
    ASSETS_FILENAME,
    EVIDENCE_DIRNAME,
    SCOPE_FILENAME,
    ReconStorageError,
    asset_document,
    ensure_evidence_dir,
    evidence_dir,
    read_recon_json,
    write_assets,
    write_evidence_json,
    write_recon_json,
    write_scope,
)
from .tool_argv import ToolCommandSpec, classify_argv, expected_live_argv

__all__ = [
    "ASSETS_FILENAME",
    "AUTHORIZED_INPUT_FILENAME",
    "AdapterFactories",
    "BatchPreflightError",
    "BrokerDenied",
    "BrokerEvent",
    "Classification",
    "DiscoveryAggregate",
    "DnsWireClient",
    "EVIDENCE_DIRNAME",
    "EXCLUDED",
    "EgressBroker",
    "EvidenceProvider",
    "IN_SCOPE",
    "InputError",
    "InstallReport",
    "MAX_TOOL_OUTPUT_CHARS",
    "OUT_OF_SCOPE",
    "PINNED_TOOLS",
    "PipelineError",
    "PolicyError",
    "ProductionError",
    "ProductionRuntime",
    "RECON_002_POLICY",
    "RECON_DIRNAME",
    "ReconNetworkPolicy",
    "RootRunResult",
    "RuntimeReport",
    "SCHEMA_VERSION",
    "SCOPE_FILENAME",
    "SandboxConfig",
    "SandboxError",
    "SandboxRunnerError",
    "SandboxToolRunner",
    "SandboxUnsupported",
    "SelfTestReport",
    "ToolCommandSpec",
    "ToolScopedBroker",
    "Asset",
    "AssetKind",
    "DiscoveryObservation",
    "DnsRecords",
    "DnsResolution",
    "DomainScope",
    "ObservationState",
    "ReconPath",
    "ReconPathError",
    "ReconStorageError",
    "ResolutionStatus",
    "ToolResult",
    "ToolRunStatus",
    "aggregate_discovery",
    "allowed_channels_for",
    "asset_document",
    "build_assets",
    "build_network_policy_document",
    "classify_argv",
    "default_factories",
    "ensure_evidence_dir",
    "evidence_dir",
    "expected_live_argv",
    "host_runtime_report",
    "parse_checksum_file",
    "prior_recon_entries",
    "read_entries",
    "read_recon_json",
    "recon_dir",
    "recon_run_dir",
    "run_batch",
    "run_root_pipeline",
    "run_self_test",
    "sandbox_supported",
    "seed_observation",
    "transient_preflight_work_dir",
    "validate_run_id",
    "verify_all_installs",
    "verify_archive_checksum",
    "verify_install",
    "write_assets",
    "write_evidence_json",
    "write_recon_json",
    "write_scope",
]
