# redteamer101

Domain-neutral, offline-first foundation for **authorized** red-team recon and
scanning. The codebase separates a deterministic **control plane** (decisions,
planning, authorization gates) from a **data plane** of objectified recon
entities, so the whole early workflow — from passive discovery to active basic
checks — is reproducible and fully offline-testable.

> **Scope & safety.** This repository contains **code only**. It ships **no**
> tool binaries, **no** secrets, and **no** target recon/scan evidence. Nothing
> here performs network or process activity at import time; every adapter injects
> its executable lookup and subprocess call. A live run against any target
> requires explicit owner authorization (an approved `CURRENT_TASK.md` package)
> and is fail-closed by default. Only test or run against systems you are
> authorized to assess.

## Architecture

- **Control plane** — the capability gateway (`capability.py` + registry) and the
  fact-driven planner (`src/red_teaming/intel/`): given a knowledge base, it
  emits one deterministic decision per stage (`eligible` / `blocked` /
  `needs_build` / `awaiting_authorization`). Web-only stages (e.g. ZAP spider)
  stay blocked until a live web service is known.
- **Data plane** — objectified entities (`Asset`, `WebService`, `KnowledgeBase`)
  built deterministically from per-tool results. Supplied HTTP `Server` headers
  can also produce bounded, source-labeled fingerprint claims without network
  access; these are separate from discovered hosts and vulnerability findings.
- **Collection** — bounded, injectable tool adapters (`amass`, `dnsx`,
  `subfinder`, `ffuf`, `zap`) with exact option-token capability checks and
  fail-closed parsing.
- **Egress sandbox** — the broker / network-namespace layer is the single point
  that opens external sockets, enforcing an explicit allowlist.
- **Evidence** — per-domain, atomic, schema-versioned artifacts (not in this
  repo).

## Repository structure

```text
redteamer101/
├── capability.py              # capability lookup / decide / handoff CLI
├── capabilities/              # capability registry (source of truth)
├── OPENCLAW.md                # gateway operating flow
├── AGENTS.md / PROJECT.md / CURRENT_TASK.md   # operating rules & status
├── scripts/                   # thin runnable CLI wrappers
│   ├── recon_plan.py          # deterministic planner (validate-only, offline)
│   ├── recon_assets.py        # bounded passive + DNS recon
│   ├── scan_target.py / stage2_spider.py / smoke_zap.py   # ZAP CLIs
│   └── project_doctor.py      # offline readiness check
├── src/red_teaming/
│   ├── intel/                 # control plane: model · facts · planner
│   ├── recon/                 # pipeline, scope, egress broker, netns sandbox
│   ├── tools/                 # tool adapters (wrappers)
│   │   ├── amass/ dnsx/ subfinder/ ffuf/ zap/
│   │   ├── adapter_base.py execution.py help_text.py observations.py
│   ├── cli/                   # argument parsing & composition
│   ├── orchestration/         # atomic state persistence
│   └── projects/              # domain/path models & validation
├── tests/unit/                # full offline unit suite
├── tools/zap/README.md        # ZAP wrapper documentation
└── pyproject.toml
```

Tool **binaries** (`.tools/`), **target evidence** (`projects/`), dependency
libraries, and caches are intentionally excluded (`.gitignore`). Binary
provisioning will be documented separately / delivered via a container.

## Requirements

- Python **3.10+** (developed on 3.12–3.14). The runtime uses the **standard
  library only** — no third-party dependencies.
- `pytest` is optional (the suite also runs under stdlib `unittest`).
- Running real tools additionally needs the binaries (`amass`, `dnsx`,
  `subfinder`, `ffuf`, OWASP ZAP) provisioned separately; the code is inert
  without them.

## Running the tests (offline, no network)

From the repository root:

```bash
python -m pytest -q
```

If `red_teaming` is not importable in your environment, either install the
package in editable mode first (no third-party deps are pulled in):

```bash
pip install -e .
python -m pytest -q
```

…or run the stdlib suite without installing anything:

```bash
# Linux/macOS
PYTHONPATH=src python -m unittest discover -s tests -t .
```

```powershell
# Windows PowerShell
$env:PYTHONPATH = "src"; python -m unittest discover -s tests -t .
```

The entire suite is offline: it uses injected fakes, touches no network, starts
no real process, and needs no tool binaries or target data.

## Trying the planner (offline, safe)

`recon_plan` prints the deterministic plan for a domain without doing anything —
no directory is created, no socket is opened, no process is started:

```bash
python scripts/recon_plan.py --domain example.com --validate-only
```

From an empty knowledge base only passive discovery is eligible; web-only stages
report `blocked: no_web_services`. A live run (`--confirm-authorized`) is wired
but fail-closed: it refuses to execute without an approved `CURRENT_TASK.md`
package defining the domain, allowlist, limits, and stop/acceptance criteria.

Add `--report {md,json,sarif}` to emit a deterministic findings report instead
of the plan. SARIF 2.1.0 output lets findings feed defensive pipelines such as
GitHub code scanning. Findings are derived purely from the knowledge base by the
deterministic orchestrator (`src/red_teaming/intel/orchestrator.py`), so the same
recon state always yields byte-identical reports.
