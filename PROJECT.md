# PROJECT.md

Domain-neutral context for this workspace. Like `AGENTS.md`, this file holds
**no target-specific records** — current status, authorizations, and run history
live in the separate private ledger (see `AGENTS.md`).

## Purpose

An offline-first foundation for **authorized** red-team recon and scanning. The
codebase separates a deterministic **control plane** (capability decisions,
fact-driven planning, authorization gates) from a **data plane** of objectified
recon entities, so the early workflow — from passive discovery to bounded active
checks — is reproducible and fully offline-testable.

See `README.md` for the architecture, repository layout, and how to run the
offline test suite.

## Principles

- **Code only, here.** This repository ships no tool binaries, no secrets, and
  no target recon/scan evidence. Nothing performs network or process activity at
  import; every adapter injects its executable lookup and its socket/subprocess
  call, so the code is inert without provisioned tools and an explicit
  authorization.
- **Fail closed.** A live run refuses to execute without a current authorization
  package (in the private ledger) that names the domain, egress allowlist,
  limits, and stop/acceptance criteria. Only assess systems you are authorized to
  assess.
- **Deterministic.** Pure functions over injected inputs; the same inputs produce
  the same decisions, plans, and reports. Reports are byte-reproducible.
- **Domain-neutral.** The authorized target identity is a runtime input, never a
  source constant. Tests and examples use the reserved documentation name
  `acme.example` and the documentation address `203.0.113.10` (RFC 5737) as
  placeholders.

## Workflow

Work proceeds as scoped Architect → Coder packages under the rules in
`AGENTS.md`. Each package is authorized, tracked, and closed in the private
ledger; this repository changes only through those scoped, reviewed tasks.

## Status

Current status, the active work package (if any), and all operational history
are recorded in the private ledger, not here.
