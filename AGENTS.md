# AGENTS.md

Project-local operating rules for this workspace. This file governs the
Architect–Coder workflow used here. It is **domain-neutral**: it contains
operating rules only, never target-specific records.

> **Operational ledger lives elsewhere.** Work-package history, authorizations,
> run evidence, and any target-specific records are kept in a **separate private
> ledger** (a private repo, mirrored locally under the git-ignored `ledger/`),
> never in this public repository. Read the ledger for current status before
> acting. This public repo ships code only — no targets, no evidence, no secrets.

## Roles

- **Architect**: reads project context, plans work, delegates scoped tasks, and
  reviews results. The Architect is the only role that authorizes scope changes.
- **Coder**: implements only the delegated, scoped task. Runs validation and
  reports evidence. Does not redesign architecture or expand scope.

## Operating rules

- Stay strictly within the explicitly authorized scope. If a task conflicts with
  the active work package or these rules, stop and report the conflict instead of
  guessing.
- **Default deny.** There is no target or network authorization by default. Any
  live activity against any domain — DNS, HTTP(S), crawling, scanning, port or
  service discovery, third-party provider requests, or any other
  target-directed traffic — requires an explicit, current authorization package
  in the private ledger that names the domain, the egress allowlist, the limits,
  and the stop/acceptance criteria. Fail closed: do not perform, schedule, or
  test against live systems without it.
- **Domain routing.** Every target-specific task must identify one explicit
  domain before target-specific work begins. Store all reports, logs, evidence,
  and tool outputs under `projects/<domain>/` (git-ignored). Never mix data
  between domain directories, and never write target-specific artifacts to the
  project root or into this repository's tracked files.
- Read `AGENTS.md`, `PROJECT.md`, and the active work package (private ledger)
  before acting; inspect relevant existing code before modifying it.
- Make the smallest correct change that satisfies the delegated task.
- **Never handle, store, create, log, persist, or commit secrets of any kind** —
  no credentials, tokens, API keys, cookies, authentication material, or
  sessions, for any target or service.
- Create and modify files only inside this project directory. No files outside
  it.
- **No system changes.** No `sudo`, privilege escalation, or package managers
  (`apt`, `pip`, `npm`, `go install`, …); no installing, updating, or
  configuring the OS, WSL, the kernel, or any system/tool config; no changes to
  `PATH`, shell profiles, or `/etc`. Report the conflict instead of proceeding if
  any of these would be required.
- Do not widen scope, add unrequested work, or create additional subagents.
- Treat prior run directories and committed evidence as immutable: never edit,
  delete, overwrite, relocate, or reuse them.

## Reporting

Every task report must include:
- files changed;
- implementation summary;
- tests/validation executed and their results;
- remaining issues or blockers.
