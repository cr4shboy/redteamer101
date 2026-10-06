# WSTG v4.2 — Information Gathering: implementation roadmap

Domain-neutral, **offline-first** plan for extending this framework along the
OWASP Web Security Testing Guide v4.2 section **4.1 Information Gathering**
(`WSTG-INFO-01` … `WSTG-INFO-10`).

Reference: <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/>

> **This document is a plan, not an authorization.** It adds no code and starts
> no activity. It is domain-neutral and code-only. Every item here is written as
> an offline, deterministic, fail-closed increment that fits the existing
> control-plane / data-plane split (see `README.md`). No live run, target DNS,
> HTTP(S) probe, crawl, scan, install, or network egress is authorized by this
> file. Any *active* stage (one that touches a target) stays
> `awaiting_authorization` in the planner and may only run under an approved
> `CURRENT_TASK.md` package that names the domain, allowlist, limits, and
> stop/acceptance criteria — exactly as the current engine already enforces.

---

## 1. Guardrails (apply to every increment)

- **Offline & deterministic.** Pure functions over injected inputs; same input →
  same output. No network or process activity at import or in unit tests. Follow
  the existing adapter pattern: inject the executable lookup and the subprocess /
  socket call so the collector is inert without binaries.
- **Fail-closed.** Unparseable / truncated / oversized / failed tool output is a
  failure, never a silent empty success substituted from stdout (this mirrors the
  Amass handling corrected in MAINTENANCE-001).
- **Data-plane claims are source-labelled, not verified.** Like
  `WebServerFingerprint`, every derived fact records *what a response reported*,
  carries an opaque `source_id`, and never asserts patch level or vulnerability
  status. Raw headers / bodies are **not** retained — only bounded, validated
  tokens.
- **No secrets, ever.** No credentials, cookies, tokens, sessions, or API keys
  are accepted, logged, or persisted — including for search-engine or CT sources.
- **Egress through one chokepoint.** Any live fetch goes through the existing
  broker / netns egress layer with an explicit allowlist; no adapter opens its
  own socket.
- **Architect–Coder workflow.** Each phase below is one scoped Coder package.
  Scope is not widened without a new Architect authorization. Reports include
  files changed, implementation summary, tests run + results, and blockers.

---

## 2. WSTG-INFO → framework mapping

| WSTG | Title | Tier | Framework placement | Status |
|---|---|---|---|---|
| INFO-01 | Search Engine Discovery Recon | Passive | New passive source adapter → `KnowledgeBase` host candidates + leakage notes | Not started |
| INFO-02 | Fingerprint Web Server | Active | `intel/fingerprint.py` (offline derive) **done**; needs active header-fetch adapter | **Partial** |
| INFO-03 | Review Webserver Metafiles | Active (light) | Metafile fetch adapter (`robots.txt`, `sitemap.xml`, `security.txt`) → entries + disclosed paths | Not started |
| INFO-04 | Enumerate Applications on Webserver | Active | Extends existing `active_subdomains` (ffuf) + vhost/port facts | Partial infra |
| INFO-05 | Review Webpage Content for Leakage | Passive (offline parse) | Pure parser over *supplied* HTML → comment/metadata leakage facts | Not started |
| INFO-06 | Identify Application Entry Points | Active | Derive entry points from spider output + supplied request/response pairs | Not started |
| INFO-07 | Map Execution Paths | Active | Already served by ZAP spider stage (`zap_spider`) | Infra exists |
| INFO-08 | Fingerprint Web App Framework | Active | Framework-signature rules over headers/cookies/paths (offline rule set) | Not started |
| INFO-09 | Fingerprint Web Application | Active | App-identity derivation reusing INFO-08 signal + content parse | Not started |
| INFO-10 | Map Application Architecture | Active | Synthesis entity aggregating all of the above into an architecture map | Not started |

---

## 3. Architectural placement

Each test lands in the layers that already exist — no new frameworks:

- **Data plane (`intel/model.py`, new `intel/*.py`)** — new frozen, validated
  entities alongside `WebService` / `WebServerFingerprint`:
  `SearchEngineLeak`, `Metafile`, `ContentLeak`, `EntryPoint`,
  `FrameworkClaim`, `ApplicationProfile`, `ArchitectureMap`. Each has
  `__post_init__` validation, an `identity` for dedup, and `to_dict()`.
- **Facts (`intel/facts.py`)** — small predicates (`has_metafiles`,
  `has_entry_points`, …) used by planner preconditions.
- **Control plane (`intel/plan.py`)** — add declarative `Stage`s with tier,
  capability, and fact precondition. Passive stages become `eligible` once their
  input exists; active stages stay `awaiting_authorization` until an approved
  live run. Reuse the existing `Decision` vocabulary — no new statuses.
- **Collection (`tools/<name>/`)** — bounded, injectable adapters mirroring
  `amass` / `dnsx` / `subfinder` / `ffuf` / `zap`: `adapter.py` (argv build +
  capability check), `parsing.py` (fail-closed parse). New adapters:
  `http_fetch` (metafiles + Server header + content body, single bounded GET),
  and a `search` source adapter for INFO-01.
- **Egress** — extend the allowlist model only; the broker/netns layer stays the
  sole socket opener.
- **Findings (`intel/findings.py`)** — additive, deterministic rules turning
  leakage/metafile/entry-point facts into host-scoped `Finding`s.
- **Report (`intel/report.py`)** — the new entities flow into the existing
  Markdown / JSON / SARIF renderers (byte-reproducible, no timestamps).

---

## 4. Phased work packages (proposed sequence)

Order favours passive-before-active and reuses the fingerprint work already
landed. Each phase is independently shippable and fully offline-tested.

### Phase A — INFO-02 completion (active web-server fingerprint)
- Add an injectable `http_fetch` adapter that performs **one** bounded GET and
  surfaces only the response status + a size-capped `Server` header, then feeds
  the existing `fingerprint_server_header()`.
- Wire a `fingerprint_web_server` active stage (precondition `has_web`,
  `awaiting_authorization` by default).
- Tests: adapter argv/caps, fail-closed on oversized/garbage headers, stage
  decision matrix. No live fetch in tests.

### Phase B — INFO-03 metafiles
- `Metafile` entity + parser for `robots.txt`, `sitemap.xml`, `security.txt`
  from **supplied** bytes (parser is pure; fetch is the Phase A adapter reused).
- Facts + `review_metafiles` active stage; findings rule for disclosed paths.

### Phase C — INFO-05 content leakage (pure, offline)
- `ContentLeak` entity + parser over supplied HTML: HTML comments, `meta`
  generator tags, inline author/debug markers, email/path tokens (bounded regex,
  no full body retained).
- This phase needs **no network** at all — it is a pure analysis of material the
  caller already holds, so it can ship first if preferred.

### Phase D — INFO-01 search-engine discovery (passive source)
- `search` source adapter + `SearchEngineLeak` facts feeding host candidates and
  leakage notes. Treat as a passive source behind the egress allowlist; no
  credentials. Fail-closed parsing.

### Phase E — INFO-04 application enumeration
- Extend `active_subdomains` output into vhost / alternate-port facts; a
  `WebService` may carry multiple apps. Mostly data-model + planner work.

### Phase F — INFO-06 / INFO-07 entry points & execution paths
- Derive `EntryPoint`s from ZAP spider output (INFO-07 infra already exists) plus
  supplied request/response pairs. New derivation module + findings.

### Phase G — INFO-08 / INFO-09 framework & application fingerprint
- Offline **signature rule set** (header/cookie/path → `FrameworkClaim`),
  deterministic and versioned. INFO-09 reuses INFO-08 + content parse to emit an
  `ApplicationProfile`. Rules carry a source label; no CVE assertions.

### Phase H — INFO-10 architecture map (synthesis)
- `ArchitectureMap` aggregates assets, web services, frameworks, entry points
  into one deterministic structure; rendered by the existing report layer. No new
  collection — pure synthesis over the knowledge base.

---

## 5. Dependencies & sequencing notes

- Phase A unblocks B and (header signal) G. Phase C is independent and can lead.
- INFO-07 is already served by the ZAP spider stage; F mainly *consumes* its
  output rather than adding collection.
- INFO-10 is last — it only synthesises what A–G populate.
- The capability registry (`capabilities/registry.yaml`) remains the single
  source of truth; new capability-gated stages route through the existing
  `decide` / `build-request` / `handoff` flow, not ad-hoc code.

---

## 6. Definition of done (per phase)

1. New/changed files listed.
2. Entities validated and deterministic; `to_dict()` stable.
3. Planner decisions correct across the fact/capability/authorization matrix.
4. Full offline suite green (`python -m pytest -q`), new unit tests included,
   no network / process / target data touched.
5. Report renderers still byte-reproducible.
6. Active stages prove they stay `awaiting_authorization` without an approved
   `CURRENT_TASK.md`.

## 7. Explicitly out of scope here

No live target contact, DNS, HTTP(S) probe, crawl, port scan, vulnerability
scan, or exploitation; no installs, binary provisioning, or system/WSL/`PATH`
changes; no secrets; no additional subagents; no edits to immutable historical
run directories. Live execution of any active stage requires a separate approved
`CURRENT_TASK.md` package.
