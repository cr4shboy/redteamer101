# OWASP ZAP headless Spider/AJAX wrapper

Domain-neutral, offline-first documentation for the bounded OWASP ZAP
Spider/AJAX Spider wrapper in this repository.

This document is reusable across domains. It contains **no** target-specific
invocation, no credentials, and no authorization. Every example below uses the
reserved placeholder domain `example.test` and the explicit path placeholder
`<absolute-zap-executable>`.

> **Placeholders must be replaced.** `example.test` is an IANA-reserved domain
> used only as a stand-in. `<absolute-zap-executable>` is not a real path.
> Replace both with real values only inside an explicitly authorized run.

---

## 1. Responsibility boundaries

The project is split into three layers with a strict separation of duties:

| Layer | Location | Responsibility |
| --- | --- | --- |
| **Source** | `src/red_teaming/` | Domain-neutral implementation: input models/validation, deterministic path resolution, atomic state persistence, loopback-only ZAP API client, ZAP daemon process manager, discovery runners, and the scan orchestrator. Contains no target data. |
| **Tools** | `src/red_teaming/tools/zap/` (code) and this `tools/zap/` document | The reusable ZAP integration and its documentation. Never stores target-specific artifacts. |
| **Projects** | `projects/<domain>/` | Target-specific work products only: reports, evidence, and scan outputs for exactly one domain. One domain's data is never mixed with another's, and target-specific output is never written to the project root. |

The CLI is the composition point:

- `src/red_teaming/cli/scan_target.py` — argument parsing, plan validation, and
  orchestration of a single run.
- `scripts/scan_target.py` — a thin, directly runnable wrapper that adds the
  in-tree `src/` directory to `sys.path` relative to its own location (never
  the current working directory), so it can be run without installing the
  package.

**Hard rule:** all scan output is written beneath
`projects/<domain>/`, never into `src/`, `tools/`, `scripts/`, or the project
root.

---

## 2. Supported modes and explicit non-capabilities

Supported modes (`--mode`):

| Mode | Behavior |
| --- | --- |
| `spider` | Traditional (non-browser) Spider only. |
| `ajax` | AJAX Spider only (browser/JavaScript-driven crawl). |
| `both` | Traditional Spider first, then AJAX Spider. |

**Not implemented (non-capabilities):** this wrapper does **not** perform active
scanning, authentication/login, API-spec (OpenAPI/GraphQL/SOAP) import, fuzzing,
reporting, or any request other than the configured discovery run. The wrapper
does **not** orchestrate, wait for, collect, or report passive-scan results;
note that ZAP may still passively inspect proxied Spider/AJAX traffic by default,
so ZAP can generate passive findings even though this wrapper never surfaces
them. There is no "active" mode: `--mode active` is rejected by the parser.
Adding any of these is a scope change that requires explicit authorization.

Even the two implemented modes are **active target interaction**:

- The traditional Spider issues HTTP requests and enumerates links.
- The AJAX Spider launches a real browser engine, executes JavaScript, and
  renders pages. It will also load third-party sub-resources referenced by the
  target page (see §8).

The mere presence or version of ZAP on a host – and the existence of this
wrapper – **does not authorize use against any target**. Each target run
requires separate, explicit approval naming the target and the requested mode.

---

## 3. Architecture: centralized process and API access

Exactly one component owns each side of the interaction:

| Component | File | Owns |
| --- | --- | --- |
| `ZapProcessManager` | `src/red_teaming/tools/zap/process.py` | The **only** code that starts, waits for, and stops the ZAP daemon. |
| `ZapApiClient` | `src/red_teaming/tools/zap/client.py` | The **only** code that builds and sends HTTP requests to the ZAP API. |
| `SpiderRunner` / `AjaxSpiderRunner` | `src/red_teaming/tools/zap/discovery.py` | The bounded polling loops; they never perform HTTP directly. |
| `ZapScanner` | `src/red_teaming/tools/zap/scanner.py` | The single-run sequence and state/artifact persistence. |
| `scan_target.py` | `src/red_teaming/cli/scan_target.py` | Argument validation and composition. |

Nothing in the package performs network or process activity at import time.

### Daemon command

`ZapProcessManager` builds a deterministic headless command with **no target URL
in it**:

```text
<executable> -daemon -host <loopback-host> -port <port> \
  -dir <scan-dir>/zap-home \
  -config api.disablekey=false \
  -config api.key=<ephemeral-key>
```

### Loopback enforcement

`ZapEndpoint` accepts only:

- schemes `http` or `https`;
- loopback hosts (`localhost`, any `127.0.0.0/8` address, or `::1`);
- an explicit, in-range port (1–65535); default `127.0.0.1:8080`;
- a root path only — credentials, query strings, fragments, and paths are
  rejected.

A non-loopback `--zap-host` is rejected before any process or request is made.

### API-key handling

- A fresh key is generated per run with `secrets.token_hex(32)`.
- The key is passed to the daemon via `-config api.key=<key>` with
  `api.disablekey=false`, and injected at request time as the `apikey` query
  parameter by `ZapApiClient`.
- Framework-owned outputs — `scan.json`, raw artifacts, and error messages —
  omit or redact the key (`***`).
- The key is nevertheless passed on the process command line and to ZAP itself.
  Process listings and ZAP-managed runtime artifacts (for example the
  `zap-home/` tree and the captured daemon logs) must therefore be treated as
  sensitive during the run and reviewed/secured according to the project's
  retention policy. The key is generated per run and is not a target credential.
- Error messages, `repr()`, and `safe_command()` redact the key (`***`).

#### Local-health smoke exception (keyless, offline)

The project-local, loopback-only ZAP daemon health smoke is the **only**
permitted use of keyless mode. Both `ZapApiClient` and `ZapProcessManager`
expose an explicit opt-in (`keyless=True`) that is rejected unless it is paired
with an already validated loopback endpoint and no supplied API key:

- `ZapApiClient(..., None, keyless=True)` never creates or sends an `apikey`
  query parameter, and its `repr()` shows `keyless=True` without implying a
  secret exists. Passing `api_key=None` *without* the opt-in remains a
  configuration error, and passing a key *with* the opt-in is rejected.
- `ZapProcessManager(..., keyless=True)` builds
  `-config api.disablekey=true` and adds **no** `api.key=...` argument. An
  injected `ZapApiClient` must agree on the keyless flag.

The same smoke may set `offline_smoke=True`, which appends deterministic ZAP
`-config` hardening verified against the installed ZAP 2.17.0 `config.xml`:

- `start.checkForUpdates=false`, `start.downloadNewRelease=false`,
  `start.checkAddonUpdates=false`, `start.installAddonUpdates=false`,
  `start.installScannerRules=false` — suppress automatic update, add-on, and
  scanner-rule activity;
- `callhome.tel.enabled=false` — suppress the callhome add-on telemetry upload.
  The add-on (callhome 0.20.0) attempted telemetry through the outbound proxy at
  both startup and shutdown; with an enforcing Stage 2 guard that attempt would
  be recorded as a denied off-host/plain-HTTP connection and fail preflight, so
  telemetry is disabled at launch and read back before any target request. The
  key and its default (`true`) were verified read-only from the installed
  add-on bytecode; only project-local runtime arguments change;
- `network.connection.httpProxy.enabled=true` with
  `network.connection.httpProxy.host=127.0.0.1` and a caller-configurable closed
  loopback guard port (`network.connection.httpProxy.port`, default `1`) — a
  defense-in-depth route for any accidental outbound HTTP(S);
- `oast.callback.localaddr=127.0.0.1`, `oast.callback.remoteaddr=127.0.0.1`,
  and `oast.callback.port=18081` — fixed, non-user-configurable loopback
  containment for any locally started OAST callback listener. The key names and
  their default semantics were verified read-only from the installed OAST
  0.24.0 `CallbackParam` bytecode and embedded help; the add-on is not
  uninstalled, disabled, or reconfigured, and only project-local runtime
  arguments change.

In addition, offline mode (and the bounded Stage 2 launch, which sets
`silent=True`) passes the ZAP `-silent` switch. `-silent` sets ZAP's
`Constant.setSilent(true)`, whose only consumer is the auto-update extension, so
every ZAP-initiated *unsolicited* request is suppressed — notably the
auto-update/news fetch to `news.zaproxy.org` that ZAP attempts during daemon
startup **independently of `start.checkForUpdates`**. Without it, that off-host
request is correctly denied by the enforcing Stage 2 guard and the fail-closed
preflight refuses to start the Spider (as happened in the historical run
`20261003T122211Z-1c4205`). The switch is a bare flag, adds no
`-config` pair, and introduces no target or external hostname.

The guard endpoint is validated as loopback with an in-range port, and no
target URL or external hostname is ever added to the command. All ZAP
configuration stays in the per-run `-dir` under the scan path.

The normal scan CLI is unchanged and remains protected by a per-run ephemeral
key (`secrets.token_hex(32)`); keyless/offline mode is not exposed by the CLI.

### Target scope

Before spidering, the scanner creates a ZAP context named `scan-<scan-id>` and
adds one anchored, escaped include-URL regex that pins the exact normalized
scheme and host plus the seed path subtree. This prevents lookalike/sibling
hosts from being in scope; it does **not** stop a browser from fetching
third-party resources referenced by an in-scope page.

---

## 4. CLI arguments

Required:

| Argument | Meaning |
| --- | --- |
| `--workspace-root` | Absolute path to **this** approved checkout (must contain `AGENTS.md`, `PROJECT.md`, `CURRENT_TASK.md`, and `projects/`). |
| `--output-dir` | Absolute path that exactly matches the canonical scan layout (see §5). Must not already exist. |
| `--zap-executable` | Absolute path to an existing regular file used to launch the ZAP daemon. |
| `--project` | The project/domain this scan belongs to (for example `example.test`). |
| `--target` | The seed URL, using `http`/`https`, no query/fragment/userinfo, default port only, and a host equal to the project domain or a subdomain. |
| `--mode` | One of `spider`, `ajax`, `both`. |

Safety flags:

| Flag | Meaning |
| --- | --- |
| `--validate-only` | Validate the whole plan and print a redacted summary. **No** directory is created, **no** process starts, **no** API call is made. |
| `--confirm-authorized` | Required for an actual run. This is a safety latch only; it does **not** itself confer legal authorization for the target. |

Connection (loopback only):

| Argument | Default |
| --- | --- |
| `--zap-host` | `127.0.0.1` |
| `--zap-port` | `8080` |

Bounded timeouts (seconds; all must be positive finite numbers):

| Argument | Default | Purpose |
| --- | --- | --- |
| `--startup-timeout` | `60` | Wait for the ZAP API to answer `core/version` and meet the minimum version. |
| `--spider-timeout` | `300` | Overall bound for the traditional Spider. |
| `--ajax-timeout` | `300` | Overall bound for the AJAX Spider. |
| `--request-timeout` | `10` | Per-request HTTP timeout for ZAP API calls. |
| `--poll-interval` | `0.25` | Poll spacing for readiness and progress loops. |
| `--graceful-timeout` | `10` | Wait for graceful (API `core/shutdown`) exit. |
| `--terminate-timeout` | `10` | Wait after `terminate()` before escalating. |
| `--kill-timeout` | `5` | Wait after `kill()`. |

Exit codes: `0` success, `2` validation/usage error, `3` runtime error.

---

## 5. Canonical output layout

A run writes only under the workspace's `projects/<domain>/` tree:

```text
<workspace>/projects/<domain>/targets/<host>/scans/zap/<scan-id>/
├── scan.json                 # atomic, schema-versioned scan state
├── logs/
│   ├── zap-stdout.log        # captured daemon stdout
│   └── zap-stderr.log        # captured daemon stderr
├── zap-home/                 # ZAP -dir home (ZAP-managed session/config files)
└── raw/
    ├── spider.json           # {"mode":"spider","scan_id":...,"results":[...]}
    └── ajax.json             # {"mode":"ajax","scan_id":...,"results":[...]}
```

- `<domain>` is the normalized project domain; `<host>` is the normalized
  target host (the domain or a subdomain).
- `<scan-id>` has the form `YYYYMMDDThhmmssZ-<hex>` and must equal the final
  component of `--output-dir`.
- `raw/spider.json` is written only for `spider`/`both`; `raw/ajax.json` only
  for `ajax`/`both`.
- `scan.json` tracks `schema_version`, `scan_id`, `project`, `target`, `mode`,
  `status`, `phase`, timestamps, `zap_version`, `context_name`, `scope_regex`,
  per-step `steps`, `artifacts`, and (on failure) a sanitized `error` plus, when
  shutdown also fails, a sanitized `shutdown_error`.

The output directory is refused if it already exists. CLI plan validation
resolves symlinks/junctions and verifies the scan path stays inside the
workspace and canonical layout; individual state and artifact writes are then
bounded **lexically** under that already-validated scan path — each write does
not independently re-run symlink/junction resolution.

---

## 6. `--validate-only` versus a real run

`--validate-only`:

- parses and fully validates the plan (workspace root, canonical layout,
  executable, project/target, mode, endpoint, timeouts);
- prints a redacted plan summary, with `authorization: not run (validate-only)`
  and `API key: not generated`;
- creates nothing and touches no process or socket.

A **real run** additionally requires `--confirm-authorized`. Without it the CLI
exits with a validation error and still creates nothing. With it, the sequence
is: persist `planned` state -> start daemon -> wait for ready/version -> create
context and scope -> run selected mode(s) -> write raw artifacts -> mark
`succeeded` -> stop the daemon. If the daemon survives shutdown the run is
instead persisted as `failed` (see §7).

> `--confirm-authorized` records operator intent; it is not legal authorization.
> Obtain explicit approval for the specific target and run parameters first.

---

## 7. Failure, timeout, and shutdown behavior

- **Startup:** bounded polling of `core/version`. A premature process exit
  raises a process-exited error; exhausting the startup timeout raises a
  readiness-timeout error; a version below the minimum (2.17.0) raises a
  version error.
- **Discovery:** the traditional Spider completes at progress `100`; the AJAX
  Spider completes at status `stopped`. On timeout, process exit, or unexpected
  status, the remote scan is asked to stop before the original error is
  re-raised.
- **Failure state:** any failure records a `failed` state with the phase, error
  type, and a redacted message, then re-raises. Persistence errors never mask
  the original failure.
- **Shutdown:** always attempted exactly once, even on failure, via API
  `core/shutdown` (graceful) then `terminate()` then `kill()`, each bounded; log
  handles are closed and readiness is cleared. If the process is still alive
  after the bounded kill wait, `stop()` raises a typed `ZapStopError` and keeps
  the live handle so a later stop can retry. A shutdown failure after otherwise
  successful discovery is itself a scan failure: a sanitized `failed` state is
  persisted and the shutdown error is propagated. If discovery already failed
  and shutdown also fails, the original discovery error is re-raised unchanged
  and the sanitized shutdown failure is recorded separately as
  `shutdown_error`. `stop()` is idempotent once the process has exited and is
  safe from `finally`/context-manager paths.

---

## 8. Security limitations

- **AJAX/browser third-party risk:** the AJAX Spider drives a real browser that
  executes page JavaScript and loads referenced sub-resources (analytics, CDNs,
  fonts, trackers). Those requests may go to third parties **outside** the
  target scope. The context include-regex constrains crawling scope, not
  browser resource loading.
- **Active interaction:** both modes generate traffic against the target. Only
  run against targets for which explicit authorization has been granted.
- **No isolation:** the wrapper does not sandbox, proxy, or rate-limit the
  target, and does not guarantee the daemon binds only to loopback beyond the
  configured endpoint.
- **Presence != authorization:** an installed ZAP does not authorize its use.
- **No secrets:** never place credentials, cookies, tokens, or API keys in the
  repository or command history. The wrapper manages its own ephemeral ZAP key;
  do not pass secrets as extra arguments, and do not commit `scan.json` if a
  future feature ever records target content.

---

## 9. Offline test and validation

No network, no daemon, and no target are needed for any of the following.

Full offline unit suite (run from the repository root):

```powershell
python -B -m unittest discover -s tests -t . -v
```

Syntax and import check without bytecode artifacts:

```powershell
python -B -c "import sys; sys.path.insert(0, 'src'); import red_teaming.cli.scan_target; print('ok')"
```

Smoke checks (replace `<repo>`; for validate-only, `--zap-executable` may point
at any existing regular file, such as a harmless empty temporary file, because
nothing is launched):

```powershell
# 1) Help / usage
python -B "<repo>\scripts\scan_target.py" --help

# 2) Expected argument-validation failure (invalid mode); exit code 2
python -B "<repo>\scripts\scan_target.py" --mode active

# 3) Validate-only success against the reserved example.test placeholder;
#    creates no directory and invokes no executable
$repo = "<repo>"
$scanId = "20261002T120000Z-abc123"
python -B "$repo\scripts\scan_target.py" `
  --workspace-root "$repo" `
  --output-dir "$repo\projects\example.test\targets\example.test\scans\zap\$scanId" `
  --zap-executable "<absolute-zap-executable>" `
  --project "example.test" `
  --target "https://example.test/" `
  --mode both `
  --validate-only
```

A real run (only after explicit authorization for the concrete target) adds
`--confirm-authorized` and **replaces every placeholder**, including
`<absolute-zap-executable>` and `example.test`:

```powershell
$repo = "<repo>"
$scanId = "<YYYYMMDDThhmmssZ-hex>"
python -B "$repo\scripts\scan_target.py" `
  --workspace-root "$repo" `
  --output-dir "$repo\projects\<domain>\targets\<host>\scans\zap\$scanId" `
  --zap-executable "<absolute-zap-executable>" `
  --project "<domain>" `
  --target "https://<host>/" `
  --mode both `
  --confirm-authorized
```

> Replace `<repo>`, `<domain>`, `<host>`, `<absolute-zap-executable>`, and
> `<YYYYMMDDThhmmssZ-hex>` before running. Never paste real credentials.

---

## 10. Bounded Stage 2 profile (dedicated, keyless, guarded)

The generic `scan_target.py` path above is AJAX-capable and is **not** the
CURRENT_TASK Stage 2 profile. In particular, the per-run ephemeral API-key
handling described for the generic path in §3 does **not** apply to the
dedicated Stage 2 path: that path is keyless and generates no key or other
secret. The generic path and its documentation are unchanged.

A separate, narrowly bounded path exists:

- `src/red_teaming/tools/zap/bounded.py` — the fixed profile, strict
  API-operation allowlist transport, preflight control evaluation, and runner.
- `src/red_teaming/cli/stage2_spider.py` and `scripts/stage2_spider.py` — a thin
  dedicated CLI. The project, seed, and mode are **fixed constants** and are not
  CLI options, so the profile cannot be widened by argument.

### Production readiness

Production is **no longer blocked by capability booleans**. There is no
`Stage2Capabilities` seam, no capability-injection option, and no
key-non-persistence or redirect-proof blocker. The runner is keyless and guarded
**by construction**, with no API key and no capability/guard override accepted
from the CLI or the runner:

- **Keyless ZAP API** bound exactly to `127.0.0.1:18080`. No API key or other
  secret is generated, accepted, injected, logged, persisted, or retained.
- **OAST callback** contained to loopback `127.0.0.1:18081`, and verified closed
  after shutdown.
- **Exact-host CONNECT egress guard** listening only on `127.0.0.1:18082`.
  ZAP's outbound HTTP(S) proxy is pinned by deterministic `-config` to exactly
  `network.connection.httpProxy.enabled=true`, `...host=127.0.0.1`, and
  `...port=18082`. The guard:
  - permits only CONNECT to the normalized host `acme.example` on port 443;
  - rejects IP literals, subdomains, other hosts/ports, and plain HTTP before
    any outbound connect;
  - is the only point of target DNS resolution: it resolves only that exact
    host, pins the accepted public IP set for the run, connects only to that
    set, and fails closed on any change (including a DNS-rebinding attempt);
  - stores bounded metadata only — no bodies, cookies, or credentials.
- **Runtime ownership checks.** Read-only local inspection before the first
  target request and after the Spider proves ZAP owns no non-loopback
  ESTABLISHED connection and the guard owns no non-loopback ESTABLISHED
  connection outside the pinned target IP set on port 443. The guard listener
  must be exactly `127.0.0.1:18082` owned by the guard PID, and the guard must
  have recorded no denied/error connection attempt.

### Exact controls and API allowlist

The run is fail-closed: a launch proceeds only when every static and runtime
control is proven active.

| Control | Enforcement / proof |
| --- | --- |
| Exact project, seed `https://acme.example/`, https/443, traditional Spider only | Deterministic profile + `ScanPath` validation |
| Keyless API = exactly `127.0.0.1:18080`, daemon identity unambiguous | Deterministic launch plan + one shared read-only lifecycle inspector |
| ZAP exactly 2.17.0 | Allowed `core/view/version` read-back |
| Exact-host scope (no subdomain) | Deterministic escaped scope regex + `scope_activated` recorded from successful allowlisted context calls before any target request |
| Depth <= 3, concurrency 1, runtime <= 300 s, <= 1 req/s, forms off | ZAP 2.17.0 `-config` pairs (`spider.maxDepth=3`, `spider.thread=1`, `spider.maxDuration=5` minutes, `spider.requestwait=1000` ms, `spider.processform=false`, `spider.postform=false`) verified by reading back the persisted project-local `zap-home/config.xml` |
| Callhome telemetry suppressed | Deterministic `callhome.tel.enabled=false` launch pair, read back from the persisted `zap-home/config.xml` `callhome/tel/enabled` value, which must be present and explicitly `false` before scope activation; missing/true/invalid fails closed |
| Egress guard exact and enforcing | Guard runtime status + proxy-config read-back (`enabled`/`host`/`port`) + guard listener and pinned-global-IP checks |
| No AJAX/browser/active scan/auth/import/report/`core/accessUrl` | Explicit API-operation allowlist enforced before the local transport |
| OAST callback loopback-only and closed after shutdown | Fixed `oast.callback.*=127.0.0.1:18081` containment + post-shutdown listener verification |
| GET/HEAD only | **Derived** (traditional Spider + forms disabled); not an independent runtime probe |
| No shutdown-time egress attempt | The retained guard records/counters are inspected one final time after ZAP shutdown and guard stop; unavailable records or any denied/error attempt (for example a shutdown-time callhome egress) fails the run |
| Clean ZAP shutdown | API shutdown attempted and sent, graceful result, daemon gone, both fixed ports closed, no control errors or terminate/kill fallback |

The complete allowlist is exactly:

```text
core/view/version
context/action/newContext
context/action/includeInContext
spider/action/scan
spider/view/status
spider/view/results
spider/action/stop
core/action/shutdown
```

Evidence is written under the run directory: `stage2-state.json` (atomic,
schema-versioned state), `stage2-prelaunch.json`, `stage2-preflight.json`,
`stage2-spider.json`, `STAGE2_SPIDER.md`, and `raw/spider.json`. The guard and
API-call records are bounded and contain no bodies, cookies, credentials, or
query strings.

`--validate-only` is side-effect-free: it validates the whole profile and prints
a summary without creating a directory, resolving DNS, opening a socket, or
starting a process. A real run additionally requires `--confirm-authorized`;
that latch is not legal authorization and the run still remains subject to the
`CURRENT_TASK.md` launch budgets (exactly one Stage 1 and, only on full success,
exactly one Stage 2; no retry for either).

### Runbook

Replace `<repo>`, `<absolute-zap-executable>`, and each fresh `<scan-id>` before
running. Use a new run directory for every launch. Under `CURRENT_TASK.md`, the
final commands must be run in strict sequence — offline tests, then exactly one
Stage 1, then only on full Stage 1 success exactly one Stage 2 — with no retry.

Both Stage 1 (offline smoke) and Stage 2 (bounded Spider) launch with the
callhome add-on telemetry suppressed (`callhome.tel.enabled=false`). Stage 2
reads that exact key back from the project-local `zap-home/config.xml` and
requires it to be explicitly `false` before scope activation; it also inspects
the retained guard records one final time after ZAP shutdown and guard stop, so
any shutdown-time off-host/plain-HTTP attempt (for example residual callhome
telemetry) fails the run closed instead of being silently recorded after the
last Spider observer.

Offline tests (from the repository root):

```powershell
python -B -m unittest discover -s tests -t . -v
```

Stage 1 — one loopback-only validation launch (no target URL, no target DNS):

```powershell
$repo = "<repo>"
$scanId = "<YYYYMMDDThhmmssZ-hex>"
python -B "$repo\scripts\smoke_zap.py" `
  --workspace-root "$repo" `
  --output-dir "$repo\projects\acme.example\targets\acme.example\scans\zap\$scanId" `
  --zap-executable "<absolute-zap-executable>" `
  --project "acme.example" `
  --confirm-local-smoke
```

Stage 2 — validate-only (side-effect-free; no key generated, nothing created):

```powershell
python -B "<repo>\scripts\stage2_spider.py" `
  --workspace-root "<repo>" `
  --output-dir "<repo>\projects\acme.example\targets\acme.example\scans\zap\<scan-id>" `
  --zap-executable "<absolute-zap-executable>" `
  --validate-only
```

Stage 2 — final actual run (only after full Stage 1 success):

```powershell
python -B "<repo>\scripts\stage2_spider.py" `
  --workspace-root "<repo>" `
  --output-dir "<repo>\projects\acme.example\targets\acme.example\scans\zap\<scan-id>" `
  --zap-executable "<absolute-zap-executable>" `
  --confirm-authorized
```
