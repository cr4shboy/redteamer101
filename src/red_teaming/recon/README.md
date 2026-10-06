# `red_teaming.recon` — bounded passive + DNS recon

Domain-neutral, offline-first recon pipeline: passive subdomain discovery and
bounded DNS resolution over an explicit, fail-closed egress allowlist. This
module ships **code only** — no target data, no evidence, and no tool binaries.
It performs no network or process activity at import; every adapter injects its
executable lookup and its socket/subprocess call, so the module is inert without
provisioned tools and an explicit authorization.

## What it does

- **Passive discovery** — passive sources (e.g. Subfinder, Amass restricted to a
  Certificate Transparency source) emit in-scope subdomain candidates.
- **DNS resolution** — `dnsx` resolves accepted candidates for A / AAAA / CNAME
  only, through the resolver named by the active network policy.
- **Scope enforcement** — a per-run policy pins the authorized root domain and
  its normalized subdomains; every DNS question and every CONNECT authority is
  classified and anything out of scope is denied before any upstream contact.
- **Egress broker / netns sandbox** — the single point that opens external
  sockets, enforcing the allowlist (fail-closed).
- **Evidence** — per-domain, atomic, schema-versioned run artifacts written
  under `projects/<domain>/` (git-ignored; never committed to this repo).

## Configuration

The authorized root domain, resolver, source allowlist, rate limits, and run
budget are **runtime inputs** supplied by an approved authorization package —
never hard-coded here. Tests and examples use the reserved documentation name
`acme.example` and the documentation address `203.0.113.10` (RFC 5737) purely as
placeholders.

## Safety

A live run is fail-closed by default and refuses to execute without an explicit,
current authorization that names the domain, the egress allowlist, the per-tool
limits, and the stop / acceptance criteria. Only run against systems you are
authorized to assess.

## Tests

The suite is fully offline — injected fakes, no network, no real process, no tool
binaries, no target data:

```bash
python -m pytest -q
# or, without installing anything:
PYTHONPATH=src python -m unittest discover -s tests -t .
```
