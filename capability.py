#!/usr/bin/env python3
"""Minimal capability lookup/decision/handoff CLI (CAPABILITY-001..008, local-only).

Reads ``capabilities/registry.yaml`` relative to this file and reports the status
of a single named capability (``python capability.py <name>``), emits the next
action for it (``python capability.py decide <name>`` and the machine-readable
``python capability.py decide-json <name>``), emits a structured build request
for an unavailable capability (``python capability.py build-request <name>``), or
submits an approved build request asynchronously to the already-running local
OpenCode Server API. A generated request for a named capability is submitted with
``python capability.py handoff <name> --approved``; an already-created
project-local JSON request is submitted verbatim with
``python capability.py handoff-request <request-file> --approved``.
Standard library only; no framework.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
REGISTRY_PATH = PROJECT_ROOT / "capabilities" / "registry.yaml"

# Local OpenCode Server API base and a small finite timeout so the CLI can never
# hang indefinitely on a stalled local server.
OPENCODE_SERVER = "http://127.0.0.1:4096"
OPENCODE_TIMEOUT = 10


def _parse_registry(text: str) -> dict:
    """Parse the tiny YAML subset used by ``registry.yaml``.

    Supported shape::

        name:
          key: value
          key: value

    Returns a mapping of ``name -> {key: value}``. This intentionally handles
    only the one nested mapping-of-scalars shape used by this project.
    """
    registry: dict = {}
    current: dict | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line[0] not in (" ", "\t"):
            if not line.endswith(":"):
                raise ValueError(f"line {lineno}: expected '<name>:'")
            name = line[:-1].strip()
            if not name:
                raise ValueError(f"line {lineno}: empty name")
            current = {}
            registry[name] = current
            continue
        if current is None:
            raise ValueError(f"line {lineno}: indented entry before any name")
        key, sep, value = line.strip().partition(":")
        key = key.strip()
        if not sep or not key:
            raise ValueError(f"line {lineno}: expected '<key>: <value>'")
        current[key] = value.strip()
    return registry


def _load_registry() -> dict:
    """Read and parse the registry from its fixed, script-relative path."""
    return _parse_registry(REGISTRY_PATH.read_text(encoding="utf-8"))


def _decide(name: str, entry: dict | None) -> dict:
    """Return the structured decision for *name* given its registry *entry*.

    Keys are inserted in output order: ``capability``, ``status``, ``action``,
    then ``path`` only for a known ``available`` capability.
    """
    if entry is None:
        return {"capability": name, "status": "unknown", "action": "propose_build"}
    if entry.get("status") == "available":
        return {
            "capability": name,
            "status": "available",
            "action": "execute",
            "path": entry.get("path", ""),
        }
    return {"capability": name, "status": "missing", "action": "propose_build"}


def _print_decision(name: str, entry: dict | None) -> None:
    """Print the next action for *name* given its registry *entry* (or None)."""
    decision = _decide(name, entry)
    print(f"capability: {decision['capability']}")
    print(f"status: {decision['status']}")
    print(f"action: {decision['action']}")
    if "path" in decision:
        print(f"path: {decision['path']}")


def _build_request(name: str) -> dict:
    """Return the ordered JSON build-request package for an unavailable *name*."""
    return {
        "request_type": "build_capability",
        "capability": name,
        "objective": f"Implement a bare-minimum working capability named {name}.",
        "implementation_mode": "bare_minimum",
        "constraints": [
            "reuse existing project structure",
            "implement only functionality required to make the capability work",
            "avoid unnecessary abstractions",
            "run only directly relevant smoke tests",
        ],
        "completion_requirements": [
            "capability works",
            "actual smoke-test output is reported",
            "registry is updated to available only after successful validation",
        ],
    }


def _http_post_json(url: str, payload: dict) -> tuple[int, bytes]:
    """POST a JSON *payload* to *url*; return ``(status, body)``.

    Transport and HTTP-status errors propagate as ``urllib`` exceptions so the
    caller can fail clearly. A small finite timeout bounds every request.
    """
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=OPENCODE_TIMEOUT) as response:
        status = getattr(response, "status", None)
        if status is None:
            status = response.getcode()
        return status, response.read()


def _submit_build_prompt(capability: str, prompt: str) -> int:
    """Submit an approved build *prompt* to the local OpenCode Server API.

    Performs the two-call transport (create session, then async prompt submit)
    and returns immediately after submission is accepted; it never waits for or
    monitors build completion. Shared by ``handoff`` and ``handoff-request``.
    """
    # 1. Create a session.
    try:
        status, body = _http_post_json(OPENCODE_SERVER + "/session", {})
    except urllib.error.HTTPError as exc:
        print(
            f"OpenCode handoff failed: session create returned HTTP {exc.code}",
            file=sys.stderr,
        )
        return 1
    except (urllib.error.URLError, OSError) as exc:
        print(f"OpenCode handoff failed: {exc}", file=sys.stderr)
        return 1
    if not 200 <= status < 300:
        print(
            f"OpenCode handoff failed: session create returned HTTP {status}",
            file=sys.stderr,
        )
        return 1
    try:
        session = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        print(
            "OpenCode handoff failed: session create returned invalid JSON",
            file=sys.stderr,
        )
        return 1
    session_id = session.get("id") if isinstance(session, dict) else None
    if not isinstance(session_id, str) or not session_id:
        print(
            "OpenCode handoff failed: session create returned no session id",
            file=sys.stderr,
        )
        return 1

    # 2. Submit the prompt asynchronously; success is exactly HTTP 204.
    prompt_url = (
        OPENCODE_SERVER
        + "/session/"
        + urllib.parse.quote(session_id, safe="")
        + "/prompt_async"
    )
    payload = {
        "agent": "architect",
        "parts": [{"type": "text", "text": prompt}],
    }
    try:
        status, _ = _http_post_json(prompt_url, payload)
    except urllib.error.HTTPError as exc:
        print(
            f"OpenCode handoff failed: prompt submit returned HTTP {exc.code}",
            file=sys.stderr,
        )
        return 1
    except (urllib.error.URLError, OSError) as exc:
        print(f"OpenCode handoff failed: {exc}", file=sys.stderr)
        return 1
    if status != 204:
        print(
            f"OpenCode handoff failed: prompt submit returned HTTP {status}",
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "capability": capability,
                "status": "submitted",
                "opencode_session_id": session_id,
            },
            indent=2,
        )
    )
    return 0


def _handoff(name: str) -> int:
    """Submit an approved, generated build request to the OpenCode Server API.

    Reuses ``_decide``/``_build_request``; returns immediately after the
    asynchronous submission is accepted and never waits for build completion.
    """
    try:
        registry = _load_registry()
    except (OSError, ValueError) as exc:
        print(f"capability.py: cannot read registry: {exc}", file=sys.stderr)
        return 1
    decision = _decide(name, registry.get(name))
    if decision["action"] != "propose_build":
        print(f"{name} is already available", file=sys.stderr)
        return 1

    request_json = json.dumps(_build_request(name), indent=2)
    prompt = (
        "This capability build request has already been approved and is submitted "
        "to you now via the local OpenCode Server API. Do not invoke "
        "`capability.py handoff` recursively.\n\n"
        "Execute the build request: design the smallest working implementation, "
        "delegate implementation to the existing `coder` subagent, run only "
        "directly relevant smoke tests, and update the registry to `available` "
        "only after successful validation.\n\n"
        "Build request:\n" + request_json
    )
    return _submit_build_prompt(name, prompt)


def _resolve_request_path(request_file: str) -> Path:
    """Resolve *request_file* inside the project root or raise ``ValueError``.

    Relative paths resolve from the project root; absolute paths are allowed
    only when they already point inside it.
    """
    candidate = Path(request_file)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    resolved = candidate.resolve()
    root = PROJECT_ROOT.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("request file must be inside the project root") from None
    return resolved


def _handoff_request(request_file: str) -> int:
    """Submit an already-created project-local JSON build request verbatim.

    The file text is validated as JSON but placed unchanged into the Architect
    prompt so the approved requirements are never regenerated, summarized,
    replaced, or otherwise altered.
    """
    try:
        path = _resolve_request_path(request_file)
    except ValueError as exc:
        print(f"OpenCode handoff failed: {exc}", file=sys.stderr)
        return 1
    try:
        file_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(
            f"OpenCode handoff failed: cannot read request file: {exc}",
            file=sys.stderr,
        )
        return 1
    try:
        request = json.loads(file_text)
    except ValueError:
        print(
            "OpenCode handoff failed: request file is not valid JSON",
            file=sys.stderr,
        )
        return 1
    if not isinstance(request, dict):
        print(
            "OpenCode handoff failed: request file must contain a JSON object",
            file=sys.stderr,
        )
        return 1
    capability = request.get("capability")
    if not isinstance(capability, str) or not capability:
        print(
            "OpenCode handoff failed: request file requires a nonempty string "
            "'capability'",
            file=sys.stderr,
        )
        return 1
    if "objective" not in request or "requirements" not in request:
        print(
            "OpenCode handoff failed: request file requires 'objective' and "
            "'requirements'",
            file=sys.stderr,
        )
        return 1

    prompt = (
        "This capability build request has already been approved and is submitted "
        "to you now via the local OpenCode Server API. Do not invoke "
        "`capability.py handoff` or `capability.py handoff-request` recursively.\n\n"
        "Execute the exact approved request below verbatim; do not regenerate, "
        "summarize, replace, or otherwise alter its requirements.\n\n"
        "Build request:\n" + file_text
    )
    return _submit_build_prompt(capability, prompt)


def main(argv: list) -> int:
    if len(argv) >= 2 and argv[1] == "handoff-request":
        if len(argv) == 4 and argv[3] == "--approved":
            return _handoff_request(argv[2])
        if len(argv) == 3 and argv[2] != "--approved":
            print("handoff-request requires --approved", file=sys.stderr)
            return 1
        print(
            "usage: python capability.py handoff-request <request-file> --approved",
            file=sys.stderr,
        )
        return 2

    if len(argv) >= 2 and argv[1] == "handoff":
        if len(argv) == 4 and argv[3] == "--approved":
            return _handoff(argv[2])
        if len(argv) == 3 and argv[2] != "--approved":
            print("handoff requires --approved", file=sys.stderr)
            return 1
        print(
            "usage: python capability.py handoff <name> --approved",
            file=sys.stderr,
        )
        return 2

    if len(argv) >= 2 and argv[1] == "decide-json":
        if len(argv) != 3:
            print("usage: python capability.py decide-json <name>", file=sys.stderr)
            return 2
        name = argv[2]
        try:
            registry = _load_registry()
        except (OSError, ValueError) as exc:
            print(f"capability.py: cannot read registry: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(_decide(name, registry.get(name)), indent=2))
        return 0

    if len(argv) >= 2 and argv[1] == "build-request":
        if len(argv) != 3:
            print("usage: python capability.py build-request <name>", file=sys.stderr)
            return 2
        name = argv[2]
        try:
            registry = _load_registry()
        except (OSError, ValueError) as exc:
            print(f"capability.py: cannot read registry: {exc}", file=sys.stderr)
            return 1
        decision = _decide(name, registry.get(name))
        if decision["action"] != "propose_build":
            print(f"{name} is already available", file=sys.stderr)
            return 1
        print(json.dumps(_build_request(name), indent=2))
        return 0

    if len(argv) >= 2 and argv[1] == "decide":
        if len(argv) != 3:
            print("usage: python capability.py decide <name>", file=sys.stderr)
            return 2
        name = argv[2]
        try:
            registry = _load_registry()
        except (OSError, ValueError) as exc:
            print(f"capability.py: cannot read registry: {exc}", file=sys.stderr)
            return 1
        _print_decision(name, registry.get(name))
        return 0

    if len(argv) != 2:
        print("usage: python capability.py <name>", file=sys.stderr)
        return 2

    name = argv[1]
    try:
        registry = _load_registry()
    except (OSError, ValueError) as exc:
        print(f"capability.py: cannot read registry: {exc}", file=sys.stderr)
        return 1

    decision = _decide(name, registry.get(name))
    if decision["status"] == "unknown":
        print(f"unknown capability: {name}", file=sys.stderr)
        return 1

    if decision["status"] == "available":
        print(f"{name}: available")
        print(decision["path"])
    else:
        print(f"{name}: missing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
