"""Deterministic report rendering: Markdown, JSON, and SARIF.

All renderers are pure functions of their inputs and emit no timestamps or other
nondeterministic data, so identical recon state yields byte-identical reports
(reproducible, diffable, and offline-testable). SARIF 2.1.0 output lets findings
feed defensive pipelines such as GitHub code scanning.
"""

from __future__ import annotations

import json
from typing import Sequence

from .facts import summary
from .findings import Finding, Severity
from .model import KnowledgeBase
from .plan import Decision

__all__ = [
    "SARIF_SCHEMA",
    "TOOL_NAME",
    "TOOL_URI",
    "TOOL_VERSION",
    "render_json",
    "render_markdown",
    "render_sarif",
]

TOOL_NAME = "redteamer101"
TOOL_VERSION = "0.0.1"
TOOL_URI = "https://github.com/cr4shboy/redteamer101"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: Finding severity -> SARIF result level.
_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "warning",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def render_json(
    kb: KnowledgeBase,
    decisions: Sequence[Decision],
    findings: Sequence[Finding],
) -> str:
    """Return a deterministic JSON report (knowledge, plan, findings)."""

    payload = {
        "domain": kb.domain,
        "facts": summary(kb),
        "assets": [asset.to_dict() for asset in kb.assets],
        "fingerprints": [item.to_dict() for item in kb.fingerprints],
        "plan": [decision.to_dict() for decision in decisions],
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_markdown(
    kb: KnowledgeBase,
    decisions: Sequence[Decision],
    findings: Sequence[Finding],
) -> str:
    """Return a deterministic Markdown report."""

    facts = summary(kb)
    lines: list[str] = []
    lines.append(f"# Recon report: {kb.domain}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- hosts discovered: {facts['hosts']}")
    lines.append(f"- resolvable: {len(facts['resolvable'])}")
    lines.append(f"- live web hosts: {len(facts['web_hosts'])}")
    lines.append(f"- findings: {len(findings)}")
    lines.append("")

    lines.append("## Web server fingerprints")
    lines.append("")
    if kb.fingerprints:
        lines.append("| host | endpoint | source | status | reported product | reported version |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for item in kb.fingerprints:
            lines.append(
                f"| {item.host} | {item.scheme}:{item.port} | {item.source_id} "
                f"| {item.status} | {item.claimed_product or ''} "
                f"| {item.claimed_version or ''} |"
            )
    else:
        lines.append("_No web server fingerprint observations supplied._")
    lines.append("")

    lines.append("## Plan")
    lines.append("")
    lines.append("| stage | tier | status | reason |")
    lines.append("| --- | --- | --- | --- |")
    for d in decisions:
        lines.append(
            f"| {d.stage} | {d.tier} | {d.status} | {d.reason or ''} |"
        )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if findings:
        lines.append("| severity | rule | host | evidence |")
        lines.append("| --- | --- | --- | --- |")
        for f in findings:
            lines.append(
                f"| {f.severity.value} | {f.rule_id} | {f.host or ''} | {f.evidence} |"
            )
    else:
        lines.append("_No findings for the current knowledge base._")
    lines.append("")
    return "\n".join(lines)


def render_sarif(
    findings: Sequence[Finding],
    *,
    domain: str | None = None,
) -> str:
    """Return a deterministic SARIF 2.1.0 report for *findings*."""

    rules_by_id: dict[str, Finding] = {}
    for finding in findings:
        rules_by_id.setdefault(finding.rule_id, finding)
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": example.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL[example.severity]},
        }
        for rule_id, example in sorted(rules_by_id.items())
    ]

    results = []
    for finding in findings:
        result = {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.evidence},
            "properties": {"category": finding.category, "domain": domain},
        }
        if finding.host:
            result["locations"] = [
                {"logicalLocations": [{"fullyQualifiedName": finding.host}]}
            ]
        results.append(result)

    document = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=False)
