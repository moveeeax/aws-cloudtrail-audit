"""Rendering: a grouped text table for humans, JSON for everything else."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .rules import Finding

ACCOUNT_SCOPE = "(account)"


def _group(findings: Iterable[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.trail or ACCOUNT_SCOPE, []).append(finding)
    return grouped


def render_text(findings: list[Finding], payload: dict[str, Any]) -> str:
    account = payload.get("account_id") or "unknown account"
    regions = payload.get("regions") or []
    trails = payload.get("trails") or []
    header = (
        f"CloudTrail audit — account {account}, "
        f"{len(trails)} trail(s), {len(regions)} region(s)"
    )

    if not findings:
        return header + "\n\nNo findings.\n"

    lines = [header, ""]
    for trail, items in _group(findings).items():
        lines.append(trail)
        width = max(len(f.rule) for f in items)
        for finding in items:
            lines.append(
                f"  {finding.severity.upper():<6} {finding.rule:<{width}}  "
                f"{finding.message}"
            )
        lines.append("")

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low") if s in counts)
    lines.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(lines) + "\n"


def render_json(findings: list[Finding], payload: dict[str, Any]) -> str:
    document = {
        "account_id": payload.get("account_id"),
        "regions": payload.get("regions") or [],
        "trail_count": len(payload.get("trails") or []),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(document, indent=2, sort_keys=False) + "\n"
