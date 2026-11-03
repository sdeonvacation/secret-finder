"""Render findings as human-readable text or stable JSON."""

from __future__ import annotations

import json
from typing import Protocol

from .models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, Finding

# Priority ordering: high first, then medium, then low; unknown ranks last.
_SEVERITY_RANK = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}


def _rank(finding: Finding) -> int:
    return _SEVERITY_RANK.get(finding.severity, 3)


class Reporter(Protocol):
    def render(self, findings: list[Finding]) -> str: ...


class TextReporter:
    """Render findings grouped by file, confidence-first.

    File groups are ordered by their best severity rank (high first), then
    filename; within a group findings are ordered by severity rank, then line.
    Format, one finding per line after a bare ``<file>:`` header::

        src/config.py:
          12: [high] aws-access-key — AWS access key ID

    Empty input renders exactly ``"No secrets found."``
    """

    def render(self, findings: list[Finding]) -> str:
        if not findings:
            return "No secrets found."
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file, []).append(finding)
        out: list[str] = []
        for file in sorted(
            by_file, key=lambda f: (min(_rank(x) for x in by_file[f]), f)
        ):
            out.append(f"{file}:")
            for finding in sorted(by_file[file], key=lambda f: (_rank(f), f.line)):
                out.append(
                    f"  {finding.line}: [{finding.severity}] {finding.rule} — {finding.reason}"
                )
        return "\n".join(out)


class JsonReporter:
    """Render findings as JSON with the stable schema.

    Stable key order: each finding uses ``file, line, rule, severity, reason,
    secret_preview``; the document uses ``findings, summary``; the summary
    uses ``total, high, medium, low``. Findings are ordered by severity rank
    (high first), then file, then line. Pretty-printed with indent=2 and a
    trailing newline. Only ``secret_preview`` (already masked) is serialized;
    raw secrets never appear.
    """

    def render(self, findings: list[Finding]) -> str:
        ordered = sorted(findings, key=lambda f: (_rank(f), f.file, f.line))
        payload = {
            "findings": [
                {
                    "file": finding.file,
                    "line": finding.line,
                    "rule": finding.rule,
                    "severity": finding.severity,
                    "reason": finding.reason,
                    "secret_preview": finding.secret_preview,
                }
                for finding in ordered
            ],
            "summary": {
                "total": len(ordered),
                SEVERITY_HIGH: sum(1 for f in ordered if f.severity == SEVERITY_HIGH),
                SEVERITY_MEDIUM: sum(
                    1 for f in ordered if f.severity == SEVERITY_MEDIUM
                ),
                SEVERITY_LOW: sum(1 for f in ordered if f.severity == SEVERITY_LOW),
            },
        }
        return json.dumps(payload, indent=2) + "\n"
