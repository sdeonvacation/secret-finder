"""Render findings as human-readable text or stable JSON."""

from __future__ import annotations

import json
from typing import Protocol

from .models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, Finding


class Reporter(Protocol):
    def render(self, findings: list[Finding]) -> str: ...


class TextReporter:
    """Render findings grouped by file (files sorted, then line, then rule).

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
        for file in sorted(by_file):
            out.append(f"{file}:")
            for finding in sorted(by_file[file], key=lambda f: (f.line, f.rule)):
                out.append(
                    f"  {finding.line}: [{finding.severity}] {finding.rule} — {finding.reason}"
                )
        return "\n".join(out)


class JsonReporter:
    """Render findings as JSON per HLD section 6.

    Stable key order: each finding uses ``file, line, rule, severity, reason,
    secret_preview``; the document uses ``findings, summary``; the summary
    uses ``total, high, medium, low``. Pretty-printed with indent=2 and a
    trailing newline. Only ``secret_preview`` (already masked) is serialized;
    raw secrets never appear.
    """

    def render(self, findings: list[Finding]) -> str:
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
                for finding in findings
            ],
            "summary": {
                "total": len(findings),
                SEVERITY_HIGH: sum(1 for f in findings if f.severity == SEVERITY_HIGH),
                SEVERITY_MEDIUM: sum(
                    1 for f in findings if f.severity == SEVERITY_MEDIUM
                ),
                SEVERITY_LOW: sum(1 for f in findings if f.severity == SEVERITY_LOW),
            },
        }
        return json.dumps(payload, indent=2) + "\n"
