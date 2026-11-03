"""Unit tests for secret_finder.report."""

from __future__ import annotations

import json

from secret_finder.models import Finding
from secret_finder.report import JsonReporter, TextReporter


def _findings() -> list[Finding]:
    return [
        Finding("b.txt", 3, "entropy", "medium", "high-entropy string", "xK9****"),
        Finding(
            "src/config.py",
            12,
            "aws-access-key",
            "high",
            "AWS access key ID",
            "AKIA****",
        ),
        Finding(
            "src/config.py",
            2,
            "generic",
            "low",
            "hardcoded password",
            "pass****",
        ),
    ]


# --- TextReporter -----------------------------------------------------------


def test_text_reporter_empty_findings():
    assert TextReporter().render([]) == "No secrets found."


def test_text_reporter_groups_by_sorted_file_and_format():
    out = TextReporter().render(_findings())
    assert out == (
        "b.txt:\n"
        "  3: [medium] entropy — high-entropy string\n"
        "src/config.py:\n"
        "  2: [low] generic — hardcoded password\n"
        "  12: [high] aws-access-key — AWS access key ID"
    )
    assert "b.txt:" in out
    assert "12:" in out
    assert "AWS access key ID" in out


# --- JsonReporter -----------------------------------------------------------


def test_json_reporter_empty_valid_schema():
    out = JsonReporter().render([])
    assert out.endswith("\n")
    data = json.loads(out)
    assert list(data.keys()) == ["findings", "summary"]
    assert data["findings"] == []
    assert list(data["summary"].keys()) == ["total", "high", "medium", "low"]
    assert data["summary"] == {"total": 0, "high": 0, "medium": 0, "low": 0}


def test_json_reporter_schema_keys_and_summary_counts():
    raw_secret = "AKIA1234567890ABCDEF"
    findings = [
        Finding(
            "src/config.py",
            12,
            "aws-access-key",
            "high",
            "AWS access key ID",
            "AKIA****",
        ),
        Finding(
            "src/config.py",
            20,
            "aws-access-key",
            "high",
            "AWS access key ID",
            "AKIA****",
        ),
        Finding("app.py", 3, "entropy", "medium", "high-entropy string", "xK9****"),
        Finding("app.py", 7, "generic", "low", "password", "hunter****"),
    ]
    out = JsonReporter().render(findings)

    assert out.endswith("\n")
    assert '"findings": [' in out  # indent=2 pretty-print
    assert '"summary": {' in out

    data = json.loads(out)
    assert list(data.keys()) == ["findings", "summary"]
    assert list(data["summary"].keys()) == ["total", "high", "medium", "low"]
    assert data["summary"] == {"total": 4, "high": 2, "medium": 1, "low": 1}
    assert len(data["findings"]) == 4
    for entry in data["findings"]:
        assert list(entry.keys()) == [
            "file",
            "line",
            "rule",
            "severity",
            "reason",
            "secret_preview",
        ]
    assert data["findings"][0] == {
        "file": "src/config.py",
        "line": 12,
        "rule": "aws-access-key",
        "severity": "high",
        "reason": "AWS access key ID",
        "secret_preview": "AKIA****",
    }
    # only the masked preview is serialized; the raw secret never leaks
    assert raw_secret not in out
    assert "AKIA****" in out
