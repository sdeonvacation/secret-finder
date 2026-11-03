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


def test_text_reporter_groups_by_severity_then_file_and_format():
    out = TextReporter().render(_findings())
    # src/config.py holds the only high finding → group first; b.txt (medium)
    # second. Within the group: high before low, then by line.
    assert out == (
        "src/config.py:\n"
        "  12: [high] aws-access-key — AWS access key ID\n"
        "  2: [low] generic — hardcoded password\n"
        "b.txt:\n"
        "  3: [medium] entropy — high-entropy string"
    )
    assert "b.txt:" in out
    assert "12:" in out
    assert "AWS access key ID" in out


def test_text_reporter_high_severity_file_group_first():
    findings = [
        Finding("zeta.py", 9, "entropy", "medium", "high-entropy string", "xK9****"),
        Finding("alpha.py", 40, "generic", "low", "weak string", "abcd****"),
        Finding("beta.py", 7, "generic", "low", "hardcoded password", "pass****"),
        Finding(
            "alpha.py", 1, "aws-access-key", "high", "AWS access key ID", "AKIA****"
        ),
        Finding("alpha.py", 30, "generic", "low", "hardcoded password", "pass****"),
    ]
    out = TextReporter().render(findings)
    # alpha.py contains the high finding → first group despite "zeta.py" name;
    # within alpha.py: high (line 1), then low sorted by line (30, 40);
    # remaining groups by best severity: zeta.py (medium) before beta.py (low).
    assert out == (
        "alpha.py:\n"
        "  1: [high] aws-access-key — AWS access key ID\n"
        "  30: [low] generic — hardcoded password\n"
        "  40: [low] generic — weak string\n"
        "zeta.py:\n"
        "  9: [medium] entropy — high-entropy string\n"
        "beta.py:\n"
        "  7: [low] generic — hardcoded password"
    )


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


def test_json_reporter_orders_findings_by_severity_file_line():
    # Deliberately shuffled: medium before high, files out of order, lines out
    # of order within a file.
    findings = [
        Finding("b.txt", 3, "entropy", "medium", "high-entropy string", "xK9****"),
        Finding("a.txt", 50, "generic", "low", "hardcoded password", "pass****"),
        Finding(
            "src/config.py",
            20,
            "aws-access-key",
            "high",
            "AWS access key ID",
            "AKIA****",
        ),
        Finding("a.txt", 7, "entropy", "medium", "high-entropy string", "xK9****"),
        Finding(
            "src/config.py",
            12,
            "aws-access-key",
            "high",
            "AWS access key ID",
            "AKIA****",
        ),
        Finding("a.txt", 2, "generic", "low", "hardcoded password", "pass****"),
    ]
    data = json.loads(JsonReporter().render(findings))

    # all high before medium before low; within severity file asc, then line asc
    assert [(e["file"], e["line"]) for e in data["findings"]] == [
        ("src/config.py", 12),
        ("src/config.py", 20),
        ("a.txt", 7),
        ("b.txt", 3),
        ("a.txt", 2),
        ("a.txt", 50),
    ]
    assert [e["severity"] for e in data["findings"]] == [
        "high",
        "high",
        "medium",
        "medium",
        "low",
        "low",
    ]
    # summary counts unchanged by ordering
    assert data["summary"] == {"total": 6, "high": 2, "medium": 2, "low": 2}
