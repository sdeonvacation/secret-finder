"""Core data models shared across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Rule id used for entropy-only findings.
ENTROPY_RULE_ID = "entropy"


@dataclass(frozen=True)
class AddedLine:
    """A single added line in the new version of a file."""

    file: str  # repo-relative path
    line: int  # 1-based line number in the new file
    content: str  # added text, no trailing newline


@dataclass(frozen=True)
class Finding:
    """One detected secret occurrence."""

    file: str
    line: int
    rule: str  # rule id, or ENTROPY_RULE_ID
    severity: str
    reason: str
    secret_preview: str  # masked snippet, never the raw secret


@dataclass
class Rule:
    """A detection rule.

    ``regex`` holds the pattern source string; detectors precompile it at
    load time (see ``detectors.RegexDetector``).
    """

    id: str
    name: str
    regex: str
    severity: str = SEVERITY_HIGH
    reason: str = ""
    path_allowlist: list[str] = field(default_factory=list)
    entropy_floor: Optional[float] = None
