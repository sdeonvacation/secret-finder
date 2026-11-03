"""Detection pipeline: regex pass, entropy pass, precedence (HLD §4, §5)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from fnmatch import fnmatch

from secret_finder.entropy import (
    extract_candidates,
    is_allowlisted,
    shannon_entropy,
)
from secret_finder.models import (
    ENTROPY_RULE_ID,
    AddedLine,
    Finding,
    Rule,
    SEVERITY_MEDIUM,
)
from secret_finder.rules import ConfigError, ScanConfig

__all__ = [
    "CREDENTIAL_CONTEXT_RE",
    "DetectionPipeline",
    "EntropyDetector",
    "HEURISTIC_RULE_IDS",
    "RegexDetector",
    "mask_secret",
]

# Secondary heuristic rules (Tier 3, "not proof"): dropped on any line where a
# primary (non-heuristic) regex rule already matched.
HEURISTIC_RULE_IDS: frozenset[str] = frozenset({"aws-credential-var"})

# Entropy pass gate: only lines assigning to a credential-like name may be
# entropy-flagged (bounded keyword — `_` prefix ok, mid-word like `compass` no).
CREDENTIAL_CONTEXT_RE = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|pass|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)['\"]?\s*[:=]"
)


def mask_secret(s: str) -> str:
    """First 4 chars + stars; fully masked when len <= 8 (HLD §4)."""
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "*" * (len(s) - 4)


def _path_matches(path: str, patterns: Iterable[str]) -> bool:
    """True when the full path or its basename matches any glob pattern."""
    base = path.rsplit("/", 1)[-1]
    return any(fnmatch(path, p) or fnmatch(base, p) for p in patterns)


class RegexDetector:
    """Runs precompiled rules over one added line (HLD §5 step 1)."""

    def __init__(self, rules: list[Rule]) -> None:
        self._rules: list[tuple[Rule, re.Pattern[str]]] = []
        for rule in rules:
            try:
                pattern = re.compile(rule.regex)
            except re.error as exc:
                raise ConfigError(
                    f"rule '{rule.id}': bad regex {rule.regex!r}: {exc}"
                ) from exc
            self._rules.append((rule, pattern))

    def scan(self, line: AddedLine) -> tuple[list[Finding], set[str]]:
        """Findings plus every raw matched substring (for entropy suppression)."""
        findings: list[Finding] = []
        matched: set[str] = set()
        for rule, pattern in self._rules:
            if _path_matches(line.file, rule.path_allowlist):
                continue
            for m in pattern.finditer(line.content):
                value = m.group(0)
                matched.add(value)
                if (
                    rule.entropy_floor is not None
                    and shannon_entropy(value) < rule.entropy_floor
                ):
                    continue
                findings.append(
                    Finding(
                        file=line.file,
                        line=line.line,
                        rule=rule.id,
                        severity=rule.severity,
                        reason=rule.reason or rule.name,
                        secret_preview=mask_secret(value),
                    )
                )
        return findings, matched


class EntropyDetector:
    """Flags high-entropy candidates the regex pass did not consume (§5 step 2)."""

    def __init__(self, threshold: float, min_length: int, allowlist: list[str]) -> None:
        self._threshold = threshold
        self._min_length = min_length
        self._allowlist: list[re.Pattern[str]] = []
        for pattern in allowlist:
            try:
                self._allowlist.append(re.compile(pattern))
            except re.error as exc:
                raise ConfigError(
                    f"entropy 'allowlist': bad pattern {pattern!r}: {exc}"
                ) from exc

    def scan(self, line: AddedLine, exclude: set[str]) -> list[Finding]:
        if not CREDENTIAL_CONTEXT_RE.search(line.content):
            return []
        findings: list[Finding] = []
        for candidate in extract_candidates(line.content, self._min_length):
            if candidate in exclude or is_allowlisted(candidate, self._allowlist):
                continue
            if shannon_entropy(candidate) < self._threshold:
                continue
            findings.append(
                Finding(
                    file=line.file,
                    line=line.line,
                    rule=ENTROPY_RULE_ID,
                    severity=SEVERITY_MEDIUM,
                    reason="High-entropy string (possible secret)",
                    secret_preview=mask_secret(candidate),
                )
            )
        return findings


class DetectionPipeline:
    """Regex pass → entropy pass → dedupe, per line (HLD §5)."""

    def __init__(self, config: ScanConfig) -> None:
        self._regex = RegexDetector(config.rules)
        self._entropy = EntropyDetector(
            config.entropy_threshold,
            config.entropy_min_length,
            config.entropy_allowlist,
        )
        self._min_length = config.entropy_min_length
        self._ignore_paths = list(config.ignore_paths)

    def run(self, lines: Iterable[AddedLine]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for line in lines:
            if _path_matches(line.file, self._ignore_paths):
                continue
            regex_findings, matched = self._regex.scan(line)
            # A primary rule firing on this line silences heuristics (HLD §5).
            if any(f.rule not in HEURISTIC_RULE_IDS for f in regex_findings):
                regex_findings = [
                    f for f in regex_findings if f.rule not in HEURISTIC_RULE_IDS
                ]
            # Regex wins for inner tokens too: exclude raw matches AND the
            # candidates extracted from them (password/JWT quote-strip cases).
            exclude = set(matched)
            for value in matched:
                exclude.update(extract_candidates(value, self._min_length))
            candidates = (*regex_findings, *self._entropy.scan(line, exclude))
            for finding in candidates:
                key = (finding.file, finding.line, finding.rule)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
        return findings
