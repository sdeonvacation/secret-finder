"""Entropy-based candidate scoring per HLD §8. Stdlib only."""

import math
import re

ENTROPY_THRESHOLD: float = 4.5
ENTROPY_MIN_LENGTH: int = 16

_QUOTES_RE = re.compile(r"""^[\s"'`]+|[\s"'`]+$""")


def shannon_entropy(s: str) -> float:
    """H = -Σ p(c)·log2 p(c) over the character distribution of `s`."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def charset_normalized_entropy(s: str) -> float:
    """H / log2(distinct chars); 0.0 when len < 2 or distinct < 2."""
    if len(s) < 2:
        return 0.0
    distinct = len(set(s))
    if distinct < 2:
        return 0.0
    return shannon_entropy(s) / math.log2(distinct)


def extract_candidates(content: str, min_length: int = ENTROPY_MIN_LENGTH) -> list[str]:
    """Collect base64-ish and hex substrings >= min_length, deduped in order.

    Each span is split on ``=`` so env-style assignments (``NAME=value``)
    score the value separately from the variable name; base64 ``=`` occurs
    only as trailing padding, so the split is safe. Empty and shorter-than-
    ``min_length`` parts are dropped.
    """
    pattern = re.compile(
        rf"[A-Za-z0-9+/=_-]{{{min_length},}}|[0-9a-fA-F]{{{min_length},}}"
    )
    out: list[str] = []
    seen: set[str] = set()
    for m in pattern.finditer(content):
        for part in m.group(0).split("="):
            token = _QUOTES_RE.sub("", part).rstrip("=")
            if len(token) < min_length or token in seen:
                continue
            seen.add(token)
            out.append(token)
    return out


def is_allowlisted(s: str, patterns: list[re.Pattern[str]]) -> bool:
    """True if any allowlist pattern fullmatches `s`."""
    return any(p.fullmatch(s) for p in patterns)
