"""Config schema, built-in rules, and merge semantics (HLD §7)."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from secret_finder.models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, Rule

_ALLOWED_SEVERITIES = {SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW}

__all__ = [
    "ConfigError",
    "DEFAULT_RULES",
    "DEFAULT_IGNORE_PATHS",
    "DEFAULT_ENTROPY",
    "ScanConfig",
    "load_config",
]


class ConfigError(Exception):
    """Config parse/validation error; message names the offending rule/key."""


def _rule(
    id: str,
    name: str,
    regex: str,
    severity: str,
    reason: str,
) -> Rule:
    return Rule(
        id=id,
        name=name,
        regex=regex,
        severity=severity,
        reason=reason,
        path_allowlist=[],
        entropy_floor=None,
    )


DEFAULT_RULES: list[Rule] = [
    _rule(
        "aws-access-key",
        "AWS Access Key ID",
        r"AKIA[0-9A-Z]{16}",
        SEVERITY_HIGH,
        "AWS access key ID",
    ),
    _rule(
        "aws-secret-key",
        "AWS Secret Access Key",
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
        SEVERITY_HIGH,
        "AWS secret access key assigned to a variable",
    ),
    _rule(
        "aws-credential-var",
        "AWS Credential Variable",
        r"(?i)\baws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key(?:[_-]?id)?\s*[:=]\s*['\"]?[A-Za-z0-9/+=_-]{16,}['\"]?",
        SEVERITY_MEDIUM,
        "Heuristic: long value assigned to AWS credential variable (format not verified)",
    ),
    _rule(
        "pem-private-key",
        "PEM Private Key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        SEVERITY_HIGH,
        "PEM/OpenSSH/PGP private key block header",
    ),
    _rule(
        "github-token",
        "GitHub Token",
        r"gh[pousr]_[A-Za-z0-9]{36,}",
        SEVERITY_HIGH,
        "GitHub personal access token or OAuth app token",
    ),
    _rule(
        "slack-token",
        "Slack Token",
        r"xox[baprs]-[0-9A-Za-z-]{10,}",
        SEVERITY_HIGH,
        "Slack API token",
    ),
    _rule(
        "jwt",
        "JSON Web Token",
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        SEVERITY_MEDIUM,
        "JSON Web Token (JWT)",
    ),
    _rule(
        "password-assignment",
        "Password Assignment",
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}['\"]?",
        SEVERITY_HIGH,
        "Hard-coded password in an assignment",
    ),
    _rule(
        "api-key-assignment",
        "API Key Assignment",
        r"(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|token)\s*[:=]\s*['\"]?[^'\"\s]{8,}['\"]?",
        SEVERITY_HIGH,
        "Hard-coded API key/secret/token in an assignment",
    ),
    _rule(
        "connection-string",
        "Connection String",
        r"(?i)(?:postgres|postgresql|mysql|mongodb|redis)://[^\s:]+:[^\s@]+@",
        SEVERITY_HIGH,
        "Database connection string with embedded credentials",
    ),
]

DEFAULT_IGNORE_PATHS: list[str] = [
    ".git/**",
    "vendor/**",
    "*.lock",
    "go.sum",
    "package-lock.json",
    "*.min.js",
    "*.map",
    "*.svg",
]

DEFAULT_ENTROPY: dict[str, object] = {
    "threshold": 4.5,
    "min_length": 16,
    "allowlist": [
        "[0-9a-f]{40}",
        "[0-9a-f]{64}",
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    ],
}

_RULE_KEYS = {
    "id",
    "name",
    "regex",
    "severity",
    "reason",
    "path_allowlist",
    "entropy_floor",
}
_ENTROPY_KEYS = {"threshold", "min_length", "allowlist"}
_TOP_KEYS = {"rules", "entropy", "ignore_paths"}


@dataclass
class ScanConfig:
    """Fully merged scan configuration."""

    rules: list[Rule] = field(default_factory=list)
    ignore_paths: list[str] = field(default_factory=list)
    entropy_threshold: float = 4.5
    entropy_min_length: int = 16
    entropy_allowlist: list[str] = field(default_factory=list)


def _parse_rule(raw: object, index: int) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"rules[{index}] must be an object, got {type(raw).__name__}")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise ConfigError(
            f"rules[{index}] has unknown key(s): {', '.join(sorted(unknown))}"
        )
    rid = raw.get("id")
    if not isinstance(rid, str) or not rid:
        raise ConfigError(f"rules[{index}] is missing a non-empty string 'id'")
    for key in ("name", "regex"):
        if not isinstance(raw.get(key), str):
            raise ConfigError(f"rule '{rid}': '{key}' must be a string")
    regex = raw["regex"]
    try:
        re.compile(regex)
    except re.error as exc:
        raise ConfigError(f"rule '{rid}': bad regex {regex!r}: {exc}") from exc
    severity = raw.get("severity", SEVERITY_HIGH)
    if not isinstance(severity, str):
        raise ConfigError(f"rule '{rid}': 'severity' must be a string")
    if severity not in _ALLOWED_SEVERITIES:
        allowed = ", ".join(sorted(_ALLOWED_SEVERITIES))
        raise ConfigError(
            f"rule '{rid}': 'severity' must be one of {allowed}, got {severity!r}"
        )
    reason = raw.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"rule '{rid}': 'reason' must be a string")
    path_allowlist = raw.get("path_allowlist", [])
    if not isinstance(path_allowlist, list) or not all(
        isinstance(p, str) for p in path_allowlist
    ):
        raise ConfigError(f"rule '{rid}': 'path_allowlist' must be a list of strings")
    entropy_floor = raw.get("entropy_floor")
    if entropy_floor is not None and (
        isinstance(entropy_floor, bool) or not isinstance(entropy_floor, (int, float))
    ):
        raise ConfigError(f"rule '{rid}': 'entropy_floor' must be a number or null")
    return Rule(
        id=rid,
        name=raw["name"],
        regex=regex,
        severity=severity,
        reason=reason,
        path_allowlist=list(path_allowlist),
        entropy_floor=float(entropy_floor) if entropy_floor is not None else None,
    )


def _merge_rules(defaults: list[Rule], user_rules: object) -> list[Rule]:
    if not isinstance(user_rules, list):
        raise ConfigError(f"'rules' must be a list, got {type(user_rules).__name__}")
    merged = list(defaults)
    for index, raw in enumerate(user_rules):
        rule = _parse_rule(raw, index)
        for i, existing in enumerate(merged):
            if existing.id == rule.id:
                merged[i] = rule  # whole-rule replace
                break
        else:
            merged.append(rule)
    return merged


def _merge_entropy(
    threshold: float, min_length: int, allowlist: list[str], raw: object
):
    if not isinstance(raw, dict):
        raise ConfigError(f"'entropy' must be an object, got {type(raw).__name__}")
    unknown = set(raw) - _ENTROPY_KEYS
    if unknown:
        raise ConfigError(f"unknown entropy key(s): {', '.join(sorted(unknown))}")
    if "threshold" in raw:
        t = raw["threshold"]
        if isinstance(t, bool) or not isinstance(t, (int, float)):
            raise ConfigError("entropy.threshold must be a number")
        t = float(t)
        if not math.isfinite(t) or t <= 0:
            raise ConfigError("entropy.threshold must be a positive finite number")
        threshold = t
    if "min_length" in raw:
        m = raw["min_length"]
        if isinstance(m, bool) or not isinstance(m, int):
            raise ConfigError("entropy.min_length must be an integer")
        if m < 1:
            raise ConfigError("entropy.min_length must be an integer >= 1")
        min_length = m
    if "allowlist" in raw:
        a = raw["allowlist"]
        if not isinstance(a, list) or not all(isinstance(p, str) for p in a):
            raise ConfigError("entropy 'allowlist' must be a list of strings")
        for pattern in a:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(
                    f"entropy 'allowlist': bad pattern {pattern!r}: {exc}"
                ) from exc
        allowlist = list(a)
    return threshold, min_length, allowlist


def load_config(path: str | None = None) -> ScanConfig:
    """Load scan config: defaults first, then optional JSON overrides (HLD §7)."""
    rules = list(DEFAULT_RULES)
    ignore_paths = list(DEFAULT_IGNORE_PATHS)
    threshold = float(DEFAULT_ENTROPY["threshold"])  # type: ignore[arg-type]
    min_length = int(DEFAULT_ENTROPY["min_length"])  # type: ignore[arg-type]
    allowlist = list(DEFAULT_ENTROPY["allowlist"])  # type: ignore[arg-type]

    if path is None:
        return ScanConfig(rules, ignore_paths, threshold, min_length, allowlist)

    config_path = Path(path)
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config '{path}': {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in config '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(
            f"config root must be a JSON object, got {type(data).__name__}"
        )

    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(sorted(unknown))}")

    if "rules" in data:
        rules = _merge_rules(rules, data["rules"])
    if "entropy" in data:
        threshold, min_length, allowlist = _merge_entropy(
            threshold, min_length, allowlist, data["entropy"]
        )
    if "ignore_paths" in data:
        extra = data["ignore_paths"]
        if not isinstance(extra, list) or not all(isinstance(p, str) for p in extra):
            raise ConfigError("'ignore_paths' must be a list of strings")
        ignore_paths = ignore_paths + list(extra)

    return ScanConfig(rules, ignore_paths, threshold, min_length, allowlist)
