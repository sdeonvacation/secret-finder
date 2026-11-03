"""Unit tests for secret_finder.rules (HLD §7 config schema + merge)."""

from __future__ import annotations

import json
import re

import pytest

from secret_finder.rules import (
    DEFAULT_ENTROPY,
    DEFAULT_IGNORE_PATHS,
    DEFAULT_RULES,
    ConfigError,
    ScanConfig,
    load_config,
)
from secret_finder.models import Rule

POSITIVE = {
    "aws-access-key": "AKIAIOSFODNN7EXAMPLE",
    "aws-secret-key": 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    "pem-private-key": "-----BEGIN RSA PRIVATE KEY-----",
    "github-token": "ghp_" + "A" * 36,
    "slack-token": "xoxb-0123456789-abcdefghij",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
    "password-assignment": 'password = "hunter2secret"',
    "api-key-assignment": 'api_key: "sk_live_abcdef12"',
    "connection-string": "postgres://user:pass@db.example.com:5432/app",
}

NEGATIVE = {
    "aws-access-key": "AKIA123TOOSHORT",
    "aws-secret-key": 'aws_secret_access_key = "too-short"',
    "pem-private-key": "-----BEGIN CERTIFICATE-----",
    "github-token": "ghp_tooshort",
    "slack-token": "xox-0123456789-abcdefghij",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.abc.def",
    "password-assignment": 'password: "abc"',
    "api-key-assignment": 'apikey: "abc123"',
    "connection-string": "postgres://db.example.com/app",
}


def write_config(tmp_path, payload) -> str:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def rule_by_id(rules: list[Rule], rid: str) -> Rule:
    return next(r for r in rules if r.id == rid)


def test_default_rule_ids_are_unique_and_expected():
    ids = [r.id for r in DEFAULT_RULES]
    assert len(ids) == len(set(ids))
    assert set(ids) == set(POSITIVE)


@pytest.mark.parametrize("rid", sorted(POSITIVE))
def test_each_default_rule_matches_positive_and_rejects_negative(rid):
    rule = rule_by_id(DEFAULT_RULES, rid)
    pattern = re.compile(rule.regex)
    assert pattern.search(POSITIVE[rid]), f"{rid} should match {POSITIVE[rid]!r}"
    assert not pattern.search(NEGATIVE[rid]), (
        f"{rid} should not match {NEGATIVE[rid]!r}"
    )
    assert rule.reason and rule.severity in {"high", "medium", "low"}


def test_defaults_shape():
    assert DEFAULT_ENTROPY["threshold"] == 4.5
    assert DEFAULT_ENTROPY["min_length"] == 16
    allowlist = DEFAULT_ENTROPY["allowlist"]
    assert isinstance(allowlist, list)
    assert len(allowlist) == 3
    for pattern in allowlist:
        re.compile(pattern)
    for needed in (
        ".git/**",
        "vendor/**",
        "*.lock",
        "go.sum",
        "package-lock.json",
        "*.min.js",
        "*.map",
        "*.svg",
    ):
        assert needed in DEFAULT_IGNORE_PATHS


def test_load_config_none_returns_defaults():
    cfg = load_config(None)
    assert isinstance(cfg, ScanConfig)
    assert cfg.rules == DEFAULT_RULES
    assert cfg.ignore_paths == DEFAULT_IGNORE_PATHS
    assert cfg.entropy_threshold == 4.5
    assert cfg.entropy_min_length == 16
    assert cfg.entropy_allowlist == DEFAULT_ENTROPY["allowlist"]
    # field types
    assert all(isinstance(r, Rule) for r in cfg.rules)
    assert all(isinstance(p, str) for p in cfg.ignore_paths)
    assert isinstance(cfg.entropy_threshold, float)
    assert isinstance(cfg.entropy_min_length, int)
    assert all(isinstance(p, str) for p in cfg.entropy_allowlist)


def test_invalid_json_raises_config_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_config(str(path))


def test_non_dict_root_raises_config_error(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ConfigError, match="object"):
        load_config(str(path))


def test_bad_regex_raises_config_error_naming_rule(tmp_path):
    path = write_config(
        tmp_path,
        {"rules": [{"id": "custom-bad", "name": "Bad", "regex": "([unclosed"}]},
    )
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "custom-bad" in str(exc.value)


def test_wrong_type_raises_config_error(tmp_path):
    path = write_config(tmp_path, {"entropy": {"threshold": "high"}})
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "threshold" in str(exc.value)


def test_rule_with_existing_id_replaces_whole_default(tmp_path):
    path = write_config(
        tmp_path,
        {
            "rules": [
                {
                    "id": "jwt",
                    "name": "Custom JWT",
                    "regex": "custom-jwt-marker",
                    "severity": "low",
                    "reason": "downgraded",
                }
            ]
        },
    )
    cfg = load_config(path)
    assert len([r for r in cfg.rules if r.id == "jwt"]) == 1
    jwt = rule_by_id(cfg.rules, "jwt")
    assert jwt.regex == "custom-jwt-marker"
    assert jwt.severity == "low"
    assert jwt.reason == "downgraded"
    # position preserved among defaults
    assert cfg.rules.index(jwt) == [r.id for r in DEFAULT_RULES].index("jwt")


def test_new_rule_id_appends(tmp_path):
    path = write_config(
        tmp_path, {"rules": [{"id": "my-rule", "name": "Mine", "regex": "zzz-[0-9]+"}]}
    )
    cfg = load_config(path)
    ids = [r.id for r in cfg.rules]
    assert ids[-1] == "my-rule"
    assert len(ids) == len(DEFAULT_RULES) + 1
    assert rule_by_id(cfg.rules, "my-rule").severity == "high"


def test_entropy_keys_override_individually(tmp_path):
    path = write_config(
        tmp_path, {"entropy": {"threshold": 5.0, "allowlist": ["keep-[a-z]+"]}}
    )
    cfg = load_config(path)
    assert cfg.entropy_threshold == 5.0
    assert cfg.entropy_allowlist == ["keep-[a-z]+"]
    # untouched key keeps default
    assert cfg.entropy_min_length == 16


def test_ignore_paths_appends_to_defaults(tmp_path):
    path = write_config(tmp_path, {"ignore_paths": ["docs/**", "*.png"]})
    cfg = load_config(path)
    assert cfg.ignore_paths[: len(DEFAULT_IGNORE_PATHS)] == DEFAULT_IGNORE_PATHS
    assert cfg.ignore_paths[-2:] == ["docs/**", "*.png"]


@pytest.mark.parametrize("bad_severity", ["critical", "HIGH", "Info", ""])
def test_invalid_severity_raises_config_error_naming_rule(tmp_path, bad_severity):
    path = write_config(
        tmp_path,
        {
            "rules": [
                {
                    "id": "custom-rule",
                    "name": "Custom",
                    "regex": "zzz-[0-9]+",
                    "severity": bad_severity,
                }
            ]
        },
    )
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    msg = str(exc.value)
    assert "custom-rule" in msg
    assert "severity" in msg
    # allowed values surfaced so the fix is actionable
    assert "high" in msg and "medium" in msg and "low" in msg


@pytest.mark.parametrize("severity", ["high", "medium", "low"])
def test_valid_severity_accepted(tmp_path, severity):
    path = write_config(
        tmp_path,
        {
            "rules": [
                {
                    "id": "custom-rule",
                    "name": "Custom",
                    "regex": "zzz-[0-9]+",
                    "severity": severity,
                }
            ]
        },
    )
    cfg = load_config(path)
    assert rule_by_id(cfg.rules, "custom-rule").severity == severity


@pytest.mark.parametrize(
    "bad_threshold",
    [-1, 0, "abc", True, float("nan"), float("inf"), float("-inf")],
)
def test_invalid_entropy_threshold_raises_config_error(tmp_path, bad_threshold):
    path = write_config(tmp_path, {"entropy": {"threshold": bad_threshold}})
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "entropy.threshold" in str(exc.value)


@pytest.mark.parametrize("threshold", [4.5, 0.5, 1])
def test_valid_entropy_threshold_accepted(tmp_path, threshold):
    path = write_config(tmp_path, {"entropy": {"threshold": threshold}})
    cfg = load_config(path)
    assert cfg.entropy_threshold == float(threshold)


@pytest.mark.parametrize("bad_min_length", [0, -5, 2.5, True])
def test_invalid_entropy_min_length_raises_config_error(tmp_path, bad_min_length):
    path = write_config(tmp_path, {"entropy": {"min_length": bad_min_length}})
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "entropy.min_length" in str(exc.value)


def test_valid_entropy_min_length_accepted(tmp_path):
    path = write_config(tmp_path, {"entropy": {"min_length": 16}})
    cfg = load_config(path)
    assert cfg.entropy_min_length == 16


def test_entropy_block_keeps_valid_keys_when_one_is_rejected(tmp_path):
    # rejection must not silently accept the bad value alongside good ones
    path = write_config(tmp_path, {"entropy": {"threshold": 4.5, "min_length": 0}})
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "entropy.min_length" in str(exc.value)
