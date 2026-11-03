"""Unit tests for the detection pipeline (pipeline, precedence, entropy gate)."""

import pytest

from secret_finder.detectors import (
    CREDENTIAL_CONTEXT_RE,
    DetectionPipeline,
    EntropyDetector,
    RegexDetector,
    mask_secret,
)
from secret_finder.entropy import shannon_entropy
from secret_finder.models import (
    ENTROPY_RULE_ID,
    AddedLine,
    Rule,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from secret_finder.rules import DEFAULT_RULES, ConfigError, ScanConfig, load_config

RULES_BY_ID = {r.id: r for r in DEFAULT_RULES}
AWS_KEY = "AKIA1234567890ABCDEF"
PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
PASSWORD_LINE = 'password = "hunter2xyz"'  # full regex match, len 23
SHA256 = "deadbeefcafebabe1234567890abcdef" * 2
# 32 distinct chars → raw Shannon H = 5.0 ≥ default threshold 4.5
HIGH_ENTROPY_TOKEN = "abcdefghijklmnopqrstuvwxyzABCDEF"
HIGH_ENTROPY_TOKEN_2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
# all-distinct alnum runs for the context gate (raw H = log2(len))
HIGH_ENTROPY_TOKEN_27 = "DxE6ZvocbX8Owkld2m19uzWhp7K"  # 27 distinct → H ≈ 4.75
HIGH_ENTROPY_TOKEN_36 = "KwEmxJ8lcDzdyX2SCsjhruTt9U6bqgG7AivP"  # → H ≈ 5.17
HIGH_ENTROPY_TOKEN_40 = "6lkN0rhEUxvWJOatR5V4YnAjpycQLiP9ZG7KBqzd"  # → H ≈ 5.32
AWS_SECRET_40 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # classic 40-char key
# 22 lowercase alnum, H ≈ 3.46 < 4.5 → entropy cannot flag it (self-validating)
LOW_ENTROPY_VALUE = "aabbccddeeffgghhiijjkk"

PRIMARY_SECRET_RULE = Rule(
    id="aws-secret-key",
    name="AWS Secret Access Key",
    regex=r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
    severity=SEVERITY_HIGH,
    reason="AWS secret access key",
)
HEURISTIC_RULE = Rule(
    id="aws-credential-var",
    name="AWS credential variable",
    regex=(
        r"(?i)\baws[_-]?(?:access|secret)[_-]?key(?:[_-]?id)?"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9/+=_-]{16,}"
    ),
    severity=SEVERITY_MEDIUM,
    reason="AWS credential-style variable assignment",
)


def _config(rules, ignore_paths=(), threshold=4.5):  # raw bits/char scale
    return ScanConfig(
        rules=list(rules),
        ignore_paths=list(ignore_paths),
        entropy_threshold=threshold,
        entropy_min_length=16,
        entropy_allowlist=[],
    )


def test_mask_secret_edge_cases():
    assert mask_secret("") == ""
    assert mask_secret("a") == "*"
    assert mask_secret("abcd1234") == "********"  # len 8 → full mask
    assert mask_secret("abcd12345") == "abcd*****"  # len 9 → first 4 only
    masked = mask_secret(AWS_KEY)  # len 20
    assert masked == "AKIA****************"
    assert len(masked) == len(AWS_KEY)
    assert masked[4:].strip("*") == ""  # no raw chars beyond the first 4


def test_regex_detector_finds_aws_pem_password():
    det = RegexDetector(list(DEFAULT_RULES))

    findings, matched = det.scan(AddedLine("src/app.py", 1, f'key_id = "{AWS_KEY}"'))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "aws-access-key"
    assert f.severity == SEVERITY_HIGH
    assert f.reason == "AWS access key ID"
    assert f.secret_preview == "AKIA" + "*" * 16
    assert matched == {AWS_KEY}

    findings, matched = det.scan(AddedLine("src/app.py", 2, PEM_HEADER))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "pem-private-key"
    assert f.reason == "PEM/OpenSSH/PGP private key block header"
    assert f.secret_preview == "----" + "*" * 27
    assert matched == {PEM_HEADER}

    findings, matched = det.scan(AddedLine("src/app.py", 3, PASSWORD_LINE))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "password-assignment"
    assert f.severity == SEVERITY_HIGH
    assert f.reason == "Hard-coded password in an assignment"
    # preview masks the VALUE ("hunter2xyz"), not the assignment fragment
    assert f.secret_preview == mask_secret("hunter2xyz")  # "hunt" + "*" * 6
    assert f.secret_preview == "hunt" + "*" * 6
    assert matched == {PASSWORD_LINE}  # group(0) (whole fragment) unchanged


def test_regex_detector_previews_masked_value_not_fragment():
    det = RegexDetector(list(DEFAULT_RULES))
    findings, matched = det.scan(
        AddedLine("src/app.py", 1, 'jobhunter_pass = "hallelujah"')
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "password-assignment"
    assert f.secret_preview == mask_secret("hallelujah")  # "hall" + "*" * 6
    assert f.secret_preview == "hall" + "*" * 6
    # must not be a masked VAR-NAME/fragment start (the old whole-match bug)
    assert not f.secret_preview.startswith(("job", "_pass", "pass"))
    # group(0) unchanged: boundary `_` + assignment fragment (preview differs)
    assert matched == {'_pass = "hallelujah"'}


def test_regex_detector_catches_aws_access_key_id_value_preview():
    config = load_config(None)  # DEFAULT_RULES + default entropy
    value = "abcdefghijklmnop"  # 16 chars: >=8 assignment, >=16 heuristic
    line = AddedLine("src/app.py", 1, f"AWS_ACCESS_KEY_ID={value}")
    findings = DetectionPipeline(config).run([line])
    # explicit api-key-assignment (high) beats the aws-credential-var heuristic
    assert [f.rule for f in findings] == ["api-key-assignment"]
    f = findings[0]
    assert f.severity == SEVERITY_HIGH
    assert f.secret_preview == mask_secret(value)  # "abcd" + "*" * 12
    assert f.secret_preview == "abcd" + "*" * 12
    assert not f.secret_preview.startswith("AWS")  # value, not var name


def test_regex_detector_near_miss_yields_nothing():
    det = RegexDetector(list(DEFAULT_RULES))
    near_misses = [
        AddedLine("src/app.py", 1, "AKIA1234567890ABCDE"),  # 15, needs 16
        AddedLine("src/app.py", 2, "password = abc"),  # unquoted ok, but 3 < 4
        AddedLine("src/app.py", 3, "-----BEGIN RSA PUBLIC KEY-----"),  # not PRIVATE
    ]
    for line in near_misses:
        findings, matched = det.scan(line)
        assert findings == []
        assert matched == set()


def test_regex_detector_path_allowlist_skips_rule():
    rule = Rule(
        id="aws-access-key",
        name="AWS Access Key ID",
        regex=RULES_BY_ID["aws-access-key"].regex,
        severity=SEVERITY_HIGH,
        reason="AWS access key ID",
        path_allowlist=["vendor/**", "app.lock"],
    )
    det = RegexDetector([rule])
    findings, matched = det.scan(AddedLine("vendor/lib.js", 1, f'k = "{AWS_KEY}"'))
    assert findings == [] and matched == set()
    findings, matched = det.scan(  # basename match
        AddedLine("cfg/app.lock", 2, f'k = "{AWS_KEY}"')
    )
    assert findings == [] and matched == set()
    findings, matched = det.scan(AddedLine("src/app.py", 3, f'k = "{AWS_KEY}"'))
    assert len(findings) == 1 and matched == {AWS_KEY}
    assert findings[0].file == "src/app.py"


def test_regex_detector_entropy_floor_gates_findings():
    rule = Rule(
        id="tok",
        name="Token",
        regex=r"token\s*=\s*[A-Za-z0-9]+",
        severity=SEVERITY_MEDIUM,
        reason="token assignment",
        entropy_floor=3.0,  # raw H bits/char (example value)
    )
    det = RegexDetector([rule])
    low_value = "token = " + "a" * 32  # match len 40
    assert shannon_entropy(low_value) < 3.0  # self-validating: raw H < floor
    low = AddedLine("src/app.py", 1, low_value)
    findings, matched = det.scan(low)
    assert findings == []
    assert matched == {low_value}  # raw match still collected
    high_value = "token = " + HIGH_ENTROPY_TOKEN  # match len 40, raw H ≈ 5.02
    assert shannon_entropy(high_value) >= 3.0  # self-validating: raw H >= floor
    high = AddedLine("src/app.py", 2, high_value)
    findings, matched = det.scan(high)
    assert len(findings) == 1
    assert findings[0].rule == "tok"
    assert findings[0].reason == "token assignment"


def test_regex_detector_invalid_regex_raises_config_error():
    bad = Rule(id="broken-rule", name="Broken", regex="(unclosed")
    with pytest.raises(ConfigError, match="broken-rule"):
        RegexDetector([bad])


def test_entropy_detector_flags_high_entropy_novel_string():
    det = EntropyDetector(threshold=4.5, min_length=16, allowlist=[])
    line = AddedLine("src/app.py", 1, f'token = "{HIGH_ENTROPY_TOKEN}"')
    findings = det.scan(line, exclude=set())
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == ENTROPY_RULE_ID
    assert f.severity == SEVERITY_MEDIUM
    assert f.reason == "High-entropy string (possible secret)"
    assert f.secret_preview == mask_secret(HIGH_ENTROPY_TOKEN)
    assert (f.file, f.line) == ("src/app.py", 1)


def test_entropy_detector_skips_excluded_candidate():
    det = EntropyDetector(threshold=4.5, min_length=16, allowlist=[])
    line = AddedLine("src/app.py", 1, f'token = "{HIGH_ENTROPY_TOKEN}"')
    assert len(det.scan(line, exclude={HIGH_ENTROPY_TOKEN})) == 0
    assert len(det.scan(line, exclude=set())) == 1  # non-vacuous control


def test_entropy_detector_skips_allowlisted_sha256():
    line = AddedLine("src/app.py", 1, f'api_key = "{SHA256}"')
    # hex strings cap at H = log2(16) = 4.0; SHA256's raw H ≈ 3.66 ≥ 3.5
    assert len(EntropyDetector(3.5, 16, []).scan(line, exclude=set())) == 1
    det = EntropyDetector(threshold=3.5, min_length=16, allowlist=[r"[0-9a-f]{64}"])
    assert det.scan(line, exclude=set()) == []


def test_entropy_detector_invalid_allowlist_pattern_raises():
    with pytest.raises(ConfigError) as exc:
        EntropyDetector(threshold=4.5, min_length=16, allowlist=["[0-9a-f"])
    assert "[0-9a-f" in str(exc.value)


def test_credential_context_regex_bounds():
    assert CREDENTIAL_CONTEXT_RE.search("x = 1") is None
    assert CREDENTIAL_CONTEXT_RE.search("compass = 'x'") is None  # mid-word
    assert CREDENTIAL_CONTEXT_RE.search("_secret: 1") is not None  # `_` prefix
    assert CREDENTIAL_CONTEXT_RE.search('password = "x"') is not None
    assert CREDENTIAL_CONTEXT_RE.search('"api_key": "x"') is not None
    assert CREDENTIAL_CONTEXT_RE.search("session_secret = x") is not None


def test_entropy_gate_rejects_xml_component_id_without_context():
    det = EntropyDetector(threshold=4.5, min_length=16, allowlist=[])
    assert shannon_entropy(HIGH_ENTROPY_TOKEN_27) >= 4.5  # self-validating
    line = AddedLine(
        ".idea/workspace.xml",
        17,
        f'<component name="comp" id="{HIGH_ENTROPY_TOKEN_27}"/>',
    )
    assert det.scan(line, exclude=set()) == []
    # non-vacuous: same token fires once credential context exists
    ctrl = AddedLine("src/app.py", 1, f"session_secret = {HIGH_ENTROPY_TOKEN_27}")
    assert len(det.scan(ctrl, exclude=set())) == 1


def test_entropy_gate_rejects_xml_option_value_without_context():
    det = EntropyDetector(threshold=4.5, min_length=16, allowlist=[])
    assert shannon_entropy(HIGH_ENTROPY_TOKEN_40) >= 4.5  # self-validating
    line = AddedLine(
        ".idea/workspace.xml",
        39,
        f'<option value="{HIGH_ENTROPY_TOKEN_40}"/>',
    )
    assert det.scan(line, exclude=set()) == []
    # non-vacuous: same token fires once credential context exists
    ctrl = AddedLine("src/app.py", 1, f"session_secret = {HIGH_ENTROPY_TOKEN_40}")
    assert len(det.scan(ctrl, exclude=set())) == 1


def test_entropy_gate_rejects_context_free_identifier_assignment():
    det = EntropyDetector(threshold=4.5, min_length=16, allowlist=[])
    assert shannon_entropy(HIGH_ENTROPY_TOKEN) >= 4.5  # self-validating
    line = AddedLine("src/app.py", 1, f'identifier = "{HIGH_ENTROPY_TOKEN}"')
    assert det.scan(line, exclude=set()) == []


def test_entropy_gate_fires_on_session_secret_assignment():
    det = EntropyDetector(threshold=4.5, min_length=16, allowlist=[])
    line = AddedLine("src/app.py", 1, f"session_secret = {HIGH_ENTROPY_TOKEN}")
    findings = det.scan(line, exclude=set())
    assert len(findings) == 1
    assert findings[0].rule == ENTROPY_RULE_ID
    assert findings[0].severity == SEVERITY_MEDIUM


def test_entropy_gate_fires_on_json_session_secret_key():
    det = EntropyDetector(threshold=4.5, min_length=16, allowlist=[])
    line = AddedLine("cfg.json", 2, f'"session_secret": "{HIGH_ENTROPY_TOKEN_40}"')
    findings = det.scan(line, exclude=set())
    assert len(findings) == 1
    assert findings[0].rule == ENTROPY_RULE_ID
    assert findings[0].secret_preview == mask_secret(HIGH_ENTROPY_TOKEN_40)


def test_pipeline_regex_beats_entropy():
    line = AddedLine("src/app.py", 1, f'token = "{AWS_KEY}"')
    # entropy alone would flag the key (raw H ≈ 4.08 ≥ 4.0)...
    assert len(EntropyDetector(4.0, 16, []).scan(line, exclude=set())) == 1
    # ...but the regex pass wins: single finding, no entropy duplicate.
    findings = DetectionPipeline(_config([RULES_BY_ID["aws-access-key"]])).run([line])
    assert len(findings) == 1
    assert findings[0].rule == "aws-access-key"
    assert findings[0].secret_preview == "AKIA" + "*" * 16


def test_pipeline_default_config_fires_on_high_entropy_token():
    config = load_config(None)
    assert config.entropy_threshold == 4.5  # production default
    candidate = HIGH_ENTROPY_TOKEN_36
    assert len(candidate) >= config.entropy_min_length
    assert shannon_entropy(candidate) >= config.entropy_threshold  # self-validating
    # Context via `token =`, but the assignment value run `ab` is below every
    # default assignment rule's value minimum → only entropy can claim this.
    line = AddedLine("src/app.py", 1, f'token = "ab" {candidate}')
    findings = DetectionPipeline(config).run([line])
    assert [f.rule for f in findings] == [ENTROPY_RULE_ID]


def test_pipeline_password_assignment_wins_over_entropy():
    config = load_config(None)
    line = AddedLine("src/app.py", 1, f'password = "{HIGH_ENTROPY_TOKEN}"')
    assert shannon_entropy(HIGH_ENTROPY_TOKEN) >= config.entropy_threshold
    # entropy alone would flag the inner token (double-report pressure)...
    control = EntropyDetector(
        config.entropy_threshold, config.entropy_min_length, config.entropy_allowlist
    )
    assert len(control.scan(line, exclude=set())) == 1
    # ...but regex wins: exactly one finding, no entropy duplicate.
    findings = DetectionPipeline(config).run([line])
    assert [f.rule for f in findings] == ["password-assignment"]


def test_pipeline_api_key_assignment_beats_entropy_for_long_random_value():
    config = load_config(None)
    value = HIGH_ENTROPY_TOKEN_40  # 40-char high-entropy literal, H ≈ 5.32
    assert len(value) == 40
    assert shannon_entropy(value) >= config.entropy_threshold  # self-validating
    line = AddedLine("src/app.py", 1, f"api_key = {value}")
    # non-vacuous control: entropy alone WOULD flag this value...
    control = EntropyDetector(
        config.entropy_threshold, config.entropy_min_length, config.entropy_allowlist
    )
    assert len(control.scan(line, exclude=set())) == 1
    # ...but the explicit rule claims it: suppression, not silence.
    findings = DetectionPipeline(config).run([line])
    assert [f.rule for f in findings] == ["api-key-assignment"]
    assert findings[0].severity == SEVERITY_HIGH
    assert findings[0].secret_preview == mask_secret(value)


def test_pipeline_dedupes_same_file_line_rule():
    line = AddedLine(
        "src/app.py",
        7,
        f'token = "{HIGH_ENTROPY_TOKEN}" y = "{HIGH_ENTROPY_TOKEN_2}"',
    )
    # duplicate line (staged+unstaged overlap) and two candidates on one line
    findings = DetectionPipeline(_config(rules=[])).run([line, line])
    assert len(findings) == 1
    assert findings[0].rule == ENTROPY_RULE_ID
    assert findings[0].line == 7


def test_pipeline_ignore_paths_skips_lines():
    config = _config(
        [RULES_BY_ID["aws-access-key"]],
        ignore_paths=["vendor/**", "notes.txt"],
    )
    findings = DetectionPipeline(config).run(
        [
            AddedLine("vendor/lib.js", 1, f'k = "{AWS_KEY}"'),
            AddedLine("cfg/notes.txt", 2, f'k = "{AWS_KEY}"'),  # basename match
            AddedLine("src/app.py", 3, f'k = "{AWS_KEY}"'),
        ]
    )
    assert [(f.file, f.line) for f in findings] == [("src/app.py", 3)]


def test_pipeline_returns_findings_in_stable_order():
    config = _config(
        [RULES_BY_ID["aws-access-key"], RULES_BY_ID["password-assignment"]]
    )
    findings = DetectionPipeline(config).run(
        [
            AddedLine("a.py", 10, f'k = "{AWS_KEY}"'),
            AddedLine("b.py", 5, PASSWORD_LINE),
            AddedLine("c.py", 3, f'token = "{HIGH_ENTROPY_TOKEN}"'),
        ]
    )
    assert [f.rule for f in findings] == [
        "aws-access-key",
        "password-assignment",
        ENTROPY_RULE_ID,
    ]
    assert [(f.file, f.line) for f in findings] == [
        ("a.py", 10),
        ("b.py", 5),
        ("c.py", 3),
    ]


def test_pipeline_primary_rule_suppresses_heuristic_on_same_line():
    assert len(AWS_SECRET_40) == 40  # self-validating: primary needs {40}
    line = AddedLine("src/app.py", 1, f"AWS_SECRET_ACCESS_KEY={AWS_SECRET_40}")
    findings = DetectionPipeline(_config([PRIMARY_SECRET_RULE, HEURISTIC_RULE])).run(
        [line]
    )
    assert [f.rule for f in findings] == ["aws-secret-key"]
    assert findings[0].severity == SEVERITY_HIGH


def test_pipeline_drops_heuristic_when_primary_matches_same_line():
    # Both rules genuinely match this line (non-vacuous suppression check).
    line = AddedLine(
        "src/app.py",
        1,
        f'aws_secret_access_key = "{AWS_SECRET_40}" '
        f'aws_secret_key = "abcdefghijklmnopqrst"',
    )
    only_primary, _ = RegexDetector([PRIMARY_SECRET_RULE]).scan(line)
    only_heuristic, _ = RegexDetector([HEURISTIC_RULE]).scan(line)
    assert [f.rule for f in only_primary] == ["aws-secret-key"]
    assert [f.rule for f in only_heuristic] == ["aws-credential-var"]

    findings = DetectionPipeline(_config([PRIMARY_SECRET_RULE, HEURISTIC_RULE])).run(
        [line]
    )
    assert [f.rule for f in findings] == ["aws-secret-key"]


def test_pipeline_keeps_heuristic_when_no_primary_matched():
    assert len(LOW_ENTROPY_VALUE) == 22  # self-validating: heuristic needs {16,}
    assert shannon_entropy(LOW_ENTROPY_VALUE) < 4.5  # entropy stays quiet
    line = AddedLine("src/app.py", 1, f"AWS_ACCESS_KEY={LOW_ENTROPY_VALUE}")
    findings = DetectionPipeline(_config([HEURISTIC_RULE])).run([line])
    assert [f.rule for f in findings] == ["aws-credential-var"]
    assert findings[0].severity == SEVERITY_MEDIUM


def test_pipeline_heuristic_suppression_is_per_line():
    findings = DetectionPipeline(_config([PRIMARY_SECRET_RULE, HEURISTIC_RULE])).run(
        [
            AddedLine(
                "src/app.py",
                1,
                f'aws_secret_access_key = "{AWS_SECRET_40}"',
            ),
            AddedLine("src/app.py", 2, f"AWS_ACCESS_KEY={LOW_ENTROPY_VALUE}"),
        ]
    )
    assert [f.rule for f in findings] == ["aws-secret-key", "aws-credential-var"]
