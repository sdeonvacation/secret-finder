"""End-to-end CLI integration tests for secret-finder.

Invocation strategy: every test launches
``[sys.executable, "-m", "secret_finder"]`` with ``PYTHONPATH`` pointing at
``<repo>/src`` instead of the installed ``secret-finder`` console script.
Rationale (README documents both entry points as equivalent):

* runs under the exact interpreter executing pytest - no PATH / venv
  assumptions for a console script;
* loads the same source tree pytest's ``pythonpath = ["src"]`` config loads,
  so the tests always exercise the checked-out code;
* independent of whether an editable install is present.

Hermeticity: git (both test setup and CLI-driven) runs with
``GIT_CONFIG_GLOBAL`` / ``GIT_CONFIG_SYSTEM`` pointed at the null device so
ambient user/system git config cannot alter diff output, branch naming, or
commit behaviour. Every subprocess call is bounded by ``timeout=30``.

Source of truth for all expectations: design/HLD_secret-finder.md (§3 data
flow, §6 JSON schema, §10 exit codes) and plans/PLAN_secret-finder.md
(Testing Strategy). Exit-code contract: 0 = no findings, 1 = findings,
2 = usage/config/git/file error; stdout carries findings only, stderr
carries diagnostics/errors.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

TIMEOUT = 30

# --- secret fixture strings (shapes documented in README/HLD) ---------------
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AKIA + 16 uppercase alnum, caught by built-in rules
PASSWORD = "hunter2supersecret"  # password-assignment fixture
SHA1_HEX = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40-hex, entropy-allowlisted
CUSTOM_SECRET = "my-custom-secret-9347"  # matched only by a custom --rules rule

# --- JSON schema (HLD §6) ---------------------------------------------------
TOP_LEVEL_KEYS = {"findings", "summary"}
FINDING_KEYS = {"file", "line", "rule", "severity", "reason", "secret_preview"}
SUMMARY_KEYS = {"total", "high", "medium", "low"}
SEVERITIES = {"high", "medium", "low"}

# --- fixtures ---------------------------------------------------------------
# Working-tree fixture: untracked file, 1-based lines
#   1: benign comment   2: AWS key   3: benign   4: password
WORKING_TREE_REL = "cfg/app.txt"
WORKING_TREE_CONTENT = (
    f'# app config\naws = "{AWS_KEY}"\nx = 1\npassword = "{PASSWORD}"\n'
)

# Unified diff fixture (diff --git + @@ hunk + +++ b/path + added lines).
# New-file line mapping: keep1=1, password=2, keep2=3, aws=4.
DIFF_FIXTURE = (
    "diff --git a/src/app.py b/src/app.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/app.py\n"
    "+++ b/src/app.py\n"
    "@@ -1,2 +1,4 @@\n"
    " keep1\n"
    f'+password = "{PASSWORD}"\n'
    " keep2\n"
    f"+{AWS_KEY}\n"
)


# --- helpers ----------------------------------------------------------------


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    pythonpath = str(SRC_DIR)
    existing = env.get("PYTHONPATH")
    if existing:
        pythonpath = pythonpath + os.pathsep + existing
    env["PYTHONPATH"] = pythonpath
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def run_cli(
    *args: str, cwd: Path, stdin: str | None = None
) -> subprocess.CompletedProcess:
    """Run the CLI as a subprocess; stdout = findings, stderr = diagnostics."""
    return subprocess.run(
        [sys.executable, "-m", "secret_finder", *args],
        cwd=str(cwd),
        input="" if stdin is None else stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=TIMEOUT,
        env=_cli_env(),
    )


def run_git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=TIMEOUT,
        env=_cli_env(),
        check=True,
    )


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    run_git(path, "init")
    return path


def commit_all(repo: Path, message: str = "wip") -> None:
    run_git(repo, "add", "-A")
    run_git(
        repo,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-m",
        message,
    )


def parse_json_output(proc: subprocess.CompletedProcess) -> dict:
    """Assert exit 0/1 and exact HLD §6 schema; returns the parsed document.

    json.loads over the *entire* stdout - any stray chatter or truncation
    fails here, which is the stdout-purity guarantee (HLD §10).
    """
    assert proc.returncode in (0, 1), f"rc={proc.returncode} stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert set(doc) == TOP_LEVEL_KEYS
    assert set(doc["summary"]) == SUMMARY_KEYS
    for finding in doc["findings"]:
        assert set(finding) == FINDING_KEYS
        assert isinstance(finding["file"], str) and finding["file"]
        assert isinstance(finding["line"], int) and finding["line"] >= 1
        assert finding["rule"]
        assert finding["severity"] in SEVERITIES
        assert isinstance(finding["reason"], str) and finding["reason"]
        assert isinstance(finding["secret_preview"], str) and finding["secret_preview"]
    summary = doc["summary"]
    counts = Counter(f["severity"] for f in doc["findings"])
    assert summary["total"] == len(doc["findings"])
    assert summary["high"] == counts["high"]
    assert summary["medium"] == counts["medium"]
    assert summary["low"] == counts["low"]
    assert summary["high"] + summary["medium"] + summary["low"] == summary["total"]
    return doc


def assert_no_raw_secrets(proc: subprocess.CompletedProcess, *secrets: str) -> None:
    blob = proc.stdout + proc.stderr
    for secret in secrets:
        assert secret not in blob, f"raw secret leaked: {secret!r}"


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Fresh, config-isolated git repository."""
    return make_repo(tmp_path / "repo")


# --- 1. working-tree mode ---------------------------------------------------


def test_working_tree_json_schema_lines_and_masking(git_repo: Path) -> None:
    target = git_repo / WORKING_TREE_REL
    target.parent.mkdir()
    target.write_text(WORKING_TREE_CONTENT, encoding="utf-8")

    proc = run_cli("--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)

    aws = [f for f in doc["findings"] if f["rule"] == "aws-access-key"]
    assert len(aws) == 1
    assert aws[0]["file"] == WORKING_TREE_REL
    assert aws[0]["line"] == 2  # 1-based line of the AWS key
    # masked preview: first 4 chars + stars, never the raw secret
    assert aws[0]["secret_preview"].startswith("AKIA")
    assert "*" in aws[0]["secret_preview"]
    assert aws[0]["secret_preview"] != AWS_KEY

    pw = [f for f in doc["findings"] if f["line"] == 4]
    assert pw, "password assignment on line 4 not reported"
    assert all(f["file"] == WORKING_TREE_REL for f in pw)

    # benign lines 1 and 3 produce no findings
    assert not any(f["line"] in (1, 3) for f in doc["findings"])
    # summary consistency is asserted inside parse_json_output
    assert_no_raw_secrets(proc, AWS_KEY, PASSWORD)


def test_working_tree_text_output(git_repo: Path) -> None:
    target = git_repo / WORKING_TREE_REL
    target.parent.mkdir()
    target.write_text(WORKING_TREE_CONTENT, encoding="utf-8")

    proc = run_cli("--text", cwd=git_repo)
    assert proc.returncode == 1
    assert WORKING_TREE_REL in proc.stdout  # grouped by file
    assert "AWS access key ID" in proc.stdout  # documented rule reason (HLD §6)
    assert_no_raw_secrets(proc, AWS_KEY, PASSWORD)


# --- 2/3. --diff file and stdin modes --------------------------------------


def test_diff_file_mode_maps_file_and_line(tmp_path: Path) -> None:
    patch = tmp_path / "changes.patch"
    patch.write_text(DIFF_FIXTURE, encoding="utf-8")

    proc = run_cli("--diff", str(patch), "--json", cwd=tmp_path)
    assert proc.returncode == 1
    doc = parse_json_output(proc)

    lines = {(f["file"], f["line"]) for f in doc["findings"]}
    assert lines == {("src/app.py", 2), ("src/app.py", 4)}
    assert any(
        f["line"] == 4 and f["rule"] == "aws-access-key" for f in doc["findings"]
    )
    assert_no_raw_secrets(proc, AWS_KEY, PASSWORD)


def test_diff_stdin_mode_identical_to_file_mode(tmp_path: Path) -> None:
    patch = tmp_path / "changes.patch"
    patch.write_text(DIFF_FIXTURE, encoding="utf-8")

    file_proc = run_cli("--diff", str(patch), "--json", cwd=tmp_path)
    stdin_proc = run_cli("--diff", "-", "--json", cwd=tmp_path, stdin=DIFF_FIXTURE)

    assert file_proc.returncode == 1
    assert stdin_proc.returncode == 1
    file_doc = parse_json_output(file_proc)
    stdin_doc = parse_json_output(stdin_proc)
    assert stdin_doc == file_doc  # identical findings across input sources
    assert_no_raw_secrets(stdin_proc, AWS_KEY, PASSWORD)


# --- 4. --commit mode -------------------------------------------------------


def test_commit_mode_reports_committed_secret(git_repo: Path) -> None:
    (git_repo / "app.txt").write_text(
        f'aws = "{AWS_KEY}"\npassword = "{PASSWORD}"\n', encoding="utf-8"
    )
    commit_all(git_repo)

    proc = run_cli("--commit", "HEAD", "--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)

    aws = [f for f in doc["findings"] if f["rule"] == "aws-access-key"]
    assert len(aws) == 1
    assert aws[0]["file"] == "app.txt"
    assert aws[0]["line"] == 1
    assert any(f["file"] == "app.txt" and f["line"] == 2 for f in doc["findings"])
    assert_no_raw_secrets(proc, AWS_KEY, PASSWORD)


def test_commit_mode_merge_commit_reports_secret(git_repo: Path) -> None:
    (git_repo / "base.txt").write_text("benign = 1\n", encoding="utf-8")
    commit_all(git_repo, "base")
    base_branch = run_git(git_repo, "symbolic-ref", "--short", "HEAD").stdout.strip()

    run_git(git_repo, "checkout", "-b", "feature")
    (git_repo / "feature.txt").write_text(
        f'aws = "{AWS_KEY}"\npassword = "{PASSWORD}"\n', encoding="utf-8"
    )
    commit_all(git_repo, "feature secrets")

    run_git(git_repo, "checkout", base_branch)
    run_git(
        git_repo,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "merge",
        "--no-ff",
        "-m",
        "merge feature",
        "feature",
    )
    merge_sha = run_git(git_repo, "rev-parse", "HEAD").stdout.strip()

    # Without -m, git show emits an empty diff for a merge commit -> would
    # exit 0 and silently miss the secrets the merge brought in.
    proc = run_cli("--commit", merge_sha, "--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)

    aws = [f for f in doc["findings"] if f["rule"] == "aws-access-key"]
    assert len(aws) == 1
    assert aws[0]["file"] == "feature.txt"
    assert aws[0]["line"] == 1
    assert any(f["file"] == "feature.txt" and f["line"] == 2 for f in doc["findings"])
    assert_no_raw_secrets(proc, AWS_KEY, PASSWORD)


# --- 5. clean-change negative ----------------------------------------------


@pytest.mark.parametrize("mode", ["default", "text", "json"])
def test_clean_working_tree_exits_zero(git_repo: Path, mode: str) -> None:
    (git_repo / "benign.txt").write_text("x = 1\n", encoding="utf-8")

    args = {"default": (), "text": ("--text",), "json": ("--json",)}[mode]
    proc = run_cli(*args, cwd=git_repo)
    assert proc.returncode == 0
    if mode == "text":
        assert "No secrets found." in proc.stdout
    else:
        doc = parse_json_output(proc)
        assert doc["findings"] == []
        assert doc["summary"]["total"] == 0


# --- 6. entropy context gate (credential-name required) ---------------------


def test_entropy_requires_credential_context(git_repo: Path) -> None:
    """Context-free high-entropy strings are never flagged: entropy is a
    secondary signal only on credential-like names (post-workspace.xml fix).
    The SHA-1 line also documents that allowlisting is now belt-and-braces —
    the context gate alone suppresses it (unit tests cover allowlist proper)."""
    from secret_finder.entropy import shannon_entropy

    novel = "abcdefghijklmnopqrstuvwxyzABCDEF"  # H = 5.0, would pass the threshold
    assert shannon_entropy(novel) >= 4.5  # precondition: fires if context present
    # SHA-1 hex caps raw H at log2(16)=4.0 < 4.5, so the threshold already
    # excludes it; the allowlist is defense-in-depth (unit-tested below 4.5).
    (git_repo / "hashes.txt").write_text(
        f"checksum {SHA1_HEX}\n"
        f'option value="{novel}"\n',  # XML-ish name, no credential keyword
        encoding="utf-8",
    )

    proc = run_cli("--json", cwd=git_repo)
    assert proc.returncode == 0
    doc = parse_json_output(proc)
    assert doc["findings"] == []
    assert doc["summary"]["total"] == 0


def test_idea_workspace_xml_fp_shapes_stay_silent(git_repo: Path) -> None:
    """Regression for commit e548bf9: the two entropy false positives —
    <component id=...> and <option value=...> in .idea/workspace.xml — must
    produce zero findings, while the file itself is still scanned (not ignored)."""
    from secret_finder.entropy import shannon_entropy

    comp_id = "3LbTq7Xk9mP2rV5wY8zA1cD4eF"  # 26-char IDE-style component id
    opt_value = "bundledPathValue0123456789AbCdEfGhIjKlMnOpQrStUvWxYz"
    assert shannon_entropy(comp_id) >= 4.5  # both would pass the entropy
    assert shannon_entropy(opt_value) >= 4.5  # threshold if ungated
    xml = git_repo / ".idea"
    xml.mkdir()
    (xml / "workspace.xml").write_text(
        '<?xml version="1.0"?>\n'
        "<project>\n"
        f'  <component name="ProjectManager" id="{comp_id}" />\n'
        f'        <option value="{opt_value}" />\n'
        "</project>\n",
        encoding="utf-8",
    )

    proc = run_cli("--json", cwd=git_repo)
    assert proc.returncode == 0
    doc = parse_json_output(proc)
    assert doc["findings"] == []


def test_entropy_fires_at_default_config_on_novel_token(git_repo: Path) -> None:
    """Full-stack guard for the raw-H gate WITH credential context: the line has
    `token = ` context but an assignment-rule-incompatible value (`ab` < 8), so
    the entropy pass alone must flag the separate high-entropy candidate at the
    default threshold 4.5. Regression for the charset-normalized-vs-threshold bug."""
    token = "abcdefghijklmnopqrstuvwxyzABCDEF"  # 32 distinct chars -> H = 5.0 bits/char
    (git_repo / "novel.txt").write_text(f'token = "ab" {token}\n', encoding="utf-8")

    proc = run_cli("--json", cwd=git_repo)  # default config: no --rules
    assert proc.returncode == 1
    doc = parse_json_output(proc)

    entropy = [f for f in doc["findings"] if f["rule"] == "entropy"]
    assert entropy, "default config must flag a novel high-entropy token via entropy"
    hit = entropy[0]
    assert hit["file"] == "novel.txt"
    assert hit["line"] == 1
    assert hit["severity"] == "medium"
    assert hit["secret_preview"].startswith(token[:4])
    # no built-in regex rule may claim this line (regex-wins must not apply here)
    assert [f for f in doc["findings"] if f["rule"] != "entropy"] == []
    assert_no_raw_secrets(proc, token)


# --- .env incident + confidence tiers (regression: commit 63f774c) ----------

# 22-char lowercase-alnum under AWS_ACCESS_KEY: no AKIA format, low entropy
# (H=3.33) — missed by every layer until the aws-credential-var heuristic.
ENV_INCIDENT_VALUE = "adsn" + "b1c2d3e4f5g6h7i8j9"
AWS_SECRET_40 = "wJalrXUtnFEMI7KMDENGB" + "PxrEfCnXmQ9tL5vY2hK"  # exactly 40 chars
PASSWORD_VALUE = "hunter2supersecret"


def test_env_access_key_assignment_catches_incident(git_repo: Path) -> None:
    """Regression for 'No secrets found' on commit 63f774c. Since `access_key`
    became a Tier-1 keyword, AWS_ACCESS_KEY=<22> flags as a high-confidence
    assignment; the aws-credential-var heuristic is then suppressed (primary wins)."""
    assert len(ENV_INCIDENT_VALUE) == 22
    (git_repo / ".env").write_text(
        f"AWS_ACCESS_KEY={ENV_INCIDENT_VALUE}\n", encoding="utf-8"
    )
    commit_all(git_repo, "add .env")

    proc = run_cli("--commit", "HEAD", "--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)
    assert doc["summary"]["total"] == 1

    hit = doc["findings"][0]
    assert hit["rule"] == "api-key-assignment"
    assert hit["file"] == ".env"
    assert hit["line"] == 1
    assert hit["severity"] == "high"
    assert not [f for f in doc["findings"] if f["rule"] == "aws-credential-var"]
    assert_no_raw_secrets(proc, ENV_INCIDENT_VALUE)


def test_unquoted_password_assignment_is_high_confidence(git_repo: Path) -> None:
    """Tier 1: quotes optional, unquoted .env-style password still high."""
    (git_repo / ".env").write_text(f"password={PASSWORD_VALUE}\n", encoding="utf-8")
    commit_all(git_repo)

    proc = run_cli("--commit", "HEAD", "--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)
    hits = [f for f in doc["findings"] if f["rule"] == "password-assignment"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "high"
    assert_no_raw_secrets(proc, PASSWORD_VALUE)


def test_findings_prioritized_high_before_heuristic(git_repo: Path) -> None:
    """Tier order: high-confidence assignment precedes Tier 3 heuristic in JSON.
    Line 2 uses `aws_secret_key` — a form the Tier-1 keywords do NOT cover
    (secret is followed by `_key`, not `[:=]`), so the medium heuristic fires."""
    (git_repo / ".env").write_text(
        f"password={PASSWORD_VALUE}\naws_secret_key = {ENV_INCIDENT_VALUE}\n",
        encoding="utf-8",
    )
    commit_all(git_repo)

    proc = run_cli("--commit", "HEAD", "--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)
    assert doc["summary"]["total"] == 2
    rank = {"high": 0, "medium": 1, "low": 2}
    sev = [f["severity"] for f in doc["findings"]]
    assert sev == sorted(sev, key=rank.__getitem__)
    assert doc["findings"][0]["rule"] == "password-assignment"
    assert doc["findings"][-1]["rule"] == "aws-credential-var"


def test_heuristic_suppressed_when_primary_matches_line(git_repo: Path) -> None:
    """Tier 3 is secondary: canonical 40-char secret assignment is claimed by
    primary rules (aws-secret-key via format, api-key-assignment via the
    `access_key` keyword) — no aws-credential-var duplicate may appear."""
    assert len(AWS_SECRET_40) == 40
    (git_repo / ".env").write_text(
        f"AWS_SECRET_ACCESS_KEY={AWS_SECRET_40}\n", encoding="utf-8"
    )
    commit_all(git_repo)

    proc = run_cli("--commit", "HEAD", "--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)
    rules_on_line = {f["rule"] for f in doc["findings"] if f["line"] == 1}
    assert "aws-secret-key" in rules_on_line
    assert "aws-credential-var" not in rules_on_line
    assert_no_raw_secrets(proc, AWS_SECRET_40)


def test_user_keyword_behavior_table_end_to_end(git_repo: Path) -> None:
    """The user-specified keyword behavior table, through the full CLI.
    All values are <16 chars so entropy contributes nothing — flags come from
    the assignment rules alone; `compass` must produce no finding at all."""
    content = (
        'jobhunter_pass = "hallelujah"\n'  # 1: pass keyword (prefix _) -> password rule
        'db_password = "abc123"\n'  # 2: password keyword -> password rule
        'MY_API_KEY="xyz12345"\n'  # 3: api_key keyword -> api-key rule
        'access_token = "eyJhbGci..."\n'  # 4: token keyword -> api-key rule
        'user_pass = "test"\n'  # 5: pass + 4-char value -> password rule (accepted FP)
        'compass = "north"\n'  # 6: `pass` embedded in `compass` -> NO flag
    )
    (git_repo / "table.env").write_text(content, encoding="utf-8")
    commit_all(git_repo, "keyword table")

    proc = run_cli("--commit", "HEAD", "--json", cwd=git_repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)

    by_line = {f["line"]: f["rule"] for f in doc["findings"]}
    assert by_line == {
        1: "password-assignment",
        2: "password-assignment",
        3: "api-key-assignment",
        4: "api-key-assignment",
        5: "password-assignment",
    }  # line 6 (compass) deliberately absent — exact map, no extras
    assert all(f["severity"] == "high" for f in doc["findings"])
    assert doc["summary"] == {"total": 5, "high": 5, "medium": 0, "low": 0}
    assert_no_raw_secrets(proc, "hallelujah", "abc123", "xyz12345", "test")


# --- 7/8/9/10. error paths (exit 2) ----------------------------------------


def test_error_bad_commit_hash(git_repo: Path) -> None:
    (git_repo / "a.txt").write_text("x = 1\n", encoding="utf-8")
    commit_all(git_repo)

    json_proc = run_cli("--commit", "deadbeefdeadbeef", "--json", cwd=git_repo)
    assert json_proc.returncode == 2
    assert json_proc.stderr.strip(), "error must be reported on stderr"
    if json_proc.stdout.strip():  # stdout empty, or (if ever emitted) parseable
        json.loads(json_proc.stdout)

    text_proc = run_cli("--commit", "deadbeefdeadbeef", cwd=git_repo)
    assert text_proc.returncode == 2
    assert text_proc.stderr.strip()
    assert text_proc.stdout.strip() == ""


def test_commit_option_injection_rejected(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo)

    marker = tmp_path / "pwned"
    # Single-token "--commit=--output=..." form: argparse hands the
    # leading-dash value to CommitAdapter instead of rejecting the token.
    proc = run_cli(f"--commit=--output={marker}", cwd=repo)
    assert proc.returncode == 2
    assert proc.stderr.strip(), "error must be reported on stderr"
    assert "invalid commit ref" in proc.stderr
    assert proc.stdout.strip() == ""
    assert not marker.exists(), "git must never run with an injected --output"


def test_error_missing_diff_file(tmp_path: Path) -> None:
    proc = run_cli(
        "--diff", str(tmp_path / "nonexistent.patch"), "--json", cwd=tmp_path
    )
    assert proc.returncode == 2
    assert proc.stderr.strip()
    assert proc.stdout.strip() == ""


def test_error_invalid_rules_json_names_problem(tmp_path: Path) -> None:
    rules = tmp_path / "broken.json"
    rules.write_text("{not valid json", encoding="utf-8")

    proc = run_cli("--rules", str(rules), "--json", cwd=tmp_path)
    assert proc.returncode == 2
    assert proc.stderr.strip()
    assert "json" in proc.stderr.lower(), "stderr must name the problem"
    assert proc.stdout.strip() == ""


def test_error_diff_and_commit_are_mutually_exclusive(tmp_path: Path) -> None:
    proc = run_cli("--diff", "x", "--commit", "y", cwd=tmp_path)
    assert proc.returncode == 2  # argparse usage error
    assert proc.stderr.strip()
    assert proc.stdout.strip() == ""


# --- 11. default JSON / --text output modes --------------------------------


def test_default_output_is_json_without_chatter(git_repo: Path) -> None:
    """JSON is the default format: a bare invocation emits one JSON document
    on stdout and stays silent on stderr (chatter is a --text-mode concern)."""
    (git_repo / "sec.txt").write_text(f'aws = "{AWS_KEY}"\n', encoding="utf-8")

    proc = run_cli(cwd=git_repo)  # no output flags at all
    assert proc.returncode == 1
    doc = parse_json_output(proc)
    assert doc["summary"]["total"] >= 1
    assert proc.stderr.strip() == "", "default (JSON) success must not chatter"
    assert_no_raw_secrets(proc, AWS_KEY)


def test_text_and_json_flags_are_mutually_exclusive(tmp_path: Path) -> None:
    proc = run_cli("--text", "--json", cwd=tmp_path)
    assert proc.returncode == 2
    assert proc.stderr.strip()


def test_json_stdout_purity_with_stderr_chatter(git_repo: Path) -> None:
    (git_repo / "sec.txt").write_text(f'aws = "{AWS_KEY}"\n', encoding="utf-8")

    # --text: human output on stdout with summary chatter on stderr;
    # --text --quiet suppresses the chatter without touching stdout.
    text_proc = run_cli("--text", cwd=git_repo)
    assert text_proc.returncode == 1
    assert text_proc.stdout.strip()
    assert text_proc.stderr.strip(), "--text mode emits chatter on stderr"

    quiet_proc = run_cli("--text", "--quiet", cwd=git_repo)
    assert quiet_proc.returncode == 1
    assert quiet_proc.stderr.strip() == ""
    assert quiet_proc.stdout == text_proc.stdout

    # --json (compat no-op, identical to default): the whole stdout parses as
    # one JSON document (no chatter or diagnostics leaked onto it), and the
    # JSON payload never appears on stderr.
    json_proc = run_cli("--json", cwd=git_repo)
    assert json_proc.returncode == 1
    doc = parse_json_output(json_proc)
    assert doc["summary"]["total"] >= 1
    assert '"findings"' not in json_proc.stderr
    assert '"summary"' not in json_proc.stderr
    assert_no_raw_secrets(json_proc, AWS_KEY)


# --- 12. --rules positive ---------------------------------------------------


def test_custom_rules_file_adds_matching_rule(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo")
    (repo / "custom.txt").write_text(
        f"nothing here\n{CUSTOM_SECRET}\n", encoding="utf-8"
    )
    # rules file lives outside the repo so it is never part of the scan
    rules = tmp_path / "custom-rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "my-custom-secret",
                        "name": "Custom Fixture Secret",
                        "regex": r"my-custom-secret-[0-9]{4}",
                        "severity": "medium",
                        "reason": "custom fixture secret",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    proc = run_cli("--rules", str(rules), "--json", cwd=repo)
    assert proc.returncode == 1
    doc = parse_json_output(proc)

    custom = [f for f in doc["findings"] if f["rule"] == "my-custom-secret"]
    assert len(custom) == 1
    assert custom[0]["file"] == "custom.txt"
    assert custom[0]["line"] == 2
    assert custom[0]["severity"] == "medium"
    assert custom[0]["reason"] == "custom fixture secret"
    assert_no_raw_secrets(proc, CUSTOM_SECRET)
