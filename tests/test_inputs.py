"""Unit tests for secret_finder.inputs."""

from __future__ import annotations

import io
import os
import subprocess

import pytest

from secret_finder.inputs import (
    CommitAdapter,
    DiffAdapter,
    ScanError,
    WorkingTreeAdapter,
    parse_unified_diff,
)
from secret_finder.models import AddedLine


def _run_git(repo, *args: str) -> str:
    env = dict(os.environ)
    env.update(
        HOME=str(repo),
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_TERMINAL_PROMPT="0",
    )
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    ).stdout


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(repo, "init")
    # Neutralize ambient global config that could alter adapter git output.
    _run_git(repo, "config", "color.ui", "false")
    _run_git(repo, "config", "diff.noprefix", "false")
    _run_git(repo, "config", "diff.mnemonicPrefix", "false")
    (repo / "app.txt").write_text("alpha\nbetasecret42\ngamma\n", encoding="utf-8")
    (repo / "notes.log").write_text("logstart\nlogsecret999\n", encoding="utf-8")
    _run_git(repo, "add", "app.txt", "notes.log")
    _run_git(
        repo,
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=Test",
        "commit",
        "-m",
        "add files",
    )
    return repo


# --- parse_unified_diff -----------------------------------------------------


def test_parse_multi_file_line_mapping_across_hunks():
    diff = """\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 keep1
+added1
 keep2
@@ -10,2 +11,3 @@
 oldctx
+added2
 tail
diff --git a/lib/util.js b/lib/util.js
index 3333333..4444444 100644
--- a/lib/util.js
+++ b/lib/util.js
@@ -5 +5 @@
-old
+new
"""
    lines = list(parse_unified_diff(diff.splitlines(keepends=True), []))
    # context/removed lines never emit; counters map across hunks
    assert lines == [
        AddedLine("src/app.py", 2, "added1"),
        AddedLine("src/app.py", 12, "added2"),
        AddedLine("lib/util.js", 5, "new"),
    ]


def test_parse_hunk_header_without_counts():
    diff = """\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-old
+new
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("a.txt", 1, "new")
    ]


def test_parse_zero_context_new_file_hunk():
    diff = """\
diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/new.txt
@@ -0,0 +1,3 @@
+first
+second
+third
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("new.txt", 1, "first"),
        AddedLine("new.txt", 2, "second"),
        AddedLine("new.txt", 3, "third"),
    ]


def test_parse_deleted_file_skipped():
    diff = """\
diff --git a/old.txt b/old.txt
deleted file mode 100644
index abc1234..0000000
--- a/old.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-one
-two
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == []


def test_parse_removed_and_context_do_not_advance_or_emit():
    diff = """\
diff --git a/f.txt b/f.txt
--- a/f.txt
+++ b/f.txt
@@ -4,3 +4,3 @@
 ctx-a
-removed
+added
 ctx-b
"""
    # new side starts at 4: ctx-a=4 (no emit), removed skipped, added=5
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("f.txt", 5, "added")
    ]


def test_parse_ignore_paths_by_path_and_basename():
    diff = """\
diff --git a/vendor/dep.py b/vendor/dep.py
--- a/vendor/dep.py
+++ b/vendor/dep.py
@@ -1 +1 @@
-old
+vendor-line
diff --git a/notes.lock b/notes.lock
--- a/notes.lock
+++ b/notes.lock
@@ -1 +1 @@
-old
+lock-line
diff --git a/keep.py b/keep.py
--- a/keep.py
+++ b/keep.py
@@ -1 +1 @@
-old
+kept-line
"""
    lines = list(parse_unified_diff(diff.splitlines(), ["vendor/**", "*.lock"]))
    assert lines == [AddedLine("keep.py", 1, "kept-line")]


def test_parse_binary_files_skip_until_next_diff():
    diff = """\
diff --git a/img.png b/img.png
index 1111111..2222222 100644
Binary files a/img.png and b/img.png differ
diff --git a/ok.txt b/ok.txt
--- a/ok.txt
+++ b/ok.txt
@@ -1 +1 @@
-old
+kept
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("ok.txt", 1, "kept")
    ]


def test_parse_git_binary_patch_skipped():
    diff = """\
diff --git a/blob.bin b/blob.bin
new file mode 100644
index 0000000..1111111
GIT binary patch
literal 4
Mc$@0!wIs~0
diff --git a/ok.txt b/ok.txt
--- a/ok.txt
+++ b/ok.txt
@@ -1 +1 @@
-old
+kept
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("ok.txt", 1, "kept")
    ]


def test_parse_path_without_b_prefix():
    diff = """\
+++ src/x.py
@@ -1,0 +1,1 @@
+hello
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("src/x.py", 1, "hello")
    ]


def test_parse_plus_plus_content_inside_hunk_not_a_header():
    diff = """\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1,0 +1,2 @@
+++ weird
+normal
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("a.txt", 1, "++ weird"),
        AddedLine("a.txt", 2, "normal"),
    ]


def test_parse_no_newline_marker_ignored():
    diff = r"""\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-old
+new
\ No newline at end of file
"""
    assert list(parse_unified_diff(diff.splitlines(), [])) == [
        AddedLine("a.txt", 1, "new")
    ]


# --- DiffAdapter ------------------------------------------------------------


def test_diff_adapter_from_string_buffer():
    buffer = io.StringIO(
        "diff --git a/src/x.py b/src/x.py\n"
        "--- a/src/x.py\n"
        "+++ b/src/x.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+one\n"
        "+two\n"
    )
    adapter = DiffAdapter(buffer, [])
    assert list(adapter.added_lines()) == [
        AddedLine("src/x.py", 1, "one"),
        AddedLine("src/x.py", 2, "two"),
    ]


# --- CommitAdapter ----------------------------------------------------------


def test_commit_adapter_yields_committed_added_lines(git_repo):
    head = _run_git(git_repo, "rev-parse", "HEAD").strip()
    lines = list(CommitAdapter(head, [], repo_root=str(git_repo)).added_lines())
    assert len(lines) == 5
    assert AddedLine("app.txt", 2, "betasecret42") in lines
    assert AddedLine("app.txt", 1, "alpha") in lines
    assert AddedLine("notes.log", 2, "logsecret999") in lines


def test_commit_adapter_respects_ignore_paths(git_repo):
    head = _run_git(git_repo, "rev-parse", "HEAD").strip()
    lines = list(CommitAdapter(head, ["*.log"], repo_root=str(git_repo)).added_lines())
    assert AddedLine("app.txt", 2, "betasecret42") in lines
    assert all(entry.file != "notes.log" for entry in lines)


def test_commit_adapter_unknown_hash_raises(git_repo):
    adapter = CommitAdapter(
        "0000000000000000000000000000000000000000", [], repo_root=str(git_repo)
    )
    with pytest.raises(ScanError):
        adapter.added_lines()


def test_commit_adapter_rejects_option_like_ref_before_git(monkeypatch):
    import secret_finder.inputs as inputs_module

    def _forbid(*_args, **_kwargs):
        raise AssertionError("git must not run for a rejected ref")

    monkeypatch.setattr(inputs_module.subprocess, "run", _forbid)
    with pytest.raises(ScanError, match="invalid commit ref"):
        CommitAdapter("--output=/tmp/x", [])


def test_commit_adapter_rejects_empty_ref():
    with pytest.raises(ScanError, match="invalid commit ref"):
        CommitAdapter("", [])


def test_commit_adapter_show_argv_has_merge_flag_and_timeout(git_repo, monkeypatch):
    import secret_finder.inputs as inputs_module

    head = _run_git(git_repo, "rev-parse", "HEAD").strip()
    real_run = inputs_module.subprocess.run
    captured: dict = {}

    def _spy(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(inputs_module.subprocess, "run", _spy)
    lines = list(CommitAdapter(head, [], repo_root=str(git_repo)).added_lines())
    assert lines  # fixture commit still parses with -m present
    assert captured["cmd"] == [
        "git",
        "show",
        "-m",
        "--format=",
        "--unified=0",
        head,
    ]
    assert captured["kwargs"]["timeout"] == inputs_module.GIT_TIMEOUT_SECONDS


def test_git_timeout_raises_scan_error(monkeypatch):
    import secret_finder.inputs as inputs_module

    def _timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=60)

    monkeypatch.setattr(inputs_module.subprocess, "run", _timeout)
    with pytest.raises(ScanError, match="timed out"):
        CommitAdapter("abc123", []).added_lines()
    with pytest.raises(ScanError, match="timed out"):
        WorkingTreeAdapter(".", []).added_lines()


# --- WorkingTreeAdapter -----------------------------------------------------


def test_working_tree_picks_up_untracked_file(git_repo):
    (git_repo / "loose.txt").write_text("first\nraw_secret_abc123\n", encoding="utf-8")
    lines = list(WorkingTreeAdapter(str(git_repo), []).added_lines())
    assert AddedLine("loose.txt", 1, "first") in lines
    assert AddedLine("loose.txt", 2, "raw_secret_abc123") in lines


def test_working_tree_picks_up_unstaged_change(git_repo):
    (git_repo / "app.txt").write_text(
        "alpha\nbetasecret42\ngamma\ndelta\n", encoding="utf-8"
    )
    lines = list(WorkingTreeAdapter(str(git_repo), []).added_lines())
    assert AddedLine("app.txt", 4, "delta") in lines
    assert AddedLine("app.txt", 1, "alpha") not in lines  # unchanged


def test_working_tree_picks_up_staged_change(git_repo):
    (git_repo / "app.txt").write_text(
        "alpha\nbetasecret42\ngamma\ndelta\n", encoding="utf-8"
    )
    _run_git(git_repo, "add", "app.txt")
    lines = list(WorkingTreeAdapter(str(git_repo), []).added_lines())
    assert AddedLine("app.txt", 4, "delta") in lines


def test_working_tree_staged_and_unstaged_in_one_run(git_repo):
    (git_repo / "app.txt").write_text(
        "alpha\nbetasecret42\ngamma\ndelta\n", encoding="utf-8"
    )
    _run_git(git_repo, "add", "app.txt")
    (git_repo / "app.txt").write_text(
        "alpha\nbetasecret42\ngamma\ndelta\nepsilon\n", encoding="utf-8"
    )
    lines = list(WorkingTreeAdapter(str(git_repo), []).added_lines())
    assert AddedLine("app.txt", 4, "delta") in lines  # staged
    assert AddedLine("app.txt", 5, "epsilon") in lines  # unstaged


def test_working_tree_skips_binary_untracked(git_repo):
    (git_repo / "blob.bin").write_bytes(b"\x00\x01\x02binarydata")
    lines = list(WorkingTreeAdapter(str(git_repo), []).added_lines())
    assert all(entry.file != "blob.bin" for entry in lines)


def test_working_tree_not_a_repo_raises(tmp_path):
    with pytest.raises(ScanError):
        WorkingTreeAdapter(str(tmp_path), []).added_lines()


def test_missing_git_binary_raises_scan_error(monkeypatch):
    import secret_finder.inputs as inputs_module

    def _raise(*_args, **_kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(inputs_module.subprocess, "run", _raise)
    with pytest.raises(ScanError, match="not found"):
        CommitAdapter("abc123", []).added_lines()
    with pytest.raises(ScanError, match="not found"):
        WorkingTreeAdapter(".", []).added_lines()
