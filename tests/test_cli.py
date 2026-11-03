"""Unit tests for cli.main output path, incl. BrokenPipeError (HLD §10).

Exit contract: 0 = no findings, 1 = findings, 2 = usage/config/git error.
stdout carries findings only; stderr carries diagnostics.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from secret_finder import cli

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AKIA + 16 uppercase alnum (built-in rule)

# Small unified diffs: one finding (bare AWS key line) and a clean pair of
# benign added lines. Same header shape as the e2e fixtures.
FINDINGS_DIFF = (
    "diff --git a/src/app.py b/src/app.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/app.py\n"
    "+++ b/src/app.py\n"
    "@@ -1,1 +1,2 @@\n"
    " keep1\n"
    f"+{AWS_KEY}\n"
)

CLEAN_DIFF = (
    "diff --git a/src/app.py b/src/app.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/app.py\n"
    "+++ b/src/app.py\n"
    "@@ -1,1 +1,2 @@\n"
    " keep1\n"
    "+keep2\n"
)

# Sentinel fd value used only with the stubbed os.dup2: never a real fd.
FAKE_FD = 7


# --- helpers -----------------------------------------------------------------


def _write_diff(tmp_path: Path, text: str) -> str:
    path = tmp_path / "changes.patch"
    path.write_text(text, encoding="utf-8")
    return str(path)


def _raise_broken_pipe(*_args: object, **_kwargs: object) -> int:
    raise BrokenPipeError(32, "Broken pipe")


def _patch_broken_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[str], list[tuple[int, int]]]:
    """Break stdout writes and stub fd redirection.

    Returns (recorded write payloads, recorded (src, dst) dup2 calls).
    dup2 is stubbed so the test can never clobber the runner's real fds.
    """
    attempts: list[str] = []

    def _write(text: str) -> int:
        attempts.append(text)
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(sys.stdout, "write", _write)
    monkeypatch.setattr(sys.stdout, "fileno", lambda: FAKE_FD)

    dup2_calls: list[tuple[int, int]] = []

    def _dup2(fd: int, fd2: int) -> int:
        dup2_calls.append((fd, fd2))
        return fd2

    monkeypatch.setattr(cli.os, "dup2", _dup2)
    return attempts, dup2_calls


def _patch_broken_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    """Break stderr writes; stub dup2 as a safety net for fd redirection."""
    monkeypatch.setattr(sys.stderr, "write", _raise_broken_pipe)
    monkeypatch.setattr(cli.os, "dup2", lambda fd, fd2: fd2)


# --- broken-pipe path --------------------------------------------------------


def test_broken_stdout_write_findings_returns_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diff = _write_diff(tmp_path, FINDINGS_DIFF)
    attempts, dup2_calls = _patch_broken_stdout(monkeypatch)

    assert cli.main(["--diff", diff]) == 1  # no exception escapes

    assert attempts, "findings write attempted before the pipe broke"
    assert "src/app.py:" in attempts[0]
    # stdout fd re-pointed at devnull so shutdown flush cannot re-raise.
    assert dup2_calls and dup2_calls[0][1] == FAKE_FD


def test_broken_stdout_write_clean_diff_returns_0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diff = _write_diff(tmp_path, CLEAN_DIFF)
    attempts, dup2_calls = _patch_broken_stdout(monkeypatch)

    assert cli.main(["--diff", diff]) == 0

    assert attempts and "No secrets found." in attempts[0]
    assert dup2_calls and dup2_calls[0][1] == FAKE_FD


def test_broken_stdout_write_json_returns_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reported scenario: `secret-finder --json | head`.
    diff = _write_diff(tmp_path, FINDINGS_DIFF)
    attempts, dup2_calls = _patch_broken_stdout(monkeypatch)

    assert cli.main(["--diff", diff, "--json"]) == 1

    assert attempts and '"findings"' in attempts[0]
    assert dup2_calls and dup2_calls[0][1] == FAKE_FD


def test_broken_stderr_summary_keeps_status_and_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    # stdout write succeeds first; only the stderr summary breaks.
    diff = _write_diff(tmp_path, FINDINGS_DIFF)
    _patch_broken_stderr(monkeypatch)

    assert cli.main(["--diff", diff]) == 1

    captured = capsys.readouterr()
    assert "AWS access key ID" in captured.out


# --- non-broken path (regression guard) --------------------------------------


def test_findings_written_to_stdout_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    diff = _write_diff(tmp_path, FINDINGS_DIFF)

    assert cli.main(["--diff", diff]) == 1

    captured = capsys.readouterr()
    assert "src/app.py:" in captured.out
    assert "AWS access key ID" in captured.out
    assert AWS_KEY not in captured.out  # raw secret never reaches stdout
    assert captured.err == "secret-finder: 1 finding\n"


def test_clean_diff_writes_no_secrets_exit_0(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    diff = _write_diff(tmp_path, CLEAN_DIFF)

    assert cli.main(["--diff", diff]) == 0

    captured = capsys.readouterr()
    assert captured.out == "No secrets found.\n"
    assert captured.err == "secret-finder: 0 findings\n"


def test_missing_diff_path_still_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    assert cli.main(["--diff", str(tmp_path / "nope.patch")]) == 2
    captured = capsys.readouterr()
    assert "secret-finder: error:" in captured.err
    assert captured.out == ""


# --- fd-redirection guard ----------------------------------------------------


class _FilenolessStdout:
    """stdout stand-in without fileno() (e.g. some capture wrappers)."""

    def write(self, text: str) -> int:
        return len(text)


def test_silence_stdout_without_fileno_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dup2_calls: list[tuple[int, int]] = []
    monkeypatch.setattr(cli.os, "dup2", lambda fd, fd2: dup2_calls.append((fd, fd2)))
    monkeypatch.setattr(cli.sys, "stdout", _FilenolessStdout())

    cli._silence_stdout()  # must return without raising or touching fds

    assert dup2_calls == []
