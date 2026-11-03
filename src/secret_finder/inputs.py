"""Input adapters and the shared unified-diff parser."""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from typing import Iterable, Iterator, Protocol

from .models import AddedLine

# Generous bound so a hung git cannot hang the CLI forever.
GIT_TIMEOUT_SECONDS = 60


class ScanError(Exception):
    """Git failure, missing file, or not-a-repo (CLI maps to exit code 2)."""


class InputAdapter(Protocol):
    def added_lines(self) -> Iterator[AddedLine]: ...


# New-file side of a hunk header: +c or +c,d (c = start line, d = count).
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _is_ignored(path: str, ignore_paths: list[str]) -> bool:
    base = os.path.basename(path)
    return any(
        fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(base, pattern)
        for pattern in ignore_paths
    )


def parse_unified_diff(
    source: Iterable[str], ignore_paths: list[str]
) -> Iterator[AddedLine]:
    """Stream added lines from unified-diff text.

    The current file comes from ``+++ b/<path>`` (or ``+++ <path>``) headers;
    ``+++ /dev/null`` marks a deleted file that is skipped. The new-file line
    counter starts at ``c`` from ``@@ -a,b +c,d @@`` (counts optional, default
    1), advances on ``+`` and context lines, and stops when the hunk's new-file
    line count is exhausted. ``-`` lines and ``\\ No newline`` markers are
    ignored. Binary files are skipped until the next ``diff --git``. Paths
    matching ``ignore_paths`` (fnmatch on full path and basename) are skipped.
    """
    file: str | None = None
    skip = False
    in_hunk = False
    new_line = 0
    remaining = 0

    for raw in source:
        line = raw.rstrip("\r\n")

        if line.startswith("diff --git"):
            file, skip, in_hunk = None, False, False
            continue

        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            skip, in_hunk = True, False
            continue

        hunk = _HUNK_RE.match(line)
        if hunk:
            if file is not None and not skip:
                new_line = int(hunk.group(1))
                remaining = int(hunk.group(2)) if hunk.group(2) is not None else 1
                in_hunk = remaining > 0
            else:
                in_hunk = False
            continue

        if not in_hunk:
            # Headers other than +++ (---, index, modes, renames, ...) need no
            # handling. +++ only appears outside hunks, so added content that
            # starts with "++" is never mistaken for a file header.
            if line.startswith("+++ "):
                path = line[4:].split("\t", 1)[0]
                if path.startswith("b/"):
                    path = path[2:]
                if path == "/dev/null":
                    file, skip = None, True
                else:
                    file = path
                    skip = _is_ignored(path, ignore_paths)
            continue

        if file is None:
            continue

        if line.startswith("\\"):
            continue
        if line.startswith("+"):
            yield AddedLine(file, new_line, line[1:])
            new_line += 1
            remaining -= 1
        elif line.startswith("-"):
            continue
        elif line.startswith(" ") or line == "":
            new_line += 1
            remaining -= 1
        else:
            continue

        if remaining <= 0:
            in_hunk = False


class DiffAdapter:
    """Yields added lines from unified-diff text (file or stdin stream)."""

    def __init__(self, source: Iterable[str], ignore_paths: list[str]) -> None:
        self._source = source
        self._ignore_paths = ignore_paths

    def added_lines(self) -> Iterator[AddedLine]:
        return parse_unified_diff(self._source, self._ignore_paths)


class CommitAdapter:
    """Yields added lines introduced by one commit via ``git show``."""

    def __init__(
        self, hash: str, ignore_paths: list[str], repo_root: str = "."
    ) -> None:
        # The ref is a list argv element (no shell), but git still parses a
        # leading-dash value as one of ITS options (e.g. --output=...), so
        # reject it before any git call. No legitimate ref starts with "-".
        if not hash or hash.startswith("-"):
            raise ScanError(
                f"invalid commit ref {hash!r}: "
                "must be non-empty and must not start with '-'"
            )
        self._hash = hash
        self._ignore_paths = ignore_paths
        self._repo_root = repo_root

    def added_lines(self) -> Iterator[AddedLine]:
        try:
            # -m shows merge commits against each parent (plain git show
            # emits an empty diff for merges -> silent false negative).
            proc = subprocess.run(
                ["git", "show", "-m", "--format=", "--unified=0", self._hash],
                cwd=self._repo_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=GIT_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            raise ScanError("git executable not found") from None
        except subprocess.TimeoutExpired:
            raise ScanError(
                f"git command timed out after {GIT_TIMEOUT_SECONDS}s"
            ) from None
        if proc.returncode != 0:
            raise ScanError(
                proc.stderr.strip()
                or f"git show failed for commit {self._hash} (exit {proc.returncode})"
            )
        return parse_unified_diff(proc.stdout.splitlines(), self._ignore_paths)


class WorkingTreeAdapter:
    """Yields added lines from unstaged + staged diffs and untracked files."""

    def __init__(self, repo_root: str, ignore_paths: list[str]) -> None:
        self._repo_root = repo_root
        self._ignore_paths = ignore_paths

    def _git(self, *args: str) -> str:
        try:
            proc = subprocess.run(
                ["git", *args],
                cwd=self._repo_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=GIT_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            raise ScanError("git executable not found") from None
        except subprocess.TimeoutExpired:
            raise ScanError(
                f"git command timed out after {GIT_TIMEOUT_SECONDS}s"
            ) from None
        if proc.returncode != 0:
            raise ScanError(
                proc.stderr.strip()
                or f"git {' '.join(args)} failed (exit {proc.returncode})"
            )
        return proc.stdout

    def added_lines(self) -> Iterator[AddedLine]:
        # git runs eagerly so failures raise ScanError before iteration starts.
        sources = [
            parse_unified_diff(
                self._git("diff", "--unified=0").splitlines(), self._ignore_paths
            ),
            parse_unified_diff(
                self._git("diff", "--cached", "--unified=0").splitlines(),
                self._ignore_paths,
            ),
        ]
        untracked = self._git("ls-files", "--others", "--exclude-standard").splitlines()
        return self._merge(sources, untracked)

    def _merge(
        self, sources: list[Iterator[AddedLine]], untracked: list[str]
    ) -> Iterator[AddedLine]:
        seen: set[AddedLine] = set()

        def take(items: Iterable[AddedLine]) -> Iterator[AddedLine]:
            for item in items:
                if item not in seen:
                    seen.add(item)
                    yield item

        for source in sources:
            yield from take(source)
        for path in untracked:
            if not path or _is_ignored(path, self._ignore_paths):
                continue
            yield from take(self._read_untracked(path))

    def _read_untracked(self, path: str) -> Iterator[AddedLine]:
        full = os.path.join(self._repo_root, path)
        try:
            with open(full, "rb") as handle:
                head = handle.read(8192)
                if b"\x00" in head:
                    return
                data = head + handle.read()
        except OSError as exc:
            raise ScanError(f"cannot read untracked file {path}: {exc}") from None
        text = data.decode("utf-8", errors="replace")
        for number, content in enumerate(text.splitlines(), start=1):
            yield AddedLine(path, number, content)
