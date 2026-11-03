"""argparse entry point: wire config, adapters, pipeline, and reporters."""

from __future__ import annotations

import argparse
import os
import sys

from .detectors import DetectionPipeline
from .inputs import CommitAdapter, DiffAdapter, ScanError, WorkingTreeAdapter
from .report import JsonReporter, TextReporter
from .rules import ConfigError, load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-finder",
        description="Scan git changes for leaked secrets before they land in a branch.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--diff",
        metavar="PATH",
        help="unified diff file to scan ('-' reads stdin)",
    )
    source.add_argument(
        "--commit",
        metavar="HASH",
        help="scan the diff introduced by a single commit",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit findings as JSON on stdout",
    )
    parser.add_argument(
        "--rules",
        metavar="PATH",
        help="JSON config file with rules/entropy/ignore_paths overrides",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress non-error diagnostics on stderr",
    )
    return parser


def _fail(message: str) -> int:
    print(f"secret-finder: error: {message}", file=sys.stderr)
    return 2


def _silence_stdout() -> None:
    """Point stdout's fd at devnull so shutdown cannot re-raise the pipe error.

    After BrokenPipeError the reader is gone; without this, the interpreter's
    shutdown flush re-raises and prints "Exception ignored" (exit 120).
    """
    try:
        fd = sys.stdout.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
    except (AttributeError, OSError, ValueError):
        # stdout has no real fd (capture/redirect) or devnull unavailable.
        return
    try:
        os.dup2(devnull, fd)
    except OSError:
        pass
    try:
        os.close(devnull)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.rules)
    except ConfigError as exc:
        return _fail(str(exc))

    stream = None
    try:
        if args.diff == "-":
            adapter = DiffAdapter(sys.stdin, config.ignore_paths)
        elif args.diff is not None:
            stream = open(args.diff, encoding="utf-8", errors="replace")
            adapter = DiffAdapter(stream, config.ignore_paths)
        elif args.commit is not None:
            adapter = CommitAdapter(args.commit, config.ignore_paths, repo_root=".")
        else:
            adapter = WorkingTreeAdapter(".", config.ignore_paths)
        findings = DetectionPipeline(config).run(adapter.added_lines())
    except (ScanError, OSError) as exc:
        # OSError covers FileNotFoundError for a missing --diff path.
        return _fail(str(exc))
    finally:
        if stream is not None:
            stream.close()

    rendered = (JsonReporter() if args.json else TextReporter()).render(findings)
    # JsonReporter output already ends with a newline; TextReporter does not.
    payload = rendered if rendered.endswith("\n") else rendered + "\n"

    try:
        sys.stdout.write(payload)
        if not args.quiet and not args.json:
            count = len(findings)
            noun = "finding" if count == 1 else "findings"
            print(f"secret-finder: {count} {noun}", file=sys.stderr)
    except BrokenPipeError:
        # Reader went away (e.g. `secret-finder --json | head`). The scan
        # itself succeeded, so keep the 0/1 status instead of reporting 2.
        _silence_stdout()
        return 1 if findings else 0

    return 1 if findings else 0
