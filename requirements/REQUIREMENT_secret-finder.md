# Requirement: secret-finder

A CLI tool that finds git-committed passwords, keys, or other secrets.

## Problem

Developers accidentally commit credentials (AWS keys, private keys, API tokens,
hardcoded passwords). Teams need a fast, local way to catch leaked secrets
before they land in a branch, and a way to audit an existing commit.

## Inputs (one of, per invocation)

| Mode | Flag | Description |
|------|------|-------------|
| Diff file | `--diff <path>` or `--diff -` | Scan a git patch/diff read from a file or stdin |
| Commit | `--commit <hash>` | Scan the diff introduced by a specific commit |
| Working tree | (default, no flag) | Scan current uncommitted changes in the repo |

## Outputs

For each finding:

- **file** — path the secret appears in
- **line** — 1-based line number in the new file
- **reason** — short human explanation (rule name + why it looks like a secret)

Formats:

- **Human text** (default): readable list/table
- **JSON** (`--json`): machine-readable, stable schema

Exit codes: `0` no findings, `1` findings found (CI-friendly), `2` usage/scan error.

## Detection

Two complementary strategies:

1. **Regex rules** — named patterns for well-known secret shapes (AWS access
   keys, AWS secret keys, PEM private-key blocks, Slack/GitHub tokens, JWT,
   generic `password`/`api_key`/`token` assignments, etc.).
2. **Shannon entropy** — flag long, high-entropy strings (base64-like, hex,
   random tokens) that match no known pattern but are likely secrets.

Rules are shipped as **built-in defaults**, overridable/extensible via a
**config file** (rules file) without code changes.

## Non-functional

- Fast enough for interactive use on typical repos.
- Streaming: does not require loading an entire large diff into memory.
- No network access; operates on local git state only.
- Skip binary files and known-benign paths (lockfiles, vendored deps, etc.).

## Deliverables

- CLI tool (Python).
- README: how to install/run, plus a "known limitations / where it fails"
  section (false positives, entropy limitations, secrets already in history).
- Tests: unit (detectors, diff parsing) + integration (sample diffs, CLI).

## Out of scope

- Scanning full history for pre-existing secrets (only new/changed lines).
- Remediation/auto-redaction.
- Remote/cloud scanning.
- Entropy-vs-rule confirmation ML or frequency tables.
