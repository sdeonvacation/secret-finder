# Plan: secret-finder

## Overview

A Python CLI that scans git changes (a diff file or stdin, a commit hash, or
the working tree) for leaked secrets. It combines named regex rules with
Shannon-entropy detection and reports findings as `file:line` plus a short
reason, in human-readable text or JSON. Built-in rules are overridable via a
config file.

## Tech Stack

- **Language:** Python 3.10+
- **CLI parsing:** argparse (stdlib) — zero-dependency runtime
- **Regex:** stdlib `re` with precompiled named patterns
- **Diff parsing:** stdlib; hunk-header parsing for line-number mapping
- **Config:** JSON rules file (stdlib `json`), YAML optional via add-on
- **Tests:** pytest
- **Packaging:** pyproject.toml, console entry point

## Testing Strategy

- **Unit:** rule loading, each regex rule (matches/non-matches), entropy
  computation (threshold boundaries), diff hunk → file/line mapping.
- **Integration:** fixtures with representative diffs — AWS keys, PEM blocks,
  `password=` assignments, tokens, and known false positives (lockfiles,
  UUIDs, hashes) that must NOT be flagged.
- **CLI:** end-to-end via subprocess — exit codes, `--json` schema, `--diff -`
  stdin, `--commit`, and default working-tree mode on a temp git repo.
- **Done when:** all tests pass; a committed-secret fixture is detected across
  all three input modes; a benign fixture produces no findings.

## Phases

### Phase 1: Scaffolding + input adapters

- Step 1: pyproject.toml, package layout (`src/secret_finder/`), console entry
  point, empty pytest harness.
- Step 2: CLI argument surface: `--diff <path|->`, `--commit <hash>`,
  `--json`, `--rules <path>`, verbosity.
- Step 3: Input adapters that normalize all three modes into a common
  `AddedLine(file, line_number, content)` stream:
  - diff file / stdin → parse `+++` file headers and `@@ -a,b +c,d @@` hunks
  - commit → `git show --format= --unified=0 <hash>` piped to the same parser
  - working tree → `git diff --unified=0` (unstaged) + staged + untracked
- Step 4: Skip binary files; skip configured benign paths.

### Phase 2: Regex rule engine + config

- Step 1: Rule model: `id`, `name`, `regex`, `severity`, `reason`, optional
  `path_allowlist`/`entropy_floor`.
- Step 2: Built-in default rule set (AWS keys, secret keys, PEM private keys,
  Slack/GitHub/Generic tokens, JWT, `password`/`api_key`/`secret` assignments,
  connection strings with credentials).
- Step 3: Rules config loader (JSON): user file merges/overrides defaults.
- Step 4: Regex detector: run precompiled patterns over added lines, capture
  matched value + rule reason.

### Phase 3: Entropy detection

- Step 1: Shannon entropy function with length + charset awareness.
- Step 2: Candidate extraction (base64-like, long hex, high-char-class
  strings) from added lines.
- Step 3: Flag candidates above an entropy threshold NOT already matched by a
  regex rule; assign generic "high-entropy string" reason.
- Step 4: Tunable threshold + allowlist to suppress obvious false positives
  (UUIDs, sha hashes, lorem ipsum, package checksums).

### Phase 4: Reporting

- Step 1: Deduplicate findings per (file, line, rule).
- Step 2: Human text reporter (grouped by file, `file:line — reason`).
- Step 3: JSON reporter with stable schema (`{file, line, rule, severity,
  reason, secret_preview}`).
- Step 4: Exit-code policy: `0` none, `1` findings, `2` error.

### Phase 5: Tests + README

- Step 1: Unit + integration + CLI tests from Testing Strategy.
- Step 2: README — install, usage examples for all three modes, config file
  format, and a "Where it fails" section (false positives, entropy limits,
  secrets already in history, binary/unusual encodings).

## Risks/Edge cases

- **False positives (entropy on minified JS/base64 blobs):** mitigate with
  tuned threshold, length floor, path allowlist, and "regex wins" precedence.
- **Diff line-number mapping:** parse `@@ -old,count +new,count @@` carefully;
  handle zero-context hunks and file renames.
- **Untracked files not in `git diff`:** enumerate via `git ls-files
  --others --exclude-standard` in working-tree mode.
- **Large diffs:** stream line-by-line; never load the whole diff.
- **Secrets already in history:** out of scope; document in README.
- **Staged + unstaged overlap:** dedupe by (file, line, rule).
- **Config file errors:** fail loudly with exit `2` and a clear message.
