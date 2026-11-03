# secret-finder

A zero-dependency Python CLI that scans git changes for leaked passwords, keys, and other secrets before they land in a branch. It normalizes three input modes (working tree, git patch file/stdin, single commit) into a stream of added lines, runs named regex rules first and Shannon-entropy detection second, and reports findings as `file:line` with a short reason — as human-readable text or stable JSON, with CI-friendly exit codes.

## Install

Requires **Python 3.10+**. Zero runtime dependencies — standard library only.

```sh
pip install -e .
```

From the repo root. This installs the `secret-finder` command (equivalently runnable as `python -m secret_finder`).

## Usage

Scan the current uncommitted working tree (unstaged + staged + untracked changes):

```sh
secret-finder
```

Scan a git patch file:

```sh
secret-finder --diff changes.patch
```

Scan a diff piped from stdin:

```sh
git diff | secret-finder --diff -
```

Scan the diff introduced by a specific commit:

```sh
secret-finder --commit a1b2c3d
```

Machine-readable JSON output on stdout:

```sh
secret-finder --json
```

Load and override rules from a JSON config file:

```sh
secret-finder --rules .secret-finder.json
```

`--quiet` suppresses the non-JSON human summary on stderr (JSON output itself is unaffected).

## Output

Human-readable output (default) groups findings by file as `file:line — reason`. With `--json`, stdout carries only the JSON document; diagnostics go to stderr.

JSON output (`--json`) follows a fixed schema:

```json
{
  "findings": [
    {
      "file": "src/config.py",
      "line": 12,
      "rule": "aws-access-key",
      "severity": "high",
      "reason": "AWS access key ID",
      "secret_preview": "AKIA****************"
    }
  ],
  "summary": { "total": 1, "high": 1, "medium": 0, "low": 0 }
}
```

- `rule` is the matched rule id, or `"entropy"` for entropy-only findings.
- `severity` is one of `high`, `medium`, `low`.
- `secret_preview` is always masked (first 4 characters + `*`); the raw secret is never printed.

## Rules & config

Detection precedence: **regex rules win**. The entropy pass only flags novel high-entropy strings that were not already matched by a rule, so known shapes always get a precise reason.

### Built-in rule categories

- AWS access key IDs and secret keys
- PEM private key blocks
- GitHub and Slack tokens
- JWTs
- `password` / `api_key` / `secret` / `token` assignments
- Connection strings with embedded credentials

### Config file format

Pass a JSON file with `--rules <path>`:

```json
{
  "rules": [
    {
      "id": "aws-access-key",
      "name": "AWS Access Key ID",
      "regex": "AKIA[0-9A-Z]{16}",
      "severity": "high",
      "reason": "AWS access key ID",
      "path_allowlist": ["*.lock", "go.sum"],
      "entropy_floor": 3.0
    }
  ],
  "entropy": {
    "threshold": 4.5,
    "min_length": 16,
    "allowlist": ["[0-9a-f]{40}", "[0-9a-f]{64}"]
  },
  "ignore_paths": ["vendor/**", "*.lock", "go.sum", "package-lock.json"]
}
```

Rule fields: `id`, `name`, `regex`, `severity`, `reason`, plus optional `path_allowlist` (globs to skip) and `entropy_floor` (optional secondary gate).

### Merge semantics

- Built-in defaults are always loaded first.
- User `rules`: a rule with an **existing `id` overrides** that default (whole-rule replace); a **new `id` appends**.
- `entropy`: user keys **override default keys individually**.
- `ignore_paths`: user list **appends** to the defaults.
- Invalid JSON, unknown types, or a bad regex → exit `2` with an error naming the offending rule.

### Entropy defaults

- `threshold = 4.5` (raw Shannon entropy in bits per character), `min_length = 16` (a length floor); both tunable via the `entropy` block.
- Default allowlist suppresses high-entropy-but-benign strings: sha1 (`[0-9a-f]{40}`), sha256 (`[0-9a-f]{64}`), and UUIDs.
- A candidate is flagged only when raw Shannon entropy `H ≥ threshold` (4.5 bits/char), length ≥ `min_length`, not on the allowlist, and not already matched by a regex rule. A 16-char string can reach at most `H = 4.0`, so `min_length` alone never satisfies the gate.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings |
| `1` | Scan completed, findings present |
| `2` | Usage error, config parse error, commit not found, git failure, missing file |

Stderr carries diagnostics; stdout carries only findings, so `--json` output stays parseable.

## Where it fails

- **Entropy false positives.** Minified JavaScript, base64 blobs, and other dense data can trip the entropy pass. Tune `entropy.threshold`, raise `min_length`, add paths to `ignore_paths`, or extend the entropy `allowlist`. The entropy pass does not consult per-rule `path_allowlist`.
- **Generated UUIDs and hashes.** Long hex or random-looking strings (checksums, build IDs) are high-entropy by nature. The default allowlist covers sha1/sha256/UUID shapes, but repo-specific hashes may still need allowlisting.
- **Secrets already in history are not found.** Only new/changed added lines are scanned — this is not a full-history audit. Use `--commit` to check one commit, or diff against an older ref, but pre-existing secrets in untouched lines are out of scope.
- **Binary and unusual encodings are skipped.** Binary files are detected and skipped entirely; secrets in non-UTF-8 or exotic encodings may not be tokenized correctly.
- **Novel secret shapes need a rule.** Regex cannot catch a token format it has never seen; entropy is the only fallback, and only for long, high-entropy candidates. Add a rule via `--rules` for new shapes.
- **Entropy threshold may need per-repo tuning.** A threshold that works on one codebase can be too aggressive or too lax on another (e.g. heavy crypto, generated code).
- **Lockfiles and checksum-heavy files** are common false-positive sources. Extend `ignore_paths` with your lockfiles (`*.lock`, `go.sum`, `package-lock.json`, etc.).

## Development

Run the test suite:

```sh
python -m pytest
```

Project layout: `src/secret_finder/` (CLI, input adapters, rules, entropy, detectors, reporters), `tests/` for unit, integration, and CLI tests, with `design/`, `plans/`, and `requirements/` documenting the spec.
