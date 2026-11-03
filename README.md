# secret-finder

A zero-dependency Python CLI that scans git changes for leaked passwords, keys, and other secrets before they land in a branch. It normalizes three input modes (working tree, git patch file/stdin, single commit) into a stream of added lines, runs named regex rules first and Shannon-entropy detection second, and reports each finding with file, line, severity, rule, and a short reason — as stable JSON by default, or human-readable text with `--text` — with CI-friendly exit codes.

## Install

Requires **Python 3.10+**. Zero runtime dependencies — standard library only.

```sh
pip install -e .
```

From the repo root. This installs the `secret-finder` command (equivalently runnable as `python -m secret_finder`).

## Usage

Scan the current uncommitted working tree (unstaged + staged + untracked changes). With no output flag, stdout is JSON — the default output format:

```sh
secret-finder
```

Human-readable output on stdout instead:

```sh
secret-finder --text
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

Load and override rules from a JSON config file:

```sh
secret-finder --rules .secret-finder.json
```

`--text` and `--json` together is a usage error (exit `2`). `--quiet` suppresses the text-mode stderr summary only (e.g. `secret-finder: N finding(s)`); it does not change stdout and is a no-op for JSON output, which has no stderr summary on success.

## Output

JSON is the default stdout format: JSON-by-default makes piping, `jq`, and CI the zero-flag path, and humans opt in with `--text`. With no output flag (or with `--json`), stdout carries only the JSON document (pretty-printed, with a trailing newline) and stderr stays silent on success; errors go to stderr with exit `2`.

`--text` writes human-readable output on stdout, grouping findings by file under a bare `<file>:` header, one finding per line as `  <line>: [<severity>] <rule> — <reason>`:

```
src/config.py:
  12: [high] aws-access-key — AWS access key ID
```

In `--text` mode a summary line (e.g. `secret-finder: 1 finding(s)`) goes to stderr unless `--quiet` is passed. `--text` and `--json` together is a usage error (exit `2`).

Findings are presented highest-confidence first: severity (`high` → `medium` → `low`), then file, then line. JSON applies that as a flat sort; the human format orders file groups by their best severity, and lines within a group by severity then line.

JSON output (the default; `--json` is a compatibility no-op) follows a fixed schema:

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
- `secret_preview` is a masked preview of the credential VALUE for assignment rules (named `(?P<secret>…)` capture — e.g. `jobhunter_pass = "hallelujah"` previews the password, not the variable name), or the masked full match for token-style rules; first 4 characters + `*`, fully masked (`*` only) when ≤ 8 characters; the raw secret is never printed.
- `findings` are ordered by severity (high → medium → low), then file, then line.

## Rules & config

Detection precedence: **regex rules win**. The entropy pass is a secondary signal for values associated with credential-like names: it flags a candidate only when the same line binds it to a credential-like name in assignment position, and only for candidates not already matched by a rule, so known shapes always get a precise reason.

### Built-in rule categories

- AWS access key IDs and secret keys
- PEM private key blocks
- GitHub and Slack tokens
- JWTs
- `password-assignment`: keywords `password` / `passwd` / `pass` / `pwd` followed by `[:=]` and a value of ≥ 4 chars (quotes optional, so `.env`/yaml-style `password = "..."` or `password = ...` both match) — `user_pass = "test"` flags
- `api-key-assignment`: keywords `api_key` / `apikey` / `secret` / `access_key_id` / `access_key` / `access_token` / `token` / `client_secret` followed by `[:=]` and a value of ≥ 8 chars (quotes optional)
- Assignment keywords are prefix-boundary `(?:^|[^A-Za-z0-9])`: `jobhunter_pass = "…"` flags (prefix `_`), while `compass = "north"` does not (`pass` embedded in a word)
- Connection strings with embedded credentials
- `aws-credential-var` heuristic: `AWS_ACCESS_KEY=` / `AWS_SECRET_ACCESS_KEY=` / `AWS_ACCESS_KEY_ID=` with a value ≥ 16 chars (format NOT verified — see Confidence tiers). `AWS_ACCESS_KEY=<16+>` now matches `api-key-assignment` (high) instead, which suppresses this Tier-3 heuristic on that line; the heuristic fires only where no primary assignment rule matches the line, e.g. `aws_secret_key=<16+>` or `aws_key=<16+>`

Severity notes: `password-assignment` is `high`; `api-key-assignment` severity is now **`high`** (raised from `medium`). JWT stays `medium`.

### Confidence tiers

Findings fall into three tiers, which drive both severity and output ordering (highest-confidence first):

- **Tier 1 — high-confidence assignments.** `password-assignment`: `password` / `passwd` / `pass` / `pwd` with a value ≥ 4 chars; `api-key-assignment`: `api_key` / `apikey` / `secret` / `access_key_id` / `access_key` / `access_token` / `token` / `client_secret` with a value ≥ 8 chars (quotes optional, works in `.env`/yaml style). Both rules severity `high`.
- **Tier 2 — recognisable credentials.** AWS access key IDs (`AKIA…`), AWS secret assignments, PEM private-key headers, GitHub/Slack tokens, connection strings — all severity `high`. JWT stays `medium` (well-defined but common in fixtures).
- **Tier 3 — potentially random credentials / heuristics.** Severity `medium`, explicitly a **secondary heuristic, not proof**. Includes the `aws-credential-var` rule (value ≥ 16 chars, format NOT verified) and entropy findings (rule `entropy`, "possible secret" — credential-context gated, see Entropy defaults). A Tier 3 rule finding is suppressed on any line where a Tier 1/2 regex rule already matched, so a primary rule's precise reason wins — e.g. `AWS_ACCESS_KEY=<16+>` reports `api-key-assignment` (high), not `aws-credential-var`.

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

Rule fields: `id`, `name`, `regex`, `severity`, `reason`, plus optional `path_allowlist` (globs to skip) and `entropy_floor` (optional secondary gate). A named `(?P<secret>…)` group inside a custom rule's `regex` controls which part becomes `secret_preview` (rules without it mask the full match).

### Merge semantics

- Built-in defaults are always loaded first.
- User `rules`: a rule with an **existing `id` overrides** that default (whole-rule replace); a **new `id` appends**.
- `entropy`: user keys **override default keys individually**.
- `ignore_paths`: user list **appends** to the defaults.
- Invalid JSON, unknown types, or a bad regex → exit `2` with an error naming the offending rule.

### Entropy defaults

- `threshold = 4.5` (raw Shannon entropy in bits per character), `min_length = 16` (a length floor); both tunable via the `entropy` block.
- Default allowlist suppresses high-entropy-but-benign strings: sha1 (`[0-9a-f]{40}`), sha256 (`[0-9a-f]{64}`), and UUIDs.
- The entropy pass is a **secondary signal for values associated with credential-like names**. A candidate is flagged only when raw Shannon entropy `H ≥ threshold` (4.5 bits/char), length ≥ `min_length`, not on the allowlist, not already matched by a regex rule, **and** the same line matches the credential-context pattern — a credential-like name in assignment position (the optional closing quote supports JSON keys):

  ```
  (?:^|[^A-Za-z0-9])(?:password|passwd|pass|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)['\"]?\s*[:=]
  ```

  Context-free flagging of any ≥16-char high-entropy string anywhere is deliberately removed (it FP'd IDE workspace.xml `id=`/`value=` attributes). A 16-char string can reach at most `H = 4.0`, so `min_length` alone never satisfies the gate.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings |
| `1` | Scan completed, findings present |
| `2` | Usage error, config parse error, commit not found, git failure, missing file |

Stderr carries diagnostics; stdout carries only findings — JSON by default (and with `--json`), human-readable text only with `--text` — so default output stays parseable.

## Where it fails

- **Entropy false positives.** Context-free entropy flagging (any ≥16-char high-entropy string anywhere) is gone by design — it FP'd IDE workspace.xml `id=`/`value=` attributes, which no longer flag on entropy alone. Keyword rules still scan XML, so `password="..."` attributes still flag via `password-assignment` and don't need `ignore_paths`. What remains can still FP when dense data shares a line with a credential-like name: minified JavaScript or base64 blobs next to `token=`/`secret=`-style names. Tune `entropy.threshold`, raise `min_length`, add paths to `ignore_paths`, or extend the entropy `allowlist`. The entropy pass does not consult per-rule `path_allowlist`.
- **Heuristic rules flag placeholders too.** Rules only check shape, not validity: `AWS_ACCESS_KEY=your_access_key_here` (≥ 16 chars) is reported as `api-key-assignment` (high) even though it is a placeholder, and where no primary rule matches the line, `aws-credential-var` fires on any ≥ 16-char value (e.g. `aws_secret_key=<placeholder>`). These are secondary/shape-only signals — verify before treating them as real secrets.
- **Entropy needs long, high-entropy values bound to credential-like names.** Candidates must be ≥ 16 chars with raw entropy `H ≥ 4.5` on a line matching the credential-context pattern (a credential-like name in assignment position). Candidate extraction splits on `=`, so a `.env` line's `NAME=value` scores the value alone (the name no longer dilutes the score) — but low-entropy values still won't fire entropy.
- **Generated UUIDs and hashes.** Long hex or random-looking strings (checksums, build IDs) are high-entropy by nature. The default allowlist covers sha1/sha256/UUID shapes, but repo-specific hashes may still need allowlisting.
- **Secrets already in history are not found.** Only new/changed added lines are scanned — this is not a full-history audit. Use `--commit` to check one commit, or diff against an older ref, but pre-existing secrets in untouched lines are out of scope.
- **Binary and unusual encodings are skipped.** Binary files are detected and skipped entirely; secrets in non-UTF-8 or exotic encodings may not be tokenized correctly.
- **Novel secret shapes need a rule.** Regex cannot catch a token format it has never seen; entropy is the only fallback, and only for long, high-entropy values whose lines carry a credential-like name in assignment position. Add a rule via `--rules` for new shapes.
- **Entropy threshold may need per-repo tuning.** A threshold that works on one codebase can be too aggressive or too lax on another (e.g. heavy crypto, generated code).
- **Lockfiles and checksum-heavy files** are common false-positive sources. Extend `ignore_paths` with your lockfiles (`*.lock`, `go.sum`, `package-lock.json`, etc.).

## Development

Run the test suite:

```sh
python -m pytest
```

Project layout: `src/secret_finder/` (CLI, input adapters, rules, entropy, detectors, reporters), `tests/` for unit, integration, and CLI tests, with `design/`, `plans/`, and `requirements/` documenting the spec.

`AI_PROMPTS.txt` is the transcript of this project's AI-assisted build — every prompt and question that shaped it, in chronological order.
