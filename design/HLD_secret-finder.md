# HLD: secret-finder

## 1. Architecture Overview

A thin CLI shell feeds three input adapters into a shared unified-diff parser,
producing a normalized stream of added lines. A two-stage detection pipeline
(regex rules, then entropy) tags findings, which are deduplicated and rendered
by a text or JSON reporter.

```
                    ┌───────────────────────────────────────────────┐
                    │                    cli.py                    │
                    │   argparse: --diff | --commit | (default)     │
                    │            --json --rules --quiet            │
                    └───────────────┬───────────────────────────────┘
                                    │ dispatch
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────┐          ┌────────────────┐          ┌─────────────────┐
│  DiffAdapter  │          │ CommitAdapter  │          │WorkingTreeAdapter│
│ (file | stdin)│          │ (git show)     │          │ (diff+cached+   │
└───────┬───────┘          └───────┬────────┘          │  untracked)     │
        │                          │                   └───────┬─────────┘
        └──────────────┬───────────┘                           │
                       ▼                                       ▼
            ┌────────────────────────────────────────────────────┐
            │        unified_diff parser (shared)                │
            │   `+++ b/` file · `@@ -a,b +c,d @@` line mapping    │
            │   emits AddedLine(file, line, content)              │
            └───────────────────────┬────────────────────────────┘
                                    │ Iterator[AddedLine]
                       ┌────────────▼─────────────┐
                       │      DetectionPipeline    │
                       │  1. RegexDetector (rules) │
                       │  2. EntropyDetector       │
                       └────────────┬─────────────┘
                                    │ Iterator[Finding]
                       ┌────────────▼─────────────┐
                       │  dedupe (file, line, rule)│
                       └────────────┬─────────────┘
                     ┌──────────────┼──────────────┐
                     ▼                             ▼
              ┌─────────────┐               ┌─────────────┐
              │ TextReporter│               │ JsonReporter│
              └─────────────┘               └─────────────┘
                       exit 0 (none) | 1 (findings) | 2 (error)
```

## 2. Modules

| Module | Responsibility |
|--------|----------------|
| `cli.py` | argparse surface, mode dispatch, exit-code mapping, top-level `main()` |
| `models.py` | `AddedLine`, `Finding`, `Rule`, severity constants |
| `inputs.py` | `InputAdapter` protocol, three adapters, shared unified-diff parser, binary/path filtering |
| `rules.py` | built-in rule registry, JSON config loader, merge logic |
| `entropy.py` | Shannon entropy, candidate extraction, allowlist |
| `detectors.py` | `RegexDetector`, `EntropyDetector`, `DetectionPipeline` |
| `report.py` | `TextReporter`, `JsonReporter` |
| `__main__.py` | `python -m secret_finder` shim |

Layout: `src/secret_finder/`, console entry point `secret-finder = secret_finder.cli:main`.

## 3. Data Flow by Input Mode

| Mode | Source | Path to AddedLine |
|------|--------|-------------------|
| `--diff path` | open file, iterate lines | `DiffAdapter(stream)` → parser |
| `--diff -` | `sys.stdin` | same |
| `--commit HASH` | `git show --format= --unified=0 HASH` | subprocess stdout → `DiffAdapter` |
| default | `git diff --unified=0` + `git diff --cached --unified=0` + `git ls-files --others --exclude-standard` | first two via `DiffAdapter`; untracked files read whole as all-added |

## 4. Core Interfaces

```python
# models.py
@dataclass
class AddedLine:
    file: str        # repo-relative path
    line: int        # 1-based line in the new file
    content: str     # added text, no trailing newline

@dataclass
class Finding:
    file: str
    line: int
    rule: str        # rule id, or "entropy"
    severity: str    # "high" | "medium" | "low"
    reason: str
    secret_preview: str   # masked snippet, e.g. "AKIA****************"

@dataclass
class Rule:
    id: str
    name: str
    regex: str                 # compiled at load time
    severity: str = "high"
    reason: str = ""
    path_allowlist: list[str] = field(default_factory=list)  # globs to skip
    entropy_floor: float | None = None   # optional secondary gate
```

```python
# inputs.py
class InputAdapter(Protocol):
    def added_lines(self) -> Iterator[AddedLine]: ...

class DiffAdapter:      # unified diff text (file or stdin)
    def __init__(self, source: Iterable[str], ignore_paths: list[str]): ...

class CommitAdapter:    # runs `git show`
    def __init__(self, hash: str, ignore_paths: list[str]): ...

class WorkingTreeAdapter:  # diff + cached + untracked
    def __init__(self, repo_root: str, ignore_paths: list[str]): ...
```

```python
# detectors.py
class RegexDetector:
    def __init__(self, rules: list[Rule]): ...        # precompiled
    def scan(self, line: AddedLine) -> Iterator[Finding]: ...

class EntropyDetector:
    def __init__(self, threshold: float, min_length: int,
                 allowlist: list[re.Pattern]): ...
    def scan(self, line: AddedLine) -> Iterator[Finding]: ...

class DetectionPipeline:
    def run(self, lines: Iterator[AddedLine]) -> Iterator[Finding]: ...
```

```python
# report.py
class Reporter(Protocol):
    def render(self, findings: list[Finding]) -> str: ...

class TextReporter: ...   # grouped by file, "file:line — reason"
class JsonReporter: ...   # stable schema (section 6)
```

## 5. Detection Pipeline & Precedence

1. **Regex pass** over each `AddedLine`: any matching rule yields a `Finding`
   with that rule's `id`, `severity`, `reason`. Skips lines whose path matches
   a rule `path_allowlist` or global `ignore_paths`.
2. **Heuristic suppression (Tier 3)**: a finding from a secondary heuristic
   rule (e.g. `aws-credential-var`) is dropped when any primary (Tier 1/2)
   regex rule already matched the same line, so the primary rule's precise
   reason wins. Tier 3 findings are "secondary heuristic, not proof".
3. **Entropy pass** runs only on candidate substrings **not already matched**
   by any regex rule in step 1, and only when the same line matches the
   credential-context pattern — a credential-like name in assignment
   position (optional closing quote supports JSON keys):

   ```
   (?:^|[^A-Za-z0-9])(?:password|passwd|pass|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)['\"]?\s*[:=]
   ```

   Entropy is a secondary signal for values associated with credential-like
   names; context-free high-entropy strings are not flagged. This is the
   "regex wins" rule: known shapes always get a precise reason; entropy only
   catches novel secrets bound to a credential-like name. This exclusion is
   unchanged — entropy suppression is unaffected by the Tier 3
   heuristic-suppression step.
4. **Dedupe**: findings keyed by `(file, line, rule)`; first occurrence wins
   (handles staged+unstaged overlap).

## 6. JSON Output Schema

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

`secret_preview` is always masked (first 4 chars + `*`), never the raw secret.
`--quiet` still emits JSON but suppresses the human summary on stderr.
`findings` are ordered by severity (high → medium → low), then file, then
line — highest-confidence first.

## 7. Config File Schema & Merge Semantics

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

Merge rules:
- Built-in defaults always loaded first.
- User `rules`: a rule with an existing `id` **overrides** that default
  (whole-rule replace); a new `id` **appends**.
- `entropy` block: user keys override default keys individually.
- `ignore_paths`: user list **appends** to defaults.
- Invalid JSON, unknown types, or bad regex in config → exit `2` with a clear
  error naming the offending rule.

## 8. Entropy Algorithm

- **Shannon entropy**: `H = -Σ p(c) · log2 p(c)` over the character
  distribution of a candidate string.
- **Candidate extraction** per line: tokenize; collect substrings matching
  base64-ish `[A-Za-z0-9+/=_-]{min_length,}` and hex `[0-9a-fA-F]{min_length,}`;
  strip surrounding quotes/whitespace/`=` padding.
- **Flag** a candidate when the **raw** Shannon entropy `H` (bits per
  character, unnormalized) satisfies `H >= threshold` **and**
  `len >= min_length` **and** it is not matched by any allowlist pattern
  **and** it was not consumed by the regex pass **and** the same line
  matches the credential-context pattern (a credential-like name in
  assignment position; optional closing quote supports JSON keys):

  ```
  (?:^|[^A-Za-z0-9])(?:password|passwd|pass|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)['\"]?\s*[:=]
  ```

  High-entropy strings without that context are deliberately not flagged —
  the context-free behavior FP'd IDE workspace.xml `id=`/`value=`
  attributes; keyword rules still flag `password="..."` attributes in XML.
  A per-rule `entropy_floor` (example `3.0`) is compared against the same
  raw `H`.
- **Charset normalization**: dividing `H` by `log2(distinct chars)` is an
  exported utility only — it is **not** part of the gating decision.
- **Allowlist** (sha1 `[0-9a-f]{40}`, sha256 `[0-9a-f]{64}`, UUID) suppresses
  high-entropy-but-benign strings (hashes, checksums).
- Defaults: `threshold = 4.5` (bits/char), `min_length = 16`; both tunable
  via config. `min_length` is a length floor: a 16-char string maxes out at
  `H = 4.0`, below `4.5`, so length alone never fires the gate.

## 9. Edge Cases → Mitigations

| Edge case | Mitigation |
|-----------|------------|
| Diff line-number mapping | Parse `@@ -a,b +c,d @@`; advance new-file counter only on `+`/context lines; handle zero-context `@@ -a,0 +c,1 @@` |
| Renames / new / deleted files | `+++ b/path` sets file; `+++ /dev/null` (deleted) skipped; new files tracked normally |
| Binary files | Detect `Binary files ... differ` / `GIT binary patch`; skip entire file |
| Untracked files (not in `git diff`) | `git ls-files --others --exclude-standard`; read directly, every line is "added" |
| Large diffs | Generator-based streaming throughout; no full materialization |
| Entropy false positives | threshold + min_length + allowlist + credential-context gate + ignore_paths + regex precedence |
| Staged+unstaged overlap | dedupe on `(file, line, rule)` |
| Config file errors | fail fast with exit `2`, message names the bad rule/key |
| `git` not installed / not a repo | catch subprocess failure → exit `2` with actionable message |

## 10. Error Handling & Exit Codes

| Code | Meaning |
|------|---------|
| `0` | scan completed, no findings |
| `1` | scan completed, findings present |
| `2` | usage error, config parse error, commit not found, git failure, missing file |

Stderr carries diagnostics; stdout carries only findings (so `--json` output
stays parseable).
