# Phase 4: SKILL.md Conversion & Legacy Retirement - Pattern Map

**Mapped:** 2026-07-24
**Files analyzed:** 3 pattern-bearing targets (1 new script, 2 split reference files); remaining phase files are edits/deletes with no code-pattern needed (see scope note)
**Analogs found:** 3 / 3

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `scripts/lint_skill_md.py` (new; suggested location `skills/owasp-security-audit/scripts/lint_skill_md.py`) | utility (CLI lint script) | file-I/O / batch (read files, emit pass/fail) | `skills/owasp-security-audit/scripts/quick_scan.py` | exact — same role (stdlib-only CLI tool under `scripts/`), same data flow (walk files, regex-check, print results) |
| `skills/owasp-security-audit/references/llm.md` (new, split from `llm-agentic.md`) | config/reference (static markdown doc) | transform (split existing content, no new content authored) | `skills/owasp-security-audit/references/masvs.md` and `top10.md` | exact — same role (single-standard reference file with edition-verification header) |
| `skills/owasp-security-audit/references/agentic.md` (new, split from `llm-agentic.md`) | config/reference (static markdown doc) | transform | `skills/owasp-security-audit/references/masvs.md` and `top10.md` | exact — same reasoning as above |
| `skills/owasp-security-audit/assets/examples/*.py`, `*.js`, `*.html`, `*.txt` (7 files, relabel only) | test/fixture (educational example code) | transform (in-place edit: header comment + category label) | Each file is its own analog — this phase edits the existing files directly, not create-from-template | n/a (edit-in-place; see scope note) |
| Both `SKILL.md` files (description edit only) | config | request-response (frontmatter drives activation) | n/a — editing existing authoritative files directly | n/a |
| `install.sh` (sentinel patch) | config/script | file-I/O (existence check) | n/a — minimal patch to existing file | n/a |

## Pattern Assignments

### `scripts/lint_skill_md.py` (utility, file-I/O/batch)

**Analog:** `skills/owasp-security-audit/scripts/quick_scan.py` (293 lines, read in full)

**Design-rule docstring pattern** (lines 1-21) — copy this shape almost verbatim, adjusted for lint's purpose:
```python
#!/usr/bin/env python3
"""Fast regex pre-scan for obvious OWASP patterns.

...

Design rules:
- Only patterns with low false-positive rate. If a pattern is ambiguous
  it lives in the reference files, not here.
- Every hit cites an OWASP category code so the reviewer can jump to
  the relevant reference.
- Output is JSON to stdout. Human-readable summary to stderr.
- Single-file dependency-free (stdlib only) so it runs anywhere Python
  3 is installed.

Usage:
    python quick_scan.py <path>
    python quick_scan.py <path> --format text
    python quick_scan.py <path> --include '*.py,*.js,*.yaml'
"""
from __future__ import annotations

import argparse
import ...
```
For `lint_skill_md.py`, restate the "stdlib only" rule explicitly in the docstring (RESEARCH.md Pitfall 5 confirms PyYAML is unavailable in the target environment) and state the purpose: "Verifies SKILL.md frontmatter against Anthropic's Agent Skills spec (FMT-01/02/05): byte-0 `---` start, name/description length + charset, no angle brackets, name matches parent directory."

**Import style** — no exotic imports; `quick_scan.py` uses only `argparse, fnmatch, json, os, re, sys, dataclasses, pathlib, typing` — all stdlib. `lint_skill_md.py` should follow the same constraint (only `re`, `sys`, `pathlib`, `argparse` needed — no `yaml`).

**Structured-result pattern** (lines 54-62) — `quick_scan.py` uses a `@dataclass` for findings so output stays structured and JSON-serializable via `asdict()`:
```python
@dataclass
class Finding:
    file: str
    line: int
    standard: str       # e.g. "Top10:A04"
    pattern: str        # short id like "hardcoded-openai-key"
    excerpt: str        # the matched line, trimmed
    note: str           # one-line human explanation
```
`lint_skill_md.py` should mirror this with a `LintResult` (or similar) dataclass: `file`, `check` (e.g. `"byte0-start"`, `"name-length"`, `"angle-brackets"`), `passed: bool`, `message: str`.

**File-walking pattern** (lines 183-203, `iter_files`) — `quick_scan.py` walks a root path, skipping known-noise dirs (`SKIP_DIRS`) and filtering by glob include list. For the lint script this is much simpler (only 2 known `SKILL.md` files, or a `Path.rglob("SKILL.md")` under `skills/`) — do not copy the full generality, just the "resolve path, iterate, handle missing gracefully" shape:
```python
def iter_files(root: Path, includes: Iterable[str]) -> Iterable[Path]:
    ...
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        ...
```

**Output-formatting pattern** (lines 231-289, `main()`) — `quick_scan.py`'s `main()` supports `--format json|text`, prints structured JSON to stdout for machine consumption and a human-readable summary to stderr/stdout for text mode, and returns a process exit code (`0` success). Copy this argparse + dual-format + exit-code shape:
```python
def main() -> int:
    parser = argparse.ArgumentParser(description="...")
    parser.add_argument("path", help="...")
    parser.add_argument("--format", choices=("json", "text"), default="json", ...)
    args = parser.parse_args()
    ...
    return 0

if __name__ == "__main__":
    sys.exit(main())
```
For the lint script, exit code should be non-zero (e.g. `1`) if any check fails, consistent with CI/gate usage implied by RESEARCH.md's Validation Architecture section (FMT-01/FMT-05 "script check" rows).

**Concrete lint-check bodies to embed** (already fully drafted in RESEARCH.md's Code Examples section — reuse verbatim, do not re-derive):
```python
# Byte-0 frontmatter start check
with open(path, 'rb') as f:
    first_bytes = f.read(3)
assert first_bytes == b'---', f"{path}: frontmatter does not start at byte 0"

# Frontmatter extraction + field checks (regex, no yaml import)
import re
content = open(path).read()
m = re.match(r'^---\n(.*?)\n---\n', content, re.DOTALL)
assert m, f"{path}: no frontmatter block found"
fm = m.group(1)
name = re.search(r'^name:\s*(.*)$', fm, re.MULTILINE).group(1).strip()
desc = re.search(r'^description:\s*(.*)$', fm, re.MULTILINE | re.DOTALL).group(1).strip()

assert len(name) <= 64, f"{path}: name exceeds 64 chars ({len(name)})"
assert re.fullmatch(r'[a-z0-9-]+', name), f"{path}: name has invalid characters"
assert 'claude' not in name and 'anthropic' not in name, f"{path}: name contains reserved word"
assert len(desc) <= 1024, f"{path}: description exceeds 1024 chars ({len(desc)})"
assert desc, f"{path}: description is empty"
assert '<' not in fm and '>' not in fm, f"{path}: frontmatter contains angle brackets"

# name must match parent directory (this repo's own D-07 convention)
parent_dir = path.split('/')[-2]
assert name == parent_dir, f"{path}: name '{name}' != parent dir '{parent_dir}'"
```
Wrap each `assert` as a soft check (append pass/fail `LintResult`, don't let one file's failure crash the whole run) rather than a hard `assert` — that's the one structural deviation from the snippet as literally written in RESEARCH.md.

**No error-handling/auth pattern needed** — this is a read-only, no-auth, no-network CLI tool; `quick_scan.py`'s only defensive pattern worth copying is the graceful `except OSError: return []` around file reads (lines 206-210), for the case a `SKILL.md` is unreadable.

---

### `skills/owasp-security-audit/references/llm.md` and `references/agentic.md` (reference/config, transform)

**Analog:** `skills/owasp-security-audit/references/top10.md` (header/intro shape) and `references/masvs.md` (single-standard structure)

**Header pattern to replicate** (from `top10.md` lines 1-17, and `masvs.md` lines 1-16):
```markdown
# OWASP <Standard Name>

<One-paragraph "load this reference when..." framing — when to reach for this file.>

**Source:** <official OWASP project name> — **<Edition> (<status>)**,
<https://...>. Retrieved <date>. <Edition-verification sentence citing how
currency was confirmed and against what source.>
```
Both `llm.md` and `agentic.md` should each get their own single-standard header in this shape, splitting off from `llm-agentic.md`'s current combined intro (lines 1-38) — the source content (edition verification prose, "Final not RC/draft" claim, warning about the invented `AG01–AG10` codes) already exists verbatim in `llm-agentic.md` lines 10-38 and "carries over verbatim" per D-05; just partition it: LLM-2025 material → `llm.md` header, Agentic-2026 material → `agentic.md` header.

**Body-section pattern** (from `llm-agentic.md` lines 50-533, e.g. `## LLM01:2025 — Prompt Injection` at line 52, `## ASI01 — Agent Goal Hijack` at line 328) — each per-item section already follows a consistent template that should be preserved unchanged across the split:
```markdown
## LLM0X:2025 — <Name>

Source: <url>

<1-3 sentence description>

**Detection signals**
- ...

**Mitigations**
```python
...
```
- ...

---
```
`llm.md` = current "Part 1: LLM01-LLM10 (2025)" section (`llm-agentic.md` lines 50-317) verbatim, with its own new file-level header.
`agentic.md` = current "Part 2: ASI01-ASI10 (Agentic, 2026)" section (`llm-agentic.md` lines 320-534) verbatim, with its own new file-level header, **plus** the `AG## → real OWASP item` mapping table (lines 536-555) — this table cross-references both LLM and ASI codes, so it belongs in `agentic.md` (its primary payload is repointing the old Agentic-only `AG` taxonomy) but should note it also resolves to LLM-side codes for entries like AG03/AG04/AG05/AG07/AG10.

**Edition-verification convention** (shared across all reference files, e.g. `masvs.md` lines 11-15, `top10.md` lines 8-17) — every split file must carry its own "Edition verification: ... confirmed current ... Source: ... Retrieved <date>" sentence; do not drop this when splitting, and do not re-verify — D-05 states "content of the edition notes carries over verbatim (Phase 3 already verified them)."

**Cross-reference repoint required** (not a pattern to copy, but a mechanical consequence of the split — flagging per RESEARCH.md): `skills/owasp-security-audit/SKILL.md`'s routing table currently points at `llm-agentic.md` and must be updated to reference both `llm.md` and `agentic.md` after the split.

---

### Example-file relabel (7 files under `assets/examples/`)

No new-file analog needed — this is an in-place edit of existing files using their own existing convention. Two concrete conventions to preserve exactly as found:

**Header cross-reference line convention** (present in every example file, e.g. `security-misconfiguration.py` line 2, `prompt-injection.txt` line 2):
```python
# OWASP Top 10 - A05: Security Misconfiguration
# For detailed guidance, see: owasp-comprehensive-security-skills.md#section-1-owasp-top-10-2021
```
Must become (per RESEARCH.md Pitfall 2, D-02, D-04):
```python
# OWASP Top 10 - A02: Security Misconfiguration
# For detailed guidance, see: references/top10.md
```
(repoint target varies by file — `top10.md` for web-app examples, future `agentic.md` for `prompt-injection.txt`'s ASI-side content, `llm.md` for any LLM-only labeled section within it per the AG-code mapping table).

**VULNERABLE/SECURE marker convention** (already established, do not alter — e.g. `security-misconfiguration.py` line 12, `prompt-injection.txt` lines 10/37):
```python
# ===== VULNERABLE: Flask Debug Mode in Production =====
```
```
### VULNERABLE: Direct Prompt Injection
### SECURE: Parameter-based separation (no string concatenation)
```
Keep these markers verbatim; only the category-ID label (line 1 of each file) and the cross-reference line (line 2) and, for `prompt-injection.txt`, each individual `AG0X` sub-heading (lines like `## AG01: Prompt Injection...`) change.

**Per-file AG-code remediation map** (do not blanket-replace — see RESEARCH.md Pitfall 3, verified against `llm-agentic.md`'s own mapping table lines 540-551):
```
AG01: Prompt Injection - Direct and Indirect Attacks   -> LLM01:2025 Prompt Injection
AG03: Insecure Output Handling - Data Leakage          -> LLM05:2025 Improper Output Handling
AG05: Denial of Service - Token Exhaustion             -> LLM10:2025 Unbounded Consumption
AG06: Unauthorized Plugin/Tool Access                  -> LLM06:2025 Excessive Agency (cross-ref ASI02/ASI03)
```
Also fix `prompt-injection.txt` line 5's stale `Status: Preview/Draft` to reflect Agentic 2026's verified **Final** status.

**2025 category ID target table** (for the other 6 example files, from `top10.md` lines 27-39 — read directly, not re-derived):
```
A01 Broken Access Control (SSRF now folded in)
A02 Security Misconfiguration      (was old-A05)
A03 Software Supply Chain Failures (new; no example exists — out of scope, not authored)
A04 Cryptographic Failures         (was old-A02)
A05 Injection                     (was old-A03)
A09 Security Logging & Alerting Failures
```

---

## Shared Patterns

### Stdlib-only tooling constraint
**Source:** `skills/owasp-security-audit/scripts/quick_scan.py` docstring, line 14-15: *"Single-file dependency-free (stdlib only) so it runs anywhere Python 3 is installed."*
**Apply to:** `scripts/lint_skill_md.py` — this is a hard project constraint (README states "no heavy runtime dependencies") and PyYAML is confirmed absent from the target environment (RESEARCH.md Pitfall 5). Use only `re`/`pathlib`/`argparse`/`sys`/`dataclasses`.

### Reference-file header shape (edition-note + "load this when" framing)
**Source:** `skills/owasp-security-audit/references/top10.md` lines 1-17, `references/masvs.md` lines 1-16
**Apply to:** `llm.md` and `agentic.md` — both new split files must open with a one-paragraph usage framing + a `**Source:**`/`**Edition verification:**` block, matching every other file in `references/`.

### VULNERABLE/SECURE comment-marker convention
**Source:** every file under `skills/owasp-security-audit/assets/examples/` (verified in `security-misconfiguration.py`, `prompt-injection.txt`)
**Apply to:** all 7 relabeled example files — do not alter this marker style during the relabel pass, only the category-ID line and cross-reference line.

### Header cross-reference-line convention (must be repointed, not removed)
**Source:** line 2 of every example file (`# For detailed guidance, see: owasp-comprehensive-security-skills.md#section-N-...`)
**Apply to:** all 7 example files — since D-02 deletes the target of this line, D-04's relabel pass must repoint each to its correct surviving reference file (`references/top10.md`, `references/llm.md`, or `references/agentic.md`) rather than deleting the line outright (RESEARCH.md Pitfall 2).

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `install.sh` sentinel patch | config/script | file-I/O (existence check) | Minimal surgical patch to an existing file (change one `[ -f ... ]` gate + trim `required_files` array) — no new pattern to copy, just edit the existing bash logic in place per RESEARCH.md Pitfall 1's recommended fix (`[ -d "skills/owasp-security-audit" ]` or `[ -f ".claude-plugin/plugin.json" ]`) |
| Two `SKILL.md` description edits (D-06) | config | request-response | Direct text edit to existing authoritative frontmatter field; no structural/code pattern involved, just prose alignment with `asvs.md`/SCP-doc reframes already verified in Phase 3 |
| Two SCP human-facing docs refresh (D-03) | documentation | n/a | Direct prose edit (reword "Quick Reference Guide" framing to "living-source"/Cheat-Cheat-Series framing) — no code pattern; planner should pull the exact reframe wording from Phase 3's `03-CONTEXT.md`/`scp-checklist.md` if a template phrase is wanted |
| Two file deletes (`owasp-css.instructions.md`, `owasp-comprehensive-security-skills.md`, `owasp-security-audit.md`) | n/a | n/a | Pure deletes — no pattern needed |

## Metadata

**Analog search scope:** `skills/owasp-security-audit/scripts/`, `skills/owasp-security-audit/references/`, `skills/owasp-security-audit/assets/examples/`
**Files scanned:** `quick_scan.py` (full, 293 lines), `llm-agentic.md` (full, 555 lines), `top10.md` (lines 1-40), `masvs.md` (lines 1-60), `security-misconfiguration.py` (lines 1-20), `prompt-injection.txt` (lines 1-40)
**Pattern extraction date:** 2026-07-24
