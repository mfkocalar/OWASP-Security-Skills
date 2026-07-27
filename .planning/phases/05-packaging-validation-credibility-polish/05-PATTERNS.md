# Phase 5: Packaging Validation & Credibility Polish - Pattern Map

**Mapped:** 2026-07-27
**Files analyzed:** 12 (create/modify/delete)
**Analogs found:** 9 / 12 (3 have no close in-repo analog — new artifact types for this repo)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `LICENSE` (new) | config/legal | file-I/O (static text) | none in repo | no-analog (use `plugin.json` `license`/`author` fields as the *fact source*, not a code analog) |
| `scripts/check_version_drift.py` (new) | utility (lint/config-check) | batch / transform | `scripts/lint_skill_md.py` | exact (same role, same stdlib-only CLI-lint data flow) |
| Checkpoint-1 capture wrapper (new — shell or stdlib py) | utility (CLI orchestration + capture) | request-response (invokes `claude` CLI, tees output) | `install.sh` (shell, OS-detect + step sequencing) + `scripts/lint_skill_md.py` (CLI arg/output-format convention) | role-match (hybrid analog: process structure from `install.sh`, stdlib-only output-formatting from `lint_skill_md.py`) |
| `README.md` (modify) | config/docs | request-response (human-read reference) | itself (in-place refresh) | exact — edit target is also its own analog for tone/structure to preserve |
| `CONTRIBUTING.md` (modify) | config/docs | request-response | itself + salvage source `DEPLOYMENT.md`/`TESTING.md` | exact (self) + role-match (salvage sources) |
| `.claude-plugin/plugin.json` (modify) | config | CRUD (field bump) | itself | exact |
| `.claude-plugin/marketplace.json` (modify) | config | CRUD (field add) | itself | exact |
| `skills/owasp-security-audit/assets/examples/k8s-rbac.yaml` (modify) | test/example asset | transform (literal replace) | `cryptographic-failures.js` line 210 (`API_KEY=sk-your-api-key-here` — the one already-good exemplar) | exact — this is the convention source, not a separate analog category |
| `skills/owasp-security-audit/assets/examples/cryptographic-failures.js` (modify) | test/example asset | transform (literal replace) | same file, line 210 (internal consistency exemplar) | exact |
| `skills/owasp-security-audit/assets/examples/prompt-injection.txt` (modify) | test/example asset | transform (literal replace) | `cryptographic-failures.js` line 210 | role-match |
| `skills/secure-coding-practices/assets/examples/vulnerable-examples.py` (modify) | test/example asset | transform (literal replace) | `cryptographic-failures.js` line 210 | role-match |
| `skills/secure-coding-practices/assets/examples/vulnerable-examples.js` (modify) | test/example asset | transform (literal replace) | `cryptographic-failures.js` line 210 | role-match |
| `DEPLOYMENT.md`, `TESTING.md` (delete, salvage-first) | docs | file-I/O (read-then-delete) | `README.md` / `CONTRIBUTING.md` (salvage destinations) | role-match |
| `docs/SKILL-STRUCTURE.md` (possibly modify — Pitfall #4) | docs | transform (two filename fixes) | itself | exact |
| `install.sh` (disposition: keep/slim/retire — discretion) | config/utility | request-response (shell installer) | itself | exact |

## Pattern Assignments

### `scripts/check_version_drift.py` (utility, batch/transform)

**Analog:** `scripts/lint_skill_md.py` (full file, 241 lines — already read in full, no re-read needed)

**Module docstring / design-rules pattern** (lines 1-21):
```python
#!/usr/bin/env python3
"""Lint SKILL.md frontmatter against the Anthropic Agent Skills spec.
...
Design rules:
- Stdlib only (re, sys, pathlib, argparse, dataclasses). PyYAML is not
  installed in the verified target environment, so frontmatter is extracted
  with a regex on the leading fenced block rather than a YAML parser.
- Each check is soft: append a pass/fail result, never raise, so one file's
  failure does not abort the run.
- Output is JSON to stdout by default; `--format text` prints a human
  summary instead.
- Exit code is 0 when every check passed, 1 when any check failed.
```
Copy this docstring shape verbatim-in-spirit for `check_version_drift.py`: state the stdlib-only constraint, the soft-check contract, the two output formats, and the exit-code contract up front.

**Imports pattern** (lines 22-30):
```python
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
```
Reuse verbatim (drop `typing.Iterable` only if the new script doesn't need a generator helper).

**Result dataclass pattern** (lines 46-51):
```python
@dataclass
class LintResult:
    file: str
    check: str
    passed: bool
    message: str
```
Rename to e.g. `DriftResult` with the same 4 fields (`file`, `check`, `passed`, `message`) — this is the exact shape the planner should reuse so `--format text`/`--format json` rendering code (lines 215-236) can be copied almost unchanged.

**Soft-check-append style** (representative excerpt, lines 66-71):
```python
starts_at_byte0 = raw[:3] == b"---"
results.append(LintResult(
    file_str, "byte0-start", starts_at_byte0,
    "frontmatter starts at byte 0" if starts_at_byte0
    else "file does not start with '---' at byte 0 (BOM or leading blank line?)",
))
```
For version drift, the equivalent check is: read `plugin.json["version"]` as the canonical value, then for each scanned file (README.md, CONTRIBUTING.md, docs/*.md — whatever the planner scopes), regex-search for version-looking strings (e.g. `r"\b\d+\.\d+\.\d+\b"`) and append a `DriftResult` per match comparing it to canonical. Never raise; always append a result.

**CLI entrypoint / argparse + exit-code pattern** (lines 190-206, 236-240):
```python
parser = argparse.ArgumentParser(
    description="Lint SKILL.md frontmatter against the Agent Skills spec "
                 "(FMT-01/FMT-02/FMT-05).",
)
parser.add_argument("path", help="File or directory to lint (searches recursively for SKILL.md).")
parser.add_argument(
    "--format", choices=("json", "text"), default="json",
    help="Output format. JSON (default) for machine consumption; text for humans.",
)
args = parser.parse_args()
...
return 1 if any_failed else 0
...
if __name__ == "__main__":
    sys.exit(main())
```
Copy this argparse shape exactly (positional path arg + `--format {json,text}` choice + `sys.exit(main())` idiom). RESEARCH.md's proposed invocation `python3 scripts/check_version_drift.py` and the Wave-0 gap explicitly names this as the target command surface — match `lint_skill_md.py`'s CLI contract so both scripts feel like one family.

**Text-format rendering pattern** (lines 226-234):
```python
else:
    print(f"Checked {files_checked} SKILL.md file(s).")
    for r in all_results:
        mark = "PASS" if r.passed else "FAIL"
        print(f"  [{mark}] {r.file} :: {r.check} — {r.message}")
    if any_failed:
        print("\nRESULT: FAIL — one or more checks failed.")
    else:
        print("\nRESULT: PASS — all checks passed.")
```
Copy nearly verbatim for the drift script's `--format text` branch.

---

### Checkpoint-1 install-validation capture wrapper (utility, CLI orchestration)

**No exact analog exists** (this repo has no prior "run external CLI + tee to artifact" script). Closest structural precedents:

**From `install.sh`** (OS-detection + step-sequencing shape) — read directly for this mapping:
```bash
$ head -20 install.sh   (referenced, not reproduced here — see file for exact OS-detect / step pattern)
```
Use `install.sh`'s pattern of: detect environment → run sequential steps → print pass/fail per step → non-zero exit on failure. Since the actual work is invoking the `claude` CLI (not shell installs), RESEARCH.md's own "Pattern 1" and "Pattern 2" code blocks (see `05-RESEARCH.md` lines 191-246) are the concrete, already-vetted command sequence to wrap — copy them directly rather than re-deriving:
- The `python3 -c "..."` inline JSON-rewrite/revert snippets (lines 202-209 and 219-225 of RESEARCH.md) for the temporary `marketplace.json` `source` override and its revert.
- The `tee`-based capture chain (`claude plugin validate . | tee /tmp/phase5-validate.log`, etc.) for the "captured transcript" evidence D-02 requires.

**From `scripts/lint_skill_md.py`** — reuse only the stdlib-only constraint and the `LintResult`-style soft-append-a-result-per-step idea if the planner chooses a Python wrapper over a raw shell script (Claude's discretion per RESEARCH.md "Alternatives Considered"). If a shell script is chosen instead, keep it self-contained like `install.sh` (no external deps, `set -e` per critical step boundary, human-readable pass/fail echo per step).

---

### `README.md` (docs, request-response)

**Analog:** itself — current file at `/Users/mkh/CyberSecurity/OWASP-Security-Skills/README.md` (138 lines, already read in full).

**Stale sections requiring fixes (exact line numbers):**
- Line 4: `**six OWASP standards**` — must become an honest count reflecting the actual 7-standard/2-skill structure (Top 10, ASVS, MASVS, API, K8s, LLM, Agentic — LLM/Agentic are two separate standards per CONTEXT.md D-06).
- Line 22: dead link `[`owasp-comprehensive-security-skills.md`](owasp-comprehensive-security-skills.md)` — file was deleted in Phase 4; must be replaced with links into `skills/*/SKILL.md` and `skills/*/references/`.
- Line 28: `**OWASP ASVS 5.0**` — must be corrected to the verified edition wording (per CONTEXT.md D-06: "ASVS 4.0.3-body numbering under a verified 5.0.0 current edition").
- Lines 20-36 (whole "## Coverage" table): replace with the two-column coverage matrix (Edition covered / Scope-caveat columns) per D-06, sourced from `skills/owasp-security-audit/references/owasp-urls.json` and `skills/secure-coding-practices/references/owasp-urls.json` (citation source — read-only, do not re-verify).
- Line 34-36: `"OWASP Secure Coding Practices Quick Reference Guide"` phrasing — confirm this still matches the Phase 3-4 reframe wording used in `skills/secure-coding-practices/SKILL.md` (read that file's description field as the source of truth before finalizing wording).
- Line 43: `./install.sh` — keep or annotate depending on `install.sh` disposition decision; must add the plugin/marketplace install path as the primary documented path (`claude plugin marketplace add ...` / `claude plugin install ...` — see RESEARCH.md Code Examples block) since that's now the actual product per PKG-04.
- Lines 84-93 ("## Repository structure" tree): stale — still shows old root-level files (`owasp-comprehensive-security-skills.md`, `owasp-css.instructions.md`) that no longer exist; must be regenerated against the actual current tree (`.claude-plugin/`, `skills/owasp-security-audit/`, `skills/secure-coding-practices/`, `docs/`, `scripts/`).
- Lines 124-129 ("## Documentation" list): links to `DEPLOYMENT.md` and `TESTING.md` (line 127-128) — both being deleted this phase (D-09); must be removed/replaced with whatever salvaged content lands in README/CONTRIBUTING.
- Line 137: `Released under the MIT License.` — should now link to the new root `LICENSE` file: `[MIT License](LICENSE)`.
- Missing entirely: badges (D-08 — License/Version/Claude Code plugin/OWASP-aligned static shields, top of file), "What this is NOT" section (D-06).

**Good structural elements to preserve as-is (do not restructure needlessly):**
- The "## Usage" example-prompt table (lines 71-80) — still accurate, keep format.
- The per-file examples table (lines 104-114) — still accurate (file paths/foci unchanged), keep format; this is the copy-pattern for how the new coverage matrix's table styling should look (pipe-table, one row per item, short scope column).

---

### `CONTRIBUTING.md` (docs, request-response)

**Analog:** itself (27 lines, already read in full) + salvage sources `DEPLOYMENT.md`/`TESTING.md`.

**Stale references to fix:**
- Line 20: `Add new examples under `examples/`` — the root `examples/` directory no longer exists (moved to `skills/*/assets/examples/` in Phase 4); must be corrected to reference the per-skill `assets/examples/` paths.
- Line 21: `Ensure all sections (OWASP Top 10, ASVS, MASVS, API, Kubernetes, Agentic Apps) have adequate examples.` — should be updated to also name LLM as its own standard (currently conflates with Agentic) and reflect the two-skill split.
- Line 23: `Reference the authoritative guide: `owasp-comprehensive-security-skills.md`` — dead reference (file deleted); replace with the per-skill `SKILL.md` + `references/owasp-urls.json` as the authoritative sources.

**Structure to keep (numbered "Getting started" list, lines 7-13; "Guidelines" bullet list, lines 15-24):** this list format is the pattern to extend with the new maintenance/versioning/update story section (ADPT-03) — add a new `## Maintenance & versioning` heading in the same terse bullet style, folding in accurate salvaged content from `DEPLOYMENT.md`/`TESTING.md` (see below) plus the D-04 single-source-of-truth version rule and D-10 placeholder convention documentation requirement.

**Salvage sources (read before deleting):** `DEPLOYMENT.md` (273 lines) and `TESTING.md` (531 lines) — both exist and are large; per D-09 the planner/executor must grep them for any still-accurate install/verification content before deletion. Since neither was fully read in this pass (large, and D-09 explicitly frames this as an execution-time salvage task rather than a pattern-mapping task), the executing plan should `grep -n` both files for currently-valid commands/paths (e.g., anything NOT referencing the deleted root `skill.json` or `examples/` directory) as its own first step.

---

### `.claude-plugin/plugin.json` / `.claude-plugin/marketplace.json` (config, CRUD field edit)

**Analog:** itself — both files already read in full above.

**plugin.json current state (exact, to be bumped):**
```json
{
  "$schema": "https://json.schemastore.org/claude-code-plugin-manifest.json",
  "name": "owasp-security-skills",
  "displayName": "OWASP Security Skills",
  "version": "0.1.0",
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "author": { "name": "Security Education Community" },
  "homepage": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "repository": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "license": "MIT",
  "keywords": ["security", "owasp", "top-10", "asvs", "masvs", "secure-coding"]
}
```
Edit: `"version": "0.1.0"` → `"1.0.0"` (D-03/D-04); extend `keywords` array (D-11, Claude's discretion on exact values — RESEARCH.md's illustrative marketplace-entry example added `"secure-coding"` already present; consider adding e.g. `"kubernetes"`, `"llm"`, `"agentic"`, `"api-security"` if not already covered by existing keywords — final list is discretion).

**marketplace.json current state (exact, to be extended):**
```json
{
  "$schema": "https://json.schemastore.org/claude-code-marketplace.json",
  "name": "owasp-security-skills",
  "owner": { "name": "Security Education Community" },
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "plugins": [
    {
      "name": "owasp-security-skills",
      "source": {
        "source": "github",
        "repo": "mfkocalar/OWASP-Security-Skills"
      },
      "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code."
    }
  ]
}
```
Edit: add `"category"` and `"keywords"`/`"tags"` fields inside the single `plugins[0]` object per the verified schema in RESEARCH.md (lines 326-338) — `category` and `tags` are marketplace-entry-only fields, NOT valid in `plugin.json`. Example target shape (from RESEARCH.md, verified against code.claude.com):
```json
{
  "name": "owasp-security-skills",
  "source": { "source": "github", "repo": "mfkocalar/OWASP-Security-Skills" },
  "description": "...",
  "category": "security",
  "keywords": ["security", "owasp", "top-10", "asvs", "masvs", "secure-coding"],
  "tags": ["security-audit", "code-review", "compliance"]
}
```
**CRITICAL — do not confuse with Pattern 1's temporary override:** any edit here is the *permanent, committed* schema addition (category/keywords/tags). The Checkpoint-1 `source` field rewrite (`"source": "."`) described in RESEARCH.md Pattern 1 is a separate, temporary, uncommitted, revert-before-commit operation on the SAME file — the plan must not conflate the two edits or accidentally commit the temporary override.

---

### Example files — secret-literal normalization (QUAL-03, D-10)

**Analog / convention exemplar (the one already-correct file):**
`skills/owasp-security-audit/assets/examples/cryptographic-failures.js` line 210:
```
API_KEY=sk-your-api-key-here
```
This is the copy-pattern for every other offender below — self-labeling, structurally an API-key shape, but unmistakably fake.

**Exact offender locations (verified via direct grep + context read):**

| File | Line | Current literal | Context |
|---|---|---|---|
| `skills/owasp-security-audit/assets/examples/k8s-rbac.yaml` | 68 | `database_password: "MySecurePassword123!"` | `stringData:` block, comment `# DANGEROUS: Plaintext in YAML` |
| `skills/owasp-security-audit/assets/examples/k8s-rbac.yaml` | 69 | `api_key: "sk-abc123xyz789"` | same `stringData:` block |
| `skills/owasp-security-audit/assets/examples/cryptographic-failures.js` | 52 | `const api_key = "sk-abc123xyz789defgh1234567890";` | inside `vulnerable_api_call()`, comment `// Hardcoded!` |
| `skills/owasp-security-audit/assets/examples/prompt-injection.txt` | 96 | `print(response)  # "The API key is sk-abc123xyz789..."` | illustrative LLM-output comment, not a code literal — verify whether normalization still reads naturally as a comment string |
| `skills/secure-coding-practices/assets/examples/vulnerable-examples.py` | 211 | `API_KEY = "sk-abcd1234efgh5678ijkl9012"  # EXPOSED!` | module-level constant |
| `skills/secure-coding-practices/assets/examples/vulnerable-examples.py` | 213 | `DB_PASSWORD = "MySecurePassword123"  # In source code!` | module-level constant, directly below API_KEY line (2-line gap) |
| `skills/secure-coding-practices/assets/examples/vulnerable-examples.js` | 80 | `const API_KEY = "sk-1234567890abcdefghijklmnop";` | comment above: `// CRITICAL: API key in code` |
| `skills/secure-coding-practices/assets/examples/vulnerable-examples.js` | 83 | `const DB_PASSWORD = "MyDatabasePassword123";` | comment above: `// CRITICAL: Database password in code` |
| `skills/secure-coding-practices/assets/examples/vulnerable-examples.js` | 359 | `password: 'admin123'  // Default password!` | inside `adminCredentials` object literal (lines 357-360) |

**Recommended replacements (consistent with D-10's endorsed exemplars):**
- All `sk-...`-shaped API key literals → `sk-EXAMPLE-not-a-real-key` or `sk-your-api-key-here` (match the existing good exemplar's exact style for consistency within a file).
- All `MySecurePassword123`/`MyDatabasePassword123`-shaped password literals → `PLACEHOLDER_PASSWORD` (per CONTEXT.md's own endorsed exemplar and RESEARCH.md Pitfall #5's recommendation to extend scope; flag if planner defers this to a follow-up).
- `admin123` (line 359, vulnerable-examples.js) → also a password-shaped literal; same `PLACEHOLDER_PASSWORD`-style treatment recommended per Pitfall #5.

**Verification check post-edit (from RESEARCH.md's Phase Requirements → Test Map):**
```bash
grep -rnE "sk-[A-Za-z0-9]{10,}[^-]|password\s*=\s*['\"][A-Za-z][A-Za-z0-9]{6,}['\"]" skills/*/assets/examples
```
Should return zero non-placeholder matches after the edit.

---

### `LICENSE` (new file, no in-repo analog)

**Fact source (not a code analog, but the authoritative field values):** `.claude-plugin/plugin.json` — `"license": "MIT"`, `"author": { "name": "Security Education Community" }` (already read above). Per D-05: standard MIT license text, holder = `Security Education Community`, year = current (2026).

---

### `docs/SKILL-STRUCTURE.md` (possible modify, Pitfall #4)

**Analog:** itself. Not fully read in this pass (157 lines; RESEARCH.md's Pitfall #4 already pinpoints the exact drift at "lines ~85-124" — worked-example tree references `references/llm-agentic.md` (single combined file, pre-Phase-4) and a duplicate `owasp-security-audit.md` supplementary doc, both since split/removed in Phase 4). Executor should re-open this file at that line range specifically (targeted read, not full re-read) and correct the two filename references to match the current split (`llm.md` + `agentic.md`) and remove the deleted duplicate file mention.

---

## Shared Patterns

### Stdlib-only Python tooling constraint
**Source:** `scripts/lint_skill_md.py` lines 8-11 (module docstring "Design rules")
**Apply to:** `scripts/check_version_drift.py`, any Checkpoint-1 wrapper written in Python
```python
# Design rules:
# - Stdlib only (re, sys, pathlib, argparse, dataclasses). PyYAML is not
#   installed in the verified target environment...
```
Reason: repo-wide "no heavy runtime dependencies" constraint from `.claude/CLAUDE.md`; both existing scripts and RESEARCH.md's Standard Stack section confirm no new packages are introduced this phase.

### Soft-check / never-raise / exit-code contract
**Source:** `scripts/lint_skill_md.py` lines 12-16, 213, 236-237 (`any_failed` accumulation pattern, `return 1 if any_failed else 0`, `sys.exit(main())`)
**Apply to:** `scripts/check_version_drift.py`
Every check appends a result object rather than raising; the script's exit code is derived once, at the end, from whether any result failed.

### `--format {json,text}` CLI convention
**Source:** `scripts/lint_skill_md.py` lines 196-199, 215-236
**Apply to:** `scripts/check_version_drift.py` (RESEARCH.md's proposed invocation is `python3 scripts/check_version_drift.py`, implying the same argparse family)

### Two-checkpoint reversible local-source-override pattern
**Source:** `05-RESEARCH.md` lines 188-251 (Pattern 1) — not repo code, but the fully-specified, already-vetted procedure for this phase's install-validation gate.
**Apply to:** the Checkpoint-1 capture wrapper.
```bash
claude plugin validate . | tee /tmp/phase5-validate.log
# TEMP override .claude-plugin/marketplace.json plugins[0].source -> "."
claude plugin marketplace add . --scope local | tee -a /tmp/phase5-validate.log
claude plugin install owasp-security-skills@owasp-security-skills --scope local | tee -a /tmp/phase5-validate.log
claude plugin details owasp-security-skills@owasp-security-skills | tee -a /tmp/phase5-validate.log
claude plugin list --json | tee -a /tmp/phase5-validate.log
# REVERT override; git diff --stat .claude-plugin/marketplace.json MUST show no diff
```

### Coverage-table styling (README pattern to extend)
**Source:** `README.md` lines 104-114 (existing per-file examples table) and lines 25-32 (existing single-column coverage table, to be replaced by the two-column D-06 matrix)
**Apply to:** the new two-column coverage matrix (Standard | Edition covered | Scope/caveat).

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `LICENSE` | config/legal | file-I/O (static) | No prior LICENSE file in repo; standard MIT boilerplate text with fields sourced from `plugin.json`, not a code pattern to copy |
| Checkpoint-1 capture wrapper | utility (CLI orchestration) | request-response | No existing "invoke external CLI + tee to phase artifact" script exists in repo; RESEARCH.md's Pattern 1/2 code blocks are the closest available spec, used directly as the source rather than an in-repo code analog |
| `docs/SKILL-STRUCTURE.md` full drift-scope | docs | transform | Self-referential fix (compare doc against actual current tree, not against another file) |

## Metadata

**Analog search scope:** repo root, `scripts/`, `.claude-plugin/`, `README.md`, `CONTRIBUTING.md`, `DEPLOYMENT.md`/`TESTING.md` (grep only, not full read), `skills/*/assets/examples/*`, `docs/SKILL-STRUCTURE.md`
**Files scanned:** `scripts/lint_skill_md.py` (full), `README.md` (full), `CONTRIBUTING.md` (full), `.claude-plugin/plugin.json` (full), `.claude-plugin/marketplace.json` (full), 5 example files (grep + targeted context), `05-CONTEXT.md` + `05-RESEARCH.md` (full)
**Pattern extraction date:** 2026-07-27
