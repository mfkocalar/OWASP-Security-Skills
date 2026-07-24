---
phase: 04-skill-md-conversion-legacy-retirement
reviewed: 2026-07-24T00:00:00Z
depth: standard
files_reviewed: 18
files_reviewed_list:
  - scripts/lint_skill_md.py
  - install.sh
  - skills/owasp-security-audit/SKILL.md
  - skills/owasp-security-audit/references/llm.md
  - skills/owasp-security-audit/references/agentic.md
  - skills/owasp-security-audit/assets/examples/api-auth-bypass.js
  - skills/owasp-security-audit/assets/examples/broken-access-control.py
  - skills/owasp-security-audit/assets/examples/cryptographic-failures.js
  - skills/owasp-security-audit/assets/examples/injection.js
  - skills/owasp-security-audit/assets/examples/k8s-rbac.yaml
  - skills/owasp-security-audit/assets/examples/logging-monitoring-failures.py
  - skills/owasp-security-audit/assets/examples/prompt-injection.txt
  - skills/owasp-security-audit/assets/examples/security-misconfiguration.py
  - skills/owasp-security-audit/assets/examples/xss.html
  - skills/secure-coding-practices/README.md
  - skills/secure-coding-practices/SKILL.md
  - skills/secure-coding-practices/secure-coding-practices.md
findings:
  critical: 0
  warning: 2
  info: 4
  total: 6
status: issues_found
---

# Phase 04: Code Review Report

**Reviewed:** 2026-07-24
**Depth:** standard
**Files Reviewed:** 18 (17 source paths in config + `scripts/lint_skill_md.py`)
**Status:** issues_found

## Summary

Reviewed the new `lint_skill_md.py` tooling, the patched `install.sh`, both restructured
`SKILL.md` skill files, two reference docs (`llm.md`, `agentic.md`), the nine paired
vulnerable/secure teaching examples, and the SCP docs.

Overall the phase work is solid. Verified independently:

- **OWASP category IDs are correct for the 2025/2026 editions.** All example labels match
  the OWASP Top 10 2025 ordering: A01 Broken Access Control, A02 Security Misconfiguration,
  A04 Cryptographic Failures, A05 Injection (incl. XSS), A09 Logging & Alerting Failures.
  `llm.md` uses `LLM01:2025`–`LLM10:2025`, `agentic.md` uses `ASI01`–`ASI10` and correctly
  flags the invented `AG##` codes as non-canonical. No ID errors found.
- **No dangling references** to the deleted files (`llm-agentic.md`,
  `owasp-comprehensive-security-skills.md`, `owasp-css.instructions.md`,
  `owasp-security-audit.md`) in any reviewed file.
- **All referenced paths exist** — every `references/*.md`, `assets/examples/`, and
  `scripts/quick_scan.py` path cited in the SKILL.md files resolves.
- **`install.sh` sentinel is correct** — `.claude-plugin/plugin.json` and the root
  `README.md` both exist, so the run-location and verify checks will not false-error.
- **`lint_skill_md.py` runs clean** against both SKILL.md files (24 checks, all PASS,
  exit 0). Frontmatter is spec-compliant (byte-0 start, name==dir, no angle brackets,
  description under 1024 chars).

The two teaching examples flagged by the injection scanner (`llm.md`, `prompt-injection.txt`)
are expected — they are documentation of prompt-injection patterns, not live payloads.

No BLOCKER-level defects. Two correctness/robustness WARNINGs in the new lint tooling and
four INFO-level items follow.

## Narrative Findings (AI reviewer)

## Warnings

### WR-01: "Advisory" body-line check actually fails the run and flips the exit code

**File:** `scripts/lint_skill_md.py:156-164` (and `213`, `236`)
**Issue:** The FMT-02 body-line check is documented as advisory. The module docstring is
silent on it, the inline comment at line 156 says *"body-line advisory — warn, do not fail"*,
and the failure message at line 163 ends with *"(advisory only)"*. But the result is appended
with `passed=body_ok` like every other check, and `any_failed = any(not r.passed ...)` at
line 213 feeds the exit code at line 236 (`return 1 if any_failed else 0`). So a SKILL.md
whose body legitimately exceeds the 500-line *guidance* will make the whole run report
`RESULT: FAIL` and exit non-zero.

Confirmed by simulation: `body_ok=False` → `any_failed=True` → exit code 1, while the
message still reads "(advisory only)". If this linter is wired into CI (it emits JSON "for
machine consumption"), a file that only trips a soft guideline will block the pipeline.
Currently latent — both SKILL.md bodies are 417 and 252 lines — but it is incorrect behavior
versus the tool's own documented contract.

**Fix:** Separate advisory checks from pass/fail. Either exclude the body-line result from
the exit-code calculation, or add a severity/advisory flag to `LintResult` and compute
`any_failed` only over hard checks:
```python
@dataclass
class LintResult:
    file: str
    check: str
    passed: bool
    message: str
    advisory: bool = False

# body-line result:
results.append(LintResult(file_str, "body-line-guidance", body_ok, "...", advisory=True))

# exit-code logic:
any_failed = any((not r.passed) and (not r.advisory) for r in all_results)
```

### WR-02: `DESC_RE` uses greedy `re.DOTALL` — over-counts description length and swallows any field after `description:`

**File:** `scripts/lint_skill_md.py:43`, used at `132-146`
**Issue:** `DESC_RE = re.compile(r"^description:\s*(.*)$", re.MULTILINE | re.DOTALL)`.
Because `re.DOTALL` makes `.` match newlines and `.*` is greedy, the capture runs from the
first `description:` to the very end of the frontmatter block, not to the end of the
description line. This only produces the correct length today because `description:` happens
to be the last frontmatter key in both files. If any key were added after `description:`
(e.g. `license:`, `allowed-tools:`, `metadata:`), its content would be folded into the
captured description, inflating the measured length and producing a false
`description-length` FAIL (or, combined with WR-01, a spurious non-zero exit). This is a
fragile parse for a spec-conformance tool.

**Fix:** Constrain the capture. Drop `DOTALL` if descriptions are single-line, or (to
support YAML folded/block scalars) capture up to the next top-level key:
```python
DESC_RE = re.compile(r"^description:[ \t]*(.*)$", re.MULTILINE)  # single-line
# or, to stop at the next 'key:' line:
DESC_RE = re.compile(r"^description:\s*(.*?)(?=^\S+:|\Z)", re.MULTILINE | re.DOTALL)
```
Add a fixture with a trailing frontmatter field to lock the behavior in.

## Info

### IN-01: Installer example count uses recursive `find -type f`, counting stray `.pyc`

**File:** `install.sh:98`
**Issue:** `find "${install_dir}/skills/owasp-security-audit/assets/examples" -type f | wc -l`
counts recursively. A local `__pycache__/` (present in the working tree after running/importing
the `.py` examples) inflates the count from the intended 9 to 12. The `-ge 9` threshold still
passes, so no false error today, but the check is measuring more than the example files it
claims to count.
**Fix:** Scope to top-level files of the expected types, e.g.
`find "${dir}" -maxdepth 1 -type f \( -name '*.py' -o -name '*.js' -o -name '*.yaml' -o -name '*.html' -o -name '*.txt' \) | wc -l`.

### IN-02: Untracked `__pycache__`/`*.pyc` artifacts in the working tree under `skills/`

**File:** `skills/owasp-security-audit/scripts/__pycache__/`,
`skills/owasp-security-audit/assets/examples/__pycache__/`,
`skills/secure-coding-practices/assets/examples/__pycache__/`
**Issue:** Compiled Python artifacts exist locally. `git ls-files` confirms none are tracked,
so they will not ship via git — but `install.sh` symlinks the entire repo root into the
assistant skills directory, so any local build artifacts become visible in an install.
**Fix:** Ensure `.gitignore` covers `__pycache__/` and `*.pyc` (repo-hygiene), and consider
`.pyc` cleanup before packaging/distribution.

### IN-03: SCP `SKILL.md` references a `scripts/` directory that does not exist

**File:** `skills/secure-coding-practices/SKILL.md:185`
**Issue:** The reference list cites `scripts/` — "Helper scripts (quick scan, pattern
matching, etc.)" but `skills/secure-coding-practices/` has only `assets/` and `references/`.
The sibling `README.md:38` labels the same entry "(future)", so this is doc drift rather than
a broken skill path.
**Fix:** Add the "(future)" qualifier in `SKILL.md` or remove the `scripts/` bullet until the
directory exists.

### IN-04: `lint_skill_md.py` exit code 2 is undocumented

**File:** `scripts/lint_skill_md.py:16` (docstring) vs `205` (`return 2`)
**Issue:** The docstring states "Exit code is 0 when every check passed, 1 when any check
failed." `main()` returns `2` when the path does not exist. The distinct code is reasonable,
but a machine consumer relying on the documented 0/1 contract could misinterpret it.
**Fix:** Document the `2` (path-not-found / usage error) exit code in the docstring.

---

_Reviewed: 2026-07-24_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
