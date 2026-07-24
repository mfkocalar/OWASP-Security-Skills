---
phase: 04-skill-md-conversion-legacy-retirement
plan: 01
subsystem: testing
tags: [python, stdlib, lint, agent-skills-spec, frontmatter]

# Dependency graph
requires: []
provides:
  - "scripts/lint_skill_md.py — repo-root, stdlib-only lint tool verifying SKILL.md frontmatter against FMT-01 (name/description limits + D-07 parent-dir match), FMT-02 (body-line advisory), and FMT-05 (byte-0 start, no angle brackets, allowed bundled directories)"
  - "Green baseline proof: both SKILL.md files pass every check today (audit name=20/desc=738/body=411 lines; SCP name=23/desc=695/body=252 lines)"
affects: [04-02, 04-03]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "LintResult dataclass (file, check, passed, message) — one soft pass/fail record per check, mirrors quick_scan.py's Finding dataclass shape"
    - "Regex-based frontmatter extraction (no PyYAML) — matches quick_scan.py's stdlib-only design rule"

key-files:
  created: [scripts/lint_skill_md.py]
  modified: []

key-decisions:
  - "Placed lint script at repo-root scripts/ (not per-skill scripts/) so it lints both skills from one place and is never shipped as either skill's installed payload, per plan objective"
  - "Every check implemented as a soft LintResult append rather than a hard assert, so one failing check does not abort the run against the other file"

patterns-established:
  - "SKILL.md lint gate: python3 scripts/lint_skill_md.py <path> [--format json|text], exit 0 = all pass, exit 1 = any fail — reusable by 04-02/04-03 after their description edits"

requirements-completed: [FMT-01, FMT-02, FMT-05]

coverage:
  - id: D1
    description: "scripts/lint_skill_md.py exists, parses, is stdlib-only (no PyYAML), and both SKILL.md files pass every FMT-01/FMT-02/FMT-05 check with exit code 0"
    requirement: "FMT-01"
    verification:
      - kind: other
        ref: "python3 scripts/lint_skill_md.py skills/ --format text (exit 0, 24/24 checks PASS)"
        status: pass
      - kind: other
        ref: "grep -c 'import yaml' scripts/lint_skill_md.py (returns 0)"
        status: pass
      - kind: other
        ref: "python3 -c \"import ast; ast.parse(open('scripts/lint_skill_md.py').read())\" (parses)"
        status: pass
    human_judgment: false
  - id: D2
    description: "FMT-02/FMT-05 mechanical sweep (wc -l body-line guidance, bundled-directory find) confirms the pre-edit baseline is green before 04-02/04-03 touch the descriptions"
    requirement: "FMT-02"
    verification:
      - kind: other
        ref: "wc -l skills/owasp-security-audit/SKILL.md skills/secure-coding-practices/SKILL.md (415 and 256 lines, both <=500)"
        status: pass
      - kind: other
        ref: "find skills -mindepth 2 -maxdepth 2 -type d | grep -vE '/(references|scripts|assets)$' (empty output)"
        status: pass
    human_judgment: false

duration: 6min
completed: 2026-07-24
status: complete
---

# Phase 04 Plan 01: SKILL.md Lint Tool Summary

**Stdlib-only Python lint script (scripts/lint_skill_md.py) proving both SKILL.md files already satisfy FMT-01/FMT-02/FMT-05, giving 04-02/04-03 a re-runnable gate for their description edits**

## Performance

- **Duration:** 6 min
- **Started:** 2026-07-24T13:49:00Z
- **Completed:** 2026-07-24T13:55:14Z
- **Tasks:** 2 completed
- **Files modified:** 1

## Accomplishments
- Built `scripts/lint_skill_md.py`, a stdlib-only (re/sys/pathlib/argparse/dataclasses — no PyYAML) CLI lint tool that regex-extracts SKILL.md frontmatter and runs 8-12 soft checks per file (byte-0 start, frontmatter-present, name-present/length/charset/no-reserved-word/matches-parent-dir, description-present/length, no-angle-brackets, body-line-guidance, allowed-bundled-dirs)
- Confirmed the green baseline: `python3 scripts/lint_skill_md.py skills/` exits 0 with all 24 checks (12 per file × 2 files) passing for both `owasp-security-audit` and `secure-coding-practices`
- Ran the full FMT-02/FMT-05 mechanical sweep independently of the lint script (`wc -l`, `find`) and confirmed identical green results — the lint script and the raw shell checks agree

## Task Commits

Each task was committed atomically:

1. **Task 1: Write the stdlib-only SKILL.md lint script** - `4d0f04f` (feat)
2. **Task 2: Establish the green baseline + FMT-02/FMT-05 sweep** - no commit (verification-only task, no file changes; all checks passed on first run, so no fix to Task 1's script was needed)

**Plan metadata:** (pending — this commit)

## Files Created/Modified
- `scripts/lint_skill_md.py` - repo-root stdlib-only lint tool; `LintResult` dataclass + `main()` with positional `path` arg and `--format json|text` flag, exit 0/1

## Decisions Made
- Confirmed repo-root `scripts/` placement (per plan objective) over a per-skill location, so one invocation covers both skills and the tool is never shipped inside either skill's installed payload
- Kept every check as a soft `LintResult` append (never a hard `assert`), per 04-PATTERNS.md's explicit deviation note from the raw RESEARCH.md snippet — a single failing check on one file cannot abort the run against the other file
- FMT-02's 500-line body check is implemented as advisory (records `passed: True/False` for visibility but does not itself gate FMT-05's overall exit code differently) — matches RESEARCH.md's confirmation that the 500-line guidance is a quality-checklist item, not a validator-enforced ceiling; both current bodies (411/252 lines counted after the frontmatter block) are well within it regardless

## Deviations from Plan

None - plan executed exactly as written. Task 2's checks were already green on first run (both SKILL.md files were already compliant per 04-RESEARCH.md), so no fix to the Task 1 script was required.

## Issues Encountered
- Minor: an early draft of `lint_file()` contained a dead/unused helper stub (`_read_bytes`) left over during iteration on the byte-0 read logic. Removed before running any verification — not a functional deviation, no separate commit needed since Task 1's single commit already reflects the cleaned-up file.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `python3 scripts/lint_skill_md.py skills/` is now the reusable, re-runnable FMT-01/FMT-02/FMT-05 gate for 04-02 (audit skill description edit) and 04-03 (SCP skill description edit) — both must re-pass this exact command after their edits.
- No blockers. Wave 0 infrastructure gap from 04-VALIDATION.md is closed.

---
*Phase: 04-skill-md-conversion-legacy-retirement*
*Completed: 2026-07-24*

## Self-Check: PASSED

- FOUND: scripts/lint_skill_md.py
- FOUND: 4d0f04f (Task 1 commit)
- FOUND: .planning/phases/04-skill-md-conversion-legacy-retirement/04-01-SUMMARY.md
