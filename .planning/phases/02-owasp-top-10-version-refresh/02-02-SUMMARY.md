---
phase: 02-owasp-top-10-version-refresh
plan: 02
subsystem: docs
tags: [owasp, top10, security-audit, quick_scan, readme, skill-md]

# Dependency graph
requires:
  - phase: 02-01
    provides: "top10.md rewritten to the 2025 (Final) taxonomy; owasp-urls.json A01-A10 2025 URLs (canonical source of truth for this sweep)"
provides:
  - "SKILL.md / owasp-security-audit.md byte-identical mirror citing OWASP Top 10 (2025), with A01 citation URLs pointing at the 2025 path"
  - "vulnerable-patterns.md index + section headers renumbered to 2025 IDs (topic-mapped, in place)"
  - "quick_scan.py Top10:Axx labels on the 2025 taxonomy with regex logic unchanged"
  - "README.md Top 10 coverage row and example-table category labels on 2025 IDs"
  - "Clean CONT-02 grep: zero stale 2021-era Top 10 IDs/names/edition labels/URLs across skills/ + README.md"
affects: [04-agent-skills-restructure, 05-public-release-polish]

# Tech tracking
tech-stack:
  added: []
  patterns: ["Topic-based (not numeric find-replace) category renumbering when a Top 10 category moves between editions"]

key-files:
  created: []
  modified:
    - skills/owasp-security-audit/SKILL.md
    - skills/owasp-security-audit/owasp-security-audit.md
    - skills/owasp-security-audit/references/vulnerable-patterns.md
    - skills/owasp-security-audit/scripts/quick_scan.py
    - README.md
    - .gitignore

key-decisions:
  - "Renumbered vulnerable-patterns.md and quick_scan.py labels by topic (crypto, injection, misconfig, SSRF) rather than by literal old-number-to-new-number substitution, avoiding accidental mislabeling of unrelated categories that share a digit"
  - "Added __pycache__/ and *.pyc to .gitignore after python3 -m py_compile (required by this plan's own verification step) left an untracked build artifact"

patterns-established:
  - "When two labels swap numbers (e.g. old-A05 Misconfig -> new-A02, old-A03 Injection -> new-A05), convert the currently-safe (non-colliding) mapping first to avoid double-converting an already-renumbered label"

requirements-completed: [CONT-02]

coverage:
  - id: D1
    description: "SKILL.md and owasp-security-audit.md mirror cites OWASP Top 10 (2025) with 2025 A01 citation URLs, kept byte-identical"
    requirement: "CONT-02"
    verification:
      - kind: other
        ref: "diff skills/owasp-security-audit/SKILL.md skills/owasp-security-audit/owasp-security-audit.md (empty); grep -q 'OWASP Top 10 (2025)' + 'Top10/2025/A01_2025-Broken_Access_Control'"
        status: pass
    human_judgment: false
  - id: D2
    description: "vulnerable-patterns.md index and section headers renumbered to 2025 IDs (topic-mapped, in place); llm-agentic.md confirmed accurate with no stale code"
    requirement: "CONT-02"
    verification:
      - kind: other
        ref: "grep -q '^## A04 — Cryptographic Failures' / '^## A05 — Injection' / '^## A02 — Security Misconfiguration' vulnerable-patterns.md"
        status: pass
    human_judgment: false
  - id: D3
    description: "quick_scan.py Top10:Axx labels renumbered to 2025 taxonomy with regex logic unchanged; README Top 10 coverage row and example labels updated to 2025 IDs; no example source file touched"
    requirement: "CONT-02"
    verification:
      - kind: other
        ref: "quick_scan.py label counts (A04=8, A05=6, A02=4, A01=1, A07=2) + python3 -m py_compile; README grep checks for 2025 row and per-example (A04)/(A05)/(A02) labels"
        status: pass
    human_judgment: false
  - id: D4
    description: "CONT-02 gate: zero stale 2021-era Top 10 IDs/names/edition labels remain across skills/ + README.md (D-01 breadcrumb prose excepted, none present in swept files)"
    requirement: "CONT-02"
    verification:
      - kind: other
        ref: "grep -rnE 'A0[1-9]_2021|A10_2021|\\(2021\\)' skills/ README.md — zero matches"
        status: pass
    human_judgment: false

duration: 14min
completed: 2026-07-21
status: complete
---

# Phase 02 Plan 02: OWASP Top 10 Consistency Sweep Summary

**Swept every remaining Top 10 category ID, name, edition label, and citation URL in the loaded skill path (SKILL.md mirror, vulnerable-patterns.md, quick_scan.py, README.md) to the 2025 (Final) taxonomy established by plan 02-01, closing the CONT-02 gate with a clean zero-stale-reference grep.**

## Performance

- **Duration:** 14 min
- **Started:** 2026-07-21T13:26:00Z
- **Completed:** 2026-07-21T13:40:47Z
- **Tasks:** 3
- **Files modified:** 6 (5 planned + `.gitignore`)

## Accomplishments
- SKILL.md and its byte-identical mirror `owasp-security-audit.md` now cite OWASP Top 10 (2025), with A01 Broken Access Control citation URLs pointing at `https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/`
- `vulnerable-patterns.md` index table and section headers renumbered by topic to 2025 IDs in place (Cryptographic Failures=A04, Injection=A05, Security Misconfiguration=A02, SSRF now shown under A01 alongside its API7 cross-reference); `llm-agentic.md` confirmed to need no change (AG09 -> web A09 slot unchanged in 2025)
- `quick_scan.py` string labels and section-comment headers renumbered to the 2025 taxonomy with regex bodies untouched (crypto=A04 x8, injection=A05 x6, misconfig=A02 x4, SSRF=A01 x1, auth=A07 x2 unchanged)
- README.md coverage-table Top 10 row now reads "OWASP Top 10 (2025)" with a refreshed scope blurb; example-table category labels updated (cryptographic-failures.js=A04, injection.js=A05, security-misconfiguration.py=A02, xss.html=A05: Injection) without touching any example source file
- CONT-02 gate verified clean: `grep -rnE "A0[1-9]_2021|A10_2021|\(2021\)" skills/ README.md` returns zero matches

## Task Commits

Each task was committed atomically:

1. **Task 1: Sweep the SKILL.md / owasp-security-audit.md mirror pair to 2025** - `c461b21` (feat)
2. **Task 2: Renumber vulnerable-patterns.md to 2025 IDs; confirm llm-agentic.md** - `07e295f` (feat)
3. **Task 3: Sweep quick_scan.py labels and README Top 10 labels to 2025** - `847d827` (feat)

**Plan metadata:** pending (docs: complete plan, this commit)

## Files Created/Modified
- `skills/owasp-security-audit/SKILL.md` - Frontmatter edition label, A01 citation URLs (x2), Standards-applied entry, and reference-index note updated to 2025
- `skills/owasp-security-audit/owasp-security-audit.md` - Replicated from SKILL.md; byte-identical mirror confirmed via `diff`
- `skills/owasp-security-audit/references/vulnerable-patterns.md` - Index table + 4 section headers renumbered by topic to 2025 IDs; A08-overlap note annotated with its 2025 name
- `skills/owasp-security-audit/scripts/quick_scan.py` - `Top10:Axx` string labels + section-comment headers renumbered to 2025 taxonomy; regex bodies unchanged; `py_compile` verified
- `README.md` - Top 10 coverage row and example-table category labels updated to 2025 IDs; no example source file edited
- `.gitignore` - Added `__pycache__/` and `*.pyc` (deviation, see below)

## Decisions Made
- Renumbered `vulnerable-patterns.md` and `quick_scan.py` labels by **topic** (what each pattern actually detects), not by literal old-number-to-new-number string substitution, to avoid mislabeling categories that happen to share a digit across editions (e.g. old-A05 Misconfig moving to new-A02 while old-A03 Injection moves to new-A05 — converting misconfig first avoided a double-conversion collision)
- Kept the SSRF section in `vulnerable-patterns.md` and its `Top10:A01` label in `quick_scan.py` cross-referenced to CWE-918 and the existing API7 pairing, rather than physically relocating the section, per the plan's "renumber in place" instruction

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking/Untracked-file cleanup] Added `__pycache__/` and `*.pyc` to `.gitignore`**
- **Found during:** Task 3 (quick_scan.py sweep) and again confirmed at plan-close verification
- **Issue:** The plan's own verification step (`python3 -m py_compile skills/owasp-security-audit/scripts/quick_scan.py`) generates a `__pycache__/quick_scan.cpython-*.pyc` file, which showed up as an untracked file after each compile check. `.gitignore` had no Python bytecode pattern.
- **Fix:** Removed the generated `__pycache__/` directory and added `__pycache__/` + `*.pyc` to `.gitignore` so future verification runs (including the plan-close full suite) don't leave untracked build artifacts.
- **Files modified:** `.gitignore`
- **Verification:** `git status --porcelain` shows a clean working tree after re-running `python3 -m py_compile` post-fix.
- **Committed in:** `847d827` (part of Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking/untracked-file cleanup)
**Impact on plan:** No scope creep — the fix was a direct, necessary consequence of running the plan's own mandated verification command. All five `files_modified` targets were swept exactly as specified; no example source file or repo-root legacy file was touched.

## Issues Encountered
None beyond the `__pycache__` cleanup documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Phase 02 (OWASP Top 10 Version Refresh) is complete: `top10.md` rewritten to 2025 (Final) in plan 02-01, and every other loaded-path citation swept to match in plan 02-02.
- CONT-02 gate is closed with a verified-clean grep across `skills/` and `README.md`.
- The two repo-root legacy files (`owasp-comprehensive-security-skills.md`, `owasp-css.instructions.md`) intentionally still carry 2021-era content — Phase 4 deletes them per D-02/D-03; no action needed from this phase.
- Example-file category re-labeling (CONT-06) remains deferred to Phase 4 as planned — no example `.py`/`.js`/`.html`/`.yaml`/`.txt` source file was modified in this plan.
- Ready to proceed to Phase 3 (citation-hardening of ASVS/MASVS/API/LLM/Agentic/K8s standards and `secure-coding-practices` re-derivation).

---
*Phase: 02-owasp-top-10-version-refresh*
*Completed: 2026-07-21*

## Self-Check: PASSED

All 5 modified files found on disk; all 3 task commit hashes (c461b21, 07e295f, 847d827) verified present in git log.
