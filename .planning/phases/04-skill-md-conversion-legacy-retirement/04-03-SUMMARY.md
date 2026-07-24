---
phase: 04-skill-md-conversion-legacy-retirement
plan: 03
subsystem: docs
tags: [owasp, secure-coding-practices, skill-md, agent-skills-spec, living-source-crosswalk]

# Dependency graph
requires:
  - phase: 04-01
    provides: scripts/lint_skill_md.py (FMT-05 lint gate)
  - phase: 03-03
    provides: scp-checklist.md Living-Source Crosswalk (the reframe wording this plan lifts)
provides:
  - secure-coding-practices SKILL.md description reworded to living-source framing (D-06)
  - secure-coding-practices.md and README.md reworded to the same framing (D-03)
  - SKILL.md body intro paragraph aligned to the same framing (in-file consistency fix)
affects: [phase-05-qual-01-sweep]

# Tech tracking
tech-stack:
  added: []
  patterns: [living-source framing mirrored verbatim from scp-checklist.md's Living-Source Crosswalk header into description + human docs]

key-files:
  created: []
  modified:
    - skills/secure-coding-practices/SKILL.md
    - skills/secure-coding-practices/secure-coding-practices.md
    - skills/secure-coding-practices/README.md

key-decisions:
  - "Also reworded SKILL.md's body intro paragraph (line 8), not just the frontmatter description, to avoid leaving a stale QRG-as-current claim contradicting the reworded description within the same file"
  - "Added an explicit pointer from both human docs' reference sections to the scp-checklist.md Living-Source Crosswalk, rather than only relabeling the QRG line, so readers have a path to current sources"

patterns-established:
  - "Historical-origin labeling pattern: any surviving 'Quick Reference Guide' mention must carry archived/historical/origin qualifier on the same line (grep-verifiable)"

requirements-completed: [FMT-01, FMT-03, FMT-05]

coverage:
  - id: D1
    description: "SCP SKILL.md description reframed to present the checklist as living-source-derived (Developer Guide / Cheat Sheet Series / Proactive Controls) with the QRG as archived origin, while preserving SCP-compliance activation triggers and passing the FMT-05 lint"
    requirement: "FMT-05"
    verification:
      - kind: other
        ref: "python3 scripts/lint_skill_md.py skills/secure-coding-practices/ (exit 0, passed:true)"
        status: pass
      - kind: other
        ref: "grep -ci 'Developer Guide|Cheat Sheet|Proactive Control' skills/secure-coding-practices/SKILL.md == 2"
        status: pass
      - kind: other
        ref: "grep -ci 'SCP compliance|secure coding' skills/secure-coding-practices/SKILL.md == 4"
        status: pass
    human_judgment: false
  - id: D2
    description: "secure-coding-practices.md and README.md reworded so no surviving 'Quick Reference Guide' mention lacks archived/historical/origin context, with living-source framing present in both and internal scp-checklist.md pointers preserved"
    requirement: "FMT-03"
    verification:
      - kind: other
        ref: "grep -rniE 'Quick Reference Guide' skills/secure-coding-practices/secure-coding-practices.md skills/secure-coding-practices/README.md | grep -vi 'archiv|historical|origin' | wc -l == 0"
        status: pass
      - kind: other
        ref: "grep -c 'references/scp-checklist.md' skills/secure-coding-practices/secure-coding-practices.md == 5 (preserved/increased)"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-07-24
status: complete
---

# Phase 04 Plan 03: SCP Living-Source Reframe (Description + Human Docs) Summary

**Reworded the secure-coding-practices skill's description and its two human-facing docs so the archived OWASP Secure Coding Practices Quick Reference Guide is framed only as historical origin, with the 14-domain checklist attributed to OWASP's living sources (Developer Guide, Cheat Sheet Series, Proactive Controls).**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-24T14:04:00Z
- **Completed:** 2026-07-24T14:11:55Z
- **Tasks:** 2 completed
- **Files modified:** 3

## Accomplishments
- SKILL.md `description` (D-06) no longer presents the archived QRG as a current source; it names the Developer Guide, Cheat Sheet Series, and Proactive Controls as the checklist's living sources and keeps the "SCP compliance"/"secure coding" activation triggers intact
- Fixed the same stale framing in SKILL.md's body intro paragraph so the file doesn't contradict its own reworded description
- secure-coding-practices.md's Purpose statement, Reference line, and External references section now use the living-source framing, with the QRG explicitly labeled "archived historical origin"
- README.md's top-line description and References section received the identical reframe
- Both human docs now point readers to the Living-Source Crosswalk in `references/scp-checklist.md` for current, actively-maintained sources

## Task Commits

Each task was committed atomically:

1. **Task 1: Reframe the SCP SKILL.md description to living-source framing (D-06)** - `3b2d6b3` (docs)
2. **Task 2: Refresh the two SCP human-facing docs (D-03)** - `196d606` (docs)

**Plan metadata:** (pending — recorded in final commit)

_Note: no TDD tasks in this plan; both are prose/frontmatter edits with grep + lint verification._

## Files Created/Modified
- `skills/secure-coding-practices/SKILL.md` - Reworded frontmatter `description` and body intro paragraph to living-source framing; lint-verified (884-char description, 0 angle brackets, exit 0)
- `skills/secure-coding-practices/secure-coding-practices.md` - Reworded Purpose/Reference lines and External references section; added Living-Source Crosswalk pointer
- `skills/secure-coding-practices/README.md` - Reworded top-line description and References section; added Living-Source Crosswalk pointer

## Decisions Made
- Extended the description-only edit (Task 1's literal scope) to also fix SKILL.md's body intro paragraph, since leaving it stale would create an internal contradiction within the same file the task modifies (Rule 1 auto-fix — directly caused by/adjacent to this task's edit, same file, same concern)
- Added explicit "living sources" pointer lines in both human docs' reference sections (not just relabeling the QRG line) so the reframe is actionable, not just corrective — readers get a path to `references/scp-checklist.md`'s Living-Source Crosswalk

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug/contradiction] Fixed stale QRG framing in SKILL.md body intro paragraph**
- **Found during:** Task 1
- **Issue:** Plan scoped Task 1 to the frontmatter `description` field only, but line 8's body intro ("This skill turns Claude into a rigorous auditor that applies the OWASP Secure Coding Practices (SCP) Quick Reference Guide checklist...") still presented the archived QRG as current, directly contradicting the just-reworded description one line below in the same file.
- **Fix:** Reworded the body intro to match the same living-source framing (Developer Guide, Cheat Sheet Series, Proactive Controls) with the QRG named as archived historical origin.
- **Files modified:** skills/secure-coding-practices/SKILL.md
- **Verification:** `grep -n -i "quick reference guide" skills/secure-coding-practices/SKILL.md` shows both remaining mentions (description + body) in archived/historical-origin context; FMT lint still exits 0.
- **Committed in:** `3b2d6b3` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug/contradiction fix)
**Impact on plan:** Necessary for accuracy — avoided shipping a file that contradicts itself between frontmatter and body. No scope creep beyond the plan's stated purpose (aligning SCP public-facing text with the Phase 3 reframe).

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- SCP skill's description and both human-facing docs are now consistent with scp-checklist.md's Phase-3 living-source reframe; nothing left in this scope for the Phase 5 QUAL-01 sweep to flag on the SCP side
- Root-level Phase-5 docs (README.md, DEPLOYMENT.md, TESTING.md, CONTRIBUTING.md) were explicitly not touched, per plan scope — remain deferred to Phase 5
- 04-04 and 04-05 remain to complete Phase 04

## Self-Check: PASSED

- FOUND: skills/secure-coding-practices/SKILL.md (commit 3b2d6b3)
- FOUND: skills/secure-coding-practices/secure-coding-practices.md (commit 196d606)
- FOUND: skills/secure-coding-practices/README.md (commit 196d606)
- FOUND: commit 3b2d6b3 in git log
- FOUND: commit 196d606 in git log

---
*Phase: 04-skill-md-conversion-legacy-retirement*
*Completed: 2026-07-24*
