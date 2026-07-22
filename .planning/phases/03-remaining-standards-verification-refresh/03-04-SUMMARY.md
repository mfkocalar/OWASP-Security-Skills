---
phase: 03-remaining-standards-verification-refresh
plan: 04
subsystem: docs
tags: [owasp, asvs, citation-accuracy, gap-closure]

# Dependency graph
requires:
  - phase: 03-remaining-standards-verification-refresh
    provides: 03-01's ASVS/MASVS/API/LLM/Agentic Apps edition-verification note precedent, which this plan reframes for ASVS specifically
provides:
  - asvs.md edition-verification note now discloses that its chapter/requirement numbering follows ASVS 4.0.3 while ASVS 5.0.0 remains the recorded current stable edition
  - asvs.md reporting exemplar (V2.1.5) now edition-labeled as a 4.0.3 identifier with an explicit instruction to verify against the edition being audited
affects: [phase-5-doc-polish, any-future-asvs-5.0.0-re-anchor]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Source-free reframe: resolve an edition/body numbering contradiction by disclosing the mismatch in prose rather than inventing externally-sourced IDs"

key-files:
  created: []
  modified:
    - skills/owasp-security-audit/references/asvs.md

key-decisions:
  - "Locked gap-closure approach: reframe the ASVS reference to be honest about its 4.0.3 numbering, not renumber the body to 5.0.0 V-series (per CONT-03 decision, avoids inventing unverified 5.0.0 requirement IDs)"

patterns-established:
  - "Numbering-disclosure clause pattern: when a reference's edition banner and body taxonomy diverge, add a prose clause naming both editions' mappings rather than silently relabeling"

requirements-completed: [CONT-03]

coverage:
  - id: D1
    description: "ASVS edition-verification note discloses 4.0.3 chapter/requirement numbering while retaining verified 5.0.0 provenance (URL, 2025-05-30 release, Retrieved 2026-07-22), with 5.0.0 V-series re-mapping named and deferred as a documented limitation"
    requirement: "CONT-03"
    verification:
      - kind: other
        ref: "grep -q '5.0.0' && grep -q 'Retrieved 2026-07-22' && grep -q '2025-05-30' && grep -q '4.0.3' && grep -q '^## Chapter 2: Authentication' && grep -c '^## Chapter' == 8 -- skills/owasp-security-audit/references/asvs.md"
        status: pass
    human_judgment: false
  - id: D2
    description: "V2.1.5 reporting exemplar edition-labeled as ASVS 4.0.3 identifier, with instruction to verify the exact requirement ID against the edition being audited; no substitute 5.0.0 ID invented"
    requirement: "CONT-03"
    verification:
      - kind: other
        ref: "grep -q 'V2.1.5' && grep -q '4.0.3 identifier' && grep -qi 'edition you are auditing' && grep -c '4.0.3' >= 2 -- skills/owasp-security-audit/references/asvs.md"
        status: pass
    human_judgment: false

# Metrics
duration: 2min
completed: 2026-07-22
status: complete
---

# Phase 3 Plan 4: ASVS Edition/Numbering Gap Closure Summary

**Reframed asvs.md's edition-verification note and reporting exemplar so the file no longer contradicts itself: it now honestly discloses ASVS 4.0.3 chapter/requirement numbering alongside verified ASVS 5.0.0 provenance, with the 5.0.0 V-series re-mapping named and explicitly deferred.**

## Performance

- **Duration:** 2 min
- **Started:** 2026-07-22T14:26:51Z
- **Completed:** 2026-07-22T14:28:08Z
- **Tasks:** 2 completed
- **Files modified:** 1

## Accomplishments
- Added a numbering-disclosure clause to the ASVS edition-verification note: retains verified 5.0.0 provenance (URL, 2025-05-30 release/venue, Retrieved 2026-07-22) and now explicitly states this reference follows ASVS 4.0.3 chapter/requirement numbering, naming the 5.0.0 V-series remap (Authentication=V6, Session Management=V7, Authorization=V8, Cryptography=V11, Configuration=V13, Validation split V1/V2) and marking full re-mapping as an intentionally deferred, documented limitation.
- Edition-labeled the `V2.1.5` reporting exemplar in the "Using this chapter-by-chapter" section as a 4.0.3 identifier, noted its 5.0.0 V6-series equivalent, and added an explicit instruction to confirm the exact requirement ID against the edition being audited before it lands in a compliance deliverable.
- Closed the verifier's blocking gap (roadmap SC1 / CONT-03): the edition note and body now agree on 4.0.3 numbering; the previously NOT-WIRED "edition note vs. body" key link is now WIRED.

## Task Commits

Each task was committed atomically:

1. **Task 1: Reframe the ASVS edition-verification note to disclose 4.0.3 numbering** - `c95a9dc` (docs)
2. **Task 2: Edition-label the V2.1.5 reporting exemplar so it is not read as a 5.0.0 ID** - `0ff26b9` (docs)

**Plan metadata:** commit pending (docs: complete plan)

## Files Created/Modified
- `skills/owasp-security-audit/references/asvs.md` - Edition-verification note gained a numbering-disclosure clause (4.0.3 body taxonomy vs. 5.0.0 current edition, deferred re-mapping); reporting exemplar's `V2.1.5` gained an edition label and edition-verification instruction

## Decisions Made
- Followed the locked gap-closure decision exactly: reframe (disclose the 4.0.3/5.0.0 mismatch in prose) rather than re-anchor (renumber chapters, invent a 5.0.0 requirement ID). No chapter heading was renumbered; no externally-sourced 5.0.0 control ID was introduced — verified by the `grep -c '^## Chapter' == 8` and `^## Chapter 2: Authentication` gates still passing after both edits.

## Deviations from Plan

None - plan executed exactly as written. Both tasks matched their `<action>` and `<acceptance_criteria>` blocks; all automated verification strings passed on first check except one self-caught wording issue (see below).

**Note (not a deviation, task-internal correction):** Task 2's first draft wrote "against the edition\n   you are auditing" across a markdown line-wrap, which the plan's own `grep -qi 'edition you are auditing'` acceptance check failed to match (grep does not match across a newline by default). Reworded the sentence to keep the phrase on one line before re-running verification, which then passed. No content or scope change — purely a line-wrap fix to satisfy the plan's own literal-string gate.

## Issues Encountered
None beyond the line-wrap self-correction noted above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- CONT-03's ASVS-specific blocking gap is closed; all five citation-hardened standards (ASVS, MASVS, API Security Top 10, LLM Top 10, Agentic Apps Top 10) now carry internally-consistent edition claims.
- No outstanding blockers for Phase 3 close-out. The full 5.0.0 V-series re-mapping remains a documented, intentionally deferred limitation (not a blocker) should a future milestone choose to re-anchor asvs.md to 5.0.0 numbering.

---
*Phase: 03-remaining-standards-verification-refresh*
*Completed: 2026-07-22*

## Self-Check: PASSED

- FOUND: skills/owasp-security-audit/references/asvs.md
- FOUND: .planning/phases/03-remaining-standards-verification-refresh/03-04-SUMMARY.md
- FOUND commit: c95a9dc
- FOUND commit: 0ff26b9
