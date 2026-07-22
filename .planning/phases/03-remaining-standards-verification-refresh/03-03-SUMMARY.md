---
phase: 03-remaining-standards-verification-refresh
plan: 03
subsystem: docs
tags: [owasp, secure-coding-practices, citation-hardening, provenance, cheat-sheet-series, proactive-controls, developer-guide]

# Dependency graph
requires:
  - phase: 03-remaining-standards-verification-refresh
    provides: "03-01/03-02 citation-hardening pattern (edition-verification note + owasp-urls.json entry shape) reused here for SCP re-anchoring"
provides:
  - "14-row Living-Source Crosswalk table in scp-checklist.md mapping every SCP domain to a living OWASP source"
  - "scp_domain_crosswalk machine-readable JSON mirror in the SCP skill's own owasp-urls.json"
  - "owasp_scp_guide marked status:archived with retrieval_date"
  - "secure-patterns.md provenance line reworded from QRG-as-current to QRG-as-archived-historical-origin"
affects: [secure-coding-practices skill, Phase 5 (public-release polish/docs)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Living-Source Crosswalk table: additive-only re-anchoring pattern (do not touch existing checklist body, D-01)"
    - "Weak-anchor surfacing: low-confidence citations explicitly labeled 'weaker anchor'/'ASSUMED' rather than silently upgraded"

key-files:
  created: []
  modified:
    - skills/secure-coding-practices/references/scp-checklist.md
    - skills/secure-coding-practices/references/owasp-urls.json
    - skills/secure-coding-practices/references/secure-patterns.md

key-decisions:
  - "QRG framed as archived historical origin (OWASP's own archival statement quoted verbatim) rather than removed or replaced — preserves existing 100+ checklist items unchanged (D-01)"
  - "File Management and Memory Management crosswalk anchors explicitly marked weak/ASSUMED in both scp-checklist.md and owasp-urls.json rather than silently presented as fully verified (03-RESEARCH.md Assumptions A2/A3)"
  - "scp_domain_crosswalk added as a new top-level JSON key in the SCP skill's own owasp-urls.json (separate file from the audit skill's owasp-urls.json — not shared)"

patterns-established:
  - "Living-Source Crosswalk pattern: additive table + JSON mirror for re-anchoring archived-guide content to living sources without touching the underlying checklist"

requirements-completed: [CONT-05]

coverage:
  - id: D1
    description: "scp-checklist.md carries a 14-row Living-Source Crosswalk table with archived-QRG framing and 2026-07-22 retrieval date; 100+ existing checklist items unchanged"
    requirement: "CONT-05"
    verification:
      - kind: other
        ref: "grep -c 'cheatsheetseries.owasp.org|devguide.owasp.org|top10proactive.owasp.org' skills/secure-coding-practices/references/scp-checklist.md → 14"
        status: pass
      - kind: other
        ref: "grep -qi 'archived' skills/secure-coding-practices/references/scp-checklist.md"
        status: pass
      - kind: other
        ref: "grep -q 'ASSUMED' and grep -qi 'weaker anchor' skills/secure-coding-practices/references/scp-checklist.md"
        status: pass
    human_judgment: false
  - id: D2
    description: "secure-coding-practices/owasp-urls.json marks owasp_scp_guide status archived and adds a 14-entry scp_domain_crosswalk key mirroring the checklist table"
    requirement: "CONT-05"
    verification:
      - kind: other
        ref: "python3 -m json.tool skills/secure-coding-practices/references/owasp-urls.json (valid JSON) + assert status=='archived' and len(scp_domain_crosswalk)==14"
        status: pass
    human_judgment: false
  - id: D3
    description: "secure-patterns.md's top provenance line reworded from QRG-as-current-reference to QRG-as-archived-historical-origin, pointing to the crosswalk"
    requirement: "CONT-05"
    verification:
      - kind: other
        ref: "grep -qi 'historical|archived' skills/secure-coding-practices/references/secure-patterns.md"
        status: pass
    human_judgment: false
  - id: D4
    description: "Manual spot-check of the two LOW-confidence anchors (File Upload Cheat Sheet for File Management, Developer Guide index for Memory Management) to confirm they actually cover the domain's controls"
    verification: []
    human_judgment: true
    rationale: "Plan's <verification> section explicitly calls this a manual-only check that must not be silently auto-passed or upgraded to 'verified' — requires a human to open the two URLs and judge topical coverage."

# Metrics
duration: 8min
completed: 2026-07-22
status: complete
---

# Phase 3 Plan 3: Secure Coding Practices Living-Source Re-Anchor Summary

**Re-anchored the secure-coding-practices skill's provenance from the archived OWASP SCP Quick Reference Guide to a 14-row living-source crosswalk (Cheat Sheet Series / Proactive Controls 2024 / Developer Guide), without touching the existing 100+-item checklist.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-22T12:17:01+02:00
- **Completed:** 2026-07-22T12:17:37+02:00
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- Added a 14-row Living-Source Crosswalk table to `scp-checklist.md`, mapping each SCP domain to a living OWASP source with URL, retrieval date (2026-07-22), and confidence — while leaving all 100+ existing checklist items untouched
- Mirrored the crosswalk into a new machine-readable `scp_domain_crosswalk` key in the SCP skill's own `owasp-urls.json`, and marked `owasp_scp_guide.status = "archived"`
- Reworded `secure-patterns.md`'s top provenance line from an implied-current QRG reference to an explicit "Historical origin" note pointing to the crosswalk

## Task Commits

Each task was committed atomically:

1. **Task 1: Add the 14-domain Living-Source Crosswalk table + archived-QRG note to scp-checklist.md** - `422cb6f` (docs)
2. **Task 2: Mark owasp_scp_guide archived + add scp_domain_crosswalk to the SCP owasp-urls.json** - `11b25c4` (docs)
3. **Task 3: Reword the stale QRG reference line in secure-patterns.md to historical origin** - `f4ce30d` (docs)

**Plan metadata:** (final commit follows this summary)

## Files Created/Modified
- `skills/secure-coding-practices/references/scp-checklist.md` - Added `## Living-Source Crosswalk` section (archived-QRG blockquote + 14-row table); reworded top `> **Reference:**` line to `> **Historical origin:**`; no other changes to the existing 100+ checklist items
- `skills/secure-coding-practices/references/owasp-urls.json` - Added `status: "archived"` + `retrieval_date` to `owasp_scp_guide`; added new top-level `scp_domain_crosswalk` key (14 entries, fields: domain/url/retrieval_date/confidence)
- `skills/secure-coding-practices/references/secure-patterns.md` - Reworded line 3 from `> **Reference:** OWASP Secure Coding Practices Quick Reference Guide` to a `> **Historical origin:**` note pointing at the crosswalk

## Decisions Made
- QRG framed as archived historical origin (quoting OWASP's own archival statement) rather than removed or replaced outright — this satisfies CONT-05's "re-derive" as new citations, not new content, per D-01/D-02 and 03-RESEARCH.md Pitfall 2
- File Management (row 12) and Memory Management (row 13) crosswalk anchors are explicitly labeled "CITED — weaker anchor" and "ASSUMED — weak anchor" respectively in both the markdown table and the JSON (`cited-weak` / `assumed` confidence values) rather than silently presented as fully verified, per 03-RESEARCH.md Assumptions A2/A3
- The SCP skill's `owasp-urls.json` is treated as a fully independent file from the audit skill's `owasp-urls.json` — the same entry shape (`domain`/`url`/`retrieval_date`/`confidence`) was applied but no data or references are shared between the two files

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- CONT-05 satisfied: all SCP citation-provenance requirements for this phase are complete (crosswalk table, JSON mirror, reworded provenance line)
- Phase 3 (Remaining Standards Verification & Refresh) plans 1-3 are now all complete
- **Outstanding manual-only item (per plan's `<verification>` section, tracked as coverage D4):** before final phase sign-off, a human should open the File Upload Cheat Sheet (File Management row) and the Developer Guide index (Memory Management row) to confirm each genuinely covers that domain's controls — these two rows are marked weak/ASSUMED and must not be silently upgraded to "verified" without that spot-check
- No blockers for Phase 4/5 — this was a citation-only change with no runtime attack surface

---
*Phase: 03-remaining-standards-verification-refresh*
*Completed: 2026-07-22*

## Self-Check: PASSED

All created/modified files exist on disk; all three task commits (`422cb6f`, `11b25c4`, `f4ce30d`) verified present in git log.
