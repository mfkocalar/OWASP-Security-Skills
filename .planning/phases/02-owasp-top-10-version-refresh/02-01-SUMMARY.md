---
phase: 02-owasp-top-10-version-refresh
plan: 01
subsystem: reference-docs
tags: [owasp, top10, documentation, security-reference]

# Dependency graph
requires:
  - phase: 01-plugin-marketplace-foundation
    provides: skills at plugin root, docs/SKILL-STRUCTURE.md convention
provides:
  - top10.md rewritten to OWASP Top 10 2025 (Final) edition, topic-mapped from 2021
  - owasp-urls.json A01-A10 block rewritten to 2025 IDs/URLs with retrieval_date
affects: [02-02-consistency-sweep, phase-3-citation-hardening, phase-4-skill-format-conversion]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Topic-first category mapping (never numeric find-and-replace) when migrating OWASP editions"
    - "'What changed: 2021 to 2025' mapping table + per-category 'formerly A0x in the 2021 edition' breadcrumbs"

key-files:
  created: []
  modified:
    - skills/owasp-security-audit/references/top10.md
    - skills/owasp-security-audit/references/owasp-urls.json

key-decisions:
  - "Resolved every 2025 category by topic against 02-RESEARCH.md's official mapping table, not by carrying the 2021 number across (6 of 10 categories changed number and/or topic)"
  - "SSRF folded into A01 as a labeled sub-section citing CWE-918, reusing the 2021 A10 SSRF content verbatim (technical content unchanged, only its home category moved)"
  - "A03 (Software Supply Chain Failures) and A10 (Mishandling of Exceptional Conditions) written fresh from verified official OWASP source text, not adapted from any 2021 section"
  - "Edition recorded as '2025 (Final)' with source URL https://owasp.org/Top10/2025/ and retrieval date 2026-07-21 in both top10.md and owasp-urls.json"

patterns-established:
  - "Pattern 1: OWASP edition migrations must resolve categories by topic first, then assign the number — verified via 02-RESEARCH.md's Summary mapping table before any content is written"

requirements-completed: [CONT-01, CONT-02]

coverage:
  - id: D1
    description: "top10.md rewritten to 2025 Final edition: 10 topic-correct category headers, mapping table, breadcrumbs, net-new A03 + A10, SSRF folded into A01 with CWE-918"
    requirement: CONT-01
    verification:
      - kind: other
        ref: "grep -cE '^## A(0[1-9]|10):' skills/owasp-security-audit/references/top10.md (=10); grep for A02/A03/A04/A05/A06/A07/A10 headers, 'OWASP Top 10 2025 (Final)', '2026-07-21', 'CWE-918', 'what changed' — all pass"
        status: pass
    human_judgment: true
    rationale: "Per 02-VALIDATION.md Manual-Only Verifications, correctness of the topic-to-ID mapping (each 2025 category carries the right OWASP topic, not just the right count) cannot be asserted by grep alone and requires a human/agent diff against 02-RESEARCH.md's official mapping table."
  - id: D2
    description: "owasp-urls.json A01-A10 block rewritten to 2025 titles/URLs/edition/retrieval_date, top10_2025 index key, file remains valid JSON"
    requirement: CONT-02
    verification:
      - kind: other
        ref: "python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json; grep checks for zero '\"edition\": \"2021\"', A03/A04/A10 topic-correct titles, top10_2025 index key, >=10 retrieval_date fields — all pass"
        status: pass
    human_judgment: false

# Metrics
duration: 1min
completed: 2026-07-21
status: complete
---

# Phase 2 Plan 1: OWASP Top 10 2025 Refresh Summary

**Rewrote `top10.md` and the Top 10 block of `owasp-urls.json` from the 2021 edition to the OWASP Top 10 2025 (Final) edition, resolving every category by topic against the official OWASP mapping — not by numeric substitution.**

## Performance

- **Duration:** 1 min (task-to-task commit gap; work completed in a prior session)
- **Started:** 2026-07-21T13:19:31+02:00 (Task 1 commit)
- **Completed:** 2026-07-21T13:20:09+02:00 (Task 2 commit)
- **Tasks:** 2/2 completed
- **Files modified:** 2

## Accomplishments
- `top10.md` now presents all 10 OWASP Top 10:2025 categories in correct numeric order, each resolved by topic per 02-RESEARCH.md's mapping table (A02 Security Misconfiguration, A03 Software Supply Chain Failures [net-new], A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions [net-new])
- SSRF folded into A01 Broken Access Control as a labeled sub-section citing CWE-918, reusing the 2021-era SSRF detection signals/mitigations/code example verbatim
- Added a "What changed: 2021 to 2025" mapping table plus "formerly A0x in the 2021 edition" breadcrumbs at every moved/renamed/net-new category
- `owasp-urls.json` A01-A10 entries rewritten to 2025 titles/URLs, `edition: "2025"`, `retrieval_date: "2026-07-21"`, `confidence: "verified"`; `_indexes` key renamed `top10_2021` → `top10_2025`
- Edition recorded as `OWASP Top 10 2025 (Final)` with official source URL `https://owasp.org/Top10/2025/` and retrieval date `2026-07-21` in both files

## Task Commits

Each task was committed atomically:

1. **Task 1: Rewrite top10.md to the 2025 Final edition (topic-mapped)** - `3f23fbe` (feat)
2. **Task 2: Rewrite the Top 10 block of owasp-urls.json to 2025** - `3a80b06` (feat)

**Plan metadata:** pending (this commit)

## Files Created/Modified
- `skills/owasp-security-audit/references/top10.md` - Full 2025 (Final) rewrite: 10 topic-correct categories, mapping table, breadcrumbs, SSRF folded into A01 (CWE-918), fresh A03/A10 content
- `skills/owasp-security-audit/references/owasp-urls.json` - A01-A10 entries rewritten to 2025 IDs/URLs/edition/retrieval_date; `top10_2021` index key renamed to `top10_2025`

## Decisions Made
- Resolved every category by TOPIC against 02-RESEARCH.md's verified official mapping table rather than by numeric position — required because 6 of 10 categories changed number and/or underlying topic between editions (e.g. 2021's A05 Security Misconfiguration is not 2025's A05, which is now Injection).
- Reused the existing per-category document shape (Detection signals → Mitigations → Code example → Checklist) for all 10 categories, satisfying the "full refresh" requirement (D-06) without inventing a new document structure.
- Left `owasp-comprehensive-security-skills.md` and `owasp-css.instructions.md` untouched per D-02/D-03 (explicit Phase 4 deletion targets, out of scope here).

## Deviations from Plan

None - plan executed exactly as written. Both tasks' automated verification commands (header greps, edition/date/CWE-918 checks, JSON validity, zero stray `"edition": "2021"` occurrences, `top10_2025` index key, ≥10 `retrieval_date` fields) all pass as specified in the plan.

## Issues Encountered

None. This SUMMARY was generated by a continuation executor after discovering both task commits (`3f23fbe`, `3a80b06`) already existed on `main` with content matching every acceptance criterion in `02-01-PLAN.md`; the executor re-ran all automated verification commands from the plan (Task 1 verify block, Task 2 verify block, and the plan-level `<verification>` section) and confirmed all pass before writing this SUMMARY.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `top10.md` and `owasp-urls.json` are now the 2025 Final source of truth for the Top 10 taxonomy; Plan 02 (consistency sweep) can safely reference the new category IDs/names when updating `SKILL.md`, `owasp-security-audit.md`, `llm-agentic.md`, `vulnerable-patterns.md`, `quick_scan.py`, and `README.md`.
- No blockers. The manual topic-diff verification (02-VALIDATION.md Manual-Only Verifications) was performed against 02-RESEARCH.md's Summary mapping table during this session and found no mis-numbered topics.

---
*Phase: 02-owasp-top-10-version-refresh*
*Completed: 2026-07-21*

## Self-Check: PASSED

- FOUND: skills/owasp-security-audit/references/top10.md
- FOUND: skills/owasp-security-audit/references/owasp-urls.json
- FOUND: 3f23fbe (Task 1 commit)
- FOUND: 3a80b06 (Task 2 commit)
