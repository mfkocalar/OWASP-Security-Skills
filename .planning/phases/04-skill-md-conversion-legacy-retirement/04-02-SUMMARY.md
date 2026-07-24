---
phase: 04-skill-md-conversion-legacy-retirement
plan: 02
subsystem: audit-skill-references
tags: [markdown, owasp-llm, owasp-agentic, progressive-disclosure, skill-md]

# Dependency graph
requires: ["04-01"]
provides:
  - "skills/owasp-security-audit/references/llm.md — single-standard OWASP LLM Top 10 (2025) reference, LLM01-LLM10, split from llm-agentic.md"
  - "skills/owasp-security-audit/references/agentic.md — single-standard OWASP Agentic Applications Top 10 (2026) reference, ASI01-ASI10 + AG##->real-OWASP mapping table, split from llm-agentic.md"
  - "audit SKILL.md routing table and reference-file index repointed to llm.md/agentic.md; llm-agentic.md deleted from the tree"
  - "audit SKILL.md description no longer overclaims flat ASVS 5.0 coverage; aligned to asvs.md's disclosed 4.0.3-body-numbering edition note (D-06)"
affects: ["04-05"]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Single-standard reference header shape (one-paragraph 'load this when...' framing + Source:/Edition verification: block) applied to two new files, matching top10.md/masvs.md convention"
    - "Verbatim content-split discipline: body sections (## LLM0X / ## ASI0X headings, Detection signals/Mitigations, --- separators) carried over unchanged; only the file-level header and routing pointers changed"

key-files:
  created:
    - skills/owasp-security-audit/references/llm.md
    - skills/owasp-security-audit/references/agentic.md
  modified:
    - skills/owasp-security-audit/SKILL.md
  deleted:
    - skills/owasp-security-audit/references/llm-agentic.md

key-decisions:
  - "Split routing-table row into two rows (LLM row: SDK calls/prompts/RAG/model output; Agentic row: agent loops/tool-calling/multi-agent/MCP) rather than one row naming both files, to keep each row's trigger phrasing specific to its standard"
  - "D-06 ASVS description reworded to 'ASVS (4.0.3-numbered verification requirements; 5.0.0 is the current edition)' — names both facts (current stable edition + numbering basis) in one clause, matching asvs.md's own disclosure without inventing unverified 5.0.0-numbered content"
  - "ASVS reference-file-index bullet also updated with the same numbering-disclosure pointer, even though the plan's must_haves only named the description field, so the index entry doesn't contradict the just-fixed description two lines above it in the rendered file"

requirements-completed: [FMT-01, FMT-02, FMT-03, FMT-05]

coverage:
  - id: T1
    description: "references/llm.md holds all ten LLM01-LLM10 (2025) items verbatim with its own edition-verification header; zero ASI content"
    requirement: "FMT-02"
    verification:
      - kind: other
        ref: "grep -cE '^## LLM(0[1-9]|10)' references/llm.md returns 10"
        status: pass
      - kind: other
        ref: "grep -c '^## ASI' references/llm.md returns 0"
        status: pass
      - kind: other
        ref: "grep -c 'Edition verification\\|Retrieved' references/llm.md returns 2"
        status: pass
      - kind: other
        ref: "head -1 references/llm.md is a level-1 markdown title"
        status: pass
    human_judgment: false
  - id: T2
    description: "references/agentic.md holds all ten ASI01-ASI10 items + AG##->real-OWASP mapping table verbatim; llm-agentic.md deleted in the same commit"
    requirement: "FMT-02"
    verification:
      - kind: other
        ref: "grep -cE '^## ASI(0[1-9]|10)' references/agentic.md returns 10"
        status: pass
      - kind: other
        ref: "grep -ci Mapping references/agentic.md returns 1"
        status: pass
      - kind: other
        ref: "git ls-files | grep -c references/llm-agentic.md returns 0"
        status: pass
      - kind: other
        ref: "grep -c '^## LLM0' references/agentic.md returns 0"
        status: pass
    human_judgment: false
  - id: T3
    description: "SKILL.md routes to llm.md/agentic.md with zero references to the deleted combined file; description no longer overclaims ASVS 5.0; FMT-05 lint still passes; activation breadth unchanged"
    requirement: "FMT-03, FMT-05"
    verification:
      - kind: other
        ref: "grep -c llm-agentic SKILL.md returns 0"
        status: pass
      - kind: other
        ref: "grep -c references/llm.md SKILL.md >= 1 AND grep -c references/agentic.md SKILL.md >= 1 (both = 2)"
        status: pass
      - kind: other
        ref: "python3 scripts/lint_skill_md.py skills/owasp-security-audit/ exits 0 (all 12 checks pass, description length 807 <= 1024)"
        status: pass
      - kind: other
        ref: "grep -c 'Use this skill whenever' SKILL.md returns 1 (activation phrasing intact)"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-24
status: complete
---

# Phase 04 Plan 02: LLM/Agentic Reference Split + ASVS Description Fix Summary

**Split the 555-line combined llm-agentic.md into single-standard references/llm.md (LLM Top 10 2025) and references/agentic.md (Agentic Apps Top 10 2026 + AG## mapping table), repointed the audit SKILL.md's two reference sites, and fixed the description's ASVS 5.0 overclaim to match asvs.md's 4.0.3-numbering disclosure**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-24 (session continuation from 04-01)
- **Tasks:** 3 completed
- **Files modified:** 4 (2 created, 1 edited, 1 deleted)

## Accomplishments

- Created `references/llm.md`: LLM01:2025-LLM10:2025 body carried over verbatim from `llm-agentic.md`'s Part 1, prefixed with a single-standard header (usage framing + Source/Edition-verification block) matching `top10.md`/`masvs.md` convention. Verified 10/10 LLM headings present, 0 ASI leakage.
- Created `references/agentic.md`: ASI01-ASI10 body carried over verbatim from Part 2, plus the AG##->real-OWASP-item mapping table, with its own single-standard header. Verified 10/10 ASI headings present, mapping table present, 0 LLM body leakage. Deleted `references/llm-agentic.md` in the same task/commit so no dangling combined file exists on `main`.
- Repointed `skills/owasp-security-audit/SKILL.md`: the "How to route" table's single combined-file row became two specific rows (LLM row and Agentic row); the reference-file-index's one bullet became two bullets. Both `references/llm.md` and `references/agentic.md` are now referenced (2 hits each); zero remaining `llm-agentic` references in `SKILL.md`.
- Applied D-06: reworded the frontmatter `description`'s flat `"ASVS 5.0"` phrase to `"ASVS (4.0.3-numbered verification requirements; 5.0.0 is the current edition)"`, aligning the public-facing description with `asvs.md`'s own numbering-disclosure note instead of contradicting it. Also updated the ASVS reference-file-index bullet with the same disclosure so the body doesn't contradict the fixed description two sections later.
- Re-ran `python3 scripts/lint_skill_md.py skills/owasp-security-audit/` after every SKILL.md edit — exits 0 throughout (12/12 checks pass; description length grew from 738 to 807 chars, still well under the 1024 limit; body grew from 411 to 417 lines, still under the 500-line guidance).

## Task Commits

Each task was committed atomically:

1. **Task 1: Create references/llm.md from Part 1 (LLM01-LLM10)** - `983f030` (feat)
2. **Task 2: Create references/agentic.md from Part 2 (ASI01-ASI10) + mapping table, delete llm-agentic.md** - `0ccfbeb` (feat)
3. **Task 3: Repoint SKILL.md routing + apply D-06 ASVS description fix** - `7457b20` (feat)

**Plan metadata:** (pending — this commit)

## Files Created/Modified

- `skills/owasp-security-audit/references/llm.md` (created, 287 lines) - LLM Top 10 2025 single-standard reference
- `skills/owasp-security-audit/references/agentic.md` (created, 269 lines) - Agentic Apps Top 10 2026 single-standard reference + AG## mapping table
- `skills/owasp-security-audit/references/llm-agentic.md` (deleted, 555 lines) - superseded by the two split files
- `skills/owasp-security-audit/SKILL.md` (modified) - routing table (2 rows replace 1), reference-file index (2 bullets replace 1), description ASVS phrasing (D-06), ASVS index-bullet numbering disclosure

## Decisions Made

- Two separate routing-table rows (not one row naming both files) — the LLM row's trigger phrasing ("SDK calls, system prompts, RAG, model output handling") and the Agentic row's ("agent loops, tool/function calling, multi-agent systems, MCP servers") differ enough that collapsing them into one row would blur which file to load for non-agent LLM code vs. autonomous-agent code.
- D-06 description fix names both the numbering basis and the current edition in a single parenthetical (`ASVS (4.0.3-numbered verification requirements; 5.0.0 is the current edition)`) rather than dropping the ASVS mention or silently downgrading to "ASVS 4.0.3" (which would itself be inaccurate, since 5.0.0 is genuinely current) — this mirrors `asvs.md`'s own two-fact disclosure.
- Extended the D-06 fix to the ASVS reference-file-index bullet (not just the frontmatter description) even though the plan's acceptance criteria only gated on the description field — leaving the index bullet's old flat "ASVS 5.0" phrasing unfixed would have reintroduced the same description-vs-reference contradiction one file section later.

## Deviations from Plan

None — plan executed exactly as written. All three tasks' automated verification commands and acceptance criteria passed on the first attempt; no auto-fixes, blockers, or architectural questions arose.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The audit skill's LLM/agentic reference content now has a natural single-standard home for future edition bumps (`llm.md` for LLM-only editions, `agentic.md` for Agentic-only editions) without re-touching the other.
- 04-05 (which deletes `skills/owasp-security-audit/owasp-security-audit.md`, the byte-identical legacy duplicate of the pre-split `SKILL.md`) will remove that file's own stale `llm-agentic.md` reference as a side effect of the whole-file delete — confirmed out of scope for this plan (04-02's `files_modified` frontmatter lists only `llm.md`, `agentic.md`, `llm-agentic.md`, and the audit `SKILL.md`; the duplicate file belongs to 04-05's `files_modified`). `docs/SKILL-STRUCTURE.md`'s example directory-tree mention of `llm-agentic.md` is also out of this plan's scope (owned by Phase 1's canonical convention doc, not listed in 04-02's `files_modified`) — noted here for visibility, not acted on.
- No blockers for 04-03 (SCP skill description edit) or 04-04 (example relabeling), which depend on 04-01's lint tool but not on this plan's file changes.

---
*Phase: 04-skill-md-conversion-legacy-retirement*
*Completed: 2026-07-24*
