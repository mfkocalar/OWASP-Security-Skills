---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
current_phase: 4
current_phase_name: SKILL.md Conversion & Legacy Retirement
status: ready
stopped_at: Phase 4 planned
last_updated: "2026-07-24T09:07:41.000Z"
last_activity: 2026-07-24
last_activity_desc: Phase 4 planned — 5 plans in 4 waves
progress:
  total_phases: 5
  completed_phases: 3
  total_plans: 9
  completed_plans: 9
  percent: 60
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-23)

**Core value:** A security engineer or developer can install the collection into Claude Code and get accurate, current, OWASP-grounded security review — reference content matching the latest published OWASP editions, packaging matching the official skill spec.
**Current focus:** Phase 4 — SKILL.md Conversion & Legacy Retirement

## Current Position

Phase: 4 — SKILL.md Conversion & Legacy Retirement
Plan: 5 plans created (Waves 1–4)
Status: Ready to execute Phase 4 — 5 plans in 4 waves (planned 2026-07-24; research done, plan verification passed)
Last activity: 2026-07-24 — Phase 4 planned (research + 5 plans, verification passed)

Progress: [██████░░░░] 60%

## Performance Metrics

**Velocity:**

- Total plans completed: 9
- Average duration: - min
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01 | 3 | - | - |
| 02 | 2 | - | - |
| 3 | 4 | - | - |

**Recent Trend:**

- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
| Phase 01-plugin-marketplace-foundation P01 | 5min | 2 tasks | 2 files |
| Phase 01 P02 | 4min | 2 tasks | 1 files |
| Phase 01 P03 | 1min | 3 tasks | 3 files |
| Phase 02 P01 | 1min | 2 tasks | 2 files |
| Phase 02 P02 | 14min | 3 tasks | 6 files |
| Phase 03 P01 | 6min | 2 tasks | 4 files |
| Phase 03 P02 | 6 | 2 tasks | 2 files |
| Phase 03 P03 | 8min | 3 tasks | 3 files |
| Phase 03 P04 | 2min | 2 tasks | 1 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Scoping: only the 2 in-repo skills (owasp-security-audit, secure-coding-practices) are in scope; the 15 global cyber-domain skills are explicitly out of scope
- OWASP Top 10 is the only standard needing a hard version bump (2021 → 2025 Final); all others (ASVS, MASVS, API, LLM, Agentic Apps) are citation-hardening only
- Kubernetes Top 10: cite 2022 stable as primary, footnote the 2025 draft — never present the draft as final
- secure-coding-practices re-derived against the living OWASP Developer Guide / Cheat Sheet Series / Proactive Controls, since the SCP Quick Reference Guide is officially archived
- [Phase 01]: plugin.json version reset to 0.1.0 (D-02), intentionally breaking legacy 1.1.0 lineage; contains only official closed-schema fields, no legacy skill.json custom fields ported (D-03)
- [Phase 01]: marketplace.json lists a single plugin entry via a github source object (mfkocalar/OWASP-Security-Skills, D-04), no version key on the entry so plugin.json 0.1.0 stays authoritative
- [Phase 01]: docs/SKILL-STRUCTURE.md locked as the single canonical skill-directory convention doc (not folded into CONTRIBUTING or a repo-root CONVENTIONS.md) — Avoids collision with .planning/codebase/CONVENTIONS.md; gives phases 2-4 a fixed reference to file content into (D-07)
- [Phase 01]: PKG-03 structural compliance (no symlinks, skills at plugin root, per-skill canonical assets/examples/) verified and recorded inline in docs/SKILL-STRUCTURE.md — Makes the invariant auditable in later phases without re-deriving the checks
- [Phase 01]: install.sh and README.md patched to per-skill canonical paths before root skill.json/examples/ removal (D-05, D-08); DEPLOYMENT.md/TESTING.md staleness tracked for Phase 5
- [Phase 02]: top10.md rewritten topic-first against OWASP's official 2025 mapping (no numeric find-and-replace); 6 of 10 categories changed number and/or topic — Prevents mis-attributing 2021 content to the wrong 2025 category ID
- [Phase 02]: SSRF folded into A01 as a labeled CWE-918 sub-section; A03 Software Supply Chain Failures and A10 Mishandling of Exceptional Conditions written fresh from verified OWASP source text — SSRF technical content unchanged, only home category moved; A03/A10 have no 2021 equivalent content to adapt
- [Phase 02]: edition recorded as 2025 (Final) with source URL https://owasp.org/Top10/2025/ and retrieval date 2026-07-21 in both top10.md and owasp-urls.json — Satisfies D-04/D-05 sourcing gate; avoids presenting a draft as final
- [Phase 02]: Renumbered vulnerable-patterns.md and quick_scan.py Top 10 labels by topic (not literal number substitution) to avoid mislabeling categories that swap numbers across the 2021->2025 edition change — Old-A05 Misconfig moves to new-A02 while old-A03 Injection moves to new-A05; converting the non-colliding mapping first avoided double-converting an already-renumbered label
- [Phase 02]: Added __pycache__/ and *.pyc to .gitignore after the plan's own py_compile verification step left an untracked build artifact — Rule 3 blocking/untracked-file cleanup per task_commit_protocol; prevents recurring untracked pollution on every future verification run
- [Phase 03]: Mirrored Phase 2's top10.md edition-note convention verbatim for ASVS/MASVS/API/LLM/Agentic edition notes (per D-03)
- [Phase 03]: Agentic Apps 2026 note quotes the primary 2025-12-09 OWASP announcement verbatim and confirms Final status, resolving the STATE.md ASI-name paraphrase gap (per D-04)
- [Phase 03]: Kubernetes 2025 edition kept as footnote only (D-05/D-06); no formal 2025 release found, so halt-and-flag did not fire
- [Phase 03]: owasp-urls.json: all remaining CONT-03 codes (ASVS/MASVS/API1-10/LLM01-10/ASI01-10) upgraded to verified provenance with retrieval_date 2026-07-22; K01-10 dated only, no 2025 K0x added
- [Phase 03]: QRG framed as archived historical origin (not removed/replaced); 14-row Living-Source Crosswalk added to scp-checklist.md + scp_domain_crosswalk mirrored into SCP's owasp-urls.json, satisfying CONT-05 without touching the 100+-item checklist body (D-01, D-02)
- [Phase 03]: File Management and Memory Management crosswalk anchors explicitly flagged weak/ASSUMED (cited-weak / assumed confidence) rather than silently upgraded to verified, per 03-RESEARCH.md Assumptions A2/A3
- [Phase 03 gap 03-04]: Reframed asvs.md edition note + reporting exemplar to disclose 4.0.3 body numbering vs. verified 5.0.0 current edition (locked source-free reframe, not a re-anchor to the 5.0.0 V-series) — Closes CONT-03/CR-01 verifier gap without inventing unverified 5.0.0 requirement IDs

### Pending Todos

None yet.

### Blockers/Concerns

- RESOLVED [03-01]: Agentic Applications Top 10 (2026) ASI01–ASI10 category names confirmed verbatim against the primary 2025-12-09 OWASP announcement (zero discrepancy); llm-agentic.md provenance note upgraded accordingly.
- RESOLVED [Phase 3]: SCP scoping decided as D-01 light re-anchor (keep the 100+-item checklist body frozen; add a living-source crosswalk) — shipped in 03-03 and verified.
- Phase 5 should re-check current Claude Code version status for documented packaging regressions (symlink-to-cache, Windows path collapse, marketplace "0 skills" bug) before assuming they still apply.
- [Phase 01]: DEPLOYMENT.md and TESTING.md still reference the now-removed root `skill.json` and root `examples/` (DEPLOYMENT.md: 4 mentions; TESTING.md: 7+ mentions including a "Test 7.2: skill.json Completeness" section) — documentation-only staleness, deferred to Phase 5 doc-polish per 01-RESEARCH.md Open Question #1.

## Deferred Items

Items acknowledged and carried forward from previous milestone close:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| v2 | EVAL-01: evals/ folder for skill activation/finding accuracy | Deferred | Requirements definition |
| v2 | EVAL-02: OpenSSF Best Practices badge | Deferred | Requirements definition |
| v2 | EVAL-03: Awesome-list / community marketplace submissions | Deferred | Requirements definition |
| v2 | EXP-01: Import/modernize the 15 global cyber-domain skills | Deferred | Requirements definition |
| v2 | EXP-02: Adopt Kubernetes Top 10 2025 once final/stable | Deferred | Requirements definition |

## Session Continuity

Last session: 2026-07-23T12:39:21.488Z
Stopped at: Phase 4 planned (5 plans, ready to execute)
Resume file: .planning/phases/04-skill-md-conversion-legacy-retirement/04-01-PLAN.md
