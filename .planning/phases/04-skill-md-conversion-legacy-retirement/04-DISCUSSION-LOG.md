# Phase 4: SKILL.md Conversion & Legacy Retirement - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-23
**Phase:** 4-skill-md-conversion-legacy-retirement
**Areas discussed:** Legacy retirement scope, Example remapping depth (CONT-06), llm-agentic.md split, Description accuracy alignment

---

## Legacy retirement scope

Context: beyond the two roadmap-named root files (`owasp-css.instructions.md`,
`owasp-comprehensive-security-skills.md`; root `skill.json` already removed in Phase 1),
three stale docs live inside the skill folders.

| Option | Description | Selected |
|--------|-------------|----------|
| Delete dup, update SCP docs | Delete byte-identical `owasp-security-audit.md` duplicate; keep `secure-coding-practices.md` guide + SCP `README.md` but refresh stale QRG framing | ✓ |
| Delete all three | Delete the duplicate AND both SCP docs — leanest loaded path, loses human-facing guide/README | |
| Delete duplicate only | Delete only the duplicate; leave both SCP docs stale (defer accuracy fix to Phase 5) | |

**User's choice:** Delete dup, update SCP docs (Recommended)
**Notes:** Treated as givens (not questions): the two roadmap-named root files are deleted per FMT-04; `owasp-css.instructions.md` was read end-to-end and confirmed fully subsumed by the two SKILL.md descriptions, so it's safe to delete outright.

---

## Example remapping depth (CONT-06)

Context: example labels are stale/mixed-edition — `xss.html` cites 2017,
`prompt-injection.txt` uses `AG01` (not `ASI01`), misconfig still `A05`, `injection.js` unlabeled.

| Option | Description | Selected |
|--------|-------------|----------|
| Relabel + re-validate content | Topic-based ID remap + fix AG01→ASI01 + add missing labels + re-validate code against 2025 requirement text; no new files | ✓ |
| Relabel IDs only | Correct labels only; don't re-read code against new requirement text | |
| Relabel + re-validate + add new-category examples | Above plus author new example files for A03/A10/A04/A06/A08 | |

**User's choice:** Relabel + re-validate content (Recommended)
**Notes:** Matches the success criterion "re-validated against the updated standard requirement text." New-category example authoring declined → deferred.

---

## llm-agentic.md split

Context: Phase 3 explicitly deferred this structural call to Phase 4. One file
currently holds both LLM Top 10 (2025, LLM01–10) and Agentic Apps Top 10 (2026, ASI01–10).

| Option | Description | Selected |
|--------|-------------|----------|
| Split into llm.md + agentic.md | Two reference files; update SKILL.md routing table + owasp-urls.json refs; natural home for ASI prefix fix | ✓ |
| Keep combined | Leave both standards in one file — less churn, but mixes two editions/ID schemes | |

**User's choice:** Split into llm.md + agentic.md (Recommended)
**Notes:** Distinct standards with distinct ID schemes and editions; cleaner progressive-disclosure loading.

---

## Description accuracy alignment

Context: SKILL.md descriptions say "ASVS 5.0" (audit) and "Quick Reference Guide
checklist" (SCP) — Phase 3 reframed ASVS to 4.0.3 body numbering and QRG to archived origin.

| Option | Description | Selected |
|--------|-------------|----------|
| Update to match Phase 3 reframes | Align both descriptions with reframed content; keeps accuracy constraint end-to-end | ✓ |
| Leave descriptions as-is | Treat descriptions as pure activation text; leaves a description-vs-reference mismatch for Phase 5 to catch | |

**User's choice:** Update to match Phase 3 reframes (Recommended)
**Notes:** Routing breadth must stay equivalent (FMT-03); only the version phrasing changes.

---

## Claude's Discretion

- FMT-05 lint mechanics (byte-0 frontmatter start, angle-bracket prohibition, allowed bundled dirs, name/description length limits).
- `.DS_Store` hygiene — remove tracked `.DS_Store` under `skills/` as part of the cleanup (low-stakes, planner's call).
- Exact split filenames (`llm.md` / `agentic.md` recommended) and precise SCP-doc refresh wording.
- Delete-vs-edit operation ordering so `main` stays consistent at each commit.

## Deferred Ideas

- New-category example files for A03 Supply Chain, A10 Exceptional Conditions, and CONCERNS-noted A04/A06/A08 — user declined for Phase 4; future example-coverage phase or v2.
- `install.sh` removal + full README/coverage-matrix/LICENSE/CONTRIBUTING — Phase 5.
- DEPLOYMENT.md / TESTING.md staleness (removed root `skill.json`/`examples/`) — Phase 5 doc-polish.
