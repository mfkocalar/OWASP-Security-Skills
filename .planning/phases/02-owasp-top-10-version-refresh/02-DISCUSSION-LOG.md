# Phase 2: OWASP Top 10 Version Refresh - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-21
**Phase:** 02-owasp-top-10-version-refresh
**Areas discussed:** Edition-change presentation, Phase 2 vs Phase 4 boundary, Sourcing & Final-vs-RC, Rewrite depth per category

---

## Edition-change presentation

| Option | Description | Selected |
|--------|-------------|----------|
| Mapping table + inline cross-refs | A '2021 to 2025 changes' table near the top + short inline notes ("SSRF, formerly A10 in 2021, now under A01") | ✓ |
| Clean 2025-only, no history | Just the 10 current categories, no backward references | |
| Appendix mapping only | 2025 categories clean in the body; one migration appendix at the end | |

**User's choice:** Mapping table + inline cross-refs
**Notes:** Repo uses plain A01–A10 codes with a prose edition note (not the A01:2021 colon format), so the "relabel" is about names/order/prose, not code strings. → CONTEXT D-01.

---

## Phase 2 vs Phase 4 boundary

| Option | Description | Selected |
|--------|-------------|----------|
| Loaded path now; legacy left for Phase 4 | Update top10.md, SKILL.md, owasp-security-audit.md, references, README, manifest; leave the two legacy files (Phase 4 deletes them); example relabel stays CONT-06/Phase 4 | ✓ |
| Everything now, incl. doomed legacy files | Scrub every 2021 ID repo-wide even in files Phase 4 deletes | |
| Loaded path + examples now; legacy left | Also pull CONT-06 example relabeling forward, skip legacy files | |

**User's choice:** Loaded path now; legacy left for Phase 4
**Notes:** "no 2021 IDs anywhere" (SC2) interpreted as "anywhere in the loaded/shipping path"; the two doomed legacy files are the documented exception. Verified manifests carry no Top 10 IDs. → CONTEXT D-02, D-03.

---

## Sourcing & Final-vs-RC

| Option | Description | Selected |
|--------|-------------|----------|
| Halt relabel, keep 2021, flag it | Don't relabel to 2025 until Final; record RC status + date; pause/re-scope rather than ship a draft as final | ✓ |
| Proceed with RC, clearly marked | Rewrite to 2025 but label every citation "Release Candidate, not final" | |
| Researcher decides, document either way | Trust researcher verification; plan branches on the finding | |

**User's choice:** Halt relabel, keep 2021, flag it
**Notes:** Protects the credibility constraint and the "never present drafts as final" rule. → CONTEXT D-04, D-05.

---

## Rewrite depth per category

| Option | Description | Selected |
|--------|-------------|----------|
| Full refresh all 10 | Detection signals, mitigations, and a vulnerable/secure code example refreshed for 2025 across all 10, incl. SSRF merged into A01 and net-new A03/A10 | ✓ |
| Minimal: relabel + new A03/A10 only | Keep existing prose; fix IDs/names/order; write full content only for the two new categories | |
| Structural + new, light touch elsewhere | Fix IDs/order, merge SSRF, write A03/A10 fully, light updates elsewhere | |

**User's choice:** Full refresh all 10
**Notes:** → CONTEXT D-06.

## Claude's Discretion

- `owasp-security-audit.md` vs `SKILL.md` are byte-identical (415 lines each) — researcher/planner to confirm which is canonical and whether the duplicate is a Phase-4 retirement candidate.
- Exact wording/format of the mapping table and inline cross-references.
- Placement of net-new A03/A10 sections and how SSRF signals weave into A01.

## Deferred Ideas

- Example-file category re-labeling → CONT-06 / Phase 4.
- Scrubbing 2021 IDs from the two legacy files → moot (Phase 4 deletes them).
- Kubernetes 2025-draft adoption → v2 (EXP-02).
