# Phase 2: OWASP Top 10 Version Refresh - Context

**Gathered:** 2026-07-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Rewrite the `owasp-security-audit` Top 10 reference from the 2021 edition to the
2025 (Final) edition — correct category IDs, names, and ordering; SSRF folded
into A01; net-new A03 (Software Supply Chain Failures) and A10 (Mishandling of
Exceptional Conditions) — and make every citation of a Top 10 category ID or
name consistent across the loaded skill path and README (CONT-01, CONT-02).

**In scope:**
- Full 2021→2025 rewrite of `skills/owasp-security-audit/references/top10.md` (CONT-01)
- Top 10 ID/name/cross-reference consistency sweep across the **loaded path**:
  `skills/owasp-security-audit/SKILL.md`, `owasp-security-audit.md`,
  `references/*.md` (esp. `llm-agentic.md`, `vulnerable-patterns.md`),
  `references/owasp-urls.json`, `scripts/quick_scan.py`, and `README.md` (CONT-02)
- Record the edition as **Final** with an official OWASP source URL + retrieval date

**Out of scope (belongs to later phases):**
- Citation-hardening of the *other* standards (ASVS, MASVS, API, LLM, Agentic, K8s) — Phase 3
- `secure-coding-practices` re-derivation — Phase 3
- Re-labeling the paired **example files** to new category IDs — CONT-06 / **Phase 4**
- `SKILL.md` frontmatter conversion + legacy retirement — Phase 4
- Legacy files `owasp-comprehensive-security-skills.md` (repo root) and
  `owasp-css.instructions.md` — **not touched here** (Phase 4 deletes them)
- README full rewrite / coverage matrix / LICENSE — Phase 5

</domain>

<decisions>
## Implementation Decisions

### Edition-change presentation
- **D-01:** Present the 2021→2025 move with a **mapping table near the top of
  `top10.md` PLUS short inline cross-references** at each affected category
  (e.g., "SSRF — formerly A10 in the 2021 edition — is now assessed under A01").
  Rationale: readers may still know the list by its 2021 identifiers; the table +
  breadcrumbs bridge them without cluttering. (Chosen over clean-2025-only and
  appendix-only.)

### Phase 2 vs Phase 4 boundary
- **D-02:** Phase 2 updates the **loaded path only**: `top10.md`, `SKILL.md`,
  `owasp-security-audit.md`, the other `references/*.md`, `owasp-urls.json`,
  `quick_scan.py`, and `README.md`. **Leave** `owasp-comprehensive-security-skills.md`
  and `owasp-css.instructions.md` untouched — Phase 4 deletes them, so scrubbing
  2021 IDs there is throwaway work. **Example-file category re-labeling stays
  CONT-06 / Phase 4** and is NOT pulled forward.
- **D-03:** Interpret ROADMAP SC2's "no 2021-era IDs remain **anywhere**" as
  "anywhere in the loaded/shipping path," consistent with D-02. The two doomed
  legacy files are the explicit, documented exception. Verify-phase should not
  fail Phase 2 on 2021 IDs surviving in those two files.

### Sourcing & Final-vs-RC policy
- **D-04:** The rewrite is gated on the edition being **Final**. If the researcher
  finds Top 10 2025 is still a **Release Candidate (not Final)** at research time:
  **halt the relabel, keep the reference on the currently-published 2021 edition,
  and flag it** (record RC status + date). Do not ship a draft as final — this
  protects the project's credibility constraint and the "never present drafts as
  final" rule. The phase's "Final" success criterion cannot be met against an RC,
  so the phase pauses / re-scopes rather than forcing the rewrite.
- **D-05:** Attach an **official OWASP source URL + retrieval date** to the recorded
  edition. The authoritative mapping must come from OWASP's official 2025
  publication/mapping, **not hand-derived and not training-data recall** (accuracy
  constraint). Fold the source URL into `references/owasp-urls.json` alongside the
  existing entries.

### Rewrite depth per category
- **D-06:** **Full refresh of all 10 categories** — each gets refreshed detection
  signals, mitigations, and a vulnerable/secure code example aligned to the 2025
  edition. This includes merging SSRF detection signals into A01 and writing A03
  (Software Supply Chain Failures) and A10 (Mishandling of Exceptional Conditions)
  from scratch. (Chosen over minimal-relabel and light-touch.)

### Claude's Discretion
- **`owasp-security-audit.md` vs `SKILL.md` are byte-identical (both 415 lines).**
  Researcher/planner to confirm which is canonical and whether `owasp-security-audit.md`
  is a redundant mirror to update in lockstep, or itself a Phase-4 retirement
  candidate. Keep them consistent regardless during Phase 2.
- Exact wording/format of the 2021→2025 mapping table and inline cross-reference
  phrasing, provided every 2025 category ID/name is correct and traceable.
- Precise placement of the new A03/A10 sections and how SSRF signals are woven
  into A01.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` §"Phase 2: OWASP Top 10 Version Refresh" — goal + 3 success criteria
- `.planning/REQUIREMENTS.md` — CONT-01, CONT-02 (this phase); CONT-06 (examples, deferred to Phase 4)
- `.planning/PROJECT.md` §Constraints, §Key Decisions — accuracy constraint, draft-as-final prohibition
- `.planning/STATE.md` §Accumulated Context — Phase 3 research gaps, scoping decisions carried forward

### Files this phase rewrites / sweeps (loaded path)
- `skills/owasp-security-audit/references/top10.md` — **primary rewrite target** (438 lines, currently 2021)
- `skills/owasp-security-audit/SKILL.md` — Top 10 references in skill body
- `skills/owasp-security-audit/owasp-security-audit.md` — byte-identical duplicate of SKILL.md (confirm canonical)
- `skills/owasp-security-audit/references/llm-agentic.md`, `vulnerable-patterns.md` — cross-reference Top 10 categories
- `skills/owasp-security-audit/references/owasp-urls.json` — source URLs; add 2025 Final URL + retrieval date
- `skills/owasp-security-audit/scripts/quick_scan.py` — any Top 10 category labels in output/mapping
- `README.md` — Top 10 mentions (keep valid; full rewrite is Phase 5)

### Explicitly NOT touched (Phase 4 deletes these)
- `owasp-comprehensive-security-skills.md` (repo root) — legacy consolidated reference
- `owasp-css.instructions.md` (repo root) — legacy routing file

### Codebase maps (existing analysis)
- `.planning/codebase/STRUCTURE.md` — directory layout
- `.planning/codebase/CONCERNS.md` — model-version staleness, single-source risks
- `.planning/codebase/CONVENTIONS.md` — naming/style conventions

### External (verify during research — do NOT rely on training recall)
- OWASP Top 10 project — <https://owasp.org/www-project-top-ten/> — confirm 2025 **Final vs RC** status,
  the official 2021→2025 category mapping, and the exact 2025 category IDs/names before any relabel.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `references/top10.md` already has a strong per-category structure (Detection signals →
  Mitigations → Code example) — reuse this shape for the 2025 rewrite, including the
  net-new A03/A10 sections.
- `references/owasp-urls.json` is the established home for canonical source URLs — the
  2025 Final URL + retrieval date go here (supports CONT-01's "source URL + retrieval date").

### Established Patterns
- Repo uses **plain `A01`–`A10` codes with a prose edition note**, NOT the `A01:2021`
  colon format. So "removing 2021 IDs" is about category **names, ordering, and prose
  edition notes** — not string-replacing a colon-suffixed code. Plan the sweep accordingly.
- kebab-case filenames; paired vulnerable/secure examples marked with `VULNERABLE`/`SECURE`.

### Integration Points
- **Manifests carry NO Top 10 IDs** (`.claude-plugin/plugin.json`, `marketplace.json` verified
  clean) — ROADMAP SC2's "manifest" scope is a no-op; do not hunt for changes there.
- Multiple reference files cross-reference Top 10 categories by name (llm-agentic.md,
  vulnerable-patterns.md) — the CONT-02 consistency sweep must cover these, not just top10.md.

</code_context>

<specifics>
## Specific Ideas

- Target edition: **OWASP Top 10 2025 (Final)** — new A03 Software Supply Chain Failures,
  new A10 Mishandling of Exceptional Conditions, SSRF folded into A01, A02 reordered.
- Presentation anchor: a "What changed: 2021 → 2025" mapping table + inline
  "formerly A0x:2021" breadcrumbs at each moved/folded category.
- Credibility gate is a hard stop: no relabel unless the edition is confirmed Final.

</specifics>

<deferred>
## Deferred Ideas

- **Example-file category re-labeling** (broken-access-control.py, cryptographic-failures.js,
  injection.js, etc. → 2025 IDs) — belongs to CONT-06 / Phase 4, once the standard text is final.
- **Scrubbing 2021 IDs from the two legacy files** — moot; Phase 4 deletes them.
- Kubernetes 2025-draft adoption — v2 (EXP-02); Phase 3 keeps 2022 stable as primary.

None of the above are new scope — all are already roadmapped to later phases.

</deferred>

---

*Phase: 2-owasp-top-10-version-refresh*
*Context gathered: 2026-07-21*
