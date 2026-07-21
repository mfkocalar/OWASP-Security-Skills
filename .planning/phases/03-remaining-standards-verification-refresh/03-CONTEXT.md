# Phase 3: Remaining Standards Verification & Refresh - Context

**Gathered:** 2026-07-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Every *other* OWASP standard cited by `owasp-security-audit` — and the checklist
content of `secure-coding-practices` — is citation-hardened and traceable to a
correctly-versioned, live OWASP source (CONT-03, CONT-04, CONT-05). This is a
verification + citation-hardening phase, not a taxonomy rewrite (Phase 2 already
handled the only hard version bump, the Top 10).

**In scope:**
- Citation-harden the 5 already-correctly-labeled standards: **ASVS 5.0.0**
  (`asvs.md`), **MASVS 2.1.0** (`masvs.md`), **API Security Top 10 2023**
  (`api-top10.md`), **LLM Top 10 2025** and **Agentic Apps Top 10 2026** (both in
  `llm-agentic.md`) — verified edition + official source URL + retrieval date (CONT-03).
- **Kubernetes** (`kubernetes-top10.md`): cite the **2022 stable** edition as
  primary; footnote the 2025 draft as in-progress, not final (CONT-04).
- **`secure-coding-practices`** re-derivation against the living OWASP Developer
  Guide / Cheat Sheet Series / Proactive Controls, QRG noted as archived origin (CONT-05).

**Out of scope (belongs to later phases):**
- OWASP Top 10 (done in Phase 2 — do not re-touch `top10.md`).
- `SKILL.md` frontmatter conversion + legacy-file retirement — Phase 4.
- Re-labeling paired **example files** to new category IDs — CONT-06 / Phase 4.
- Full README rewrite, LICENSE, and the QUAL-02 **coverage matrix** artifact — Phase 5
  (this phase *produces the per-standard verification metadata that feeds it*, but does
  not build the matrix).

</domain>

<decisions>
## Implementation Decisions

### SCP re-derivation depth (CONT-05)
- **D-01:** **Light re-anchor.** Preserve the existing 14-domain checklist
  structure and its 100+ items (honors the "refresh, not teardown" compatibility
  constraint). Do NOT restructure around Proactive Controls and do NOT rebuild
  content from scratch. (Chosen over "restructure to Proactive Controls" and
  "full content rebuild".)
- **D-02:** **Per-domain crosswalk.** Add a crosswalk table mapping each of the
  14 domains to its living-source anchor (e.g., Input Validation → Input Validation
  Cheat Sheet + Proactive Control C3), each with an official source URL + retrieval
  date. Note the OWASP SCP Quick Reference Guide as the **archived historical origin**,
  not a current source. Granularity chosen for auditability (accuracy / QUAL-01 spirit)
  over a single blanket top-level statement.

### Citation-hardening format — the 5 already-versioned standards (CONT-03)
- **D-03:** **Mirror the Phase 2 convention.** For each of ASVS 5.0.0, MASVS 2.1.0,
  API Security 2023, LLM 2025, and Agentic Apps 2026: add a short **edition-verification
  note** inside the standard's reference file (edition + official source URL + retrieval
  date + verified status) AND a matching **`owasp-urls.json` entry** (`edition`,
  `retrieval_date`, `confidence: verified`). This self-documents each file when loaded and
  directly feeds the Phase 5 coverage matrix (QUAL-02). (Chosen over "owasp-urls.json only".)

### Agentic Apps 2026 & Kubernetes (CONT-03, CONT-04)
- **D-04:** **Agentic Apps 2026 — primary source + Final-gate.** Pull the exact
  **ASI01–ASI10 IDs/names verbatim from the official OWASP Agentic Apps Top 10 primary
  source** (NOT the paraphrase in prior research — STATE.md flagged this gap). Apply
  Phase 2's D-04 rule: if the edition is still **RC/draft or unverifiable** at research
  time, **halt the relabel, keep provenance conservative, and flag status + date** rather
  than presenting a draft as final.
- **D-05:** **Kubernetes — minimal footnote.** Keep **2022 stable** as the primary
  cited edition; add a **one-line footnote** noting a 2025 edition is in progress and not
  yet final. Do not enumerate draft categories as if authoritative. (Chosen over a longer
  "what's changing" note.)

### Version-drift policy (carried forward, applies phase-wide)
- **D-06:** The **draft-as-final prohibition + halt-if-RC gate** established in Phase 2
  (D-04) extends to **every** standard verified here — not just Agentic. If live research
  finds any expected label is wrong (an edition bumped past ASVS 5.0.0 / MASVS 2.1.0, LLM
  2025 changed, etc.), **halt-and-flag**: record the discrepancy, cite the newest
  *verified stable* edition, and surface it rather than silently relabeling.

### Claude's Discretion
- Exact wording/placement of each per-file edition-verification note and the SCP
  crosswalk table, provided every edition/ID/URL is correct and traceable.
- Whether LLM 2025 and Agentic 2026 keep sharing `llm-agentic.md` or are split — a
  structural call for research/planner (Phase 4 owns file restructuring; keep them
  consistent here regardless).
- Per-domain source selection for the SCP crosswalk (which Cheat Sheet / Proactive
  Control best anchors each of the 14 domains) — a research task.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` §"Phase 3: Remaining Standards Verification & Refresh" — goal + 3 success criteria
- `.planning/REQUIREMENTS.md` — CONT-03, CONT-04, CONT-05 (this phase); QUAL-01/QUAL-02 (Phase 5, but fed by this phase's metadata)
- `.planning/PROJECT.md` §Constraints, §Key Decisions — accuracy constraint, draft-as-final prohibition
- `.planning/STATE.md` §Blockers/Concerns — Agentic ASI-name paraphrase gap + SCP scoping call (both resolved by D-04 / D-01)
- `.planning/phases/02-owasp-top-10-version-refresh/02-CONTEXT.md` §decisions — Phase 2 D-04 (Final-gate) and D-05 (owasp-urls.json convention) are the precedents D-03/D-06 mirror

### Standard reference files this phase hardens (owasp-security-audit loaded path)
- `skills/owasp-security-audit/references/asvs.md` — ASVS 5.0.0 edition note
- `skills/owasp-security-audit/references/masvs.md` — MASVS 2.1.0 edition note
- `skills/owasp-security-audit/references/api-top10.md` — API Security Top 10 2023 edition note
- `skills/owasp-security-audit/references/llm-agentic.md` — **both** LLM Top 10 2025 and Agentic Apps Top 10 2026 (ASI01–ASI10 land here)
- `skills/owasp-security-audit/references/kubernetes-top10.md` — 2022 stable primary + 2025-draft footnote
- `skills/owasp-security-audit/references/owasp-urls.json` — add/verify edition + retrieval_date + confidence for each standard above

### secure-coding-practices files this phase re-anchors
- `skills/secure-coding-practices/references/scp-checklist.md` — the 14-domain checklist (add crosswalk table here)
- `skills/secure-coding-practices/references/owasp-urls.json` — SCP skill's own URL index (living-source URLs + retrieval dates)
- `skills/secure-coding-practices/references/secure-patterns.md` — confirm no stale QRG-as-current citations

### Explicitly NOT touched
- `skills/owasp-security-audit/references/top10.md` — owned by Phase 2 (already 2025 Final)
- Paired example source files — CONT-06 / Phase 4
- Repo-root legacy files (`owasp-comprehensive-security-skills.md`, `owasp-css.instructions.md`) — Phase 4 deletes them

### External (verify live during research — do NOT rely on training recall)
- OWASP ASVS — confirm 5.0.0 is current stable + official URL/date
- OWASP MASVS — confirm 2.1.0 + official URL/date
- OWASP API Security Top 10 — confirm 2023 + official URL/date
- OWASP LLM Top 10 — confirm 2025 edition + official URL/date
- OWASP Agentic Apps Top 10 — **primary source for exact ASI01–ASI10 + Final-vs-RC status** (D-04)
- OWASP Kubernetes Top 10 — confirm 2022 stable; verify 2025 draft status for the footnote
- OWASP Developer Guide / Cheat Sheet Series / Proactive Controls — living sources for the SCP crosswalk (D-02)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Phase 2 already established the `owasp-urls.json` entry shape (`edition`,
  `retrieval_date`, `confidence: verified`) and the in-file prose edition-note pattern in
  `top10.md` — reuse both verbatim for the 5 standards and the SCP files (D-03).
- The 14-domain `scp-checklist.md` structure is strong and stays intact (D-01) — the
  crosswalk table is additive, not a rewrite.

### Established Patterns
- Repo uses **plain codes + prose edition notes** (not colon-suffixed `:YYYY` codes) and
  kebab-case filenames; keep that style in every new note.
- **Two separate `owasp-urls.json` files** exist — one per skill
  (`owasp-security-audit/references/` and `secure-coding-practices/references/`). Hardening
  must update the correct file per skill; they are not shared.

### Integration Points
- `llm-agentic.md` is a **shared** file for two standards (LLM 2025 + Agentic 2026) — both
  edition notes live there; do not assume one-file-per-standard.
- Verification metadata recorded here is the upstream input to the Phase 5 QUAL-02 coverage matrix.

</code_context>

<specifics>
## Specific Ideas

- Phase-wide guardrail: **halt-and-flag beats silent relabel** whenever a live edition/status
  contradicts the expected label (D-06) — protects the project's #1 accuracy/credibility constraint.
- SCP crosswalk is the one place per-domain living-source URLs + retrieval dates are recorded (D-02).
- Kubernetes stays deliberately conservative: 2022 primary, one-line 2025-draft footnote (D-05).

</specifics>

<deferred>
## Deferred Ideas

- **QUAL-02 coverage matrix** (which editions are covered vs. intentionally not) — Phase 5; this
  phase only produces the per-standard verification metadata that feeds it.
- **Kubernetes Top 10 2025 adoption** once final/stable — v2 (EXP-02); Phase 3 keeps 2022 primary.
- **Splitting `llm-agentic.md`** into separate LLM / Agentic files — a Phase 4 file-structure concern,
  not required for citation-hardening.

None of the above are new scope — all are already roadmapped to later phases or v2.

</deferred>

---

*Phase: 3-remaining-standards-verification-refresh*
*Context gathered: 2026-07-21*
