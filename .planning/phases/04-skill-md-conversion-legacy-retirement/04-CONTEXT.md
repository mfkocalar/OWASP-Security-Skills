# Phase 4: SKILL.md Conversion & Legacy Retirement - Context

**Gathered:** 2026-07-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Both skills are spec-compliant Anthropic Agent Skills, and no legacy routing or
manifest file remains in the loaded path. Examples are remapped to the correct
2025 Top 10 category IDs and re-validated against the updated requirement text.
Covers FMT-01, FMT-02, FMT-03, FMT-04, FMT-05, CONT-06.

**Key current-state finding (verified 2026-07-23):** the frontmatter "conversion"
is *already substantially done* — both `SKILL.md` files already have
spec-compliant frontmatter (folder-matching `name`, a `description`) and sit
within the ~500-line progressive-disclosure budget (audit **415** lines, SCP
**256** lines). So FMT-01/FMT-02 are largely satisfied at entry. **The real
weight of this phase is retirement + doc cleanup + example remapping + a lint
pass**, not authoring frontmatter from scratch.

**In scope:**
- Retire the roadmap-named legacy files from the loaded path (FMT-04): repo-root
  `owasp-css.instructions.md` (114 lines) and `owasp-comprehensive-security-skills.md`
  (900 lines). Routing/activation is preserved via each skill's `description`
  (FMT-03) — already verified subsumed (see D-01 rationale).
- Retire the byte-identical in-skill duplicate `owasp-security-audit.md` (D-02).
- Refresh (do not delete) the two SCP human-facing docs to remove stale QRG
  framing (D-03).
- Remap all example category IDs to 2025 **by topic** + re-validate example code
  against the updated 2025 requirement text (CONT-06 / D-04).
- Split `references/llm-agentic.md` into `llm.md` + `agentic.md` (D-05).
- Update both `SKILL.md` `description` fields to match Phase 3 reframes (D-06).
- Frontmatter lint pass (FMT-05): byte-0 frontmatter start, no angle brackets,
  only allowed bundled directories.

**Out of scope (belongs to later phases):**
- Authoring brand-new example files for uncovered 2025 categories (A03 Supply
  Chain, A10 Exceptional Conditions, and the CONCERNS-noted A04/A06/A08 gaps) —
  see Deferred Ideas.
- Removing `install.sh` and the full README rewrite / coverage matrix / LICENSE /
  CONTRIBUTING — Phase 5 (PKG-04/05, QUAL-*, ADPT-*).
- Re-touching already-hardened reference content (`top10.md`, `asvs.md`,
  `masvs.md`, `api-top10.md`, `kubernetes-top10.md`, SCP checklist body) — Phases
  2–3 own these; this phase only *moves/splits/relabels*, never re-verifies editions.

</domain>

<decisions>
## Implementation Decisions

### Legacy retirement scope (FMT-03, FMT-04)
- **D-01:** **Delete `owasp-css.instructions.md` outright.** Its
  routing/activation content was read end-to-end during discussion and confirmed
  fully subsumed by the two `SKILL.md` `description` fields — and it is itself
  stale (says "seven/six OWASP standards", "Top 10 (2021)", points at the
  soon-deleted `owasp-comprehensive-security-skills.md` and the legacy
  `secure-coding-practices.md` guide). No routing content needs to be salvaged
  into the descriptions first; FMT-03 is satisfied by the existing descriptions.
- **D-02:** **Delete `owasp-comprehensive-security-skills.md` (900 lines) and the
  byte-identical in-skill duplicate `skills/owasp-security-audit/owasp-security-audit.md`.**
  The duplicate is `diff`-identical to `SKILL.md` (verified) — `SKILL.md` is
  authoritative. The 900-line monolith is superseded by the per-skill `references/`
  tree (its content already lives, refreshed, in Phases 2–3 reference files).
  **Planner must spot-check** that no unique, still-current content exists *only*
  in the 900-line file before deleting (salvage-check), but the expectation is a
  clean delete.
- **D-03:** **Keep, but refresh, the two SCP human-facing docs.** Retain
  `skills/secure-coding-practices/secure-coding-practices.md` (275-line guide) and
  `skills/secure-coding-practices/README.md` (234 lines); reword their stale
  "Quick Reference Guide checklist" framing to match Phase 3's archived-origin /
  living-source reframe (Developer Guide / Cheat Sheet Series / Proactive Controls).
  Rationale: they are useful human-facing docs and deleting them would leave the
  SCP skill with no README while removing onboarding value — but they must not
  contradict the reframed reference body. (Chosen over "delete all three" and
  "delete duplicate only, leave SCP docs stale".)

### Example remapping depth — CONT-06 (D-04)
- **D-04:** **Relabel by topic + re-validate code.** Remap every example's OWASP
  category ID to the 2025 edition **by topic, not literal number substitution**
  (Phase 2 precedent), fix the wrong Agentic prefix (`AG01` → **`ASI01`**, per
  Phase 3 D-04), and add the missing label on `injection.js`. **In addition**,
  re-validate each example's vulnerable/secure code against the 2025 requirement
  text — especially SSRF now folded into A01 (CWE-918), and the A02/A05 reorder
  (old-A05 Misconfig → new-A02; old-A03 Injection → new-A05). Matches the phase
  success criterion "re-validated against the updated standard requirement text."
  **No new example files are authored in this phase.**
  - Known stale labels to fix (verified): `xss.html` cites the **2017** edition;
    `prompt-injection.txt` uses `AG01`; `security-misconfiguration.py` still labeled
    A05; `injection.js` has no OWASP label; `broken-access-control.py` A01 (still
    A01 but must note SSRF now lives here); `cryptographic-failures.js` A02 and
    `logging-monitoring-failures.py` A09 need topic re-verification against 2025.

### File structure — llm-agentic split (D-05)
- **D-05:** **Split `references/llm-agentic.md` into `references/llm.md` (LLM Top 10
  2025, IDs LLM01–LLM10) + `references/agentic.md` (Agentic Apps Top 10 2026, IDs
  ASI01–ASI10).** Distinct standards, distinct ID schemes and editions; the split
  gives cleaner progressive-disclosure loading and a natural home for the ASI
  prefix. **Must also update** the `SKILL.md` routing table and both
  `owasp-urls.json` entry references that point at `llm-agentic.md`. Content of the
  edition notes carries over verbatim (Phase 3 already verified them).

### Description accuracy alignment (D-06)
- **D-06:** **Update both `SKILL.md` `description` fields to match Phase 3 reframes.**
  Soften the audit skill's "ASVS 5.0" phrasing to align with `asvs.md`'s disclosed
  4.0.3-body-numbering edition note; reword the SCP skill's "Quick Reference Guide
  checklist" to the living-source framing. Preserves the accuracy constraint
  end-to-end and removes a public-facing description-vs-reference contradiction the
  Phase 5 QUAL-01 sweep would otherwise flag. Do not otherwise change activation
  breadth (routing behavior must stay equivalent — FMT-03).

### Claude's Discretion
- **FMT-05 lint mechanics** — exact enforcement of byte-0 frontmatter start, no
  angle brackets in frontmatter, and "only allowed bundled directories"
  (`references/`, `scripts/`, `assets/`). Note: audit `description` currently
  contains straight double-quotes around example phrasings — confirm quotes are
  fine and only literal `<`/`>` angle brackets are disallowed.
- **`.DS_Store` hygiene** — tracked `.DS_Store` files exist under `skills/`
  (`skills/.DS_Store`, `skills/owasp-security-audit/.DS_Store`) and a build artifact
  `scripts/__pycache__/`. Since this phase already touches the loaded path, remove
  tracked `.DS_Store` from git (`.gitignore` already lists it) as part of the
  cleanup, supporting the FMT-05 clean-loaded-path spirit. Low-stakes; planner's call.
- Exact new filenames for the split (`llm.md` / `agentic.md` recommended) and the
  precise refresh wording of the two SCP docs, provided accuracy is preserved.
- Ordering of delete-vs-edit operations so `main` stays consistent at each commit.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` §"Phase 4: SKILL.md Conversion & Legacy Retirement" — goal + 4 success criteria
- `.planning/REQUIREMENTS.md` — FMT-01, FMT-02, FMT-03, FMT-04, FMT-05, CONT-06 (this phase)
- `.planning/PROJECT.md` §Constraints (Accuracy, Format, Compatibility), §Key Decisions
- `.planning/STATE.md` §Blockers/Concerns — Phase 1 doc-staleness note (DEPLOYMENT.md/TESTING.md → Phase 5)

### Prior-phase context (decisions that constrain this phase)
- `.planning/phases/01-plugin-marketplace-foundation/01-CONTEXT.md` §decisions — D-09 (css.instructions.md + comprehensive .md deliberately left for Phase 4; install.sh removal is Phase 5), D-07 (docs/SKILL-STRUCTURE.md is the canonical convention doc)
- `.planning/phases/02-owasp-top-10-version-refresh/02-CONTEXT.md` §decisions — topic-first (not literal-number) relabeling precedent for CONT-06; SSRF→A01, misconfig old-A05→new-A02
- `.planning/phases/03-remaining-standards-verification-refresh/03-CONTEXT.md` §decisions + §deferred — ASI01–ASI10 verbatim IDs (D-04), ASVS 4.0.3-body reframe, QRG archived reframe, and the explicit "splitting llm-agentic.md is a Phase 4 concern" deferral

### The canonical skill-directory convention
- `docs/SKILL-STRUCTURE.md` — locked in Phase 1 (D-07); the authority on the
  target `SKILL.md` + `references/` + `scripts/` + `assets/` layout. Plan must
  conform retirement/split work to this.

### Files this phase DELETES
- `owasp-css.instructions.md` (repo root, 114 lines) — routing subsumed by SKILL.md descriptions (D-01)
- `owasp-comprehensive-security-skills.md` (repo root, 900 lines) — superseded by per-skill references (D-02, salvage-check first)
- `skills/owasp-security-audit/owasp-security-audit.md` — byte-identical duplicate of SKILL.md (D-02)

### Files this phase EDITS / SPLITS
- `skills/owasp-security-audit/SKILL.md` — description update (D-06) + routing table update for the llm/agentic split (D-05)
- `skills/secure-coding-practices/SKILL.md` — description update (D-06)
- `skills/secure-coding-practices/secure-coding-practices.md` — refresh stale QRG framing (D-03)
- `skills/secure-coding-practices/README.md` — refresh stale QRG framing (D-03)
- `skills/owasp-security-audit/references/llm-agentic.md` → split into `references/llm.md` + `references/agentic.md` (D-05)
- `skills/owasp-security-audit/references/owasp-urls.json` — update refs that point at `llm-agentic.md` (D-05)
- `skills/owasp-security-audit/assets/examples/*` — relabel to 2025 IDs + re-validate code (D-04): `broken-access-control.py`, `cryptographic-failures.js`, `injection.js`, `security-misconfiguration.py`, `xss.html`, `logging-monitoring-failures.py`, `prompt-injection.txt` (AG01→ASI01), plus `api-auth-bypass.js`, `k8s-rbac.yaml` as needed

### Explicitly NOT touched (owned by other phases)
- `skills/owasp-security-audit/references/top10.md`, `asvs.md`, `masvs.md`, `api-top10.md`, `kubernetes-top10.md`, `vulnerable-patterns.md` — content owned by Phases 2–3 (edition-verified). This phase does not re-verify editions.
- `skills/secure-coding-practices/references/scp-checklist.md` body — Phase 3 froze the 100+-item body (D-01 light re-anchor)
- `install.sh`, root `README.md` full rewrite, `DEPLOYMENT.md`, `TESTING.md` — Phase 5

### External (verify live during research — do NOT rely on training recall)
- Official Anthropic Agent Skills spec — the FMT-05 lint rules (frontmatter byte-0 start, angle-bracket prohibition, allowed bundled directory set, `name`≤64 / `description`≤1024 limits). Confirm against the live spec.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Both `SKILL.md` files already carry spec-compliant frontmatter and are within
  the ~500-line budget — treat them as the authoritative skill definition; the
  in-skill `.md` guide files are secondary/legacy.
- `skills/*/references/owasp-urls.json` — two separate per-skill files (not
  shared); the split (D-05) touches only the audit skill's copy.
- Phase 2 established topic-first relabeling and the `owasp-urls.json` entry shape
  — reuse both for CONT-06 and the split.

### Established Patterns
- kebab-case filenames; per-skill self-contained directories; plain codes + prose
  edition notes (not colon-suffixed `:YYYY`).
- `owasp-css.instructions.md` used bold `**keyword**` activation-trigger lists —
  that routing job is now the `SKILL.md` `description`'s responsibility.

### Integration Points
- `SKILL.md` "How to route" table references `llm-agentic.md` — must be repointed
  to `llm.md` / `agentic.md` after the split (D-05), or routing breaks.
- Deleting the 900-line comprehensive file and css.instructions.md must not break
  any surviving cross-reference (grep the repo for links to both before deleting).
- `main` must stay consistent/installable at each commit boundary (Phase 1/2/3
  discipline) — stage deletes and reference-repoints in the right order.

</code_context>

<specifics>
## Specific Ideas

- Verified duplicate: `diff -q SKILL.md owasp-security-audit.md` → IDENTICAL — safe delete (D-02).
- Verified stale example labels: `xss.html` cites "the 2017 edition"; `prompt-injection.txt`
  headers use `AG01` (must become `ASI01`); `security-misconfiguration.py` still `A05`;
  `injection.js` carries no OWASP category label at all.
- `owasp-css.instructions.md` self-describes as "the backbone of the skill system"
  and points at now-deleted/renamed targets — a strong signal it is fully legacy.
- Accuracy is the project's #1 constraint: the D-06 description fixes and D-04
  re-validation exist to keep the public-facing skill internally consistent before
  the Phase 5 QUAL-01 sweep.

</specifics>

<deferred>
## Deferred Ideas

- **New-category example files** — authoring paired vulnerable/secure examples for
  2025 categories that currently lack them: **A03 Software Supply Chain Failures**,
  **A10 Mishandling of Exceptional Conditions**, plus the CONCERNS-noted gaps
  **A04 Insecure Design / A06 Vulnerable & Outdated Components / A08 Software & Data
  Integrity Failures**. User explicitly declined this scope for Phase 4 (chose
  "relabel + re-validate", not "+ add new-category examples"). Candidate for a
  future example-coverage phase or v2 — not new scope invented here.
- **install.sh removal + full README/coverage-matrix/LICENSE/CONTRIBUTING** — Phase 5.
- **DEPLOYMENT.md / TESTING.md staleness** (still reference removed root `skill.json`
  and root `examples/`) — Phase 5 doc-polish (carried from Phase 1).

</deferred>

---

*Phase: 4-skill-md-conversion-legacy-retirement*
*Context gathered: 2026-07-23*
