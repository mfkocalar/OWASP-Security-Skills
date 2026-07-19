# Phase 1: Plugin/Marketplace Foundation - Context

**Gathered:** 2026-07-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Stand up a valid, installable Claude Code plugin/marketplace skeleton and lock the skill-directory convention every later phase files content into.

**In scope:**
- `.claude-plugin/plugin.json` (closed official schema fields only) — PKG-01
- `.claude-plugin/marketplace.json` listing the single plugin, resolvable via a self-hosted GitHub source — PKG-02
- Both skills sit at plugin root with canonical, self-contained per-skill examples (no cross-dir/symlink refs) — PKG-03
- A documented target skill-directory convention (`SKILL.md` + `references/` + `scripts/` + `assets/`) for phases 2–4 to file into — SC4
- Retire the root `skill.json` (directly superseded by `plugin.json`)
- Patch `install.sh` + README references that break when root `examples/` is deleted

**Out of scope (belongs to later phases):**
- OWASP content refresh (Top 10 2025, citation-hardening) — Phases 2–3
- `SKILL.md` frontmatter conversion + retiring `owasp-css.instructions.md` / `owasp-comprehensive-security-skills.md` — Phase 4
- Full README rewrite, coverage matrix, LICENSE, CONTRIBUTING, clean-env install validation — Phase 5

</domain>

<decisions>
## Implementation Decisions

### Plugin packaging shape
- **D-01:** Package as **one plugin** named **`owasp-security-skills`** that bundles both skills (`owasp-security-audit` + `secure-coding-practices`). ROADMAP/PROJECT consistently say "the plugin" (singular).
- **D-02:** `plugin.json` **version baseline = `0.1.0`** (reset from the old `skill.json` 1.1.0 lineage). Signals pre-1.0 while content refresh lands across phases 2–5; reaches `1.0.0` when the milestone ships clean.
- **D-03:** `plugin.json` contains **only the closed official plugin-schema fields**. None of the custom fields from the old `skill.json` (standards, activation, functionality, models, performance, metadata, examples_by_category, deployment, changelog, roadmap) get ported. Researcher must confirm the exact allowed field set against the official spec.

### Marketplace source
- **D-04:** `marketplace.json` lists the one plugin with a **GitHub source: `mfkocalar/OWASP-Security-Skills`** (this repo is the self-hosted marketplace; origin remote confirmed). Public-install ready. A local-path source is NOT added.

### Examples de-duplication (PKG-03)
- **D-05:** **Each skill owns its examples** in its own `assets/examples/`; **delete the root `examples/` directory** entirely. Single source of truth per skill, clean copy-on-install, no cross-directory dependency. (The 9 Top-10 examples already live in `owasp-security-audit/assets/examples/`; `secure-coding-practices` keeps its own 2 files.)
- **D-06:** Deleting root `examples/` breaks `install.sh` (example file-count check, lines ~100–105 and reference at ~146) and 8 README links (lines ~102–109). **Patch both in Phase 1** — update the `install.sh` example check and repoint README links to each skill's `assets/examples/` — so `main` stays consistent/installable at every phase boundary. (Full README rewrite still happens in Phase 5; this is just keeping links valid.)

### Convention documentation (SC4)
- **D-07:** Document the locked skill-directory convention in a dedicated **`docs/SKILL-STRUCTURE.md`** — the single canonical reference phases 2–4 (and contributors) cite. Not folded into CONTRIBUTING; not a repo-root `CONVENTIONS.md` (avoids collision with the existing `.planning/codebase/CONVENTIONS.md`).

### Legacy handling
- **D-08:** **Retire the root `skill.json` now** — it is directly superseded by `plugin.json` and two manifests at root risk plugin-validation ambiguity during phases 1–3.
- **D-09:** **Leave** `owasp-css.instructions.md`, `owasp-comprehensive-security-skills.md`, and `install.sh` in place for now — their formal retirement is Phase 4 (routing/manifest) / Phase 5 (install story), and Phase 4 depends on final content first. (Exception: `install.sh` gets the D-06 example-check patch, but is not removed.)

### Claude's Discretion
- Exact `plugin.json` / `marketplace.json` field names, ordering, and required-vs-optional structure — resolve against the official Claude Code plugin spec during research/planning.
- Precise structure/wording of `docs/SKILL-STRUCTURE.md`, provided it fixes the `SKILL.md` + `references/` + `scripts/` + `assets/` convention unambiguously.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` §"Phase 1: Plugin/Marketplace Foundation" — goal + 4 success criteria
- `.planning/REQUIREMENTS.md` — PKG-01, PKG-02, PKG-03 (Phase 1); PKG-05 (single version source, downstream)
- `.planning/PROJECT.md` §Constraints, §Key Decisions — distribution/format constraints

### Codebase maps (existing analysis)
- `.planning/codebase/STRUCTURE.md` — current directory layout, notes the examples duplication
- `.planning/codebase/CONCERNS.md` — install.sh single-point-of-failure, model-version staleness
- `.planning/codebase/CONVENTIONS.md` — naming/style conventions (kebab-case filenames, etc.)

### Files this phase touches
- `skill.json` (repo root) — to be **deleted** (superseded by plugin.json)
- `install.sh` §~100–105, ~146 — example-count check to patch after root `examples/` delete
- `README.md` §~89–109 — root `examples/` links to repoint at per-skill paths
- `examples/` (repo root) — to be **deleted** (9 files, all duplicated in `owasp-security-audit/assets/examples/`)
- `skills/owasp-security-audit/` and `skills/secure-coding-practices/` — canonical skill homes

### External (verify during research)
- Official Anthropic/Claude Code plugin spec — the closed `plugin.json` field schema and `marketplace.json` source-declaration format. Verify field set against the live spec; do NOT rely on training-data recall (accuracy constraint).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `skills/owasp-security-audit/assets/examples/` — already holds all 9 Top-10 example files (become canonical after root delete).
- `skills/secure-coding-practices/assets/examples/` — holds `vulnerable-examples.py` / `.js` (its own canonical set).
- Both skills already follow the progressive-disclosure layout (`SKILL.md` + `references/` + `scripts/` + `assets/`) — the convention to document in D-07 largely already exists; Phase 1 formalizes and locks it.

### Established Patterns
- No symlinks currently exist in `skills/` (verified) — examples are plain-file copies, so PKG-03's "no symlink refs" is already partially satisfied; the remaining work is de-duplication (D-05).
- kebab-case filenames, per-skill self-contained directories.

### Integration Points
- `install.sh` symlinks skill directories into assistant skill dirs and verifies file counts — it reads the root `examples/` dir, creating the D-06 dependency on the delete.
- README documents the repo layout and links example files — must stay valid at each phase boundary.

</code_context>

<specifics>
## Specific Ideas

- Plugin identity is fixed: `name: owasp-security-skills`, `version: 0.1.0`, marketplace GitHub source `mfkocalar/OWASP-Security-Skills`.
- Version-honesty principle: pre-1.0 until the milestone's credibility work (Top 10 2025, citations) ships in Phase 5 — reach `1.0.0` then. This baseline feeds PKG-05's single-canonical-version requirement downstream.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. Legacy-file retirement (`owasp-css.instructions.md`, `owasp-comprehensive-security-skills.md`, `install.sh` removal) and the full README/coverage-matrix rewrite are already roadmapped to Phases 4–5, not new ideas.

</deferred>

---

*Phase: 1-plugin-marketplace-foundation*
*Context gathered: 2026-07-19*
