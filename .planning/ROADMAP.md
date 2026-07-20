# Roadmap: OWASP Security Skills Modernization

## Overview

This milestone takes a mature, working repo of two OWASP-grounded skills — `owasp-security-audit` and `secure-coding-practices` — and turns it into a credible, publicly distributable Claude Code plugin. The work runs in horizontal layers because each layer gates the next: the plugin/marketplace skeleton and locked directory convention must exist before content can be filed into its final home; the hard 2021→2025 Top 10 rewrite is isolated first because it's the single highest credibility risk; the remaining standards (ASVS, MASVS, API, LLM, Agentic Apps, Kubernetes, secure-coding-practices) are citation-hardening work that can proceed in parallel once the convention is set; both skills then convert to spec-compliant `SKILL.md` frontmatter and retire their legacy routing/manifest files now that the content they'll point to is final; and packaging validation plus public-release polish comes last, because testing an install or writing a coverage matrix against not-yet-final content would be wasted effort.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Plugin/Marketplace Foundation** - Stand up `.claude-plugin/plugin.json` + `marketplace.json` and lock the target skill-directory convention that every later phase builds on
- [ ] **Phase 2: OWASP Top 10 Version Refresh** - Rewrite the Top 10 reference from 2021 to 2025 (Final) with correct category IDs, consistent everywhere it's cited
- [ ] **Phase 3: Remaining Standards Verification & Refresh** - Citation-harden ASVS, MASVS, API Security, LLM, Agentic Apps, and Kubernetes; re-derive secure-coding-practices against the living OWASP Developer Guide
- [ ] **Phase 4: SKILL.md Conversion & Legacy Retirement** - Convert both skills to spec-compliant frontmatter, retire legacy routing/manifest files, remap examples to new category IDs
- [ ] **Phase 5: Packaging Validation & Credibility Polish** - Verify clean-environment install end-to-end and ship the public-release trust signals (LICENSE, coverage matrix, README, CONTRIBUTING, discoverability)

## Phase Details

### Phase 1: Plugin/Marketplace Foundation

**Goal**: The repo has a valid, installable Claude Code plugin/marketplace skeleton, and both skills sit in a locked directory convention that every later phase relies on.
**Depends on**: Nothing (first phase)
**Requirements**: PKG-01, PKG-02, PKG-03
**Success Criteria** (what must be TRUE):

  1. `.claude-plugin/plugin.json` exists at repo root, contains only the closed official schema's fields (no custom fields ported from the old `skill.json`), and passes plugin validation
  2. `.claude-plugin/marketplace.json` exists and lists the plugin, resolvable via a local/self-hosted source
  3. `skills/owasp-security-audit/` and `skills/secure-coding-practices/` sit at plugin root (never inside `.claude-plugin/`), and each skill's examples are canonical and self-contained per skill (no fragile cross-directory or symlink references)
  4. The target skill-directory convention (`SKILL.md` + `references/` + `scripts/` + `assets/`) is documented so later phases have a fixed structure to file content into

**Plans**: 1/3 plans executed
**Wave 1**

- [x] 01-01-PLAN.md — Plugin & marketplace manifests (plugin.json + marketplace.json)
- [ ] 01-02-PLAN.md — Skill-directory convention doc (docs/SKILL-STRUCTURE.md) + PKG-03 structural lock

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 01-03-PLAN.md — Break-surface patches (install.sh + README) & legacy retirement (skill.json + root examples/)

### Phase 2: OWASP Top 10 Version Refresh

**Goal**: The Top 10 reference accurately reflects the 2025 Final edition, with every citation of it consistent across the repo.
**Depends on**: Phase 1
**Requirements**: CONT-01, CONT-02
**Success Criteria** (what must be TRUE):

  1. The Top 10 reference lists all 10 2025 categories with the official ID/name mapping (new A03 Software Supply Chain Failures, new A10 Mishandling of Exceptional Conditions, SSRF folded into A01, A02 reordered) — sourced from the official OWASP mapping, not hand-derived
  2. Every place a Top 10 category ID or name appears (skill body, references, examples, README, manifest) uses the 2025 label — no 2021-era IDs (A04, A06, A08, A10 old-style) remain anywhere
  3. The edition is recorded as Final (not RC) with an official OWASP source URL and retrieval date attached

**Plans**: TBD

### Phase 3: Remaining Standards Verification & Refresh

**Goal**: Every other OWASP standard cited by `owasp-security-audit`, and the checklist content of `secure-coding-practices`, is citation-hardened and traceable to a correctly-versioned, live OWASP source.
**Depends on**: Phase 1
**Requirements**: CONT-03, CONT-04, CONT-05
**Success Criteria** (what must be TRUE):

  1. ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Applications Top 10 (2026) each cite a verified official OWASP source URL and retrieval date in their reference file
  2. The Kubernetes reference cites the 2022 stable edition as primary, with the 2025 draft explicitly footnoted as in-progress and not presented as final
  3. `secure-coding-practices` content is re-derived against the living OWASP Developer Guide / Cheat Sheet Series / Proactive Controls, with the archived SCP Quick Reference Guide noted as historical origin, not cited as a current source

**Plans**: TBD

### Phase 4: SKILL.md Conversion & Legacy Retirement

**Goal**: Both skills are spec-compliant Anthropic Agent Skills, and no legacy routing or manifest file remains in the loaded path.
**Depends on**: Phase 2, Phase 3
**Requirements**: FMT-01, FMT-02, FMT-03, FMT-04, FMT-05, CONT-06
**Success Criteria** (what must be TRUE):

  1. Each skill's `SKILL.md` has frontmatter with `name` exactly matching its parent folder (≤64 chars) and `description` (≤1024 chars) stating what it does and when to use it, and passes lint (byte-0 frontmatter start, no angle brackets, only allowed bundled directories)
  2. Each `SKILL.md` body stays within the progressive-disclosure budget (~500 lines), with deep per-standard content living in `references/`, loaded on demand
  3. `owasp-css.instructions.md`, the custom `skill.json`, and the ~900-line `owasp-comprehensive-security-skills.md` no longer sit in the loaded path, and the routing behavior they used to provide is preserved through each skill's `description` (and `when_to_use`/`paths` where supported)
  4. Paired vulnerable/secure examples are re-validated against the updated standard requirement text (especially Top 10 2025) and mapped to the correct new category IDs

**Plans**: TBD

### Phase 5: Packaging Validation & Credibility Polish

**Goal**: A new user can discover, install, and trust the plugin end-to-end on a clean environment.
**Depends on**: Phase 4
**Requirements**: PKG-04, PKG-05, QUAL-01, QUAL-02, QUAL-03, ADPT-01, ADPT-02, ADPT-03, ADPT-04
**Success Criteria** (what must be TRUE):

  1. On a clean environment, `claude plugin validate`, marketplace add, install, and an activation smoke test all succeed end-to-end for both skills
  2. A single canonical version source drives every version string across the manifest, README, and both skills — no drift
  3. The README states an honest coverage matrix (exactly which editions are covered, and which intentionally are not), and every OWASP version/edition/category ID claim cites an official source URL with a retrieval date
  4. A LICENSE file exists at repo root; CONTRIBUTING plus a maintenance/versioning/update story is documented; repo topics/tags and marketplace category/keywords are set for discoverability
  5. Example credentials/secrets follow a clear placeholder convention — nothing that looks like a real, valid secret

**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Plugin/Marketplace Foundation | 1/3 | In Progress|  |
| 2. OWASP Top 10 Version Refresh | 0/TBD | Not started | - |
| 3. Remaining Standards Verification & Refresh | 0/TBD | Not started | - |
| 4. SKILL.md Conversion & Legacy Retirement | 0/TBD | Not started | - |
| 5. Packaging Validation & Credibility Polish | 0/TBD | Not started | - |
