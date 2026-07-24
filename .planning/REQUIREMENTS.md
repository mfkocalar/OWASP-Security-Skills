# Requirements: OWASP Security Skills

**Defined:** 2026-07-19
**Core Value:** A developer can install the collection into Claude Code and get accurate, current, OWASP-grounded security review — reference content matching the latest published OWASP editions, packaging matching the official skill spec.

## v1 Requirements

Requirements for this modernization milestone. Each maps to roadmap phases.

### Content — OWASP Version Refresh

- [x] **CONT-01**: `owasp-security-audit` Top 10 reference is updated 2021 → 2025 (Final) using OWASP's official category mapping (new A03 Supply Chain Failures, new A10 Exceptional Conditions, SSRF folded into A01, reordered A02)
- [x] **CONT-02**: Top 10 category IDs, names, and cross-references are consistent everywhere they appear (skill body, references, examples, README, manifest)
- [x] **CONT-03**: ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Apps (2026) references are citation-hardened with verified edition, official source URL, and retrieval date
- [x] **CONT-04**: Kubernetes reference cites the 2022 stable edition; the 2025 draft is footnoted as in-progress (not presented as final)
- [x] **CONT-05**: `secure-coding-practices` is re-derived against the living OWASP Developer Guide / Cheat Sheet Series / Proactive Controls (the archived SCP Quick Reference Guide origin is noted)
- [x] **CONT-06**: Paired vulnerable/secure examples are re-validated against the updated standard requirement text (especially Top 10 2025) and mapped to the correct new category IDs

### Format — Agent Skills Spec Conversion

- [x] **FMT-01**: Each skill has a spec-compliant `SKILL.md` — frontmatter `name` matches the parent folder and is ≤64 chars; `description` is ≤1024 chars and states what the skill does + when to use it
- [x] **FMT-02**: `SKILL.md` bodies stay within the progressive-disclosure budget (~500 lines); deep content lives in `references/`, loaded on demand
- [x] **FMT-03**: The routing/activation behavior of the legacy `owasp-css.instructions.md` is preserved through per-skill `description` (and `when_to_use`/`paths` where supported)
- [ ] **FMT-04**: Legacy files are retired — `owasp-css.instructions.md`, custom `skill.json`, and the ~900-line `owasp-comprehensive-security-skills.md` no longer sit in the loaded path
- [x] **FMT-05**: Skill frontmatter passes lint — byte-0 frontmatter start, no angle brackets, only allowed bundled directories

### Packaging — Plugin & Marketplace

- [x] **PKG-01**: `.claude-plugin/plugin.json` exists at repo root with required plugin identity fields
- [x] **PKG-02**: `.claude-plugin/marketplace.json` exists and lists the plugin(s) for distribution
- [x] **PKG-03**: `skills/` stays at plugin root (never inside `.claude-plugin/`); each skill's examples are canonical per-skill so they survive copy-on-install (no fragile cross-dir/symlink references)
- [ ] **PKG-04**: Install is verified end-to-end on a clean environment (`claude plugin validate`, marketplace add, install, activation smoke test)
- [ ] **PKG-05**: A single canonical version source drives all version strings (no drift across manifest, README, and skills)

### Quality — Accuracy & Verification

- [ ] **QUAL-01**: Every OWASP version/edition/category ID cites an official OWASP source URL with a retrieval date
- [ ] **QUAL-02**: A coverage matrix documents exactly which editions are covered and which are intentionally not (honest, no overclaiming of detection capability)
- [ ] **QUAL-03**: Example credentials/secrets use a clear placeholder convention (nothing that looks like a real, valid secret)

### Adoption — Public-Release Polish

- [ ] **ADPT-01**: A LICENSE file is added (currently missing)
- [ ] **ADPT-02**: README is refreshed — what/why, install steps, usage, the coverage matrix, and status badges
- [ ] **ADPT-03**: CONTRIBUTING and a maintenance/versioning/update story are documented
- [ ] **ADPT-04**: Discoverability metadata is set — repo topics/tags and marketplace category/keywords

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Evaluation & Trust

- **EVAL-01**: An `evals/` folder with correctness tests for skill activation and finding accuracy
- **EVAL-02**: OpenSSF Best Practices badge pursued
- **EVAL-03**: Submission to relevant "awesome" lists / community marketplaces

### Expansion

- **EXP-01**: Import and modernize the 15 global cyber-domain skills into this repo
- **EXP-02**: Adopt Kubernetes Top 10 2025 once it reaches final/stable

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Live SAST engine / autonomous auto-fix | Repo is reference/guidance-driven, not a runtime scanner; conflicts with Core Value |
| Importing the 15 global cyber-domain skills (this milestone) | They live outside this repo; deferred to v2 EXP-01 |
| Presenting draft OWASP editions as final | Credibility risk; cite stable editions, footnote drafts |
| CI/CD / VCS / live-system integrations | Reviews stay stateless and prompt/filesystem-scoped |
| New example languages beyond Python/JS/YAML/HTML | Not required unless an updated standard demands it |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| PKG-01 | Phase 1 | Complete |
| PKG-02 | Phase 1 | Complete |
| PKG-03 | Phase 1 | Complete |
| CONT-01 | Phase 2 | Complete |
| CONT-02 | Phase 2 | Complete |
| CONT-03 | Phase 3 | Complete |
| CONT-04 | Phase 3 | Complete |
| CONT-05 | Phase 3 | Complete |
| FMT-01 | Phase 4 | Complete |
| FMT-02 | Phase 4 | Complete |
| FMT-03 | Phase 4 | Complete |
| FMT-04 | Phase 4 | Pending |
| FMT-05 | Phase 4 | Complete |
| CONT-06 | Phase 4 | Complete |
| PKG-04 | Phase 5 | Pending |
| PKG-05 | Phase 5 | Pending |
| QUAL-01 | Phase 5 | Pending |
| QUAL-02 | Phase 5 | Pending |
| QUAL-03 | Phase 5 | Pending |
| ADPT-01 | Phase 5 | Pending |
| ADPT-02 | Phase 5 | Pending |
| ADPT-03 | Phase 5 | Pending |
| ADPT-04 | Phase 5 | Pending |

**Coverage:**

- v1 requirements: 23 total
- Mapped to phases: 23 (Phase 1: 3, Phase 2: 2, Phase 3: 3, Phase 4: 6, Phase 5: 9)
- Unmapped: 0 ✓

---
*Requirements defined: 2026-07-19*
*Last updated: 2026-07-19 after roadmap creation*
