# OWASP Security Skills

## What This Is

A pair of OWASP-focused security skills for Claude Code (and compatible AI coding assistants) that bring OWASP standards and secure-coding practices into automated code, infrastructure, and configuration review. This milestone modernizes the repo: OWASP content is refreshed to its newest published editions, both skills are restructured into Anthropic's official Agent Skills format, and the whole repo is polished for public distribution via the Claude Code plugin marketplace.

<!-- SCOPE NOTE (corrected 2026-07-19): This repository's skills/ directory contains only two skills — owasp-security-audit and secure-coding-practices. The 15 cyber-domain skills (recon, malware, red-team, etc.) are globally-installed skills living outside this repo (~/.claude/skills) and are NOT in scope for this milestone. -->


## Core Value

A security engineer or developer can install the collection into Claude Code and get accurate, current, OWASP-grounded security review — with the reference content matching the *latest* published OWASP editions and the packaging matching the *official* skill spec so it installs cleanly and is worth sharing.

## Requirements

### Validated

<!-- Inferred from existing codebase (see .planning/codebase/). Already built and relied upon. -->

- ✓ `owasp-security-audit` skill covering Top 10, ASVS, MASVS, API Security, Kubernetes, Agentic Apps — existing
- ✓ `secure-coding-practices` skill (14-domain, 100+ item checklist) — existing
- ✓ `quick_scan.py` regex-based lead scanner — existing
- ✓ Paired vulnerable/secure code examples (Python, JavaScript, YAML, HTML) — existing
- ✓ Symlink-based installer (`install.sh`) for Claude / Copilot / custom targets — existing
- ✓ Repo packaged as a Claude Code plugin with `.claude-plugin/plugin.json` + `.claude-plugin/marketplace.json`, skills at plugin root, skill-directory convention documented (`docs/SKILL-STRUCTURE.md`) — Validated in Phase 1: Plugin/Marketplace Foundation (PKG-01, PKG-02, PKG-03)
- ✓ OWASP Top 10 reference refreshed 2021 → 2025 (Final) using OWASP's official topic-based ID mapping — new A03 Software Supply Chain Failures, new A10 Mishandling of Exceptional Conditions, SSRF folded into A01 (CWE-918), A02 reordered — and made consistent across every cited file in the loaded skill path — Validated in Phase 2: OWASP Top 10 Version Refresh (CONT-01, CONT-02)
- ✓ Remaining OWASP standards citation-hardened with verified edition + official source URL + retrieval date (ASVS 5.0.0, MASVS 2.1.0, API Security 2023, LLM 2025, Agentic Apps 2026); Kubernetes cites 2022 stable with the 2025 edition explicitly footnoted as in-progress; `secure-coding-practices` re-anchored to living OWASP sources (Cheat Sheet Series / Proactive Controls 2024 / Developer Guide) with the archived SCP Quick Reference Guide noted as historical origin. ASVS reference reframed to disclose its 4.0.3 body numbering rather than falsely claim 5.0.0 taxonomy — Validated in Phase 3: Remaining Standards Verification & Refresh (CONT-03, CONT-04, CONT-05)
- ✓ Both skills converted to spec-compliant Anthropic Agent Skills — each `SKILL.md` has a folder-matching `name` (≤64) + `description` (≤1024) and a body within the ~500-line progressive-disclosure budget with deep content in `references/` (LLM/Agentic split into `llm.md` + `agentic.md`); the legacy `owasp-css.instructions.md`, custom `skill.json`, `owasp-comprehensive-security-skills.md`, and the in-skill `owasp-security-audit.md` duplicate retired from the loaded path with routing preserved via per-skill descriptions; paired examples re-validated and relabeled to the 2025/2026 category IDs; a stdlib-only `scripts/lint_skill_md.py` enforces the frontmatter spec — Validated in Phase 4: SKILL.md Conversion & Legacy Retirement (FMT-01, FMT-02, FMT-03, FMT-04, FMT-05, CONT-06)
- ✓ Public-release trust signals shipped and clean-environment install proven end-to-end: root MIT LICENSE; single canonical version (`plugin.json` 1.0.0) guarded by a stdlib-only `scripts/check_version_drift.py`; honest README (static-only badges, cited two-column coverage matrix + retrieval dates, a "What this is NOT" scope disclosure) with plugin/marketplace as the primary install path; CONTRIBUTING carrying the maintenance/versioning story, the example-secret placeholder convention, and a manual GitHub-topics command list; stale `DEPLOYMENT.md`/`TESTING.md` retired; example secrets normalized to self-labeling placeholders; `docs/SKILL-STRUCTURE.md` citations re-synced to the live SKILL.md editions; and a captured Checkpoint-1 transcript proving `claude plugin validate` + local-source install + discovery of BOTH skills (marketplace.json source override reverted clean) — Validated in Phase 5: Packaging Validation & Credibility Polish (PKG-04, PKG-05, QUAL-01, QUAL-02, QUAL-03, ADPT-01, ADPT-02, ADPT-03, ADPT-04)

### Active

<!-- This milestone. All are hypotheses until shipped and validated. -->

- ✓ Public-release polish: LICENSE, strong README, clear docs, working examples, low-friction/cross-platform install, and discoverability — delivered and verified in Phase 5 (see Validated above)
- ✓ Version accuracy verified — no OWASP edition, control ID, or standard change relies on unverified training-data recall — enforced by `check_version_drift.py` and cited owasp-urls.json provenance, validated in Phase 5

_All milestone requirements are content-complete and verified (16/16 must-haves, Phase 5). Remaining before v1.0 is declared shipped: `/gsd-secure-phase 05`, `/gsd-validate-phase 05`, then push + the deferred Checkpoint-2 github-source install at ship time._

### Out of Scope

- Building a runtime/executable security scanner beyond the existing `quick_scan.py` lead-finder — the repo remains reference/guidance-driven, not a live SAST engine; no autonomous "auto-fix"/remediation
- Importing or modernizing the 15 globally-installed cyber-domain skills (recon, malware, red-team, etc.) — they live outside this repo and are not in scope for this milestone
- Adopting draft/release-candidate OWASP editions as if final (e.g. Kubernetes Top 10 2025 draft) — cite the current stable edition, footnote drafts only
- CI/CD, version-control, or live-system integrations — reviews stay stateless and prompt/filesystem-scoped
- Rewriting example code into new languages beyond those already represented (Python, JavaScript, YAML, HTML) unless required by an updated standard

## Context

- **Existing codebase is mature and mapped** — see `.planning/codebase/` (ARCHITECTURE, STACK, STRUCTURE, CONVENTIONS, INTEGRATIONS, TESTING, CONCERNS). This is a refactor/refresh milestone on a working system, not a greenfield build.
- **Version landscape (verified 2026-07-19, see `.planning/research/STACK.md`):** Only OWASP Top 10 needs a hard bump (2021 → 2025 Final). ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), Agentic Apps (2026) are already correctly labeled and need citation-hardening only. Kubernetes Top 10 2025 is still draft (cite 2022). The OWASP Secure Coding Practices Quick Reference Guide is archived (folded into the OWASP Developer Guide).
- **Agent Skills readiness:** the existing `references/`/`scripts/`/`assets/` layout already matches the spec's progressive-disclosure convention, so the reformat is mostly `SKILL.md` frontmatter + content-format compliance and retiring legacy root files — not a directory teardown.
- **No build system / package manager** — pure documentation + a small Python script; delivery is symlink install today, plugin packaging is a goal of this milestone.
- **Public ambition** — the repo is intended to be attractive, widely useful, and adoption-worthy (GitHub stars as a signal), which sets a public-facing quality bar for accuracy, docs, and packaging.

## Constraints

- **Accuracy**: Every OWASP version number, category, and control ID must be verified against official OWASP sources — Why: a public security reference loses all credibility if editions or IDs are wrong.
- **Format**: Must conform to Anthropic's official Agent Skills spec (`SKILL.md` + frontmatter + progressive disclosure) — Why: enables clean Claude Code install and marketplace distribution.
- **Tech stack**: Markdown-first, optional Python for tooling; no heavy runtime dependencies — Why: keeps the skill lightweight, portable, and easy to install.
- **Distribution**: Must be installable via Claude Code plugin/marketplace mechanisms — Why: this is the definition of "done" for reach and adoption.
- **Compatibility**: Preserve the value of existing content (examples, checklists, scanner) through the restructure — Why: this is a refresh, not a teardown.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Conform to the official Anthropic Agent Skills spec | Standard format installs cleanly in Claude Code and is marketplace-distributable | ✓ Done — Phase 4 (both `SKILL.md` pass lint 24/24; legacy routing/manifest files retired from the loaded path; examples remapped to 2025/2026 IDs) |
| Verify all OWASP versions against official sources (no training-data recall) | Public credibility depends on edition/ID accuracy | In progress — Phases 2–3 verified Top 10 + all remaining standards against official URLs with retrieval dates; final QUAL-01 sweep in Phase 5 |
| Scope = the 2 in-repo OWASP skills only (15 domain skills are global, out of scope) | Corrected after verifying actual repo contents; keeps milestone focused and shippable | — Pending |
| Re-derive `secure-coding-practices` against the living OWASP Developer Guide | The SCP Quick Reference Guide is officially archived by OWASP | ✓ Done — Phase 3 (D-01 light re-anchor: 14-row living-source crosswalk added, 100+-item checklist body frozen) |
| Cite stable OWASP editions only; footnote drafts (e.g. K8s 2025) | Avoids presenting draft standards as final | ✓ Done — Phase 3 (K8s 2022 primary; 2025 footnoted in-progress; no formal 2025 release found, halt-and-flag did not fire) |
| ASVS 5.0.0 reference: disclose 4.0.3 body numbering, don't re-anchor to the 5.0.0 V-series | Gap-closure locked decision — a source-free reframe removes the edition contradiction (5.0.0 banner over 4.0.3 chapters/`V2.1.5`) without inventing unverified 5.0.0 control IDs; full re-anchor deferred | ✓ Done — Phase 3 (03-04 gap plan) |
| Target Claude Code plugin/marketplace distribution | Maximizes reach, adoption, and shareability | — Pending |
| Refresh rather than rebuild | Existing content, examples, and scanner are valuable and mapped | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-07-28 after Phase 5 (Packaging Validation & Credibility Polish) completion — final phase; milestone v1.0 content-complete and verified, pending ship gates (secure-phase, validate-phase, push + Checkpoint-2)*
