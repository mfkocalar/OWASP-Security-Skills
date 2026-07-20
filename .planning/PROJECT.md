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

### Active

<!-- This milestone. All are hypotheses until shipped and validated. -->

- [ ] OWASP Top 10 refreshed 2021 → 2025 (Final), using OWASP's official ID mapping — new A03 Supply Chain, new A10 Exceptional Conditions, SSRF folded into A01, A02 reordered
- [ ] Remaining standards citation-hardened to their (already-correct) editions: ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), Agentic Apps (2026); Kubernetes cites 2022 (2025 still draft)
- [ ] `secure-coding-practices` re-derived against the living OWASP Developer Guide / Cheat Sheet Series / Proactive Controls (the SCP Quick Reference Guide is archived by OWASP)
- [ ] Both skills restructured into the official Anthropic Agent Skills format (`SKILL.md` frontmatter: folder-matching `name` ≤64 chars, `description` ≤1024 chars; progressive-disclosure `references/`/`scripts/`/`assets/`)
- [ ] Legacy Copilot-style `owasp-css.instructions.md`, custom `skill.json`, and the ~900-line `owasp-comprehensive-security-skills.md` retired/replaced under the spec; routing preserved via per-skill descriptions
- [ ] Public-release polish: LICENSE (currently missing), strong README, clear docs, working examples, low-friction/cross-platform install, and discoverability aimed at broad adoption
- [ ] Version accuracy verified — no OWASP edition, control ID, or standard change relies on unverified training-data recall

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
| Conform to the official Anthropic Agent Skills spec | Standard format installs cleanly in Claude Code and is marketplace-distributable | — Pending |
| Verify all OWASP versions against official sources (no training-data recall) | Public credibility depends on edition/ID accuracy | — Pending |
| Scope = the 2 in-repo OWASP skills only (15 domain skills are global, out of scope) | Corrected after verifying actual repo contents; keeps milestone focused and shippable | — Pending |
| Re-derive `secure-coding-practices` against the living OWASP Developer Guide | The SCP Quick Reference Guide is officially archived by OWASP | — Pending |
| Cite stable OWASP editions only; footnote drafts (e.g. K8s 2025) | Avoids presenting draft standards as final | — Pending |
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
*Last updated: 2026-07-20 after Phase 1 (Plugin/Marketplace Foundation) completion*
