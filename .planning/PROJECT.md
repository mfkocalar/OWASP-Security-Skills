# OWASP Security Skills

## What This Is

A collection of security skills for Claude Code (and compatible AI coding assistants) that brings OWASP standards and secure-coding practices into automated code, infrastructure, and configuration review. This milestone modernizes the collection: every OWASP standard is refreshed to its newest published edition, every skill is restructured into Anthropic's official Agent Skills format, and the whole repo is polished for public distribution via the Claude Code plugin marketplace.

## Core Value

A security engineer or developer can install the collection into Claude Code and get accurate, current, OWASP-grounded security review — with the reference content matching the *latest* published OWASP editions and the packaging matching the *official* skill spec so it installs cleanly and is worth sharing.

## Requirements

### Validated

<!-- Inferred from existing codebase (see .planning/codebase/). Already built and relied upon. -->

- ✓ OWASP audit skill covering Top 10, ASVS, MASVS, API Security, Kubernetes, Agentic Apps — existing
- ✓ Secure Coding Practices skill (14-domain, 100+ item checklist) — existing
- ✓ 15 cyber-domain skills (recon/OSINT, vuln scanning, exploit dev, reverse engineering, malware, threat hunting, incident response, network, web, cloud, SOC automation, log analysis, crypto, red team, blue team) — existing
- ✓ `quick_scan.py` regex-based lead scanner — existing
- ✓ Paired vulnerable/secure code examples (Python, JavaScript, YAML, HTML) — existing
- ✓ Symlink-based installer (`install.sh`) for Claude / Copilot / custom targets — existing

### Active

<!-- This milestone. All are hypotheses until shipped and validated. -->

- [ ] All OWASP standards updated to their newest published editions (Top 10, ASVS, MASVS, API Security, Kubernetes, LLM, Agentic, Secure Coding Practices), each verified against official OWASP sources
- [ ] Every skill restructured into the official Anthropic Agent Skills format (per-skill `SKILL.md` with YAML frontmatter + progressive-disclosure `references/`/`scripts/`/`assets/`)
- [ ] Legacy Copilot-style `owasp-css.instructions.md` and custom `skill.json` manifest retired or replaced by spec-compliant equivalents
- [ ] Repo packaged as a Claude Code plugin / marketplace-installable collection with correct plugin metadata
- [ ] Public-release polish: strong README, clear docs, working examples, low-friction install, and discoverability aimed at broad adoption
- [ ] Version accuracy verified — no OWASP edition, control ID, or standard change relies on unverified training-data recall

### Out of Scope

- Building a runtime/executable security scanner beyond the existing `quick_scan.py` lead-finder — the collection remains reference/guidance-driven, not a live SAST engine
- CI/CD, version-control, or live-system integrations — reviews stay stateless and prompt/filesystem-scoped
- Authoring net-new cyber-domain skills beyond the existing 15 — this milestone refreshes and reformats, it does not expand domain coverage
- Rewriting example code into new languages beyond those already represented (Python, JavaScript, YAML, HTML) unless required by an updated standard

## Context

- **Existing codebase is mature and mapped** — see `.planning/codebase/` (ARCHITECTURE, STACK, STRUCTURE, CONVENTIONS, INTEGRATIONS, TESTING, CONCERNS). This is a refactor/refresh milestone on a working system, not a greenfield build.
- **Current declared coverage** (pre-update, from `skill.json` 1.1.0 / codebase map): OWASP Top 10 (2021), ASVS 5.0, MASVS v2.1.0, API Security Top 10 (2023), Kubernetes Top 10 (2022), Agentic Apps (2026), Secure Coding Practices. Newest-edition targets must be confirmed against official OWASP during research — several of these have moved.
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
| Update all ~17 skills (not just the two OWASP ones) | User wants the whole collection modernized and consistent | — Pending |
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
*Last updated: 2026-07-19 after initialization*
