# Project Research Summary

**Project:** OWASP-Security-Skills modernization milestone
**Domain:** Security-reference skill collection for Claude Code (OWASP-grounded audit/secure-coding skills, packaged as Anthropic Agent Skills + a Claude Code plugin/marketplace)
**Researched:** 2026-07-19
**Confidence:** MEDIUM-HIGH

## Scope Correction (read first)

This repository's `skills/` directory contains **only two skills** — `owasp-security-audit` and `secure-coding-practices`. The "15 cyber-domain skills" (`01-recon-osint`, `02-vulnerability-scanner`, etc.) referenced in early project context are **globally-installed skills living outside this repo** (`~/.claude/skills`) and are **not** part of this codebase. All research below (and the roadmap it informs) should be scoped to: the two OWASP skills, the root reference/routing files (`owasp-comprehensive-security-skills.md`, `owasp-css.instructions.md`, `skill.json`, `examples/`, `install.sh`), README/project docs, and new plugin/marketplace packaging. Any prior mention of a 17-skill collection in the research files should be read down to this 2-skill scope — the packaging/spec/pitfall guidance still applies, just to a much smaller skill count.

## Executive Summary

This is a refresh of a mature, already well-structured repo, not a greenfield build. The repo's two OWASP skills already follow the Agent Skills directory shape (`references/`, `scripts/`, `assets/`) but are packaged with a pre-standard, custom `skill.json` + Copilot-style `owasp-css.instructions.md` router instead of the official `SKILL.md` YAML-frontmatter format, and are not installable as a Claude Code plugin/marketplace entry. Of the seven OWASP standards referenced across the two skills, only **OWASP Top 10 needs a hard version bump** (2021 → 2025 Final, a full category renumbering with two new categories and SSRF folded into Broken Access Control) — ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Applications Top 10 (2026) are already correctly labeled and just need citation-hardening. The Secure Coding Practices Quick Reference Guide is a separate, non-version finding: OWASP has **archived** that project entirely, folding its content into the Developer Guide, which forces a scoping decision (keep SCP as a labeled historical checklist, or re-source current guidance from the Developer Guide/Cheat Sheet Series/Proactive Controls) rather than a simple renumber.

The recommended approach is: (1) stand up the plugin/marketplace skeleton (`.claude-plugin/plugin.json` + `.claude-plugin/marketplace.json` at repo root, skills/ remaining at plugin root, never inside `.claude-plugin/`), (2) refresh each OWASP standard's reference content against its official, edition-verified source with an explicit RC-vs-Final check, (3) convert both skills to spec-compliant `SKILL.md` frontmatter (retiring `skill.json` and `owasp-css.instructions.md`, re-hosting their routing logic inside each skill's `description`/`when_to_use`/`paths` fields — Claude Code's own model-driven activation replaces the hand-rolled keyword router), and (4) close credibility gaps (missing LICENSE, unverified coverage claims, stale example citations) before any public/marketplace polish.

The key risks are all "looks-done-but-isn't" traps specific to a refresh: mixing old and new category IDs when only the version label is bumped; citing an RC as final (OWASP Top 10:2025 had a Nov 2025 RC before its final release); copying the existing 900-line `owasp-comprehensive-security-skills.md` into `SKILL.md` verbatim, which defeats progressive disclosure; silently dropping the routing intelligence currently encoded in `owasp-css.instructions.md` during conversion; and packaging pitfalls specific to Claude Code's plugin cache (symlinked files not copied into cache, cross-directory file references breaking with a "path escapes plugin directory" error). All are addressable with disciplined phase ordering and verification checklists, detailed below.

## Key Findings

### Recommended Stack

Seven OWASP standards are in scope across the two skills. **OWASP Top 10** is the only one requiring a full content rewrite: 2021 → 2025 (Final), with A02 jumping from #5, two new categories (A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions), and SSRF folded into Broken Access Control (A01). ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), and LLM Top 10 (2025) are current as claimed — verification/citation-hardening only. Agentic Applications Top 10 (2026) is current in edition but its exact ASI01–ASI10 category names could not be confirmed from a primary source in this research pass (gap — pull from the primary PDF before writing reference content). Kubernetes Top 10 2022 remains the citable stable edition; a 2025 draft exists but is explicitly marked non-final and should not be adopted as primary. Secure Coding Practices Quick Reference Guide is archived by OWASP — a scoping decision, not a version bump.

**Core technologies:**
- Anthropic Agent Skills spec (`SKILL.md` YAML frontmatter: `name` <=64 chars matching folder name exactly, `description` <=1024 chars stating what+when) — the actual discovery/activation contract, replacing the legacy `skill.json`
- Claude Code plugin manifest (`.claude-plugin/plugin.json`, closed schema, `name` the only required field) — declares plugin identity; must NOT contain custom fields like `standards`/`activation.triggers` from the old `skill.json`
- Claude Code marketplace catalog (`.claude-plugin/marketplace.json`, `name`/`owner`/`plugins[]`) — enables `/plugin marketplace add` + `/plugin install`; recommend one plugin, self-hosted marketplace (`"source": "."`), given only two skills

### Expected Features

**Must have (table stakes):**
- Spec-compliant `SKILL.md` frontmatter for both skills (reliable auto-activation depends on it)
- Verified, current OWASP edition coverage with per-file "verified as of [date] against [URL]" provenance
- Legacy `skill.json` / `owasp-css.instructions.md` retired or clearly deprecated (no dual source of truth)
- `plugin.json` + `marketplace.json` enabling marketplace install
- LICENSE file (currently missing — blocks credibility/enterprise adoption)
- README rewrite: scope, install paths, badges, one real before/after example
- Paired vulnerable/secure examples extended/re-validated for any renamed/new Top 10:2025 categories

**Should have (competitive):**
- Provenance/verification transparency visible in docs (not just buried in a references file)
- `evals/` correctness tests per skill (rare among comparable repos, strong differentiator for a security tool)
- OpenSSF Best Practices badge pursuit (requires LICENSE + security policy + CI first)
- Awesome-list / marketplace directory submissions once polish is done

**Defer (v2+):**
- OWASP-release-cadence update automation (manual changelog discipline is sufficient to start)
- Expanding cross-assistant install targets beyond Claude Code/Copilot
- Auto-remediation / live SAST scanning — explicitly out of scope; conflicts with the project's guidance-only positioning

### Architecture Approach

Treat each `skills/<name>/` directory (`owasp-security-audit`, `secure-coding-practices`) as a fully self-contained, independently-refreshable unit — its own `SKILL.md`, `references/`, `scripts/`, `assets/`, with zero cross-skill file references (the one deliberate exception, `owasp-urls.json` duplicated independently in both skills, should stay duplicated, not centralized). Within `owasp-security-audit`, each OWASP standard gets its own `references/<standard>.md`, with `SKILL.md` acting as a thin dispatcher pointing at the right reference file — this pattern already exists in the repo and should be preserved, not restructured; the fix is disciplining what stays in `SKILL.md` (must shrink to a router, <500 lines) vs. what moves to `references/`.

**Major components:**
1. Marketplace catalog (`.claude-plugin/marketplace.json`) — lists the plugin, resolved via `"source": "."` for this single-plugin repo
2. Plugin manifest (`.claude-plugin/plugin.json`) — identity only (name, version, author, license); closed schema, no custom fields
3. Skill directories (`skills/owasp-security-audit/`, `skills/secure-coding-practices/`) — each with `SKILL.md` (frontmatter + dispatcher body), `references/*.md` (per-standard deep content), `scripts/*.py` (e.g. `quick_scan.py`), `assets/examples/` (canonical vulnerable/secure pairs — root `examples/` directory should be retired as a duplicate source)

### Critical Pitfalls

1. **Mixing edition numbering when only some standards are refreshed** — updating the version label ("Top 10 2025") while leaving old category IDs (A04, A06, A08, A10 from 2021) untouched in examples/cross-references creates internal inconsistency. Avoid by regenerating the full ID->name mapping from the official OWASP source first, diffing against existing repo content, before touching prose.
2. **Citing an RC as final or vice versa** — OWASP Top 10:2025 had a Nov 2025 RC before final publication; ambiguous "latest" search results can bake in RC-only wording. Avoid by recording exact publication status (Final/RC/Draft) + date next to every version claim, sourced only from the canonical OWASP page/repo.
3. **Bloated SKILL.md that defeats progressive disclosure** — converting the 900-line `owasp-comprehensive-security-skills.md` into `SKILL.md` verbatim (or inlining full category tables) burns context on every activation. Avoid by keeping `SKILL.md` a thin router (<500 lines) pointing at `references/*.md`, one level deep only.
4. **Weak/overlapping description fields break auto-activation** — with only two skills in this repo's actual scope, the risk is narrower than originally framed (not 17 skills), but `owasp-security-audit` and `secure-coding-practices` still need clearly differentiated "when to use" boundaries (standards-cited audit vs. checklist-driven SCP review) so they don't compete for the same generic "review my code" prompt.
5. **Losing legacy routing logic during conversion** — `owasp-css.instructions.md` and `skill.json` currently encode which standard to surface for a given request; deleting them without re-hosting that logic inside `SKILL.md`'s own "when the request is about X, read references/Y.md" guidance silently regresses activation accuracy.
6. **Frontmatter spec violations that silently fail to load** — `name` must exactly match the parent folder name, start at byte 0, use only lowercase/hyphens, and contain no angle brackets. Add a pre-ship validator asserting all of these.
7. **Symlink/packaging failures under the native plugin/marketplace mechanism** — the existing `install.sh` symlink pattern doesn't disappear as a risk when packaging is added; it changes shape (documented Claude Code regressions include symlinked dirs not copied into plugin cache, and "path escapes plugin directory" errors for cross-directory file references). Test the actual `/plugin marketplace add` + install flow on a clean environment, not just JSON validity.

## Implications for Roadmap

Based on combined research, suggested phase structure:

### Phase 1: Plugin/Marketplace Foundation
**Rationale:** Nothing downstream can be verified "spec-compliant" without the skeleton and the target `skills/<name>/{SKILL.md,references/,scripts/,assets/}` convention existing first; this is small, serial, and blocking.
**Delivers:** `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, documented target skill-directory convention
**Uses:** Claude Code plugin/marketplace manifest schema from STACK.md
**Avoids:** Pitfall 8 (manifest schema violations) — keep manifests to the closed official schema only, no custom fields ported from `skill.json`

### Phase 2: OWASP Top 10 Version Refresh
**Rationale:** This is the only standard needing a full content rewrite (2021->2025), and it's the highest-visibility credibility risk if left stale or done sloppily (RC-vs-final, mixed numbering).
**Delivers:** Refreshed `references/top10.md` with the new 2025 category set, cross-referenced against the official OWASP mapping; re-validated example citations
**Addresses:** "Verified, current OWASP edition coverage" table-stakes feature from FEATURES.md
**Avoids:** Pitfalls 1 (mixed numbering) and 2 (RC-vs-final) from PITFALLS.md

### Phase 3: Remaining Standards Verification (parallelizable)
**Rationale:** ASVS, MASVS, API Top 10, LLM Top 10, Agentic Apps 2026, Kubernetes Top 10, and the SCP scoping decision are each independent, citation-hardening-only tasks with no cross-file dependency — can run as parallel workstreams per STACK.md's build-order guidance.
**Delivers:** Verified/dated citations for 5 already-current standards, an explicit stable-vs-draft decision for Kubernetes (cite 2022, footnote 2025 draft), and an explicit SCP scoping decision (frozen historical checklist vs. re-sourced from Developer Guide/Cheat Sheet Series/Proactive Controls)
**Uses:** STACK.md's version matrix as the source-of-truth table

### Phase 4: SKILL.md Conversion & Legacy Retirement
**Rationale:** Depends on Phase 2-3 content being finalized (the dispatcher body needs to point at settled reference filenames); converts both skills to spec-compliant frontmatter and retires the legacy router/manifest files.
**Delivers:** `owasp-security-audit/SKILL.md` and `secure-coding-practices/SKILL.md` with compliant frontmatter, differentiated descriptions, and explicit reference-routing guidance; `skill.json` and `owasp-css.instructions.md` retired (routing logic migrated, not dropped)
**Implements:** Architecture Pattern 2 (reference file as parallelizable unit within a skill) and Pattern 3 (progressive disclosure sizing discipline)
**Avoids:** Pitfalls 3 (bloated SKILL.md), 4 (weak descriptions), 5 (lost routing logic), 6 (frontmatter violations)

### Phase 5: Packaging Validation & Credibility Polish
**Rationale:** Last, because it depends on all content and structural work being final; bundles the "does it actually install" verification with the public-facing trust-signal work since both gate a credible public launch.
**Delivers:** End-to-end `/plugin marketplace add` + install test on a clean environment; LICENSE added; README rewrite with an honest coverage matrix (not superlative claims); badges; retired root `examples/` duplication in favor of per-skill `assets/examples/`
**Addresses:** LICENSE, README, coverage-matrix table-stakes features from FEATURES.md
**Avoids:** Pitfalls 7 (symlink/cache packaging failures), 9 (version/changelog drift), 10 (overclaimed coverage), 11 (stale example citations)

### Phase Ordering Rationale

- Foundation must come first because it defines the convention every other phase follows (ARCHITECTURE.md's "suggested build order").
- Top 10 refresh is isolated ahead of the other standards because it's the only one requiring a full rewrite rather than verification — sequencing it first surfaces the hardest content risk early.
- The remaining five/six standards can run in parallel since each is an independent, self-contained `references/<standard>.md` file with no cross-dependency (ARCHITECTURE.md Pattern 1 and Pattern 2).
- SKILL.md conversion is sequenced after content is settled so the dispatcher's reference-routing text doesn't need rewriting mid-phase.
- Packaging validation and polish come last because both depend on final, stable content and structure — testing an install or writing a coverage matrix against not-yet-final content wastes the work.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 2 (Top 10 refresh):** Full category renumbering with two new categories is high-complexity content work; the official OWASP 2021->2025 mapping artifact should be pulled directly rather than hand-derived.
- **Phase 3 (remaining standards):** The Agentic Applications 2026 exact ASI01-ASI10 category names are an explicit gap in STACK.md — needs primary-source (PDF) research before this phase can finalize its reference file. The SCP scoping decision also needs a deliberate call (frozen vs. re-sourced) that should be made explicit before drafting content.
- **Phase 5 (packaging validation):** Cross-platform install testing (macOS/Linux/Windows) surfaces documented Claude Code regressions (symlink-to-cache issues, Windows path collapse) that may need version-specific research if problems are hit.

Phases with standard patterns (skip research-phase):
- **Phase 1 (foundation):** Plugin/marketplace manifest shape is fully documented in STACK.md/ARCHITECTURE.md with working examples — standard pattern, no additional research needed.
- **Phase 4 (SKILL.md conversion):** Frontmatter spec and progressive-disclosure conventions are well-documented and already partially followed by the existing repo structure.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM-HIGH | All findings fetched live from official owasp.org/genai.owasp.org/platform.claude.com/code.claude.com pages; automated confidence-classifier caps generic web fetches at MEDIUM even for primary sources. One explicit gap: Agentic Applications 2026 category names (LOW, needs primary PDF). |
| Features | HIGH (spec/packaging mechanics), MEDIUM (adoption/star-driving claims, inferred from comparable-repo patterns, no single authoritative source) | Verified against official Anthropic docs for spec/marketplace; adoption-lever claims are reasonable inference, not empirically confirmed for this specific repo. |
| Architecture | HIGH | Primary source: official Anthropic/Claude Code docs, cross-checked against 2+ independent doc pages and reference implementations (anthropics/claude-code, anthropics/claude-plugins-official). |
| Pitfalls | MEDIUM | Cross-checked web sources on Anthropic/Claude Code specs and OWASP edition histories; corroborated across 2+ independent sources per claim, but no single HIGH-confidence primary citation available for a synthesized pitfalls corpus. Several pitfalls cite specific Claude Code GitHub issues as evidence of real regressions. |

**Overall confidence:** MEDIUM-HIGH

### Gaps to Address

- **Agentic Applications Top 10 (2026) exact category names (ASI01-ASI10):** only paraphrased themes were found via secondary sources; pull the exact official names from the primary PDF before writing `references/agentic-apps-top10.md` content (Phase 3).
- **Secure Coding Practices scoping decision:** research surfaced the archived-status finding but did not make the call — the roadmap/planning stage must explicitly decide between "frozen historical checklist" and "re-sourced from Developer Guide/Cheat Sheet Series/Proactive Controls" before Phase 3 content work begins.
- **Kubernetes Top 10 stable-vs-draft decision:** similarly, research surfaced the 2022-stable-vs-2025-draft tension but the roadmap should make an explicit, documented choice (recommend: cite 2022 as primary, footnote 2025 draft) rather than leaving it ambiguous.
- **Cross-platform packaging behavior:** documented Claude Code GitHub issues (symlink-to-cache regression, Windows path collapse, marketplace "0 skills" bug) are real but version-specific; Phase 5 planning should check current Claude Code version status for these before assuming they still apply.

## Sources

### Primary (HIGH confidence)
- https://owasp.org/Top10/2025/ — OWASP Top 10:2025 official page
- https://github.com/OWASP/ASVS/releases , https://owasp.org/www-project-application-security-verification-standard/ — ASVS 5.0.0
- https://github.com/OWASP/masvs/releases — MASVS 2.1.0
- https://owasp.org/API-Security/editions/2023/en/0x00-header/ — API Security Top 10 2023
- https://owasp.org/www-project-kubernetes-top-ten/ (2022 stable, 2025 draft)
- https://genai.owasp.org/llm-top-10/ — LLM Top 10 2025
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ — Agentic Applications 2026
- https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/ , https://devguide.owasp.org/ — SCP archived status
- https://code.claude.com/docs/en/skills , .../plugins , .../plugins-reference , .../plugin-marketplaces — Claude Code skill/plugin/marketplace schema
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview , .../best-practices — Agent Skills spec
- https://github.com/anthropics/claude-code/blob/main/plugins/plugin-dev/skills/plugin-structure/SKILL.md — reference implementation
- https://github.com/anthropics/claude-plugins-official/blob/main/.claude-plugin/marketplace.json — reference implementation

### Secondary (MEDIUM confidence)
- https://equixly.com/blog/2025/12/01/owasp-top-10-2025-vs-2021/ , https://blog.qualys.com/qualys-insights/2026/06/15/what-changed-in-owasp-top-10-2025-and-recommendations-for-each-category — Top 10 2021->2025 change summaries
- https://softwaremill.com/whats-new-in-asvs-5-0/ , https://deepwiki.com/owasp-ja/asvs-ja/12-differences-between-asvs-5.0-and-4.0 — ASVS 4->5 changes
- https://www.vervali.com/blog/owasp-masvs-in-2026-current-version-the-8-categories-and-what-changed/ — MASVS changes
- github/copilot-cli#3494 , danielmiessler/Personal_AI_Infrastructure#1205 — description length limit real-world reports
- anthropics/claude-code issues #54967, #52435, #53948, #18949 — plugin/marketplace packaging regressions

### Tertiary (LOW confidence)
- Agentic Applications 2026 exact ASI01-ASI10 category names — paraphrased themes only, needs primary PDF verification
- General adoption/star-driving inferences (awesome-list submission value, OpenSSF badge ROI) — reasonable inference from comparable OSS patterns, not empirically measured for this repo

---
*Research completed: 2026-07-19*
*Ready for roadmap: yes*
