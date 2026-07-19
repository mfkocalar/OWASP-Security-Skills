# Feature Research

**Domain:** Security-skill collection for Claude Code (OWASP-grounded code/config review, packaged as installable Agent Skills / marketplace plugin)
**Researched:** 2026-07-19
**Confidence:** HIGH (spec/format and marketplace mechanics — verified against official Anthropic docs and repos); MEDIUM (star-driving/adoption claims — inferred from comparable OSS repo patterns, no single authoritative "why repos go viral" source)

## Feature Landscape

### Table Stakes (Users Expect These)

Features a security-reference skill collection is assumed to have. Missing these makes the repo look unfinished or untrustworthy to the exact audience (security engineers) most likely to scrutinize it.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Official Agent Skills spec compliance (`SKILL.md` + YAML frontmatter `name`/`description`, progressive disclosure via `references/`, `scripts/`, `assets/`) | This is the literal install/activation contract for Claude Code and (since Dec 2025) an open standard also adopted by Codex/ChatGPT. Non-compliant skills fail to load or fail to trigger. | MEDIUM | Repo already has this shape (per `STRUCTURE.md`) but still carries a legacy `skill.json` + `owasp-css.instructions.md` (Copilot-era) that must be retired or bridged — see anti-features. Ref: [anthropics/skills](https://github.com/anthropics/skills), [Claude Code Docs — Extend Claude with skills](https://code.claude.com/docs/en/skills). |
| Description field engineered for reliable triggering ("what it does" + "Use when...") | The single most important field for whether Claude ever invokes the skill; vague descriptions = silent non-activation, the #1 reported skill bug in the wild. | LOW | Anthropic/community guidance: "if your skill isn't firing, the description is wrong, not the body." Recommended target ~500 chars, hard spec ceiling 1024 (some hosts silently drop skills whose description exceeds ~650 chars — [github/copilot-cli#3494](https://github.com/github/copilot-cli/issues/3494), [danielmiessler/Personal_AI_Infrastructure#1205](https://github.com/danielmiessler/Personal_AI_Infrastructure/issues/1205)). Applies to all ~17 skills in this collection, not just the two OWASP ones. |
| Current, verifiable OWASP edition coverage (version numbers and control IDs that match owasp.org today) | This is a security *reference*; the audience will fact-check version numbers before trusting anything else in the repo. | MEDIUM | Confirmed via research: **OWASP Top 10:2025 is now published** ([owasp.org/Top10/2025](https://owasp.org/Top10/2025/)), while this repo's current content is pinned to **Top 10:2021** — a visible staleness gap for launch-day critics. ASVS 5.0.0 (May 2025, ~350 reqs/17 chapters) is current; MASVS version needs direct confirmation from mas.owasp.org. This reinforces the milestone's own "verify against official sources, no training-data recall" constraint. |
| README that a security engineer can evaluate in under 60 seconds: what it does, what standards it covers, one-command install, a real before/after example | Baseline expectation for any OSS tool; doubly true for security tooling where users won't `curl \| bash` something they can't quickly vet. | LOW | Should show scope (which OWASP docs, which languages), not just marketing copy. Aligns with general "awesome-readme" conventions ([matiassingers/awesome-readme](https://github.com/matiassingers/awesome-readme)). |
| LICENSE file (OSI-approved, e.g., MIT or Apache-2.0) | No visible LICENSE in current structure. Absence blocks enterprise/legal adoption outright and is one of the fastest ways to lose credibility and stars — many orgs' security policy forbids using unlicensed code. | LOW | Must add explicitly; currently missing from repo root per `STRUCTURE.md`. |
| Badges for at-a-glance trust signals (license, last-updated/version, OWASP-edition-covered) | Badges are the visual shorthand reviewers use to sort "maintained, credible project" from "abandoned gist." | LOW | Use [shields.io](https://github.com/badges/shields); don't add badges you can't back up (e.g., a "build passing" badge with no CI is worse than no badge). |
| Working CONTRIBUTING.md + issue/PR templates | Already exists (`CONTRIBUTING.md`) but should be checked for actual issue/PR templates and a lightweight CODE_OF_CONDUCT — table stakes for any repo hoping for external contributions once it's public and starred. | LOW | Existing file is a base; extend with `.github/ISSUE_TEMPLATE/` and `.github/PULL_REQUEST_TEMPLATE.md`. |
| Marketplace-installable packaging (`plugin.json` + `marketplace.json` at root or `.claude-plugin/`) | This is literally the definition of "marketplace-ready" per the project's own success criteria; without it the repo is symlink-install-only and invisible to marketplace discovery/search. | MEDIUM | Required fields: marketplace `name` (kebab-case), `owner`, `plugins[]`; each plugin entry needs `name`, `source`, `description`, `version`, `author`, plus marketplace-specific `category`/`tags` for discoverability. Refs: [Claude Code Docs — Create and distribute a plugin marketplace](https://code.claude.com/docs/en/plugin-marketplaces), [anthropics/claude-code marketplace.json example](https://github.com/anthropics/claude-code/blob/main/.claude-plugin/marketplace.json), unofficial [claude-code-json-schema](https://github.com/hesreallyhim/claude-code-json-schema) for validation. |
| Paired vulnerable/secure examples with detection signals and remediation per vulnerability class | Already a strength of this repo (per `CONVENTIONS.md` — `VULNERABLE:`/`SECURE:` markers, testing notes). This is the baseline depth expected of *any* credible OWASP reference, not a differentiator — competitors without this look shallow. | LOW (maintain) / MEDIUM (extend to new/updated categories) | Must be extended to cover any newly-added Top 10:2025 categories and any renumbered/renamed ones. |
| "Authorized use only" framing on offensive-capable skills (exploit-dev, red-team, recon) | A public security-skill collection that ships exploit/recon guidance without explicit authorized-testing framing invites both reputational and policy risk; this is what separates "security education tool" from "attack toolkit" in the eyes of adopters, security teams, and platform policy. | LOW | Already partially present in skill descriptions (per skill listing) — needs to be consistent and visible (README + each offensive skill's frontmatter), not just implicit. |

### Differentiators (Competitive Advantage)

Features that would make this collection stand out among the growing number of Claude Code skill/plugin repos and earn stars, not just installs.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Full-breadth, single-collection OWASP coverage kept in lockstep (Top 10, ASVS, MASVS, API Top 10, Kubernetes Top 10, LLM/Agentic Top 10, Secure Coding Practices) | Most Claude Code security skills seen in the wild are narrow (one OWASP list, or generic "code review"). A collection that credibly spans web, API, mobile, cloud-native, and AI/agentic risk in one coherent, cross-referenced package is unusual and matches how real AppSec teams actually work (one reviewer, many standards). | MEDIUM (maintain) | This is the repo's existing core differentiator (per `PROJECT.md` "Core Value") — research validates it's rare; most competing repos are single-purpose or generic. Risk: breadth without depth reads as bloat if each standard isn't genuinely current and well-cross-referenced. |
| Provenance/verification transparency — every version claim traceable to a live OWASP URL | Directly counters the credibility risk unique to LLM-authored security content (training-data recall of stale facts). A visible `owasp-urls.json` + "last verified against official source on [date]" note per standard is a trust signal almost no competing skill repo offers. | LOW | Already has the scaffolding (`owasp-urls.json` exists per `STRUCTURE.md`) — differentiator is making verification dates/sources visible in the README/SUMMARY rather than buried in a references file. |
| `evals/` folder with skill-correctness tests | Anthropic's own skill-authoring guidance recommends an `evals/` directory with an `evals.json` for validating skill behavior — very few third-party skill collections actually ship this. For a *security* skill, demonstrable correctness testing is an unusually strong differentiator (it answers "how do I know this skill gives accurate guidance?"). | MEDIUM | Ref: skill folder structure guidance from [agentskills.io](https://agentskills.io/home) / Anthropic engineering blog ["Equipping agents for the real world with Agent Skills"](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills). |
| Cross-assistant install path (Claude Code, GitHub Copilot, generic) via `install.sh` | Already exists. Most competing repos are Claude-only; supporting Copilot/custom targets from one canonical source broadens the addressable audience (and thus potential stargazers) beyond the Claude Code niche. | LOW (maintain) | Keep as a stated differentiator in README messaging once repo is public; don't let it justify keeping the legacy Copilot instructions format as a second source of truth (see anti-features). |
| OpenSSF Best Practices badge (or working toward it) | For a security-focused repo specifically, this badge is unusually on-brand and rare among Claude Code skill collections — it signals "this project takes its own security practices seriously," which is a credibility multiplier precisely because the product *is* a security tool. | MEDIUM | Requires: LICENSE (table stakes above), a documented security policy, CI, and a baseline of OpenSSF's passing-tier criteria. Ref: [coreinfrastructure/best-practices-badge](https://github.com/coreinfrastructure/best-practices-badge). |
| Listing in curated "awesome" lists and community marketplaces | Concrete discovery channel: repos like [hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code), [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills) (reported 24k+ stars, 1000+ skills curated), and directory sites (claudemarketplaces.com, claudepluginhub.com) are where users actually browse for skills — being PR'd into these is a direct, low-cost adoption lever once the repo is spec-compliant and polished. | LOW | Submission is typically a PR to the awesome-list README with name/description/link — cheap to do once other table stakes are met. |
| Real, runnable demo transcripts/GIFs of an actual audit ("before/after" on the repo's own example files) | Static docs describing a skill are less convincing than a captured transcript showing the skill catching a real vulnerable pattern and citing the specific OWASP control. This is what turns a browsing visitor into a star. | LOW-MEDIUM | Can reuse existing `examples/` vulnerable/secure pairs — no new content needed, just capture/record a session. |
| Lightweight maintenance cadence tied to OWASP's release calendar | Static prompt collections tend to visibly rot (this project's own current 2021 Top 10 vs. now-published 2025 edition is proof). A stated update cadence/changelog signals the collection won't go stale the way most competitors silently do. | LOW | Can be as simple as a CHANGELOG.md entry + version bump whenever an OWASP standard ships a new edition; doesn't require automation to start. |

### Anti-Features (Commonly Tempting, Actually Harmful)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|------------------|-------------|
| Keeping outdated OWASP editions (Top 10:2021) as "current" without flagging | Feels lower-risk to leave working content alone during a refresh | Directly falsifiable by any visitor who checks owasp.org; for a security-credibility project this is the single fastest way to lose trust and stars on day one, since OWASP Top 10:2025 is already published | Do the version-verification pass this milestone already requires; label each reference file with the exact edition + verification date |
| Overclaiming automated detection capability ("automatically finds all vulnerabilities," "SAST-grade scanning") | Sounds more impressive in marketing copy / README | The repo is explicitly a guided-review + regex-leads tool, not a SAST engine (confirmed out of scope in `PROJECT.md`); research on security tooling trust shows overclaiming detection accuracy erodes credibility faster than admitting scope limits — false-positive-prone tools "actively damage security programs by eroding developer trust" | State scope honestly: "structured OWASP-grounded review assistant with a regex lead-scanner," not a scanner replacement |
| Cramming full standard text into `SKILL.md` bodies instead of using progressive disclosure `references/` | Feels simpler to have "everything in one file" | Burns context on every session — research shows an unoptimized skill index can add tens of thousands of tokens vs. ~100 tokens/skill with proper progressive disclosure; also risks silent truncation/drop if description/body exceeds host-specific limits | Keep bodies lean (<500 lines), push standard-specific detail into `references/*.md`, load on demand — matches what the repo mostly already does |
| Building a live/runtime SAST or continuous-scanning engine | Tempting "make it more useful" scope creep once you're touching the scanner script | Explicitly out of scope per `PROJECT.md`; increases false-positive surface (the exact trust-eroding failure mode found in the false-positive research above) and turns a lightweight, portable reference into a maintenance-heavy product | Keep `quick_scan.py` as a lightweight, transparent lead-generator only; document its regex rules openly so users can judge its limits themselves |
| Auto-remediation / "auto-fix" that rewrites user code without review | Seems like a natural next step after "detect vulnerability" | A tool that silently patches security-sensitive code can introduce new vulnerabilities and removes the human-in-the-loop review that security work requires; also expands liability/trust surface enormously for very little added value | Always show vulnerable → secure code as a *reference pattern* for the user to apply, never apply edits autonomously |
| Maintaining the legacy Copilot `owasp-css.instructions.md` + custom `skill.json` alongside the new spec-compliant format indefinitely ("just in case") | Avoids breaking any existing installs during transition | Two sources of truth for the same skills guarantees drift (one gets updated, the other doesn't) and confuses new adopters about which format is canonical — directly undermines the "install cleanly" goal | Retire or clearly mark legacy files as deprecated/migration-only, per the milestone's own decision to do this |
| Chasing GitHub stars/visibility through low-substance growth tactics (mass-tagging, star-exchange, AI-generated filler content) | Appealing shortcut to the stated "GitHub stars" adoption signal | Damages credibility with the exact audience (security professionals) who scrutinize repos closely, and risks anti-abuse flags; hollow stars don't convert to real usage or trust | Earn visibility organically via awesome-list PRs, real demo content, and genuinely current/accurate reference material — slower but durable |
| Offensive-skill content (exploit-dev, red-team) without consistent "authorized testing only" framing | Framing feels like unnecessary boilerplate once already implied elsewhere | For a *public* repo, inconsistent or missing authorized-use framing is both a policy risk and an adoption blocker for security teams who'd otherwise recommend the repo internally | Make the authorized-use disclaimer consistent across every offensive-capable skill's frontmatter description and the top-level README, not just implied by naming |

## Feature Dependencies

```
Marketplace-installable packaging (plugin.json + marketplace.json)
    └──requires──> Official Agent Skills spec compliance (SKILL.md + frontmatter, per-skill)
                       └──requires──> Retiring/bridging legacy skill.json + owasp-css.instructions.md

OpenSSF Best Practices badge
    └──requires──> LICENSE file
    └──requires──> Documented security policy
    └──requires──> Basic CI (lint/syntax checks already implied by TESTING.md)

evals/ folder (skill-correctness tests)
    └──requires──> Finalized per-skill SKILL.md structure (spec compliance)

Provenance/verification transparency (dated OWASP-source citations)
    └──requires──> Current, verified OWASP edition coverage (table stakes)
    └──enhances──> Credibility differentiator, README trust signals

Awesome-list / marketplace directory listings
    └──requires──> README quality + badges + working install (table stakes)
    └──requires──> Marketplace-installable packaging (to be listed as an actual plugin, not just a repo link)

Auto-remediation ("auto-fix") ──conflicts──> Guidance-only positioning / Out-of-scope constraint (no live SAST engine)

Legacy Copilot format retained indefinitely ──conflicts──> Single-source-of-truth spec compliance goal
```

### Dependency Notes

- **Marketplace packaging requires spec compliance:** `marketplace.json`/`plugin.json` entries point at skill directories that must already conform to the official `SKILL.md` format — packaging is the last mile, not a parallel track.
- **OpenSSF badge requires LICENSE + security policy + CI first:** all three are independently table-stakes/low-complexity items; the badge itself is a differentiator built on top of them, so sequence LICENSE and security-policy work before attempting the badge.
- **Verification transparency depends on the edition-accuracy work already mandated by this milestone:** it's a presentation layer on top of required accuracy work, not additional research.
- **evals/ depends on finalized SKILL.md structure:** writing correctness tests before the skill body/structure is locked in phase order would mean rewriting tests when structure changes.
- **Auto-remediation conflicts with the project's own Out of Scope constraint** ("not a live SAST engine," "reviews stay stateless") — flag this explicitly so no phase accidentally scope-creeps toward it.
- **Legacy-format retention conflicts with the single-spec goal** — the milestone's own Key Decisions already call for retiring/replacing these files; treat "keep both indefinitely" as the anti-feature outcome to avoid.

## MVP Definition

### Launch With (v1 — this milestone)

- [ ] Every skill's `SKILL.md` frontmatter compliant with the official Agent Skills spec (name, "Use when..." description under practical length limits) — required for any skill to reliably activate at all
- [ ] All OWASP standard references verified/updated against official sources (Top 10:2025, ASVS 5.0.0, current MASVS, API/K8s/LLM/Agentic/SCP) with per-file "verified as of [date] against [URL]" notes — the accuracy this project is explicitly built to deliver
- [ ] Legacy `skill.json`/`owasp-css.instructions.md` retired or clearly marked deprecated in favor of spec-compliant files — required to avoid dual-source drift
- [ ] `plugin.json` + `marketplace.json` at repo root enabling Claude Code marketplace install — the literal definition of "marketplace-ready" per this milestone
- [ ] LICENSE file added — blocks all serious/enterprise adoption if missing
- [ ] README rewritten: scope, install (marketplace + symlink paths), badges, one real example — first-impression surface that drives stars
- [ ] Paired vulnerable/secure examples extended to cover any new/renamed 2025-edition categories — keeps the repo's core content depth intact through the version bump

### Add After Validation (v1.x)

- [ ] `evals/` correctness tests per skill — add once SKILL.md structure is locked and stable
- [ ] Submit to `awesome-claude-code` / `awesome-claude-skills` and marketplace directories — do once the repo is genuinely polished, not before (a weak submission wastes the one shot at a curator's attention)
- [ ] OpenSSF Best Practices badge pursuit — natural follow-on once LICENSE + security policy + CI are in place
- [ ] Demo transcripts/GIFs of real audit sessions — high value, but can follow initial launch

### Future Consideration (v2+)

- [ ] Update-cadence automation/alerting tied to OWASP release calendar — nice signal of long-term maintenance, but manual changelog discipline is sufficient to start
- [ ] Expanding cross-assistant install targets beyond Claude/Copilot — defer until the core Claude Code / marketplace path is proven and adopted

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Verified current OWASP editions | HIGH | MEDIUM | P1 |
| Official Agent Skills spec compliance per skill | HIGH | MEDIUM | P1 |
| Marketplace packaging (plugin.json/marketplace.json) | HIGH | MEDIUM | P1 |
| LICENSE + README overhaul + badges | HIGH | LOW | P1 |
| Retire legacy skill.json/instructions.md | MEDIUM | LOW | P1 |
| Extended vulnerable/secure examples for new categories | MEDIUM | MEDIUM | P1 |
| Provenance/verification citations visible in docs | MEDIUM | LOW | P2 |
| evals/ correctness tests | MEDIUM | MEDIUM | P2 |
| Awesome-list / marketplace directory submissions | MEDIUM | LOW | P2 |
| OpenSSF Best Practices badge | MEDIUM | MEDIUM | P2 |
| Demo transcripts/recordings | MEDIUM | LOW | P2 |
| OWASP-release-cadence automation | LOW | MEDIUM | P3 |

**Priority key:**
- P1: Must have for this milestone's launch
- P2: Should have, add once P1 is stable
- P3: Nice to have, future consideration

## Competitor Feature Analysis

| Feature | Generic "awesome-claude-skills" curated lists | Single-standard security skills (e.g., one-OWASP-list-only repos) | Our Approach |
|---------|--------------------------------------------|---------------------------------------------------------------------|--------------|
| Standard breadth | N/A (aggregator, not a skill itself) | Narrow — usually just OWASP Top 10 or generic "code review" | Full-breadth: Top 10, ASVS, MASVS, API, K8s, LLM/Agentic, SCP in one coherent, cross-referenced collection |
| Spec compliance | Varies wildly by submission — many entries are informal prompt files, not spec-compliant `SKILL.md` | Mixed; many predate the Dec 2025 open standard | Full compliance with official Agent Skills spec across all ~17 skills |
| Version currency | Not applicable/not curated for accuracy | Frequently stale (pinned to whatever edition existed at authoring time, rarely revisited) | Explicit verification pass this milestone + stated update cadence |
| Marketplace packaging | Aggregators just link out | Rare — most are plain repos, not registered plugins | `plugin.json`/`marketplace.json` for direct marketplace install |
| Correctness testing (evals/) | Not evaluated | Essentially never present | Add `evals/` as a differentiator |
| Licensing/badges/OpenSSF signal | Inconsistent across listed repos | Frequently missing (no LICENSE is common in smaller security-prompt repos) | LICENSE, badges, and OpenSSF badge pursuit as explicit milestone/follow-on work |

## Sources

- [Anthropic Engineering — Equipping agents for the real world with Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Claude Code Docs — Extend Claude with skills](https://code.claude.com/docs/en/skills)
- [Claude Code Docs — Create plugins](https://code.claude.com/docs/en/plugins)
- [Claude Code Docs — Create and distribute a plugin marketplace](https://code.claude.com/docs/en/plugin-marketplaces)
- [anthropics/skills (official repo)](https://github.com/anthropics/skills)
- [anthropics/claude-code marketplace.json example](https://github.com/anthropics/claude-code/blob/main/.claude-plugin/marketplace.json)
- [hesreallyhim/claude-code-json-schema (unofficial schema)](https://github.com/hesreallyhim/claude-code-json-schema)
- [agentskills.io — Optimizing skill descriptions](https://agentskills.io/skill-creation/optimizing-descriptions)
- [github/copilot-cli#3494 — descriptions silently dropped above char limit](https://github.com/github/copilot-cli/issues/3494)
- [danielmiessler/Personal_AI_Infrastructure#1205 — skill descriptions exceeding ceiling](https://github.com/danielmiessler/Personal_AI_Infrastructure/issues/1205)
- [hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code)
- [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP ASVS project page](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP/ASVS GitHub](https://github.com/OWASP/ASVS)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [coreinfrastructure/best-practices-badge (OpenSSF)](https://github.com/coreinfrastructure/best-practices-badge)
- [badges/shields](https://github.com/badges/shields)
- [matiassingers/awesome-readme](https://github.com/matiassingers/awesome-readme)
- [ZeroPath — Code Security Platforms: False Positives (2026)](https://zeropath.com/articles/code-security-platforms-reducing-false-positives)
- [MindStudio — What Is Context Rot in Claude Code Skills?](https://www.mindstudio.ai/blog/context-rot-claude-code-skills-bloated-files)
- Project context: `.planning/PROJECT.md`, `.planning/codebase/STRUCTURE.md`, `.planning/codebase/CONVENTIONS.md`

---
*Feature research for: Security-skill collection for Claude Code (OWASP modernization milestone)*
*Researched: 2026-07-19*
