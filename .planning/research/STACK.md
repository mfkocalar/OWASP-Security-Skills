# Stack Research

**Domain:** OWASP-standards reference skill collection, packaged as Anthropic Agent Skills + a Claude Code plugin/marketplace
**Researched:** 2026-07-19
**Confidence:** MEDIUM-HIGH (all findings fetched live from official owasp.org / genai.owasp.org / github.com/OWASP / platform.claude.com / code.claude.com pages on the research date; the automated confidence-classifier seam caps generic `websearch`/`webfetch` fetches at MEDIUM even for primary-source pages, so MEDIUM below should be read as "verified against the official page directly," not "secondhand." Two items are explicitly flagged LOW/gap where the primary PDF/category list could not be extracted.)

This is a refresh milestone on a mature repo (see `.planning/codebase/`). This document is the authoritative version matrix + packaging spec for that refresh — it does not re-derive the existing architecture.

## Recommended Stack

### OWASP Standards — Version Matrix (verify-before-roadmap deliverable)

| Standard | Repo currently claims | Newest verified edition | Status | Action needed | Official source |
|----------|------------------------|--------------------------|--------|----------------|------------------|
| OWASP Top 10 (web app) | 2021 | **Top 10:2025** (8th edition) | **FINAL** — GitHub README states "OWASP Top 10:2025 (Final)", superseding the RC1 published 6 Nov 2025 at Global AppSec Washington DC | **UPDATE — outdated.** Full category rewrite: A03 and A10 are new, A02 jumped from #5→#2, SSRF folded into Broken Access Control | https://owasp.org/Top10/2025/ , repo README https://github.com/OWASP/Top10 |
| OWASP ASVS | 5.0 | **5.0.0** (30 May 2025) | FINAL/stable. A "bleeding edge" build regenerated continuously from `master` also exists but is explicitly marked unstable, not for production use | **No change** — repo claim is current. Watch for v5.0.1 patch | https://github.com/OWASP/ASVS/releases , https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP MASVS | 2.1.0 | **2.1.0** (18 Jan 2024) | FINAL/stable | **No change** — repo claim is current | https://github.com/OWASP/masvs/releases |
| OWASP API Security Top 10 | 2023 | **2023** | FINAL/stable, no newer edition in progress found | **No change** — repo claim is current | https://owasp.org/API-Security/editions/2023/en/0x00-header/ |
| OWASP Kubernetes Top 10 | 2022 | 2022 stable; **2025 draft exists** | 2022 = FINAL/stable. 2025 = explicitly labeled **DRAFT** ("2025 Top 10 Risks now available. Feedback welcome. Please open issues or PRs for changes") | **Decision point, not a bug.** Repo's 2022 claim is still the correct *stable* reference. Roadmap must decide: ship against 2022 (safe) or track the 2025 draft with a "draft" disclaimer (riskier, could shift under you) | Stable: https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/ · Draft: https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/ |
| OWASP Top 10 for LLM Applications | 2025 | **2025 (v2.0)**, published 18 Nov 2024 | FINAL/stable, designations LLM01:2025–LLM10:2025 | **No change** — repo claim is current | https://genai.owasp.org/llm-top-10/ |
| OWASP Top 10 for Agentic Applications | 2026 | **2026**, announced 9 Dec 2025 | Presented as final/GA ("globally peer-reviewed," no RC/draft label found), designations ASI01–ASI10 | **No change in edition** — repo claim is current. **Gap:** exact official ASI01–ASI10 category names could not be extracted from the summary page; only paraphrased category *themes* (planning, tool use, identity, supply chain, code execution, memory, inter-agent communication, cascading failures, human-agent trust, rogue agents) were found via secondary sources — **pull the exact names from the primary PDF before writing reference content** | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ , https://genai.owasp.org/initiatives/agentic-security-initiative/ |
| OWASP Secure Coding Practices Quick Reference Guide | (unversioned checklist) | v2.0.1 (Nov 2012 reissue) — **but the project itself is ARCHIVED** | **Archived.** Official banner: "The OWASP Secure Coding Practices Quick-reference Guide project has now been archived." Content (overview, glossary, checklists) has been migrated into the **OWASP Developer Guide** (devguide.owasp.org), though the Developer Guide is a cross-reference hub rather than a single consolidated checklist replacement | **Biggest finding of this research.** The `secure-coding-practices` skill is built on a project OWASP itself no longer maintains. Roadmap must decide: (a) keep the SCP checklist as a frozen/historical reference with an explicit "archived, last v2.0.1" disclaimer, or (b) re-derive the 14-domain checklist against current equivalents — OWASP Developer Guide, [Cheat Sheet Series](https://cheatsheetseries.owasp.org/), and [Top 10 Proactive Controls](https://owasp.org/www-project-proactive-controls/) — and cite those as primary going forward | https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/ , https://devguide.owasp.org/ |

**Net effect on the repo:** of 7 standards covered, only **OWASP Top 10** needs a hard version bump (2021→2025, full rewrite), and **Secure Coding Practices** needs a scoping decision because its source project is archived. ASVS, MASVS, API Security Top 10, LLM Top 10, and Agentic Applications 2026 are all already correctly labeled at their current editions — the milestone's job for those five is verification/citation-hardening, not renumbering.

### Anthropic Agent Skills — SKILL.md Spec

Source: `platform.claude.com/docs/en/agents-and-tools/agent-skills/overview` and `.../best-practices` (fetched live).

**Required YAML frontmatter (cross-product spec, applies everywhere Skills run):**

| Field | Required | Constraints |
|-------|----------|-------------|
| `name` | Yes | Max 64 characters; lowercase letters, numbers, hyphens only; no XML tags; cannot contain reserved words `anthropic` or `claude` |
| `description` | Yes (recommended) | Non-empty; max 1024 characters (cross-product spec); must state both **what** the skill does and **when** to use it; write in third person ("Processes X" not "I can help..."); no XML tags |

**Claude Code extends this** (`code.claude.com/docs/en/skills`) with additional optional frontmatter fields — all optional, none required beyond the two above: `when_to_use`, `argument-hint`, `arguments`, `disable-model-invocation`, `user-invocable`, `allowed-tools`, `disallowed-tools`, `model`, `effort`, `context` (`fork` for subagent execution), `agent`, `hooks`, `paths` (glob-scoped auto-activation), `shell`. Note: Claude Code truncates the combined `description` + `when_to_use` text at **1,536 characters** in the skill listing (not the 1024-char spec limit) — front-load the key use case.

**Progressive disclosure (3 levels):**

| Level | When loaded | Token cost | Content |
|-------|-------------|------------|---------|
| 1. Metadata | Always, at startup | ~100 tokens/skill | `name` + `description` from frontmatter |
| 2. Instructions | When skill triggers | Keep under 5k tokens; **hard guidance: keep SKILL.md body under 500 lines** | SKILL.md body |
| 3. Resources/code | On demand only | Zero until accessed | Bundled files (references, scripts, assets); scripts execute via bash, only output enters context |

**Bundled directory conventions** (not enforced by schema, but the standard pattern used by Anthropic's own skills and matching the repo's existing layout): `references/` (lookup docs, checklists), `scripts/` (executable utilities, run not read), `assets/` (templates, examples, icons). This already matches the repo's `skills/*/references/`, `skills/*/scripts/`, `skills/*/assets/` layout — no restructuring needed at the directory level, only frontmatter/content-format compliance.

**Best-practice rules directly applicable to this repo's refresh:**
- Keep file references **one level deep** from SKILL.md (don't nest `advanced.md → details.md`) — the repo's existing `references/*.md` files are already flat, good.
- Reference files over 100 lines should carry a table of contents at the top (the repo's `owasp-comprehensive-security-skills.md` at ~2,500 lines and the 14-domain `scp-checklist.md` both need this).
- Avoid time-sensitive phrasing ("as of 2021…") — put superseded material in a collapsed "old patterns" section instead of deleting it, since edition history has value here.
- Naming convention: gerund or noun-phrase preferred (`auditing-owasp-standards` or `owasp-security-audit`), avoid vague names (`helper`, `tools`) — repo's existing `owasp-security-audit` / `secure-coding-practices` names already conform.

### Claude Code Plugin & Marketplace Packaging

Source: `code.claude.com/docs/en/plugins`, `.../plugins-reference`, `.../plugin-marketplaces` (fetched live).

**Plugin manifest** — `<plugin-root>/.claude-plugin/plugin.json`:
- Manifest itself is **optional** (Claude Code auto-discovers `skills/`, `agents/`, etc. by convention if omitted) — but for a public-marketplace-quality collection, ship one explicitly.
- Only required field if present: `name` (kebab-case, no spaces — this becomes the skill-invocation namespace, e.g. `/owasp-security-skills:owasp-security-audit`).
- Common optional fields: `displayName`, `version`, `description`, `author {name, email, url}`, `homepage`, `repository`, `license` (SPDX id, e.g. `MIT`), `keywords`, and component-path overrides (`skills`, `commands`, `agents`, `hooks`, `mcpServers`, `outputStyles`, `lspServers`, `experimental`, `dependencies`).
- **Critical structural rule:** only `plugin.json` goes inside `.claude-plugin/`. Directories like `skills/`, `commands/`, `agents/`, `hooks/` must live at the **plugin root**, sibling to `.claude-plugin/`, not inside it. This is called out explicitly in the docs as "common mistake."
- Skills are auto-discovered from a plugin-root `skills/<name>/SKILL.md` directory layout; a plugin shipping exactly one skill may instead place `SKILL.md` directly at plugin root.

**Marketplace catalog** — `<repo-root>/.claude-plugin/marketplace.json`:
- Required top-level: `name` (kebab-case, public-facing, e.g. `/plugin install owasp-security-audit@owasp-security-skills`), `owner {name, email?}`, `plugins[]`.
- Each `plugins[]` entry requires `name` + `source`. `source` may be a relative path (`"./"` or `"./plugins/x"`, must start with `./`, resolved against the marketplace root), or an object: `{source:"github", repo, ref?, sha?}`, `{source:"url", url, ref?, sha?}`, `{source:"git-subdir", url, path, ref?, sha?}`, or `{source:"npm", package, version?, registry?}`.
- Optional per-plugin fields mirror `plugin.json` (`description`, `version`, `author`, `homepage`, `repository`, `license`, `keywords`) plus marketplace-only fields (`category`, `tags`, `strict`, `relevance`, `defaultEnabled`).
- **Reserved marketplace names** (cannot be used): `claude-code-marketplace`, `claude-code-plugins`, `claude-plugins-official`, `claude-plugins-community`, `claude-community`, `anthropic-marketplace`, `anthropic-plugins`, `agent-skills`, `anthropic-agent-skills`, and several vertical-specific reserved names — irrelevant to this project's naming but confirms `owasp-security-skills` (or similar) is safe to use.
- Validate before publishing: `claude plugin validate .` (add `--strict` to fail on unrecognized-field warnings, useful in CI).
- Distribution path for this repo: host `marketplace.json` + plugin(s) in this same GitHub repo, users add via `/plugin marketplace add <owner>/<repo>` then `/plugin install <plugin-name>@<marketplace-name>`. For public-marketplace visibility beyond direct installs, the repo can also be submitted to Anthropic's community marketplace (`claude-plugins-community`) via the in-app submission form — optional stretch goal, not required for "installable."

**One-plugin-vs-two-plugins decision for the roadmap:** the repo currently ships two conceptually separate skills (`owasp-security-audit`, `secure-coding-practices`) plus 15 other cyber-domain skills. The plugin/marketplace schema supports either "one marketplace, one plugin with many skills/" or "one marketplace, many plugins" — recommend **one plugin** (e.g. `owasp-security-skills`) bundling all `skills/*/SKILL.md` directories, since they share one install/versioning lifecycle and the namespacing (`owasp-security-skills:owasp-security-audit`) reads cleanly.

## Installation / Validation Commands

```bash
# Local test before publishing
claude --plugin-dir ./owasp-security-skills   # loads plugin without install
/reload-plugins                                # picks up edits without restart

# Validate manifest + all skill/agent frontmatter
claude plugin validate ./owasp-security-skills --strict

# Publish path
/plugin marketplace add <owner>/<repo>
/plugin install owasp-security-skills@<marketplace-name>
```

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|--------------------------|
| One plugin bundling all skills | One plugin per skill (17 separate plugins) | Only if skills need fully independent versioning/release cadence — adds marketplace-entry overhead for no real benefit here since all skills ship together today |
| Keep `owasp-css.instructions.md`/`skill.json` retired, replaced by `SKILL.md` frontmatter | Keep both formats side-by-side for Copilot compatibility | Only if Copilot/other-assistant support is still a stated goal — PROJECT.md's Active requirements say the legacy files should be "retired or replaced," so full retirement is the cleaner target |
| Cite OWASP Developer Guide + Cheat Sheet Series + Proactive Controls for secure-coding content going forward | Keep citing only the archived SCP Quick Reference Guide | Only acceptable if the roadmap explicitly treats SCP as a frozen historical checklist and says so in the skill's docs — silently citing an archived project as if current would fail the "no unverified/stale claims" constraint in PROJECT.md |
| Track Kubernetes Top 10 2022 as primary, footnote the 2025 draft | Adopt the 2025 draft as primary now | Only if the roadmap is willing to accept churn risk — OWASP explicitly says the 2025 doc is still accepting PRs/issues, i.e., not stable |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|--------------|
| Custom `skill.json` manifest format (current repo pattern) as the skill descriptor | Not the official Agent Skills format; Claude Code doesn't read it for skill discovery — YAML frontmatter in `SKILL.md` is the actual discovery mechanism | `SKILL.md` YAML frontmatter (`name`, `description`, optional Claude-Code-specific fields) |
| `owasp-css.instructions.md` as the activation/routing layer | Copilot-instructions-style file, not part of the Agent Skills or plugin spec; Claude Code doesn't consume it | Rely on each skill's own `description` field for auto-activation; Claude Code's model-driven skill selection replaces manual keyword routing |
| ASVS/MASVS "bleeding edge" / master-branch builds as a citation source | Explicitly marked unstable, continuously regenerated, "cannot be relied upon for stability" | Pin to the tagged stable release (ASVS v5.0.0, MASVS v2.1.0) |
| Citing OWASP Kubernetes Top 10 2025 as if it were the stable edition | It is an open, still-being-edited draft accepting PRs/issues | Cite 2022 as stable; mention 2025 only as "upcoming, in draft" if referenced at all |
| Presenting the archived SCP Quick Reference Guide as an actively maintained OWASP standard | The project page itself says "archived"; OWASP has moved this content into the Developer Guide | Either explicitly label SCP content as a frozen historical checklist, or re-source the equivalent guidance from Developer Guide / Cheat Sheet Series / Proactive Controls |

## Version Compatibility

| Standard/Doc | Compatible With | Notes |
|--------------|------------------|-------|
| OWASP Top 10:2025 | ASVS 5.0.0, MASVS 2.1.0 | All three are independently versioned OWASP projects; no cross-dependency, but Top 10:2025's new A03 (Software Supply Chain Failures) overlaps conceptually with ASVS V14 (dependency/build-chain controls) — cross-reference when rewriting `top10.md` |
| OWASP LLM Top 10 (2025) | OWASP Agentic Applications Top 10 (2026) | Explicitly non-overlapping by design: LLM Top 10 excludes "autonomous-agent-specific risks," which the Agentic Top 10 owns. Keep these as two distinct reference files, not merged |
| SKILL.md frontmatter spec | Claude Code v2.1.x (skills-as-plugin-components) | The `skills` field pointing at custom paths, `disable-model-invocation`, and several other fields carry `min-version` notes in the docs (e.g. `displayName` requires v2.1.143+, `renames` requires v2.1.193+) — if the plugin targets a broad Claude Code install base, avoid depending on very recent (>v2.1.190) fields for core functionality |

## Sources

- https://owasp.org/Top10/2025/ — OWASP Top 10:2025 official page (confirmed FINAL via GitHub README cross-check) — MEDIUM/direct-primary
- https://github.com/OWASP/Top10 — README confirms "OWASP Top 10:2025 (Final)" — MEDIUM/direct-primary
- https://github.com/OWASP/ASVS/releases , https://owasp.org/www-project-application-security-verification-standard/ — ASVS 5.0.0 stable confirmation — MEDIUM/direct-primary
- https://github.com/OWASP/masvs/releases — MASVS 2.1.0 confirmation — MEDIUM/direct-primary
- https://owasp.org/API-Security/editions/2023/en/0x00-header/ — API Security Top 10 2023 confirmation — MEDIUM/direct-primary
- https://owasp.org/www-project-kubernetes-top-ten/ , .../2025/en/src/ , .../2022/en/src/ — Kubernetes Top 10 stable-vs-draft confirmation — MEDIUM/direct-primary
- https://genai.owasp.org/llm-top-10/ — LLM Top 10 2025 confirmation — MEDIUM/direct-primary
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ , https://genai.owasp.org/initiatives/agentic-security-initiative/ — Agentic Applications 2026 confirmation — MEDIUM/direct-primary; **category-name list is LOW confidence (gap, see table above)**
- https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/ , https://devguide.owasp.org/ — SCP archived-status confirmation — MEDIUM/direct-primary
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview , .../best-practices — Agent Skills spec (frontmatter, progressive disclosure) — MEDIUM/direct-primary
- https://code.claude.com/docs/en/skills , .../plugins , .../plugins-reference , .../plugin-marketplaces — Claude Code skill/plugin/marketplace schema — MEDIUM/direct-primary

---
*Stack research for: OWASP Security Skills modernization milestone*
*Researched: 2026-07-19*
