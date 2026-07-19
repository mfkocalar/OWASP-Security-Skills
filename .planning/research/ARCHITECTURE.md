# Architecture Research

**Domain:** Claude Code Agent Skills packaging — multi-skill security-reference plugin/marketplace
**Researched:** 2026-07-19
**Confidence:** HIGH (primary source: official Anthropic/Claude Code docs, cross-checked against 2 independent doc pages + community aggregators)

## Standard Architecture

### System Overview

```
┌───────────────────────────────────────────────────────────────────────────┐
│  MARKETPLACE  (.claude-plugin/marketplace.json)                           │
│  Catalog: name, owner, plugins[] → {name, source, description, version}   │
│  Added by user: /plugin marketplace add mfkocalar/OWASP-Security-Skills   │
├───────────────────────────────────────────────────────────────────────────┤
│  PLUGIN  (.claude-plugin/plugin.json)  — "owasp-security-skills"          │
│  Identity: name, version, author, homepage, license, keywords             │
│  Installed by user: /plugin install owasp-security-skills@owasp-security- │
│  skills → copied to ~/.claude/plugins/cache/<marketplace>/<plugin>/<ver>/ │
├───────────────────────────────────────────────────────────────────────────┤
│  SKILLS  (skills/<skill-name>/SKILL.md)  — N independent units            │
│  ┌────────────────────┐ ┌────────────────────┐ ┌──────────────────────┐  │
│  │ owasp-security-audit│ │secure-coding-practi│ │ ...15 domain skills  │  │
│  │  SKILL.md (dispatcher│ │ces  SKILL.md       │ │  (recon-osint, vuln- │  │
│  │  across 6 standards) │ │                    │ │  scanner, ... )      │  │
│  └─────────┬───────────┘ └─────────┬──────────┘ └──────────┬───────────┘  │
│            │  references/          │  references/          │  references/│
│            │  scripts/             │  assets/               │  assets/    │
│            │  assets/               │                        │            │
├───────────────────────────────────────────────────────────────────────────┤
│  PROGRESSIVE DISCLOSURE (per skill, 3 levels)                              │
│  L1 metadata (~100 tok, always) → L2 SKILL.md body (<5k tok, on trigger)  │
│  → L3 references/ scripts/ assets/ (0 tok until Claude reads/runs them)   │
└───────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Typical Implementation |
|-----------|----------------|-------------------------|
| Marketplace catalog (`.claude-plugin/marketplace.json`) | Lists installable plugins and where to fetch them; the thing users add with `/plugin marketplace add` | One `name`, one `owner`, one or more entries in `plugins[]`, each with `name` + `source` |
| Plugin manifest (`.claude-plugin/plugin.json`) | Declares plugin identity (name, version, author, license); optionally overrides default component discovery paths | Single JSON file; `name` is the only required field; everything else optional and auto-discovered |
| Skill directory (`skills/<name>/SKILL.md`) | One independent, model-invoked capability; owns its own trigger description and workflow | Folder name = skill's local name (namespaced by plugin as `/plugin-name:skill-name`) |
| `references/*.md` | Deep, standard-specific lookup content loaded only when the SKILL.md body points Claude at it | One file per OWASP standard (top10, asvs, masvs, api-top10, kubernetes-top10, agentic) |
| `scripts/*.py` | Deterministic, executable logic invoked via bash; source code itself never enters context, only stdout | `quick_scan.py` — regex lead-finder |
| `assets/*` | Templates/examples the skill produces or consumes; read only if referenced | Paired vulnerable/secure code samples |

## Recommended Project Structure

```
OWASP-Security-Skills/                       # repo root = plugin root = marketplace root
├── .claude-plugin/
│   ├── plugin.json                          # REPLACES skill.json
│   └── marketplace.json                     # NEW — repo self-lists as a marketplace source
│
├── skills/
│   ├── owasp-security-audit/
│   │   ├── SKILL.md                         # frontmatter (name/description) + dispatcher workflow
│   │   ├── references/
│   │   │   ├── top10.md                     # OWASP Top 10 — refreshed edition
│   │   │   ├── api-top10.md                 # API Security Top 10 — refreshed edition
│   │   │   ├── asvs.md                      # ASVS — refreshed edition
│   │   │   ├── masvs.md                     # MASVS — refreshed edition
│   │   │   ├── kubernetes-top10.md          # K8s Top 10 — refreshed edition
│   │   │   ├── agentic-apps-top10.md        # Agentic Apps — refreshed edition
│   │   │   ├── vulnerable-patterns.md
│   │   │   └── owasp-urls.json
│   │   ├── scripts/
│   │   │   └── quick_scan.py
│   │   └── assets/
│   │       └── examples/                    # canonical, self-contained copies (see Migration §4)
│   │           ├── broken-access-control.py
│   │           ├── cryptographic-failures.js
│   │           ├── injection.js
│   │           ├── security-misconfiguration.py
│   │           ├── xss.html
│   │           ├── logging-monitoring-failures.py
│   │           ├── api-auth-bypass.js
│   │           ├── k8s-rbac.yaml
│   │           └── prompt-injection.txt
│   │
│   ├── secure-coding-practices/
│   │   ├── SKILL.md
│   │   ├── references/
│   │   │   ├── scp-checklist.md
│   │   │   ├── secure-patterns.md
│   │   │   └── owasp-urls.json
│   │   └── assets/examples/
│   │       ├── vulnerable-examples.py
│   │       └── vulnerable-examples.js
│   │
│   └── <domain-skill>/                      # one dir per additional skill in scope (recon-osint,
│       ├── SKILL.md                         # vulnerability-scanner, exploit-development, reverse-
│       ├── references/                      # engineering, malware-analysis, threat-hunting,
│       ├── scripts/                         # incident-response, network-security, web-security,
│       └── assets/                          # cloud-security, csoc-automation, log-analysis,
│                                             # crypto-analysis, red-team-ops, blue-team-defense
│                                             # — each fully self-contained, same 4-part shape
│
├── README.md                                # rewritten: plugin install instructions first
├── CONTRIBUTING.md                          # rewritten: "add a skill/reference" = new skills/<x>/ dir
├── DEPLOYMENT.md                            # rewritten: /plugin marketplace add + install.sh fallback
├── TESTING.md                               # rewritten: claude plugin validate + --plugin-dir smoke test
└── install.sh                               # kept, scoped to non-Claude-Code targets (Copilot/custom)
```

### Structure Rationale

- **`.claude-plugin/` holds only the two manifests.** This is a hard rule, not a style choice: `commands/`, `agents/`, `skills/`, `hooks/` must sit at plugin root, never inside `.claude-plugin/`, or Claude Code fails to discover them.
- **`skills/<name>/` is the unit of both activation and refresh work.** Each directory is fully self-contained (its own `references/`, `scripts/`, `assets/`) so it can be authored, verified against its OWASP source, and reformatted independently of every other skill — this is the mechanism that answers "how do we parallelize the restructure."
- **One plugin, self-hosted marketplace, for this milestone.** The repo root doubles as both the plugin (`.claude-plugin/plugin.json`) and the marketplace (`.claude-plugin/marketplace.json`, listing itself with `"source": "."`). This is the lowest-friction shape for a single-collection public repo: one `git clone`/`/plugin marketplace add owner/repo` gets everything. See "Alternative: multi-plugin marketplace" below for the scale-out path.
- **`examples/` at repo root is retired as a second canonical source.** Today it's duplicated (by design) into each skill's `assets/examples/`. Post-packaging, the plugin's installed cache is a copy of the plugin root, so keeping two sources of truth for the same files is pure drift risk with no packaging benefit — `assets/examples/` per skill becomes the only canonical location.

## Migration Path: Current → Spec-Compliant

| Current artifact | Disposition | Target | Why |
|---|---|---|---|
| `owasp-css.instructions.md` (Copilot-style router: keyword sets, confidence threshold >0.7, context→standard mapping) | **Retired.** No file replaces it 1:1. | Routing logic decomposes into each skill's `description` (+ optional `when_to_use`, `paths`) frontmatter field | The spec has no "router" concept. Claude's model itself matches the user's request against every installed skill's `description` at Level 1 — this *is* the activation mechanism. A hand-written keyword/confidence router duplicates what the model already does natively and can drift out of sync with the skills it routes to. |
| `skill.json` (custom manifest: metadata, `standards[]`, `activation.triggers[]`, `files.skills`) | **Replaced.** | `.claude-plugin/plugin.json` (identity: name/version/author/license) | `plugin.json` has no `activation.triggers` concept — that's exactly the field that moves into per-skill `description`s (see row above). `standards[]` and `files.skills` bookkeeping is unnecessary once `skills/` auto-discovery is the source of truth. |
| `owasp-comprehensive-security-skills.md` (900-line consolidated reference across all 6 standards) | **Retired from the loaded context path.** Optionally kept as pure human-facing documentation (not linked from any SKILL.md). | none (or `docs/overview.md`, never `Read` by a skill) | Violates progressive disclosure by design: a single 900-line file loaded wholesale defeats the entire point of splitting standards into `references/*.md` that load only on demand. The per-standard reference files already existing under `skills/owasp-security-audit/references/` are the spec-correct decomposition of this content. |
| `skills/owasp-security-audit/owasp-security-audit.md`, `skills/secure-coding-practices/secure-coding-practices.md` (secondary "metadata + guide" files sitting beside SKILL.md) | **Retired/merged.** | Content folds into `SKILL.md` frontmatter+body, or becomes a `references/` file if it's genuinely deep guidance | The spec defines exactly one metadata carrier per skill: `SKILL.md`'s frontmatter. A second parallel metadata file is redundant and a maintenance-drift risk (two files can disagree about what the skill does). |
| `examples/` (root, canonical) + `skills/*/assets/examples/` (duplicated/symlinked) | **Root copy retired.** `assets/examples/` becomes sole canonical source. | `skills/<name>/assets/examples/` | Plugin install copies the plugin directory into a versioned cache; paths outside a plugin's own tree, and especially symlinks resolved outside it, are the most common "files not found after install" failure. Keeping one real (non-symlinked) copy per skill removes the whole class of bug. |
| `install.sh` (symlink installer for Claude/Copilot/custom targets) | **Kept, scope narrowed.** | Same file, but DEPLOYMENT.md reframes it as the path for *non*-Claude-Code assistants; Claude Code users are pointed at `/plugin marketplace add` | Copilot and "custom assistant" targets have no plugin/marketplace concept — the existing symlink mechanism is still the only way to reach them, so it stays, just demoted from "primary" to "compatibility" install path. |
| `skill.json`'s `activation.triggers` (7 contexts × keyword lists × example prompts) | **Preserved, relocated.** | Each skill's `description` (what + when, ≤1,024 chars) and, in Claude Code specifically, the optional `when_to_use` field (combined cap 1,536 chars) and `paths` glob field | This is the actual "preserve routing under the spec" answer: the trigger-keyword *content* isn't thrown away, it's rewritten as natural-language "when to use" text inside the description Claude already matches against, and file-type context detection (web/K8s/mobile) can additionally use the `paths` glob field so Claude Code auto-considers a skill when the open file matches (`*.yaml`, `*.py`, etc.). |

## Architectural Patterns

### Pattern 1: Skill as the parallelizable unit of work

**What:** Every `skills/<name>/` directory is self-contained: its own `SKILL.md`, `references/`, `scripts/`, `assets/`. No skill reads another skill's files.
**When to use:** Any time more than one contributor/phase needs to touch different standards or domains concurrently.
**Trade-offs:** Some duplication (e.g. `owasp-urls.json` already exists independently in both `owasp-security-audit/` and `secure-coding-practices/` today — keep that pattern, don't "DRY" it across skill boundaries) in exchange for zero cross-skill coordination cost and safe independent versioning/refresh.

### Pattern 2: Reference file as the parallelizable unit *within* a skill

**What:** Inside `owasp-security-audit/`, each OWASP standard gets its own `references/<standard>.md` (top10, asvs, masvs, api-top10, kubernetes-top10, agentic-apps-top10). The `SKILL.md` body is a short dispatcher ("web app code → read `references/top10.md`; REST/GraphQL → read `references/api-top10.md`; ...").
**When to use:** When one skill legitimately spans several independently-versioned standards (this project's exact situation — one audit workflow, six OWASP editions with different release cadences).
**Trade-offs:** Keeps the user-facing skill count small and the "audit my code" mental model intact, while still letting each standard be refreshed against its own official OWASP source with zero blast radius on the others. This is the correct target shape here — no need to split into six separate skills.

### Pattern 3: Progressive disclosure sizing discipline

**What:** Level 1 (frontmatter `name`+`description`) always loaded, ~100 tokens/skill; Level 2 (`SKILL.md` body) loaded only on trigger, budget <5,000 tokens (~500 lines); Level 3 (`references/`, `scripts/`, `assets/`) loaded only when the body explicitly points to it, effectively free until touched.
**When to use:** Every `SKILL.md` in the collection.
**Trade-offs:** Forces genuinely deep content (checklists, full standard text, code samples) out of `SKILL.md` and into `references/`/`assets/` — this is exactly the discipline `owasp-comprehensive-security-skills.md` (900 lines) currently violates, and the reason it's retired from the loaded path rather than kept as-is.

**Example (dispatcher-style SKILL.md body, abbreviated):**
```markdown
---
name: owasp-security-audit
description: Perform OWASP-aligned security audits of source code, API handlers, mobile apps, Kubernetes manifests, and LLM/agent code. Covers OWASP Top 10, ASVS, MASVS, API Security Top 10, Kubernetes Top 10, and Agentic Applications Top 10. Use for security reviews, vulnerability audits, threat assessments, or compliance checks.
paths: "*.py,*.js,*.ts,*.yaml,*.yml,Dockerfile"
---

## Workflow
1. Scope: snippet, file, or directory? What's the deployment context?
2. Detect code type → load the matching reference:
   - Web app code → `references/top10.md`
   - REST/GraphQL API → `references/api-top10.md`
   - Mobile app code → `references/masvs.md`
   - Kubernetes manifest → `references/kubernetes-top10.md`
   - LLM/agent tool-calling code → `references/agentic-apps-top10.md`
   - Otherwise, general web/API code → `references/asvs.md`
3. Optionally run `scripts/quick_scan.py <path>` for an initial lead list (leads, not verdicts).
4. Read code like an attacker would; cross-reference findings against the loaded standard.
5. Report: grouped by category, ranked by severity, with file:line and remediation.
```

## Marketplace Packaging

### Two viable shapes — recommendation

**Recommended for this milestone: single plugin, self-hosted marketplace.**

```json
// .claude-plugin/plugin.json
{
  "name": "owasp-security-skills",
  "version": "2.0.0",
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code",
  "author": { "name": "..." },
  "homepage": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "repository": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "license": "MIT",
  "keywords": ["owasp", "security", "audit", "secure-coding", "asvs", "masvs"]
}
```

```json
// .claude-plugin/marketplace.json
{
  "name": "owasp-security-skills",
  "owner": { "name": "..." },
  "description": "OWASP-grounded security skills for Claude Code",
  "plugins": [
    {
      "name": "owasp-security-skills",
      "source": ".",
      "description": "OWASP-aligned security audit and secure-coding-practices skills"
    }
  ]
}
```

Install path for users: `/plugin marketplace add mfkocalar/OWASP-Security-Skills` then `/plugin install owasp-security-skills@owasp-security-skills`. All skills load with the `/owasp-security-skills:` namespace prefix (e.g. `/owasp-security-skills:owasp-security-audit` if directly invoked; auto-invocation via description match needs no prefix).

**Alternative (future evolution, not this milestone): multi-plugin marketplace.** Split into e.g. `owasp-audit-plugin`, `secure-coding-plugin`, `cyber-ops-plugin` (bundling the 15 domain skills), each with its own `plugin.json`, all cataloged in one root `marketplace.json` using relative-path `source` entries (`"./plugins/owasp-audit-plugin"`, etc.). This buys users the ability to install only the subset they want and lets each cluster version independently. Because every `skills/<name>/` directory is already self-contained (Pattern 1), moving to this shape later is a directory-move + manifest-split operation, not a content rewrite — the recommended layout above is forward-compatible with it.

**Reserved marketplace names to avoid:** `claude-code-marketplace`, `claude-code-plugins`, `claude-plugins-official`, `claude-plugins-community`, `claude-community`, `anthropic-marketplace`, `anthropic-plugins`, `agent-skills`, and names that look official (`official-claude-plugins`, etc.) are blocked for third parties — `owasp-security-skills` is clear of this list.

## Progressive Disclosure — Frontmatter Field Reference

Two overlapping specs apply, and this collection should satisfy both for maximum portability (Claude Code today, potentially claude.ai/API custom-skill upload later):

**General Agent Skills spec (portable across surfaces):**
| Field | Required | Constraint |
|---|---|---|
| `name` | Yes | ≤64 chars, lowercase + hyphens only, no XML tags, no "anthropic"/"claude" |
| `description` | Yes | Non-empty, ≤1,024 chars, must state both *what* and *when* |

**Claude Code extensions (additive, all optional):**
| Field | Purpose |
|---|---|
| `when_to_use` | Extra routing context (trigger phrases, example requests); appended to `description`, combined cap 1,536 chars in the skill listing |
| `paths` | Glob patterns (e.g. `*.yaml,Dockerfile`) — auto-considers the skill only when the active file matches; a direct file-type-based replacement for the old router's "context detection" step |
| `disable-model-invocation` | Set `true` for workflows that should only ever be manually invoked (`/skill-name`), never auto-triggered — not needed for this collection's audit-style skills, which should stay auto-invocable |
| `allowed-tools` / `disallowed-tools` | Pre-approve or block specific tools for the turn that invokes the skill (e.g., pre-approve `Bash(python3 scripts/quick_scan.py *)`) |

**Body and resource budget:**
- SKILL.md body: recommended ceiling ~5,000 tokens / ~500 lines. Anything longer belongs in `references/`.
- `references/*.md`: no hard limit, but keep each file scoped to one standard/domain so Claude reads only what a given request needs.
- `scripts/*`: Python/Bash/JS supported; only stdout enters context, never source.
- `assets/*`: templates/examples, read only when the body names them.

## Anti-Patterns

### Anti-Pattern 1: Keeping a hand-rolled router file alongside spec-compliant skills

**What people do:** Leave `owasp-css.instructions.md`-style keyword/confidence logic in place "just in case," pointing at the new `skills/` layout.
**Why it's wrong:** Claude Code doesn't consult arbitrary instructions files to decide which skill to load — activation is driven entirely by matching the request against each skill's `description` at Level 1. A stale or contradictory router file adds confusion (which routing wins?) with no runtime effect on Claude Code's own activation.
**Do this instead:** Delete it; put every routing signal it contained into the relevant skill's `description`/`when_to_use`/`paths`.

### Anti-Pattern 2: One mega-skill for "all of OWASP"

**What people do:** Collapse everything (Top 10, ASVS, MASVS, API, K8s, Agentic, SCP) into a single skill with a single giant `SKILL.md` body trying to cover all cases.
**Why it's wrong:** Blows the ~5,000-token body budget immediately (this is effectively what `owasp-comprehensive-security-skills.md` already is, at 900 lines) and makes the `description` an unfocused grab-bag that matches poorly against specific requests.
**Do this instead:** Keep the workflow-level skill (`owasp-security-audit`) thin — a dispatcher — and push each standard into its own `references/<standard>.md`, loaded only when relevant (Pattern 2 above). This is exactly the shape already partially in place; the fix is retiring the redundant mega-doc and manifest files around it, not restructuring the references.

### Anti-Pattern 3: Symlinking shared assets across skill/plugin boundaries

**What people do:** Keep `examples/` at repo root as the "real" files and symlink or copy them into each skill's `assets/examples/` at commit time, as done today.
**Why it's wrong:** Plugin install copies the plugin directory into a versioned cache (`~/.claude/plugins/cache/...`); this generally works fine for real files inside the plugin root, but is the single most common cause of "files not found after installation" reports when symlinks or path assumptions leak outside a skill's own directory.
**Do this instead:** Treat `skills/<name>/assets/examples/` as the sole canonical location for that skill's examples; drop the root `examples/` duplication entirely (or keep it only as a non-packaged contributor scratch area with a lint step, not a build dependency).

## Suggested Build Order / Parallelization

This is input to roadmap phase structure, not a phase list itself.

1. **Foundation (serial, blocking, small):** Create `.claude-plugin/plugin.json` + `.claude-plugin/marketplace.json`; decide/document the target `skills/<name>/{SKILL.md,references/,scripts/,assets/}` shape as the convention every subsequent phase must follow. Nothing else can be verified as "spec-compliant" without this skeleton existing first.
2. **Per-standard/per-skill refresh (parallel, independent):** Because each `references/<standard>.md` (and each additional domain skill) has zero cross-file dependency on the others, these can run as fully parallel phases/workstreams:
   - OWASP Top 10 refresh + verification
   - ASVS refresh + verification
   - MASVS refresh + verification
   - API Security Top 10 refresh + verification
   - Kubernetes Top 10 refresh + verification
   - Agentic Applications refresh + verification
   - Secure Coding Practices (14-domain checklist + secure-patterns) refresh + verification
   - Each of the additional domain skills (recon-osint, vulnerability-scanner, ... blue-team-defense), if in scope, refreshed/reformatted independently
3. **Per-skill SKILL.md reformatting (parallel once step 1's convention exists, but depends on step 2's content for the two OWASP skills):** Rewrite each skill's frontmatter (`description`/`when_to_use`/`paths`) and dispatcher body against the finalized reference content; retire the redundant `owasp-security-audit.md`/`secure-coding-practices.md` metadata files.
4. **Root retirement pass (serial, after 2–3):** Remove `owasp-css.instructions.md`, `skill.json`, `owasp-comprehensive-security-skills.md` from the loaded path (delete or relocate to non-loaded docs); dedupe `examples/` into per-skill `assets/examples/`.
5. **Marketplace/plugin validation (serial, last):** `claude plugin validate .`, `claude --plugin-dir .` smoke test of every skill's auto-activation and manual invocation, then `/plugin marketplace add ./` + `/plugin install` end-to-end.
6. **Public polish (parallel with 5, low coupling):** README, CONTRIBUTING (new skill-authoring workflow), DEPLOYMENT.md (marketplace install as primary path, `install.sh` as compatibility path), TESTING.md (validation commands).

### Parallelization boundary rule

A phase touching `skills/<A>/**` should never need to read or write `skills/<B>/**`. The one deliberate exception already in the current codebase — `owasp-urls.json` existing independently inside both `owasp-security-audit/references/` and `secure-coding-practices/references/` — should be *kept* as independent duplicate files, not centralized, precisely so the two skills stay parallel-refreshable without a shared-file merge conflict.

## Sources

- [Create plugins — Claude Code Docs](https://code.claude.com/docs/en/plugins)
- [Plugins reference — Claude Code Docs](https://code.claude.com/docs/en/plugins-reference)
- [Create and distribute a plugin marketplace — Claude Code Docs](https://code.claude.com/docs/en/plugin-marketplaces)
- [Extend Claude with skills — Claude Code Docs](https://code.claude.com/docs/en/skills)
- [Agent Skills overview — Claude Platform Docs](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
- [Equipping agents for the real world with Agent Skills — Anthropic Engineering Blog](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [anthropics/claude-code plugin-structure SKILL.md (reference implementation)](https://github.com/anthropics/claude-code/blob/main/plugins/plugin-dev/skills/plugin-structure/SKILL.md)
- [anthropics/claude-plugins-official marketplace.json (reference implementation)](https://github.com/anthropics/claude-plugins-official/blob/main/.claude-plugin/marketplace.json)
- [Agent Skills open specification — agentskills.io](https://agentskills.io/specification)

---
*Architecture research for: Claude Code Agent Skills / plugin-marketplace packaging*
*Researched: 2026-07-19*
