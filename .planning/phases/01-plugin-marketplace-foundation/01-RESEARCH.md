# Phase 1: Plugin/Marketplace Foundation - Research

**Researched:** 2026-07-19
**Domain:** Claude Code plugin/marketplace packaging spec + Agent Skills directory convention
**Confidence:** HIGH

## Summary

Phase 1 has one real risk: getting `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`
byte-for-byte correct against Anthropic's *current* schema, not training-data recall. I fetched the
live official docs directly (`code.claude.com/docs/en/plugins-reference`, `/en/plugin-marketplaces`,
`/en/plugins`, `/en/skills`) on 2026-07-19 and cross-checked them against each other — they are
internally consistent. This is the strongest evidence tier available in this environment (no MCP
docs providers are enabled per `.planning/config.json`; `context7`/`brave`/etc. are all `false`), so
findings are tagged `[CITED: <url>]` rather than `[VERIFIED]`, but confidence is high because three
independent official pages agree and each shows worked examples that match the pattern this repo
needs.

The critical finding for Success Criterion 1: **only `name` is a strictly required field** in
`plugin.json` if a manifest is present at all — not the "name/version/description/author" 4-field
set some third-party blog posts (surfaced in initial web search) claim. Unrecognized top-level
fields are *warnings*, not load failures, unless `--strict` is passed to `claude plugin validate`.
This actually strengthens D-03 rather than weakening it: technically the repo *could* leave stray
custom fields in and still pass a non-strict validate, but doing so risks exactly the "schema drift"
CONTEXT.md is trying to avoid, and the community-marketplace review pipeline runs the same validator
Anthropic recommends running locally — so building clean now avoids a future strict-mode failure.

A second critical finding, **not previously flagged in CONTEXT.md's break-surface list**: `install.sh`'s
`verify_installation()` function has a hardcoded `required_files` array that includes `"skill.json"`
(line 87). D-08 retires `skill.json` this phase. Unless that array is also patched, `install.sh`
verification will **always report a missing file and exit 1** after this phase, independent of the
`examples/` count fix CONTEXT.md already flagged. Both patches are needed for `install.sh` to keep
working.

**Primary recommendation:** Write a minimal `plugin.json` (name, description, version, author,
homepage, repository, license, keywords — all officially-supported fields, none of the retired custom
ones) and a `marketplace.json` with a single plugin entry using a `github` source object pointing at
`mfkocalar/OWASP-Security-Skills` (per D-04). Patch `install.sh` in two places (required_files array
+ examples count) and repoint the 9 README example links, then run `claude plugin validate .` as the
closing verification step for Success Criterion 1.

## Architectural Responsibility Map

This phase is packaging/config work, not a runtime app, but the "tiers" here are Claude Code's own
plugin-loading layers:

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Plugin identity/metadata | `.claude-plugin/plugin.json` (plugin manifest tier) | — | Sole source of plugin name, version, description per Claude Code's plugin loader |
| Marketplace catalog/discovery | `.claude-plugin/marketplace.json` (marketplace tier) | GitHub repo (source tier) | Catalog lists plugins and where to fetch each; distinct concern from plugin identity |
| Skill content & activation | `skills/<name>/SKILL.md` (skill tier) | — | Must live at plugin root per spec, never inside `.claude-plugin/` |
| Install verification / local dev convenience | `install.sh` (installer script tier) | — | Legacy pre-plugin installer; kept per D-09, must not silently break |
| Human-facing documentation | `README.md`, `docs/SKILL-STRUCTURE.md` | — | Must stay accurate at each phase boundary per D-06's rationale |

No capability in this phase spans browser/API/DB tiers — it's entirely repo-packaging and Claude
Code's own plugin-loader contract.

## User Constraints

<user_constraints>
### Locked Decisions

- **D-01:** Package as **one plugin** named **`owasp-security-skills`** that bundles both skills
  (`owasp-security-audit` + `secure-coding-practices`).
- **D-02:** `plugin.json` **version baseline = `0.1.0`** (reset from the old `skill.json` 1.1.0
  lineage). Reaches `1.0.0` when the milestone ships clean (Phase 5).
- **D-03:** `plugin.json` contains **only the closed official plugin-schema fields**. None of the
  custom fields from the old `skill.json` (standards, activation, functionality, models,
  performance, metadata, examples_by_category, deployment, changelog, roadmap) get ported.
- **D-04:** `marketplace.json` lists the one plugin with a **GitHub source:
  `mfkocalar/OWASP-Security-Skills`** (this repo is the self-hosted marketplace; origin remote
  confirmed). Public-install ready. A local-path source is NOT added.
- **D-05:** **Each skill owns its examples** in its own `assets/examples/`; **delete the root
  `examples/` directory** entirely. (The 9 Top-10 examples already live in
  `owasp-security-audit/assets/examples/`; `secure-coding-practices` keeps its own 2 files.)
- **D-06:** Deleting root `examples/` breaks `install.sh` (example file-count check, lines ~100–105
  and reference at ~146) and README links (lines ~102–109). **Patch both in Phase 1.**
- **D-07:** Document the locked skill-directory convention in a dedicated **`docs/SKILL-STRUCTURE.md`**
  — the single canonical reference phases 2–4 (and contributors) cite. Not folded into CONTRIBUTING;
  not a repo-root `CONVENTIONS.md`.
- **D-08:** **Retire the root `skill.json` now** — directly superseded by `plugin.json`.
- **D-09:** **Leave** `owasp-css.instructions.md`, `owasp-comprehensive-security-skills.md`, and
  `install.sh` in place for now — formal retirement is Phase 4/5. Exception: `install.sh` gets the
  D-06 example-check patch, but is not removed.

### Claude's Discretion

- Exact `plugin.json` / `marketplace.json` field names, ordering, and required-vs-optional
  structure — resolved against the official Claude Code plugin spec in this research (see below).
- Precise structure/wording of `docs/SKILL-STRUCTURE.md`, provided it fixes the `SKILL.md` +
  `references/` + `scripts/` + `assets/` convention unambiguously.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope. Legacy-file retirement
(`owasp-css.instructions.md`, `owasp-comprehensive-security-skills.md`, `install.sh` removal) and the
full README/coverage-matrix rewrite are already roadmapped to Phases 4–5.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PKG-01 | `.claude-plugin/plugin.json` exists at repo root with required plugin identity fields | Exact field schema below (Standard Stack); only `name` is hard-required, but repo should also set `description`, `version`, `author`, `homepage`, `repository`, `license`, `keywords` for a public-facing plugin |
| PKG-02 | `.claude-plugin/marketplace.json` exists and lists the plugin(s) for distribution | Exact marketplace schema below; GitHub-source plugin entry pattern confirmed with worked example |
| PKG-03 | `skills/` stays at plugin root (never inside `.claude-plugin/`); each skill's examples are canonical per-skill so they survive copy-on-install (no fragile cross-dir/symlink refs) | Directory-placement rule confirmed verbatim from official docs (three separate warnings say the same thing); examples de-dup already verified byte-identical between root and per-skill copies |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Format constraint:** Must conform to Anthropic's official Agent Skills spec (`SKILL.md` +
  frontmatter + progressive disclosure) — directly relevant to D-07/SC4.
- **Distribution constraint:** Must be installable via Claude Code plugin/marketplace mechanisms —
  this phase is the literal definition-of-done gate for that constraint.
- **Tech stack constraint:** Markdown-first, optional Python, no heavy runtime dependencies —
  `plugin.json`/`marketplace.json` are plain JSON; nothing in this phase introduces a dependency.
- **Compatibility constraint:** Preserve value of existing content through the restructure — D-05's
  canonical-per-skill-examples approach satisfies this (verified byte-identical, see below).
- **GSD workflow enforcement (project CLAUDE.md):** File-changing work must go through a GSD command
  (`/gsd-execute-phase`, etc.) — not a research-phase concern, but the planner should carry this
  forward into task framing.

No CLAUDE.md directive contradicts any locked decision in this phase.

## Standard Stack

### Core

| Field/File | Version | Purpose | Why Standard |
|---|---|---|---|
| `.claude-plugin/plugin.json` | Claude Code plugin manifest schema (current as of Claude Code v2.1.x docs, fetched 2026-07-19) | Plugin identity + component declarations | Only schema Claude Code's plugin loader recognizes; required for `claude plugin validate` to pass |
| `.claude-plugin/marketplace.json` | Claude Code marketplace schema (same doc snapshot) | Lists installable plugin(s) + fetch source | Required for `/plugin marketplace add` / public GitHub-based install |

### `plugin.json` — confirmed field set `[CITED: code.claude.com/docs/en/plugins-reference, fetched 2026-07-19]`

**Required (if manifest included at all):**

| Field | Type | Notes |
|---|---|---|
| `name` | string | kebab-case, no spaces. This IS the plugin's namespace prefix (`owasp-security-skills:skill-name`) |

**Metadata fields (all optional):**

| Field | Type | Notes |
|---|---|---|
| `$schema` | string | Editor autocomplete only; Claude Code ignores at load time. Recommended value: `https://json.schemastore.org/claude-code-plugin-manifest.json` |
| `displayName` | string | Human-readable name for UI; falls back to `name`. Requires Claude Code v2.1.143+ |
| `version` | string | Semantic version. **D-02 locks this to `0.1.0`.** If also set in marketplace entry, `plugin.json` wins |
| `description` | string | Brief plugin purpose |
| `author` | object | `{name, email?, url?}` |
| `homepage` | string | Docs URL |
| `repository` | string | Source code URL |
| `license` | string | SPDX identifier, e.g. `MIT` |
| `keywords` | array | Discovery tags |
| `defaultEnabled` | boolean | Whether plugin starts enabled (default `true`). Requires Claude Code v2.1.154+ |

**Component path fields (all optional — this repo does not need any of these since default locations
`skills/` at plugin root are used as-is):** `skills`, `commands`, `agents`, `hooks`, `mcpServers`,
`outputStyles`, `lspServers`, `experimental.themes`, `experimental.monitors`, `userConfig`,
`channels`, `dependencies`.

**Confirmed NOT part of the schema (D-03 validated):** `standards`, `activation`, `functionality`,
`models`, `performance`, `metadata`, `examples_by_category`, `deployment`, `changelog`, `roadmap` —
none of these appear anywhere in the official field list. `[CITED: code.claude.com/docs/en/plugins-reference]`

**Important nuance for planning:** Claude Code *ignores* unrecognized top-level fields as a soft
warning (plugin still loads and passes non-strict `claude plugin validate`); only `--strict` promotes
this to a hard failure. So technically D-03 is a cleanliness/anti-drift decision, not something the
validator would reject by default — but the community-marketplace submission pipeline runs the same
validator Anthropic tells authors to run locally, and a stray field with the *wrong type* (e.g. an
old `keywords` shaped as an object instead of array) IS a hard load error regardless of `--strict`.
Recommendation stands: emit a clean schema-only manifest and run `claude plugin validate --strict`
locally before considering PKG-01 done.

**Minimal example for this repo (illustrative, not final task output):**
```json
{
  "$schema": "https://json.schemastore.org/claude-code-plugin-manifest.json",
  "name": "owasp-security-skills",
  "displayName": "OWASP Security Skills",
  "version": "0.1.0",
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "author": { "name": "Security Education Community" },
  "homepage": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "repository": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "license": "MIT",
  "keywords": ["security", "owasp", "top-10", "secure-coding"]
}
```
This relies on the default `skills/` directory scan (both `owasp-security-audit/` and
`secure-coding-practices/` are auto-discovered; no `skills` field needed since neither is a custom
path).

### `marketplace.json` — confirmed field set `[CITED: code.claude.com/docs/en/plugin-marketplaces, fetched 2026-07-19]`

**Required top-level fields:**

| Field | Type | Notes |
|---|---|---|
| `name` | string | Marketplace identifier (kebab-case). Public-facing (`/plugin install x@this-name`). NOT reserved (checked against the reserved-names list below) |
| `owner` | object | `{name (required), email (optional)}` |
| `plugins` | array | List of plugin entries |

**Reserved marketplace names (must avoid):** `claude-code-marketplace`, `claude-code-plugins`,
`claude-plugins-official`, `claude-plugins-community`, `claude-community`, `anthropic-marketplace`,
`anthropic-plugins`, `agent-skills`, `anthropic-agent-skills`, `knowledge-work-plugins`,
`life-sciences`, `claude-for-legal`, `claude-for-financial-services`,
`financial-services-plugins`, `first-party-plugins`, `healthcare`, plus anything that impersonates an
official name (e.g. `official-claude-plugins`). `owasp-security-skills` or similar does not collide
with any of these.

**Optional top-level fields:** `$schema`, `description`, `version`, `metadata.pluginRoot`,
`allowCrossMarketplaceDependenciesOn`, `renames`.

**Each `plugins[]` entry — required:**

| Field | Type | Notes |
|---|---|---|
| `name` | string | Plugin identifier (kebab-case) |
| `source` | string \| object | Where to fetch the plugin — see below |

**Each `plugins[]` entry — optional (subset relevant here):** `description`, `version`, `author`,
`homepage`, `repository`, `license`, `keywords`, `category`, `tags`, `strict` (default `true`),
`defaultEnabled`.

**GitHub source object shape (D-04's chosen source type):**
```json
{
  "source": "github",
  "repo": "owner/repo",
  "ref": "optional-branch-or-tag",
  "sha": "optional-40-char-commit-sha"
}
```
`repo` is required; `ref`/`sha` are optional (omit both to track the default branch).

**Recommended entry for this repo, per D-04:**
```json
{
  "name": "owasp-security-skills",
  "source": {
    "source": "github",
    "repo": "mfkocalar/OWASP-Security-Skills"
  },
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code."
}
```

**Design note — why `github` source (not a relative path) is correct here:** the plugin and the
marketplace live in the *same* repo (self-hosted, single-plugin marketplace). A relative-path source
(`"./"`) would technically also work when the marketplace is added via git clone, but the official
docs explicitly warn that relative paths **fail** when a marketplace is added via a direct URL to
`marketplace.json` (URL-based add only downloads that one file, not the plugin's files). D-04's
locked choice of a `github` source object avoids that failure mode entirely and matches the docs'
explicit recommendation ("For URL-based distribution, use GitHub, npm, or git URL sources instead").
`[CITED: code.claude.com/docs/en/plugin-marketplaces §"Plugins with relative paths fail in URL-based marketplaces"]`

**Version resolution order** (first one set wins): `plugin.json` version → marketplace entry version
→ git commit SHA → `unknown`. Since D-02 sets `version: "0.1.0"` in `plugin.json`, do **not** also
set a conflicting `version` in the marketplace entry — the docs warn `plugin.json` always wins
silently, so a mismatched marketplace-entry version would be misleading, not additive. Omit
`version` from the marketplace entry.

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| GitHub source object | Relative path (`"./"`) source | Simpler, but breaks for URL-based marketplace adds — explicitly against D-04 and the official warning above |
| Single combined plugin | Two separate plugins (one per skill) | Rejected by D-01; ROADMAP/PROJECT consistently describe "the plugin" singular |
| `commands`/`agents` custom paths in plugin.json | Default `skills/` directory scan | Not needed — both skill dirs already sit at the default `skills/` location, no custom path field required |

**Installation (verification, not an npm dependency):**
```bash
claude plugin validate . --strict
/plugin marketplace add ./.  # or: claude plugin marketplace add mfkocalar/OWASP-Security-Skills
/plugin install owasp-security-skills@owasp-security-skills   # exact name depends on marketplace `name` chosen
```

**Version verification:** N/A — no npm/pip/cargo packages are installed by this phase. The "package"
here is the Claude Code plugin schema itself, verified directly against the live official docs pages
listed in Sources (not training-data recall), satisfying the project's #1 accuracy constraint.

## Package Legitimacy Audit

**N/A — this phase installs no external npm/pip/cargo packages.** It only authors two JSON manifest
files (`plugin.json`, `marketplace.json`) consumed by Claude Code's own plugin loader. The Package
Legitimacy Gate protocol does not apply. No packages to disposition.

## Architecture Patterns

### System Architecture Diagram

```
                         ┌────────────────────────────────────┐
                         │   github.com/mfkocalar/            │
                         │   OWASP-Security-Skills (this repo)│
                         └──────────────────┬──────────────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       ▼                       ▼
      .claude-plugin/plugin.json   .claude-plugin/marketplace.json   skills/  (plugin root, NOT
      (plugin identity manifest)   (catalog: lists 1 plugin entry,    inside .claude-plugin/)
                    │               source = github self-reference)      │
                    │                       │                            ├── owasp-security-audit/
                    │                       │                            │     SKILL.md + references/
                    │                       │                            │     + scripts/ + assets/examples/
                    │                       │                            │     (9 canonical files)
                    │                       │                            │
                    │                       │                            └── secure-coding-practices/
                    │                       │                                  SKILL.md + references/
                    │                       │                                  + assets/examples/
                    │                       │                                  (2 canonical files)
                    │                       ▼
                    │        User: `/plugin marketplace add
                    │                 mfkocalar/OWASP-Security-Skills`
                    │                       │
                    │                       ▼
                    │        Claude Code clones repo → resolves
                    │        plugins[0].source (github, same repo)
                    └──────────────────────►│
                                            ▼
                              User: `/plugin install
                               owasp-security-skills@<marketplace-name>`
                                            │
                                            ▼
                        Claude Code copies plugin dir into
                        ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/
                                            │
                                            ▼
                        Both skills auto-discovered from cached
                        skills/ dir, namespaced as
                        owasp-security-skills:owasp-security-audit
                        and owasp-security-skills:secure-coding-practices
```

### Recommended Project Structure

```
OWASP-Security-Skills/                  (repo root == plugin root == marketplace root)
├── .claude-plugin/
│   ├── plugin.json                     # NEW — plugin identity manifest (PKG-01)
│   └── marketplace.json                # NEW — catalog listing the 1 plugin (PKG-02)
├── skills/                             # plugin root, unchanged location (PKG-03)
│   ├── owasp-security-audit/
│   │   ├── SKILL.md
│   │   ├── references/
│   │   ├── scripts/
│   │   └── assets/examples/            # 9 files — canonical after root examples/ delete (D-05)
│   └── secure-coding-practices/
│       ├── SKILL.md
│       ├── references/
│       └── assets/examples/            # 2 files — already canonical
├── docs/
│   └── SKILL-STRUCTURE.md              # NEW — documents the convention (D-07/SC4)
├── install.sh                          # PATCHED — required_files array + example count (D-06 + new finding)
├── README.md                           # PATCHED — 9 example links repointed to per-skill paths
├── owasp-comprehensive-security-skills.md   # unchanged (D-09, retirement is Phase 4)
├── owasp-css.instructions.md                # unchanged (D-09, retirement is Phase 4)
└── skill.json                          # DELETED (D-08)
    examples/                           # DELETED (D-05)
```

### Pattern 1: Single-plugin, self-hosted marketplace (repo doubles as both)

**What:** One GitHub repo serves simultaneously as (a) the plugin itself (has its own
`.claude-plugin/plugin.json` at repo root) and (b) the marketplace catalog (has
`.claude-plugin/marketplace.json` at the same repo root, listing itself via a `github` source
pointing back at the same `owner/repo`).

**When to use:** Exactly this repo's situation — a small, single-plugin project that wants to be
publicly installable via `/plugin marketplace add owner/repo` without standing up a separate
marketplace repo.

**Example** (illustrative combination of both manifests, both at repo root):
```json
// .claude-plugin/plugin.json
{
  "name": "owasp-security-skills",
  "version": "0.1.0",
  "description": "OWASP-aligned security audit and secure-coding-practices skills.",
  "author": { "name": "Security Education Community" }
}
```
```json
// .claude-plugin/marketplace.json
{
  "name": "owasp-security-skills",
  "owner": { "name": "Security Education Community" },
  "plugins": [
    {
      "name": "owasp-security-skills",
      "source": { "source": "github", "repo": "mfkocalar/OWASP-Security-Skills" },
      "description": "OWASP-aligned security audit and secure-coding-practices skills."
    }
  ]
}
```
`[CITED: code.claude.com/docs/en/plugin-marketplaces — "Walkthrough: create a local marketplace" adapted to a self-hosted GitHub-source pattern]`

Note the marketplace `name` and the plugin `name` can be identical strings without conflict — they
are looked up in different namespaces (`/plugin marketplace add` vs. `/plugin install
<plugin>@<marketplace>`).

### Anti-Patterns to Avoid

- **Putting `skills/`, `commands/`, `agents/`, or `hooks/` inside `.claude-plugin/`:** This is called
  out as a "common mistake" in three separate official doc sections. Only `plugin.json` (and
  `marketplace.json`, for the marketplace file) belong there. Getting this wrong makes skills
  "load but appear missing" — a silent failure mode, not a validate-time error in all cases.
- **Setting `version` in both `plugin.json` and the marketplace entry:** `plugin.json` silently wins,
  so a stale/mismatched marketplace-entry version misleads maintainers into thinking a bump did
  nothing. Set version once, in `plugin.json` only (per D-02).
- **Using a relative-path source for a GitHub-distributed marketplace:** Works for local
  `/plugin marketplace add ./path` testing but fails for URL-based `marketplace.json` fetches. D-04
  already locks the `github` source object — do not substitute a relative path even though it looks
  simpler for a same-repo plugin.
- **Porting old `skill.json` custom fields "just in case":** They add no functionality (Claude Code
  ignores or warns on unrecognized fields) and reintroduce exactly the schema-drift/staleness problem
  CONCERNS.md already documented for the old file (stale line counts, stale model names).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Plugin manifest validation | A custom JSON-schema checker script | `claude plugin validate . --strict` (built into Claude Code CLI) | It's the exact validator the community-marketplace review pipeline runs; building a parallel checker risks drift from the real spec |
| Marketplace GitHub-source resolution | A custom fetch/clone script for install | Claude Code's built-in `/plugin marketplace add` + cache mechanism | Already handles version resolution, caching to `~/.claude/plugins/cache`, and update detection — reinventing this is pure risk for zero benefit |
| Example de-duplication tracking | A symlink or build-step "sync examples" script | Plain per-skill canonical copies (D-05) — verified byte-identical already | Symlinks are explicitly noted as fragile across plugin-cache copy semantics (dereferenced/skipped depending on target location); flat files avoid the entire class of bug |

**Key insight:** Every "don't hand-roll" item here already has a first-party Claude Code mechanism;
this phase's actual work is authoring two small JSON files correctly and deleting/patching what
conflicts with them, not building tooling.

## Runtime State Inventory

> Included per the mandatory rename/refactor trigger — this phase deletes `skill.json` and
> `examples/`, which is a retirement/removal action on tracked repo files.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — this repo has no database, cache, or external datastore that references `skill.json` or `examples/` by name. Verified: no `.env`, no DB config, no CI pipeline files exist in the repo (only `.gitignore`, `README.md`, `install.sh`, and docs at root). | None |
| Live service config | None — no external service (n8n, Datadog, Tailscale, Cloudflare Tunnel, etc.) references this repo's file paths. This is a public documentation/skill repo with no deployed service. | None |
| OS-registered state | None — `install.sh` creates a **symlink** (not a copy) at the target skill directory (e.g. `~/.claude/skills/owasp-security`), pointing at the repo's working directory. Any machine that has already run `install.sh` will have that symlink continue to resolve correctly after this phase's file deletions/patches, since the symlink points at the repo root, not at `examples/` or `skill.json` specifically. No OS task-scheduler or process-manager entries reference these paths. | None — existing symlink installs are unaffected by internal file changes |
| Secrets/env vars | None — no secret or env-var name in this repo references `skill.json` or `examples/` by name (grep confirms no `.env`-style references). | None |
| Build artifacts / installed packages | None — this repo has no build step, no compiled artifact, and is not installed as an npm/pip package anywhere. `skill.json` is a documentation-metadata file only, not consumed by a package manager (its filename collides in spelling with `package.json` conventions but has no `main`/`dependencies` fields and no `npm install` ever reads it). | None |

**Canonical-question answer:** After `skill.json` and root `examples/` are deleted, the only
runtime artifact that still references either by name is `install.sh`'s `required_files` array
(line 87, `"skill.json"`) and its example-count check (lines 100–106) plus the cosmetic echo at line
146 — all three are **code in this same repo**, not external runtime state, and are the explicit
D-06 patch target (plus the newly-found `required_files` issue). DEPLOYMENT.md and TESTING.md also
reference both (see Open Questions below) but are **not code that executes at install time** — they
are documentation files a human reads, out of this phase's declared file-touch list per CONTEXT.md.

## Common Pitfalls

### Pitfall 1: Assuming `plugin.json` needs `version`/`description`/`author` to be "valid"

**What goes wrong:** A plan that gates PKG-01 on emitting all of name/version/description/author (a
pattern surfaced by several third-party blog posts in initial web search, e.g. "the four required
fields") over-constrains the manifest and risks the planner treating an absent field as a validation
failure when it isn't one.

**Why it happens:** Secondary sources (mcpmarket.com, tonsofskills.com, community skill wrappers)
describe a stricter "four required fields" convention that isn't what the official schema enforces.
Only `name` is required by Claude Code itself.

**How to avoid:** Cite the official docs' "Required fields" table directly (`name` only) but still
*choose* to include description/version/author/etc. as a matter of quality for a public plugin —
Success Criterion 1 says "passes plugin validation," and a plugin with just `name` would technically
pass but be a poor public listing.

**Warning signs:** A task or verification step that says "fails if `plugin.json` is missing
`version`" — this should say "recommended, not schema-required."

### Pitfall 2: Deleting `skill.json` without patching `install.sh`'s `required_files` array

**What goes wrong:** `install.sh`'s `verify_installation()` function (used by choices 1, 2, 3, and 4
in the interactive menu) hardcodes `"skill.json"` in its `required_files` array (line 87). After D-08
deletes `skill.json`, every future run of `install.sh` — including the "Test only" option 4 that a
new contributor would run first — reports `skill.json (missing)` and exits non-zero, even though the
plugin/skills themselves work fine. This is a distinct, previously-unflagged break from the
`examples/`-count issue CONTEXT.md already called out.

**Why it happens:** CONTEXT.md's break-surface note focused on the `examples/` deletion (D-05) but
didn't separately trace the `skill.json` deletion (D-08) through `install.sh`'s verification logic.

**How to avoid:** Remove `"skill.json"` from the `required_files` array (line 87) in the same task
that patches the examples-count check (lines 100–106) and the line-146 echo string.

**Warning signs:** Running `./install.sh` (option 4, test-only) after this phase's file deletions and
seeing `✗ skill.json (missing)` in the output.

### Pitfall 3: Using a relative-path marketplace source for a same-repo plugin

**What goes wrong:** It's tempting to use `"source": "./"` since the plugin and marketplace share a
repo — this works for local testing (`/plugin marketplace add ./my-marketplace`) and for git-clone-based
adds, but silently fails if anyone ever adds the marketplace via a direct URL to the raw
`marketplace.json` file (URL-based marketplace add downloads only that one file).

**Why it happens:** Relative-path sources are the simplest pattern shown in the "quickstart" walkthrough
in the official docs, and it's the path of least resistance for a single-plugin repo.

**How to avoid:** D-04 already locks the `github` source object — follow it. Confirmed via direct
docs citation above that this is the documented correct choice for public GitHub distribution.

**Warning signs:** A `marketplace.json` plugins[].source that is a bare string starting with `./`
rather than a `{source: "github", repo: ...}` object.

### Pitfall 4: Forgetting the marketplace reserved-names list

**What goes wrong:** Choosing a marketplace `name` (top-level `marketplace.json` field, distinct from
the plugin `name`) that collides with Anthropic's reserved list causes the marketplace to fail to
load with an "untrusted source" error — checked on *every* load, not just at add time.

**Why it happens:** The reserved list includes generic-sounding names like `agent-skills` that a
security-focused OWASP repo might plausibly reach for.

**How to avoid:** Confirm the chosen marketplace `name` (e.g. `owasp-security-skills`) is not on the
reserved list (see full list above) before finalizing `marketplace.json`.

**Warning signs:** `claude plugin marketplace add` reporting the marketplace is "registered from an
untrusted source."

## Code Examples

### `plugin.json` (complete, schema-only)
```json
// Source: code.claude.com/docs/en/plugins-reference, fetched 2026-07-19
{
  "$schema": "https://json.schemastore.org/claude-code-plugin-manifest.json",
  "name": "owasp-security-skills",
  "displayName": "OWASP Security Skills",
  "version": "0.1.0",
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "author": { "name": "Security Education Community" },
  "homepage": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "repository": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "license": "MIT",
  "keywords": ["security", "owasp", "top-10", "asvs", "masvs", "secure-coding"]
}
```

### `marketplace.json` (complete, single self-referencing GitHub-source plugin entry)
```json
// Source: code.claude.com/docs/en/plugin-marketplaces, fetched 2026-07-19
{
  "$schema": "https://json.schemastore.org/claude-code-marketplace.json",
  "name": "owasp-security-skills",
  "owner": { "name": "Security Education Community" },
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "plugins": [
    {
      "name": "owasp-security-skills",
      "source": {
        "source": "github",
        "repo": "mfkocalar/OWASP-Security-Skills"
      },
      "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code."
    }
  ]
}
```
Exact `name` strings (marketplace vs. plugin) are Claude's Discretion per CONTEXT.md — the example
above uses the same string for both for simplicity; the planner may choose to differentiate if
clearer for install messaging (`/plugin install owasp-security-skills@owasp-security-skills` reads
redundant — an alternative marketplace name like `owasp-security-skills-marketplace` avoids the
repetition, at the cost of a longer install command).

### `install.sh` patch targets (exact current line numbers, verified by direct read)
```bash
# Line 83-88 — required_files array: REMOVE "skill.json" (D-08 deletes this file)
local required_files=(
    "owasp-comprehensive-security-skills.md"
    "owasp-css.instructions.md"
    "README.md"
    "skill.json"          # <-- REMOVE this line
)

# Line 100-106 — examples/ count check: point at a still-existing dir or remove the check
# Line 101: local example_count=$(find "${install_dir}/examples" -type f | wc -l)
# Line 102-106: compares to "expected 9" — both examples/ (root) is being deleted (D-05)

# Line 146 — cosmetic echo, now stale
echo "  3. Paste any example from examples/ folder"
```

### README.md example-link locations (exact current line numbers, verified by grep)
```
Line 89:  examples/                                9 vulnerable/secure code samples   (structure diagram)
Line 97:  The [`examples/`](examples/) directory contains **9 code samples**...
Line 102: [broken-access-control.py](examples/broken-access-control.py)
Line 103: [cryptographic-failures.js](examples/cryptographic-failures.js)
Line 104: [injection.js](examples/injection.js)
Line 105: [security-misconfiguration.py](examples/security-misconfiguration.py)
Line 106: [xss.html](examples/xss.html)
Line 107: [logging-monitoring-failures.py](examples/logging-monitoring-failures.py)
Line 108: [api-auth-bypass.js](examples/api-auth-bypass.js)
Line 109: [k8s-rbac.yaml](examples/k8s-rbac.yaml)
Line 110: [prompt-injection.txt](examples/prompt-injection.txt)
```
9 links total (lines 102–110), plus the structure-diagram line (89) and the intro sentence (97) —
11 total spots referencing `examples/` in README.md. Each of the 9 file links should repoint to its
existing canonical location:
- `broken-access-control.py`, `cryptographic-failures.js`, `injection.js`,
  `security-misconfiguration.py`, `xss.html`, `logging-monitoring-failures.py`,
  `api-auth-bypass.js`, `k8s-rbac.yaml`, `prompt-injection.txt` →
  `skills/owasp-security-audit/assets/examples/<same-filename>`

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `.claude/skills/`, `.copilot/skills/` symlink installs of a whole repo (this repo's `install.sh`) | Claude Code plugin/marketplace system (`.claude-plugin/plugin.json` + `marketplace.json`, `/plugin install`) | Plugins reached public beta per official announcement; this milestone's whole purpose | Symlink install still works and is explicitly kept (D-09) as a fallback path, but is no longer the primary distribution mechanism after this phase |
| Custom `skill.json` metadata schema (activation triggers, models, functionality, roadmap) | Official `plugin.json` (8-ish real fields) + Agent Skills `SKILL.md` frontmatter (`description`-driven activation) | This phase (D-08) | Activation/routing logic moves from `skill.json`'s keyword-trigger arrays into each `SKILL.md`'s `description` field — already done in both skills' current `SKILL.md` files (confirmed by direct read: both already have spec-shaped frontmatter with `name` + rich `description`) |

**Deprecated/outdated:**
- Root `skill.json`: superseded by `plugin.json` for identity, and by per-`SKILL.md` `description`
  frontmatter for activation routing. Retiring now per D-08.
- Root `examples/`: superseded by per-skill canonical `assets/examples/` copies (already byte-identical,
  verified via `diff`). Retiring now per D-05.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The commonly-cited "SKILL.md name ≤64 chars / description ≤1024 chars" limits (referenced in this project's own REQUIREMENTS.md FMT-01) are NOT stated on Claude Code's current `/en/skills` docs page — they likely trace to the original Anthropic engineering blog post or the `agentskills.io` open-standard spec, a different (though related) source. Not independently re-verified against that blog post/spec in this research pass, since FMT-01 is Phase 4 scope, not Phase 1. | Common Pitfalls / Sources | Low risk to Phase 1 (no FMT requirement is in scope here); Phase 4's research must re-verify this against `agentskills.io` or the original blog post directly before FMT-01 is planned, since a stale/wrong char limit would be presented as a hard spec constraint in `docs/SKILL-STRUCTURE.md` if copied uncritically |
| A2 | Recommended marketplace/plugin `name` strings (`owasp-security-skills` for both) are a *suggestion*, not a locked value — CONTEXT.md's "Claude's Discretion" explicitly leaves exact naming/ordering open. | Standard Stack / Code Examples | Low risk — purely cosmetic; either name choice satisfies PKG-01/PKG-02 as long as it avoids the reserved-names list (Pitfall 4) |

**All schema-shape claims (required/optional field names, directory-placement rules, source-object
shapes) are `[CITED]` directly from official docs fetched this session — not training-data recall,**
satisfying the project's #1 accuracy constraint for the highest-priority research item.

## Open Questions

1. **Should DEPLOYMENT.md and TESTING.md be patched in this phase too?**
   - What we know: Both files reference `skill.json` extensively (DEPLOYMENT.md: 4 mentions;
     TESTING.md: 7+ mentions including a whole "Test 7.2: skill.json Completeness" section) and
     reference root `examples/` paths (both files, multiple `cat`/`python3 -m py_compile`/`node
     --check` commands against `examples/*.py`, `examples/*.js`, etc.).
   - What's unclear: CONTEXT.md's "Files this phase touches" list does not mention DEPLOYMENT.md or
     TESTING.md, and D-09 only names `owasp-css.instructions.md`,
     `owasp-comprehensive-security-skills.md`, and `install.sh` as explicitly deferred. These two
     files fall into neither the "patch now" nor the "explicitly deferred" bucket.
   - Recommendation: Since these are documentation-only (not code that executes and fails), and
     D-06's stated rationale is keeping `main` "consistent/installable" (an execution concern,
     which `install.sh` + README satisfy), treat DEPLOYMENT.md/TESTING.md staleness as an accepted
     gap for this phase — but the planner should flag it explicitly in the phase's verification
     notes so it isn't silently forgotten before Phase 5's "full README rewrite" work, in case
     DEPLOYMENT.md/TESTING.md aren't in Phase 5's scope either. Recommend a one-line addition to
     STATE.md's "Blockers/Concerns" noting this gap, mirroring how Phase 3's Agentic Apps citation
     gap was already tracked there.

2. **Exact marketplace `name` value** — `owasp-security-skills` (matching the plugin name) vs. a
   distinct name like `owasp-skills-marketplace`.
   - What we know: Both are valid; CONTEXT.md leaves this to Claude's Discretion.
   - What's unclear: Whether identical marketplace/plugin names cause any UX confusion in `/plugin`
     install messages (`owasp-security-skills@owasp-security-skills`).
   - Recommendation: Default to matching names (simplest, matches D-01's "one plugin" framing) unless
     the planner has a specific UX reason to differentiate.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `claude` CLI (`claude plugin validate`, `/plugin marketplace add`) | Success Criterion 1 (validation), manual verification of PKG-01/02 | Not verified in this research pass — no shell access to a `claude` binary was exercised here (research agent scope is read-only investigation) | Unknown | The planner/executor must confirm `claude --version` supports the plugin CLI subcommands (`plugin validate`, `plugin marketplace add`) documented here before treating "passes plugin validation" as machine-checkable; if unavailable, fall back to manual JSON-schema review against the field tables in this document |
| `git` (repo already a git repo, origin confirmed) | Marketplace GitHub source resolution | ✓ | — (origin remote confirmed: `https://github.com/mfkocalar/OWASP-Security-Skills.git`) | — |
| `bash` (`install.sh`) | D-06 patch verification | ✓ (already used by existing `install.sh`, unchanged requirement) | — | — |

**Missing dependencies with no fallback:** None outright blocking — but the `claude` CLI's plugin
subcommands are the only way to literally execute Success Criterion 1's "passes plugin validation"
check. If unavailable in the execution environment, the plan needs a documented manual-review
fallback (schema table comparison) as noted above.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | None (this repo has no test runner — pure Markdown/JSON/shell). Verification is manual/CLI-based |
| Config file | none — see Wave 0 |
| Quick run command | `claude plugin validate . --strict` |
| Full suite command | `claude plugin validate . --strict && ./install.sh` (option 4, test-only) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PKG-01 | `plugin.json` exists, schema-valid, no custom fields | smoke | `claude plugin validate . --strict` | ❌ Wave 0 — file doesn't exist yet, must be created this phase |
| PKG-02 | `marketplace.json` exists, lists plugin, GitHub source resolves | smoke | `claude plugin validate . --strict` (validates marketplace when pointed at a dir containing `.claude-plugin/marketplace.json`) | ❌ Wave 0 |
| PKG-03 | `skills/` at plugin root, examples canonical per-skill, no cross-dir refs | manual + scripted | `find skills -type l` (expect empty — no symlinks) `&&` `diff -rq skills/owasp-security-audit/assets/examples examples/` (expect "no differences" BEFORE delete, confirming safety of delete) | ✅ — already verified in this research pass (byte-identical, see Runtime State Inventory) |
| SC4 (docs) | `docs/SKILL-STRUCTURE.md` exists and documents convention unambiguously | manual review | N/A — human/plan-checker review of doc content against this research's confirmed directory-convention facts | ❌ Wave 0 — file doesn't exist yet |
| install.sh regression | `./install.sh` option 4 (test-only) exits 0 after `skill.json`/`examples/` deletion + patches | smoke | `./install.sh` (interactive, choose option 4) | ✅ file exists, needs patching this phase |

### Sampling Rate

- **Per task commit:** `claude plugin validate . --strict` (once `.claude-plugin/` exists)
- **Per wave merge:** Full suite (`claude plugin validate . --strict && ./install.sh` option 4)
- **Phase gate:** Full suite green before `/gsd-verify-work`, plus a manual check that all 9 README
  example links resolve (no 404s) and that `docs/SKILL-STRUCTURE.md` accurately describes the
  existing `SKILL.md`+`references/`+`scripts/`+`assets/` layout already present in both skill dirs.

### Wave 0 Gaps

- [ ] `.claude-plugin/plugin.json` — does not exist yet; core deliverable of PKG-01
- [ ] `.claude-plugin/marketplace.json` — does not exist yet; core deliverable of PKG-02
- [ ] `docs/SKILL-STRUCTURE.md` — does not exist yet; core deliverable of D-07/SC4
- [ ] No test framework to install — this repo is intentionally test-runner-free (Markdown/JSON/shell
      only); `claude plugin validate` IS the test framework for this phase's domain

## Security Domain

> `security_enforcement: true` in `.planning/config.json` (absent-default applies regardless).
> This phase is packaging/manifest work with no runtime code, no user input handling, no
> authentication, and no data storage — most ASVS categories do not apply.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | No auth surface introduced — plugin manifests are static config, not a service |
| V3 Session Management | No | N/A |
| V4 Access Control | No | N/A — GitHub repo visibility (public) governs access, unchanged by this phase |
| V5 Input Validation | Marginal | `claude plugin validate` itself performs the input validation (JSON schema + type checks) on the manifests this phase authors — no custom validation code to write |
| V6 Cryptography | No | N/A — no secrets, keys, or crypto operations in this phase's deliverables |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Marketplace source confusion / typosquatting a marketplace name | Spoofing | Anthropic's reserved-names list + exact-match `github repo` field in `source` (D-04 locks the exact `owner/repo` string, no ambiguity) |
| Supply-chain risk from an over-broad `commands`/`hooks`/`mcpServers` declaration | Elevation of Privilege | This phase's `plugin.json` declares no hooks, no MCP servers, no custom commands — purely `skills` via default directory scan, minimizing attack surface by design |
| Stale/incorrect public metadata (version, repository URL) misleading users about plugin trustworthiness | Repudiation / Tampering (of trust signal) | D-02's version-honesty principle (`0.1.0` until credibility work ships) directly addresses this; `repository`/`homepage` fields point at the verified real origin URL, not a placeholder |

No new attack surface is introduced by this phase — it is the packaging layer around existing
reference/documentation content, with no code execution added (no hooks, no MCP servers, no scripts
beyond the pre-existing `quick_scan.py`, which is unchanged this phase).

## Sources

### Primary (HIGH confidence — official docs, fetched directly this session)
- [code.claude.com/docs/en/plugins-reference](https://code.claude.com/docs/en/plugins-reference) — complete `plugin.json` schema, directory structure warnings, CLI command reference, fetched 2026-07-19
- [code.claude.com/docs/en/plugin-marketplaces](https://code.claude.com/docs/en/plugin-marketplaces) — complete `marketplace.json` schema, GitHub/relative-path/npm source types, reserved-names list, fetched 2026-07-19
- [code.claude.com/docs/en/plugins](https://code.claude.com/docs/en/plugins) — quickstart walkthrough, `--plugin-dir` local testing, directory-placement warning (independent confirmation), fetched 2026-07-19
- [code.claude.com/docs/en/skills](https://code.claude.com/docs/en/skills) — SKILL.md frontmatter field table, progressive-disclosure guidance (500-line recommendation), fetched 2026-07-19

### Secondary (MEDIUM confidence — cross-referenced against primary, used only to identify search terms)
- WebSearch result summaries pointing at the above official pages (not used as final source of truth
  where they conflicted with the primary docs — e.g. the "4 required fields" claim was corrected
  against the primary source)

### Codebase evidence (direct tool verification, this session)
- `diff -q` confirmed all 9 files in `examples/` are byte-identical to
  `skills/owasp-security-audit/assets/examples/` — safe to delete root copy (D-05)
- `find skills -type l` returned empty — no symlinks currently in `skills/` tree
- `grep -n` against `install.sh` and `README.md` — exact line numbers for all patch targets
- `git config --get remote.origin.url` confirmed `mfkocalar/OWASP-Security-Skills`
- Direct read of both existing `SKILL.md` files confirmed they already carry spec-shaped
  frontmatter (`name` + rich `description`) — D-07's documentation task is formalizing an existing
  pattern, not inventing one

## Metadata

**Confidence breakdown:**
- Standard stack (plugin.json/marketplace.json schema): HIGH — fetched directly from 3
  mutually-consistent official Anthropic docs pages this session, cross-checked against each other
  and against a live example in the docs
- Architecture: HIGH — directly derived from the same official docs plus direct codebase inspection
  (diff, grep, find) in this session
- Pitfalls: HIGH for schema/directory pitfalls (official docs); MEDIUM for the DEPLOYMENT.md/TESTING.md
  staleness gap (my own analysis extending beyond CONTEXT.md's explicit scope — flagged as Open
  Question rather than asserted as phase-blocking)

**Research date:** 2026-07-19
**Valid until:** 30 days (Claude Code plugin spec is actively evolving per version-gated notes in the
official docs — e.g. several fields note "Requires Claude Code v2.1.14x or later" — re-verify field
list if this phase's execution is delayed past that window)
