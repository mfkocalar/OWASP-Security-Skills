# Phase 4: SKILL.md Conversion & Legacy Retirement - Research

**Researched:** 2026-07-23
**Domain:** Anthropic Agent Skills spec compliance + legacy-file retirement (docs-only phase)
**Confidence:** HIGH (spec verified live against 3 official Anthropic domains; repo-state findings verified by direct inspection)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Legacy retirement scope (FMT-03, FMT-04)**
- **D-01:** Delete `owasp-css.instructions.md` outright. Its routing/activation content was read end-to-end during discussion and confirmed fully subsumed by the two `SKILL.md` `description` fields — and it is itself stale (says "seven/six OWASP standards", "Top 10 (2021)", points at the soon-deleted `owasp-comprehensive-security-skills.md` and the legacy `secure-coding-practices.md` guide). No routing content needs to be salvaged into the descriptions first; FMT-03 is satisfied by the existing descriptions.
- **D-02:** Delete `owasp-comprehensive-security-skills.md` (900 lines) and the byte-identical in-skill duplicate `skills/owasp-security-audit/owasp-security-audit.md`. The duplicate is `diff`-identical to `SKILL.md` (verified) — `SKILL.md` is authoritative. The 900-line monolith is superseded by the per-skill `references/` tree (its content already lives, refreshed, in Phases 2-3 reference files). Planner must spot-check that no unique, still-current content exists only in the 900-line file before deleting (salvage-check), but the expectation is a clean delete.
- **D-03:** Keep, but refresh, the two SCP human-facing docs. Retain `skills/secure-coding-practices/secure-coding-practices.md` (275-line guide) and `skills/secure-coding-practices/README.md` (234 lines); reword their stale "Quick Reference Guide checklist" framing to match Phase 3's archived-origin / living-source reframe (Developer Guide / Cheat Sheet Series / Proactive Controls).

**Example remapping depth — CONT-06 (D-04)**
- **D-04:** Relabel by topic + re-validate code. Remap every example's OWASP category ID to the 2025 edition by topic, not literal number substitution (Phase 2 precedent), fix the wrong Agentic prefix (`AG01` -> `ASI01`, per Phase 3 D-04), and add the missing label on `injection.js`. Re-validate each example's vulnerable/secure code against the 2025 requirement text — especially SSRF now folded into A01 (CWE-918), and the A02/A05 reorder (old-A05 Misconfig -> new-A02; old-A03 Injection -> new-A05). No new example files are authored in this phase.

**File structure — llm-agentic split (D-05)**
- **D-05:** Split `references/llm-agentic.md` into `references/llm.md` (LLM Top 10 2025, IDs LLM01-LLM10) + `references/agentic.md` (Agentic Apps Top 10 2026, IDs ASI01-ASI10). Must also update the `SKILL.md` routing table (and any other cross-references) that point at `llm-agentic.md`. Content of the edition notes carries over verbatim (Phase 3 already verified them).

**Description accuracy alignment (D-06)**
- **D-06:** Update both `SKILL.md` `description` fields to match Phase 3 reframes. Soften the audit skill's "ASVS 5.0" phrasing to align with `asvs.md`'s disclosed 4.0.3-body-numbering edition note; reword the SCP skill's "Quick Reference Guide checklist" to the living-source framing. Do not otherwise change activation breadth (routing behavior must stay equivalent — FMT-03).

### Claude's Discretion
- FMT-05 lint mechanics — exact enforcement of byte-0 frontmatter start, no angle brackets in frontmatter, and "only allowed bundled directories" (`references/`, `scripts/`, `assets/`). Note: audit `description` currently contains straight double-quotes around example phrasings — confirm quotes are fine and only literal `<`/`>` angle brackets are disallowed.
- `.DS_Store` hygiene — tracked `.DS_Store` files exist under `skills/` (`skills/.DS_Store`, `skills/owasp-security-audit/.DS_Store`) and a build artifact `scripts/__pycache__/`. Since this phase already touches the loaded path, remove tracked `.DS_Store` from git as part of the cleanup. Low-stakes; planner's call.
- Exact new filenames for the split (`llm.md` / `agentic.md` recommended) and the precise refresh wording of the two SCP docs, provided accuracy is preserved.
- Ordering of delete-vs-edit operations so `main` stays consistent at each commit.

### Deferred Ideas (OUT OF SCOPE)
- New-category example files (A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions, plus CONCERNS-noted A04/A06/A08 gaps) — user explicitly declined this scope for Phase 4.
- `install.sh` removal + full README/coverage-matrix/LICENSE/CONTRIBUTING rewrite — Phase 5 (PKG-04/05, QUAL-*, ADPT-*).
- `DEPLOYMENT.md` / `TESTING.md` staleness (still reference removed root `skill.json` and root `examples/`) — Phase 5 doc-polish, carried from Phase 1.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| FMT-01 | Each skill has a spec-compliant `SKILL.md` — `name` matches parent folder and is ≤64 chars; `description` ≤1024 chars, states what+when | Both files already verified compliant (name 20/23 chars, description 738/695 chars, no angle brackets, no reserved words) — see Verified Live Spec below. FMT-01 is a **no-op / verification-only** requirement for this phase, not an authoring task. |
| FMT-02 | `SKILL.md` bodies stay within progressive-disclosure budget (~500 lines) | Confirmed 500 lines is *guidance*, not a hard limit (official docs, verbatim quotes below). Current: audit 415 lines, SCP 256 lines — both compliant with headroom for D-06 description edits. |
| FMT-03 | Routing/activation behavior of legacy `owasp-css.instructions.md` preserved through per-skill `description` (and `when_to_use`/`paths` where supported) | Confirmed live: activation is driven by `description`; `when_to_use` and `paths` are real, optional Claude Code frontmatter fields (not required — D-01 already confirms description alone suffices). See Architecture Patterns. |
| FMT-04 | Legacy files retired — `owasp-css.instructions.md`, custom `skill.json`, `owasp-comprehensive-security-skills.md` no longer in loaded path | Root `skill.json` **already retired in Phase 1** (commit `088df58`) — confirmed via `git log`. This phase's real FMT-04 work is only the two files D-01/D-02 name. Mechanical check in Validation Architecture below. |
| FMT-05 | Frontmatter passes lint — byte-0 start, no angle brackets, only allowed bundled directories | Both SKILL.md files verified byte-0 `---` start (no BOM), zero angle brackets in name/description. Bundled-dir set (`references/`, `scripts/`, `assets/`) confirmed as the standard Agent Skills convention (Anthropic's own skill-creator repo uses the identical three names). Concrete lint commands provided below. |
| CONT-06 | Paired examples re-validated against 2025 requirement text, correct category IDs | Verified exact stale-label inventory (7 files) — see Common Pitfalls #2/#3. `top10.md` 2025 category list confirmed for correct target IDs. |

</phase_requirements>

## Summary

This phase is ~80% settled by CONTEXT.md. The only genuine external unknown was **the live 2026 Anthropic Agent Skills spec**, which I verified directly against three official Anthropic domains (`platform.claude.com`, `code.claude.com`, plus the `anthropics/claude-code` and `anthropics/skills` GitHub issue trackers for edge-case confirmation). All FMT-05 lint questions from CONTEXT.md's "Claude's Discretion" section now have concrete, sourced answers (below) — none of it requires further research at plan time.

Beyond the spec, direct repository inspection surfaced several **corrections and unlisted risks** that CONTEXT.md did not fully anticipate and that the planner needs to account for:

1. **`install.sh` will hard-fail after D-02's delete.** `install_skill()` gates every install path on `[ -f "owasp-comprehensive-security-skills.md" ]` and exits 1 if absent. Deleting that file (D-02, explicitly in scope) breaks the *currently-shipping* install mechanism, even though full `install.sh` removal is Phase 5 scope. The plan needs a minimal-patch decision here (see Common Pitfalls #1).
2. **Every example file's header comment cites the file being deleted.** All 7 files under `assets/examples/` (and `prompt-injection.txt`) contain a `# For detailed guidance, see: owasp-comprehensive-security-skills.md#section-N-...` line. D-02's delete breaks these unless D-04's example-relabeling pass also repoints them — this is *implied* by D-04's scope ("re-validate each example's...code") but not spelled out in CONTEXT.md as a concrete edit target. Flagging explicitly.
3. **`prompt-injection.txt` contains four distinct `AG0x` codes** (AG01, AG03, AG05, AG06), each mapping to a *different* real OWASP code per `llm-agentic.md`'s own mapping table — not a single find-and-replace of `AG01` → `ASI01` as CONTEXT.md's phrasing might suggest. See Code Examples below for the exact per-occurrence mapping.
4. **The `owasp-urls.json` "must repoint llm-agentic.md references" note in CONTEXT.md is unfounded** — I inspected both skills' `owasp-urls.json` files directly; neither contains any field referencing a source `.md` filename (entries are `title`/`edition`/`url`/`retrieval_date`/`confidence` only). The only real repoint targets for D-05 are inside `SKILL.md` itself (2 lines: the routing table and the reference-file-index bullet). Don't spend a task hunting for a repoint in `owasp-urls.json` that doesn't exist.
5. **The `.DS_Store` cleanup item in CONTEXT.md's discretion list appears to be stale/incorrect.** `git ls-files` and `git status --short` both confirm `.DS_Store` files are **not tracked** (already correctly ignored via the existing `.gitignore` entry). Same for `scripts/__pycache__/` (already gitignored, untracked). This cleanup item can likely be dropped or verified-and-closed in one command rather than executed as an edit.

**Primary recommendation:** Treat FMT-01/FMT-02/FMT-05 as **verification tasks** (write and run a small stdlib-only Python lint script; confirm pass; commit the script under `skills/owasp-security-audit/scripts/` or a repo-root `scripts/` if a cross-skill tool is preferred) rather than authoring tasks — the frontmatter is already compliant. Spend the plan's task budget on: the delete + cross-reference repointing (D-01/D-02, including the example-header fix above), the llm-agentic split (D-05, only 2 real repoint sites), the description edits (D-06, well within the character budget), the SCP doc refresh (D-03), and the CONT-06 example relabeling (with the corrected per-occurrence AG-code mapping for `prompt-injection.txt`).

## Architectural Responsibility Map

This is a documentation-restructuring phase with no runtime application tiers; the "architecture" here is the skill-package's own internal layering (per `docs/SKILL-STRUCTURE.md`) plus one integration point outside it (`install.sh`).

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Skill discovery / activation | `SKILL.md` frontmatter (`description`) | — | Per live spec, `description` is the sole required activation signal; no separate manifest layer exists post-retirement |
| Deep reference lookup | `references/*.md` + `references/owasp-urls.json` | `SKILL.md` routing table (pointer only) | Progressive disclosure: SKILL.md body stays a pointer, not a copy |
| Example/pattern content | `assets/examples/*` | `references/vulnerable-patterns.md` (cross-link) | Self-contained per PKG-03; must not depend on the file being deleted (D-02) |
| Executable tooling | `scripts/quick_scan.py` | — | Unaffected by this phase; verified it does not reference either doomed file |
| Legacy routing (retiring) | *(none — removed)* | — | `owasp-css.instructions.md`'s job is fully absorbed into `SKILL.md description` per D-01 |
| Install/packaging glue | `install.sh` (repo root, Phase-5-owned) | — | **Not owned by this phase**, but structurally coupled to D-02's delete target — see Common Pitfalls #1 |

## Verified Live Spec (FMT-05 — the phase's primary external unknown)

All of the following was fetched live from `platform.claude.com/docs/en/agents-and-tools/agent-skills/overview`, `platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices`, and `code.claude.com/docs/en/skills` (2026-07-23), cross-checked against a live GitHub issue (`anthropics/claude-code#63081`) for the angle-bracket edge case. `[CITED: platform.claude.com/docs/en/agents-and-tools/agent-skills/overview]` unless noted otherwise.

### 1. Required frontmatter fields
- **`name`**: max 64 chars; lowercase letters, numbers, hyphens only; **cannot contain XML tags**; **cannot contain the reserved words "anthropic" or "claude"**.
- **`description`**: must be non-empty; max 1024 chars; **cannot contain XML tags**.
- Both files in this repo pass all of these today (verified by direct extraction, not assumed): `owasp-security-audit` name=20 chars, description=738 chars; `secure-coding-practices` name=23 chars, description=695 chars. Neither name contains "claude"/"anthropic". Zero literal `<`/`>` characters in either frontmatter block.

### 2. The angle-bracket rule — exact scope
The public spec phrasing is "cannot contain XML tags," but a live bug report (`anthropics/claude-code#63081`, `[CITED: github.com/anthropics/claude-code/issues/63081]`) confirms the *practical* validator behavior: it is an HTML/XML-sanitizer that rejects **literal `<` and `>` characters anywhere in the `description` field**, regardless of intent (e.g. `Pass \`<name> <prompt>\` as arguments` fails). Confirmed via the same report's bisection: **square brackets, backticks, and straight double quotes are all safe** — only literal angle brackets trigger rejection. This directly resolves CONTEXT.md's open question: the audit skill's straight double quotes around example phrasings (`"is this login flow secure?"`) are fine; do not touch them for FMT-05.

### 3. Allowed frontmatter keys — two overlapping specs, resolved for this repo
Two specs exist and this distinction matters:
- The **generic cross-tool Agent Skills standard** (used by the claude.ai/API skill uploader) recognizes a narrower set: `name`, `description`, `license`, `allowed-tools`, `metadata` — unexpected keys error with `"unexpected key in SKILL.md frontmatter: properties must be in (...)"`. `[CITED: github.com/anthropics/skills, via issue #37 discussion]` (MEDIUM confidence — derived from a GitHub issue, not the primary docs page).
- **Claude Code's own parser** (the actual runtime for this repo, since it ships as a Claude Code plugin) recognizes a much larger superset, confirmed directly from `code.claude.com/docs/en/skills`: `name`, `description`, `when_to_use`, `argument-hint`, `arguments`, `disable-model-invocation`, `user-invocable`, `allowed-tools`, `disallowed-tools`, `model`, `effort`, `context`, `agent`, `hooks`, `paths`, `shell`. All are optional; only `description` is "recommended."
- **For this repo (a Claude Code plugin), the Claude Code superset is the operative spec.** Both `SKILL.md` files use only `name`+`description` today — a strict subset of *both* specs, so no field-rejection risk exists regardless of which validator runs at install/marketplace time. Do not add `license`/`metadata`/`version`/`author`/`category` — the last three are explicitly rejected by the generic validator (`"version"`, `"author"`, `"category"` cause the unexpected-key error above), so if a future phase is tempted to add a `version:` field to `SKILL.md` for PKG-05's "single canonical version source," **it must not go in SKILL.md frontmatter** — flagging for Phase 5 awareness, out of scope here.

### 4. Byte-0 frontmatter start
**Not found as an explicitly documented rule in any of the three official pages fetched.** This appears to be a defensive parsing assumption (standard YAML-frontmatter convention: `---` must be the literal first line, no BOM, no leading blank line) rather than a published, numbered spec requirement. `[ASSUMED]` that a leading blank line or BOM would break the frontmatter parser — not verified against an official statement, but consistent with how every YAML-frontmatter tool (Jekyll, Hugo, gray-matter, etc.) behaves, and is the safe default regardless. **Moot for this phase regardless of provenance**: both files already start with `2d 2d 2d` (`---`) as the literal first 3 bytes, no BOM, verified via `head -c 3 | xxd`. FMT-05's byte-0 check is a pure verification step here, not a fix.

### 5. Progressive-disclosure body budget — confirmed guidance, not a hard limit
Direct quotes: *"Keep SKILL.md body under 500 lines for optimal performance. If your content exceeds this, split it into separate files"* (Technical notes > Token budgets) and *"Keep `SKILL.md` under 500 lines. Move detailed reference material to separate files"* (`code.claude.com/docs/en/skills`). Both are phrased as recommendations tied to "optimal performance," not validator-enforced limits — nothing in the docs states a file >500 lines is rejected. The authoring checklist lists it as a quality-checklist item ("SKILL.md body is under 500 lines"), reinforcing it's a best-practice gate, not a hard spec ceiling. **Confirms FMT-02's "~500 lines" framing is correct as guidance language** — current 415/256 lines both comply with real headroom.

### 6. Routing/activation via `description` (FMT-03) — confirmed, plus two optional mechanisms
Confirmed verbatim: *"The `description` is what Claude matches your request against when determining whether to trigger the Skill."* This validates D-01's premise that retiring `owasp-css.instructions.md`'s keyword-trigger routing is safe once descriptions carry that load — no separate "triggers" array exists in the current spec (the old `skill.json` keyword-array model has no live equivalent).

Two **optional** Claude Code-specific fields exist that CONTEXT.md's FMT-03 wording anticipated and asked about:
- **`when_to_use`** — "Additional context for when Claude should invoke the skill, such as trigger phrases or example requests. Appended to `description` in the skill listing" (counts toward the same combined 1,536-char listing cap as `description`).
- **`paths`** — "Glob patterns that limit when this skill is activated... Claude loads the skill automatically only when working with files matching the patterns."

Both are real and available today, but **neither is required** — D-01 already establishes that the existing `description` fields fully subsume the legacy routing content, so adding `when_to_use`/`paths` is a discretionary enhancement, not a phase requirement. Recommend the planner note this as a "could add, not required" line rather than a task.

### 7. Bundled subdirectory convention
Confirmed against Anthropic's own published skill (`anthropics/skills` repo, `skill-creator/SKILL.md`, fetched live): the three-directory convention is `scripts/` (executable code), `references/` (docs loaded on demand), `assets/` (files used in output — templates, icons, fonts). This is **exactly** the three names `docs/SKILL-STRUCTURE.md` already locks in (D-07) and CONTEXT.md assumes — confirmed exhaustive and current, no fourth convention name found in any source consulted. Note: Claude Code's own filesystem-navigation model does not technically *restrict* subdirectory names (Claude just reads whatever `SKILL.md` links to) — the three-name set is a **convention for cross-tool portability and clarity**, not a hard parser-enforced allowlist. FMT-05's "only allowed bundled directories" check should therefore be framed as "matches the documented convention" rather than "rejected by a validator if violated" — still worth linting for consistency.

## Runtime State Inventory

This phase deletes/renames/relabels files, so the trigger condition applies. This is a pure git-tracked documentation repo with no deployed instances, external services, or databases — most categories are empty by nature of the project, but each is checked explicitly below rather than left blank.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — no database, no persisted state; this is a static skill-content repo | None |
| Live service config | None — no external service holds skill config outside git (no n8n/Datadog/Tailscale equivalent in this repo) | None |
| OS-registered state | None — no OS task scheduler, launchd, systemd, or pm2 registrations reference these filenames | None |
| Secrets/env vars | None — no `.env`, no SOPS keys, no CI/CD env vars reference `owasp-css.instructions.md` or `owasp-comprehensive-security-skills.md` by name (verified via repo-wide grep) | None |
| Build artifacts / installed packages | **`install.sh`'s `install_skill()` function hard-checks for `owasp-comprehensive-security-skills.md`'s existence as a repo-root sentinel file** (line 51: `if [ ! -f "owasp-comprehensive-security-skills.md" ]; then ... return 1; fi`). This is not a stored/deployed artifact but a **code edit dependency**: install.sh's logic breaks the moment D-02 deletes the file. | **Code edit** required — see Common Pitfalls #1 for the exact minimal-patch recommendation. This is the one real "runtime state" finding for this phase; everything else in this category is clean. |

**Correction to CONTEXT.md discretion note:** `.DS_Store` under `skills/` and `scripts/__pycache__/` are **already gitignored and untracked** (verified via `git ls-files` returning zero matches and `git status --short` returning clean). No cleanup edit is needed; if the planner wants to close this out, a single verification step (`git ls-files | grep -i ds_store` returns empty) suffices — no task required.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3 | FMT-05 lint script (stdlib-only, no PyYAML) | Yes | 3.14.6 | — |
| PyYAML | Full YAML frontmatter parsing | **No** — `ModuleNotFoundError: No module named 'yaml'` | — | Use regex-based frontmatter extraction (see Code Examples) — matches `quick_scan.py`'s own "stdlib only" design rule already documented in that script's docstring |
| git | Cross-reference verification, `git ls-files` checks | Yes | 2.53.0 | — |

No missing dependencies block execution; the PyYAML absence just steers the lint-script implementation toward regex/stdlib parsing, consistent with the repo's existing tooling convention.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Full YAML frontmatter parsing for the lint script | A hand-rolled generic YAML parser | Simple regex extraction of the `---\n...\n---` block + `name:`/`description:` line matches (as verified in this research session) | PyYAML isn't installed in the target environment; the frontmatter shape here is fixed two-key YAML, not general YAML — a full parser is unnecessary complexity for a two-field extraction |
| Detecting "no legacy file in loaded path" (FMT-04) | A custom file-tree walker | `git ls-files | grep -E '<pattern>'` — empty output proves the path left the tracked tree | `git ls-files` is the authoritative "what's in the loaded/installed path" signal for a git-distributed plugin; a filesystem walk could false-negative on `.gitignore`'d copies still on disk |

**Key insight:** This phase needs verification tooling, not application code — every "don't hand-roll" here is about not over-engineering a two-file, stdlib-only lint check.

## Common Pitfalls

### Pitfall 1: `install.sh` hard-fails immediately after D-02's delete
**What goes wrong:** `install_skill()` (called by every menu choice 1-4) contains `if [ ! -f "owasp-comprehensive-security-skills.md" ]; then echo "Please run this script from the OWASP-Security-Skills directory" >&2; return 1; fi`. This is meant as a "are we in the right directory" sentinel check, but once D-02 deletes the file, **every installation attempt fails**, even run from the correct directory. `verify_installation()`'s `required_files` array also lists both doomed files and would print red `✗` marks post-install (non-fatal, cosmetic).
**Why it happens:** install.sh predates the plugin/marketplace packaging model (Phase 1) and was never updated to use a file that survives past Phase 4; Phase 1 patched *paths* inside install.sh but didn't touch this specific existence-gate line (confirmed via Phase 1 STATE.md notes, which only mention "install.sh...patched to per-skill canonical paths").
**How to avoid:** This phase's CONTEXT.md explicitly scopes full `install.sh` rework to Phase 5. Recommend the plan include a **minimal, surgical patch** (not the "full README/install.sh rewrite" Phase 5 owns) — change the sentinel check to something that survives this phase, e.g. `[ -d "skills/owasp-security-audit" ]` or `[ -f ".claude-plugin/plugin.json" ]`, and correspondingly drop/replace the two doomed filenames from `verify_installation()`'s `required_files` array. This keeps `main` installable at every commit boundary (the discipline CONTEXT.md's Integration Points section explicitly calls for) without doing Phase 5's full rewrite. Flag this precisely in the plan rather than silently leaving install.sh broken until Phase 5 — a broken install script between Phase 4 and Phase 5 would fail PKG-04's eventual "verified end-to-end on a clean environment" check retroactively.
**Warning signs:** Running `./install.sh` (option 4, test-only) after the delete and seeing "Please run this script from the OWASP-Security-Skills directory" while standing in the correct directory.

### Pitfall 2: Example-file header comments cite the file being deleted
**What goes wrong:** All of `broken-access-control.py`, `security-misconfiguration.py`, `logging-monitoring-failures.py`, `cryptographic-failures.js`, `xss.html`, `injection.js`, and `prompt-injection.txt` contain a line like `# For detailed guidance, see: owasp-comprehensive-security-skills.md#section-1-owasp-top-10-2021` (or `#section-6-owasp-agentic-applications-2026` for the prompt-injection file). After D-02 deletes the target, these become dead anchor-links to a nonexistent file.
**Why it happens:** The examples were authored before the per-skill `references/` tree existed and were never repointed when Phases 2-3 built out the new reference files.
**How to avoid:** Treat this as part of D-04's "re-validate each example's...code" scope — repoint each header comment to the correct current reference file (e.g. `references/top10.md`, or the future `references/agentic.md` for `prompt-injection.txt`) as part of the same edit pass that fixes the category ID. Don't split this into a separate task; it's the same file, same line region.
**Warning signs:** `grep -rn "owasp-comprehensive-security-skills" skills/` returning any hits after the phase claims completion.

### Pitfall 3: `prompt-injection.txt`'s AG-codes don't map 1:1 to a single ASI code
**What goes wrong:** The file contains four separate headers — `AG01: Prompt Injection`, `AG03: Insecure Output Handling`, `AG05: Denial of Service`, `AG06: Unauthorized Plugin/Tool Access` — and CONTEXT.md's phrasing ("fix the wrong Agentic prefix, AG01 → ASI01") could be misread as a single blanket substitution. Per `llm-agentic.md`'s own mapping table (verified, will move into the new `agentic.md` per D-05):

| Old (invented) | Real OWASP item(s) |
|---|---|
| AG01 Prompt Injection | **LLM01** Prompt Injection (primary); related ASI01 |
| AG03 Insecure Output Handling | **LLM05** Improper Output Handling |
| AG05 Denial of Service | **LLM10** Unbounded Consumption |
| AG06 Unauthorized Tool Access | **LLM06** Excessive Agency; ASI02; ASI03 |

Only AG01 has a *direct* ASI-side relative (ASI01 Agent Goal Hijack is related but not identical — AG01's actual content in the example is classic prompt injection, which is LLM01 territory, not a goal-hijack scenario).
**Why it happens:** The old invented `AG` taxonomy mixed LLM-only concerns and agentic-only concerns under one prefix; the real OWASP split (LLM Top 10 vs Agentic Top 10) doesn't preserve that numbering.
**How to avoid:** Relabel each of the four headers individually against the table above, don't do a blanket `AG01→ASI01`-style regex replace across the file. The file's own preamble line 5 ("Status: Preview/Draft — content based on evolving standards") is also stale and contradicts Phase 3's verified "Final" status for Agentic Apps 2026 — fix this line too as part of the same edit.
**Warning signs:** Any remaining `AG0\d` string in the file after the phase claims CONT-06 done; the word "Preview" or "Draft" surviving in the file's own status line.

### Pitfall 4: Root-level docs (README, DEPLOYMENT, TESTING, CONTRIBUTING, `.claude/CLAUDE.md`) all cite the doomed files too, and are out of this phase's edit scope
**What goes wrong:** `README.md` (3 mentions incl. a markdown link), `DEPLOYMENT.md` (4 mentions), `TESTING.md` (4 mentions), `CONTRIBUTING.md` (1 mention), and this repo's own `.claude/CLAUDE.md` (4 mentions, including in its own Architecture/Component-Responsibilities tables) all reference `owasp-comprehensive-security-skills.md` and/or `owasp-css.instructions.md` as if current. CONTEXT.md explicitly defers README/DEPLOYMENT/TESTING to Phase 5.
**Why it happens:** These docs were last touched before this milestone's restructure; Phase 1's STATE.md already flagged DEPLOYMENT.md/TESTING.md staleness and deferred it.
**How to avoid:** Don't scope-creep into fixing these in Phase 4 — but the plan/PR description should explicitly note "README.md, DEPLOYMENT.md, TESTING.md, CONTRIBUTING.md, and .claude/CLAUDE.md will contain broken references to deleted files until Phase 5; this is a known, tracked gap, not an oversight" so a reviewer doesn't flag it as a missed cross-reference during this phase's own review. `.claude/CLAUDE.md` in particular wasn't explicitly named in CONTEXT.md's deferred list (only README/DEPLOYMENT/TESTING/install.sh were) — flagging it here as the same class of deferred staleness for Phase 5, since fixing this project's own instructions file is a documentation-polish task, not legacy-file retirement.
**Warning signs:** A plan-review or PR-review pass flagging these as "unaddressed broken links" — pre-empt with an explicit note.

### Pitfall 5: PyYAML unavailable — don't write a lint script that imports `yaml`
**What goes wrong:** `python3 -c "import yaml"` fails (`ModuleNotFoundError`) in the verified environment. A lint script that imports PyYAML will crash for anyone without it pre-installed, and this repo has zero runtime dependencies today (a stated project constraint: "no heavy runtime dependencies").
**Why it happens:** PyYAML isn't in the Python stdlib and this repo intentionally ships no `requirements.txt`/dependency manifest.
**How to avoid:** Write the FMT-05 lint check using stdlib-only regex extraction of the `---\n(.*?)\n---` block (see Code Examples) — consistent with `quick_scan.py`'s own documented design rule ("Single-file dependency-free (stdlib only) so it runs anywhere Python 3 is installed").
**Warning signs:** `ModuleNotFoundError` when running the lint script in a clean environment.

## Code Examples

### FMT-05 lint checks (stdlib-only, no PyYAML dependency)

```python
# Byte-0 frontmatter start check
with open(path, 'rb') as f:
    first_bytes = f.read(3)
assert first_bytes == b'---', f"{path}: frontmatter does not start at byte 0"

# Frontmatter extraction + field checks (regex, no yaml import)
import re
content = open(path).read()
m = re.match(r'^---\n(.*?)\n---\n', content, re.DOTALL)
assert m, f"{path}: no frontmatter block found"
fm = m.group(1)
name = re.search(r'^name:\s*(.*)$', fm, re.MULTILINE).group(1).strip()
desc = re.search(r'^description:\s*(.*)$', fm, re.MULTILINE | re.DOTALL).group(1).strip()

assert len(name) <= 64, f"{path}: name exceeds 64 chars ({len(name)})"
assert re.fullmatch(r'[a-z0-9-]+', name), f"{path}: name has invalid characters"
assert 'claude' not in name and 'anthropic' not in name, f"{path}: name contains reserved word"
assert len(desc) <= 1024, f"{path}: description exceeds 1024 chars ({len(desc)})"
assert desc, f"{path}: description is empty"
assert '<' not in fm and '>' not in fm, f"{path}: frontmatter contains angle brackets"

# name must match parent directory (this repo's own D-07 convention, stricter than the live spec)
parent_dir = path.split('/')[-2]
assert name == parent_dir, f"{path}: name '{name}' != parent dir '{parent_dir}'"
```

```bash
# FMT-02: body line count (guidance, not hard limit — flag, don't fail hard)
wc -l skills/owasp-security-audit/SKILL.md skills/secure-coding-practices/SKILL.md

# FMT-04: prove legacy files left the loaded (git-tracked) path
git ls-files | grep -E "^owasp-css\.instructions\.md$|^owasp-comprehensive-security-skills\.md$|^skills/owasp-security-audit/owasp-security-audit\.md$"
# Expect: empty output

# FMT-05: allowed bundled directories only
find skills -mindepth 2 -maxdepth 2 -type d | grep -vE "/(references|scripts|assets)$"
# Expect: empty output

# Cross-reference sweep before/after delete (D-02 salvage-check gate)
grep -rn "owasp-comprehensive-security-skills\|owasp-css.instructions" . \
  --include="*.md" --include="*.json" --include="*.py" --include="*.js" \
  --include="*.txt" --include="*.html" --include="*.yaml" --include="*.sh" \
  2>/dev/null | grep -v "^\.planning/"
# Run before delete to enumerate every cross-reference that needs a decision
# (fix now vs. explicitly defer to Phase 5 per Pitfall 4)
```

### `prompt-injection.txt` AG-code remediation map (verified against `llm-agentic.md`'s own mapping table)

```
AG01: Prompt Injection - Direct and Indirect Attacks   -> LLM01:2025 Prompt Injection
AG03: Insecure Output Handling - Data Leakage          -> LLM05:2025 Improper Output Handling
AG05: Denial of Service - Token Exhaustion             -> LLM10:2025 Unbounded Consumption
AG06: Unauthorized Plugin/Tool Access                  -> LLM06:2025 Excessive Agency (cross-ref ASI02/ASI03 if agentic framing is kept)
```
Also fix the file's own preamble (currently line 5: `Status: Preview/Draft - content based on evolving standards`) — Agentic Apps 2026 is verified **Final**, not draft, per Phase 3.

### 2025 Top 10 category IDs (for correct CONT-06 relabeling — read from the already-locked `top10.md`, not re-derived)

```
A01: Broken Access Control
A02: Security Misconfiguration        (was A05:2021)
A03: Software Supply Chain Failures   (new; expands old A06:2021 Vulnerable/Outdated Components)
A04: Cryptographic Failures           (was A02:2021)
A05: Injection                        (was A03:2021)
A06: Insecure Design
A07: Authentication Failures
A08: Software or Data Integrity Failures
A09: Security Logging & Alerting Failures
A10: Mishandling of Exceptional Conditions  (new)
```
Cross-check each example's current stale label against this table before writing the new one — e.g. `security-misconfiguration.py` (currently labeled A05) needs **A02**, not a straight "increment"; `cryptographic-failures.js` (currently A02) needs **A04**.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | None — documentation-only phase, no test runner in this repo |
| Config file | none |
| Quick run command | The FMT-05 lint script (see Code Examples), run per-file |
| Full suite command | Full grep/wc/git-ls-files sweep (all commands in Code Examples run together) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FMT-01 | `name`/`description` compliant | script check | Python regex snippet above, run against both `SKILL.md` files | ❌ Wave 0 — needs a small lint script written |
| FMT-02 | Body ≤~500 lines | shell check | `wc -l skills/*/SKILL.md` | ✅ trivial, no new file needed |
| FMT-03 | Description carries routing load | manual + grep | `grep -c "Use this skill whenever\|Use when" skills/*/SKILL.md` (non-zero) plus manual read | ✅ no new file needed |
| FMT-04 | Legacy files not in loaded path | shell check | `git ls-files | grep -E '<pattern>'` (empty) | ✅ no new file needed |
| FMT-05 | Frontmatter lint passes | script check | Same lint script as FMT-01, extended with byte-0 + angle-bracket + bundled-dir checks | ❌ Wave 0 — same script as FMT-01 |
| CONT-06 | Examples re-validated + correctly labeled | grep + manual read | `grep -rn "AG0[0-9]\|A05: Security Misconfiguration\|2017 edition\|2021 edition" skills/owasp-security-audit/assets/examples/` (expect zero post-fix) + manual code re-read against `top10.md`/`llm.md`/`agentic.md` | ✅ no new file needed, manual review required (code correctness isn't grep-verifiable) |

### Sampling Rate
- **Per task commit:** Run the relevant grep/wc check for the file(s) just touched.
- **Per wave merge:** Run the full Code Examples command block (FMT-04 + FMT-05 + cross-reference sweep) once.
- **Phase gate:** All five FMT/CONT-06 checks green, plus a manual read-through confirming `prompt-injection.txt`'s four AG-codes are individually corrected (not just find-replaced) and `install.sh`'s sentinel patch (Pitfall 1) is in place.

### Wave 0 Gaps
- [ ] A small stdlib-only Python lint script (no PyYAML dependency) covering FMT-01/FMT-02/FMT-05 checks — suggest `skills/owasp-security-audit/scripts/lint_skill_md.py` or a repo-root `scripts/` if it should cover both skills from one place. Not required to be fancy; a ~40-line script matching `quick_scan.py`'s existing style is sufficient.
- [ ] No conftest/fixtures needed — this is a documentation repo, not an application with a test suite.

## Sources

### Primary (HIGH confidence — official Anthropic docs, fetched live 2026-07-23)
- `platform.claude.com/docs/en/agents-and-tools/agent-skills/overview` — full frontmatter spec (name/description limits, reserved words, XML-tag rule), progressive disclosure model, Level 1/2/3 loading, token-budget table
- `platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices` — confirms same frontmatter limits verbatim in a second location, confirms "under 500 lines" is guidance/checklist item not a validator gate, describes writing effective `description` fields
- `code.claude.com/docs/en/skills` — Claude-Code-specific frontmatter field superset (`when_to_use`, `paths`, `allowed-tools`, etc.), confirms `description` drives triggering, confirms plugin-skill `name`-vs-directory-name behavior

### Secondary (MEDIUM confidence — GitHub issues/repo, cross-referencing official behavior)
- `github.com/anthropics/claude-code/issues/63081` — confirms angle-bracket rejection is specifically a `description`-field HTML/XML-sanitizer behavior; confirms straight quotes/brackets/backticks are safe
- `github.com/anthropics/skills` (`skill-creator/SKILL.md`, fetched live) — confirms the `scripts/`/`references/`/`assets/` three-directory bundled-resource convention this repo already follows
- `github.com/anthropics/skills/issues/37` (via WebSearch synthesis) — generic-spec allowed-key list (`name`, `description`, `license`, `allowed-tools`, `metadata`); noted as the *narrower* of two overlapping specs, not the operative one for this Claude-Code-plugin repo

### Tertiary (repo-internal verification — direct inspection, not external research)
- `git log`, `git ls-files`, `git status`, `diff`, `wc -l`, `head -c`/`xxd`, and `grep` run directly against this repository during this research session (all findings in Runtime State Inventory, Common Pitfalls, and the Summary's numbered corrections)

## Metadata

**Confidence breakdown:**
- Standard stack: N/A — no external packages installed in this phase (markdown/docs restructuring only)
- Live Agent Skills spec (FMT-05 primary goal): HIGH — verified against 3 official Anthropic domains with direct quotes, cross-checked against a live bug report for the angle-bracket edge case
- Repo-state findings (install.sh breakage, example cross-references, AG-code mapping, .DS_Store correction, owasp-urls.json correction): HIGH — all verified by direct tool inspection (grep/diff/git) in this session, not inferred
- CONT-06 category-ID targets: HIGH — read directly from the already-locked, Phase-2-verified `top10.md`; not re-derived or re-verified against OWASP itself (correctly out of this phase's scope)

**Research date:** 2026-07-23
**Valid until:** Spec section — Anthropic's Agent Skills spec is actively evolving (Claude Code doc noted several `min-version` gated features); re-verify if this phase's execution is delayed more than ~30 days. Repo-state findings are valid until the next commit touches these files.
