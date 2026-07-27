# Phase 5: Packaging Validation & Credibility Polish - Research

**Researched:** 2026-07-27
**Domain:** Claude Code plugin/marketplace packaging mechanics, release-identity hygiene (version/license/README), and documentation credibility (citation completeness, honest coverage, secret-placeholder convention)
**Confidence:** HIGH (CLI mechanics: verified live against official docs + version check in this environment; repo-local facts: verified by direct inspection; regression status: MEDIUM — GitHub issues found and read, but no maintainer confirmation of fix status at the exact installed version)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Install validation depth (PKG-04)**
- **D-01:** Two-checkpoint validation — local now, github at ship. Run `claude plugin validate` + add a local marketplace source (the repo directory) + install + smoke test in this environment now as the Phase 5 gate, capturing real command output. Defer the true github-source marketplace add + install to the ship/release step, after all Phase 5 polish commits land and are pushed (the GitHub remote is currently behind local HEAD, so a github install today would pull stale content). `claude` CLI v2.1.201 is present, so the local validation is genuinely runnable here. (Chosen over "local only + document github" and "push first then github".)
- **D-02:** Activation smoke test = scripted + captured transcript. A small, repeatable check (script or documented command sequence, stdlib-only to match repo tooling style) that confirms both skills are discoverable/loadable post-install, with the actual output captured into the phase artifacts as reproducible evidence. (Chosen over manual prompt walkthrough and structural-only verification.)
- **Re-check before relying on install mechanics:** per STATE.md §Blockers/Concerns, verify current Claude Code (v2.1.201) status for documented packaging regressions (symlink-to-cache, Windows path collapse, marketplace "0 skills" bug) rather than assuming they still apply.

**Version & release identity (PKG-05, ADPT-01)**
- **D-03:** Ship at 1.0.0. First credible public release of the modernized plugin. Phase 1 deliberately reset to 0.1.0 to break the legacy 1.1.0 lineage, so 1.0.0 is a fresh, honest v1 — not a continuation of the old versioning.
- **D-04:** `plugin.json` `version` is the single canonical source (PKG-05). README/docs reference it without hardcoding a competing copy where avoidable; a tiny stdlib check (extend `scripts/` tooling) asserts no conflicting version string exists elsewhere. Skills do not carry their own version — the `SKILL.md` frontmatter spec has no version field. Consistent with Phase 1's "marketplace.json carries no version key; plugin.json is authoritative."
- **D-05:** MIT LICENSE at repo root, holder = "Security Education Community" (matches `plugin.json` author), current year. Zero new claims — aligns with the already-declared `plugin.json` `"license": "MIT"`. (Chosen over a different holder and over Apache-2.0.)

**README & honest coverage matrix (ADPT-02, QUAL-02, QUAL-01)**
- **D-06:** Two-column coverage matrix + "What this is NOT" note. One matrix row per standard with an explicit "Edition covered" column AND a "Scope / caveat" column stating limits inline (K8s 2022 not the 2025 draft; ASVS 4.0.3-body numbering under a verified 5.0.0 current edition; LLM/Agentic as two separate standards). Plus a short "What this is NOT" section: guidance/reference — not a runtime scanner; and example files do not yet cover every 2025 category (A03 Supply Chain, A04 Insecure Design, A06 Vulnerable & Outdated Components, A08 Software & Data Integrity, A10 Exceptional Conditions). Caveats must be impossible to miss.
- **D-07:** Every matrix/edition/ID claim cites an official source URL + retrieval date (QUAL-01). Source the citations from the already-hardened per-skill `owasp-urls.json` files (Phases 2–3) — do not re-derive or re-verify editions; confirm completeness and consistency across README ↔ references ↔ manifests.
- **D-08:** Static, honest badge set only. License (MIT), version (1.0.0), "Claude Code plugin", and OWASP-aligned — static shields reflecting true facts. No CI/coverage/build badges (there is no CI pipeline; deferred to v2 EVAL-01). Badges must never misrepresent capability.
- README is currently stale and must be corrected: it links the deleted `owasp-comprehensive-security-skills.md`, says "six OWASP standards", "ASVS 5.0", and "SCP Quick Reference Guide" — all superseded by Phase 3–4 reframes.

**Legacy docs & example secrets (QUAL-03, ADPT-03)**
- **D-09:** Fold useful bits, then delete `DEPLOYMENT.md` + `TESTING.md`. Salvage anything still accurate into README (install/usage) and CONTRIBUTING (the maintenance/versioning/update story — this also satisfies ADPT-03), then delete both stale files (they still reference the removed root `skill.json` / `examples/` and describe the pre-plugin symlink-install era). Matches Phase 4's "retire superseded files" pattern. (Chosen over full rewrite and over the split rewrite-TESTING/delete-DEPLOYMENT option.)
- **D-10:** Self-labeling placeholder convention for example secrets (QUAL-03). Standardize on obviously-fake, self-documenting values across ALL examples: e.g. `sk-EXAMPLE-not-a-real-key`, `sk-your-api-key-here`, `PLACEHOLDER_PASSWORD`. Structurally recognizable enough to still teach the hardcoded-secret anti-pattern, but unmistakably fake to a human AND to secret scanners (GitHub push protection, GitGuardian). Document the convention once (CONTRIBUTING or a comment banner). Current offenders to normalize include `sk-abc123xyz789` (k8s-rbac.yaml, prompt-injection.txt, cryptographic-failures.js), `sk-abcd1234efgh5678ijkl9012` (SCP vulnerable-examples.py), and `sk-1234567890abcdefghijklmnop` (SCP vulnerable-examples.js). (Chosen over angle-bracket redaction and RFC-2606/documented-fake conventions.)

**Discoverability handling (ADPT-04)**
- **D-11:** In-repo metadata now + documented GitHub topics for user to apply. Set/align `plugin.json` keywords and add a `marketplace.json` category + keywords during execution. Provide the exact `gh repo edit --add-topic ...` command list in the deliverable for the user to apply/approve — GitHub repo topics are an outward-facing change to the live public repo and stay user-controlled (do NOT run `gh repo edit` automatically). (Chosen over auto-applying via gh and over in-repo-manifests-only.)

### Claude's Discretion
- Exact drift-check implementation for D-04 (script vs. lint-extension), where it lives in `scripts/`, and precisely which files it scans.
- Exact CONTRIBUTING structure and wording of the maintenance/versioning story.
- Precise matrix layout/column headers and badge shield styling.
- The exact `gh repo edit --add-topic` topic list content (see D-11) and the final `plugin.json` keyword / `marketplace.json` category+keyword values.
- `install.sh` disposition — keep as a documented alternative install path vs. slim/retire now that plugin/marketplace is the primary path (planner's call; it was patched to per-skill canonical paths in Phase 1 and is currently functional).

### Deferred Ideas (OUT OF SCOPE)
- New-category example files (A03 Supply Chain, A04 Insecure Design, A06 Vulnerable & Outdated Components, A08 Software & Data Integrity, A10 Exceptional Conditions) — the coverage matrix discloses the gap; authoring them is a future example-coverage phase / v2, explicitly declined for Phase 4 and not invented here.
- CI / eval tooling — v2 EVAL-01 (`evals/` correctness tests), EVAL-02 (OpenSSF badge), EVAL-03 (awesome-list submissions). Out of this milestone; badges here stay static/honest because there is no CI.
- Kubernetes Top 10 2025 adoption — v2 EXP-02, once final/stable.
- Auto-applying GitHub repo topics — kept as a user-controlled manual step (D-11); not automated in this phase.

None of these expand Phase 5 scope — all are pre-existing v2/future-phase items.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-------------------|
| PKG-04 | Install verified end-to-end on a clean environment (`claude plugin validate`, marketplace add, install, activation smoke test) | Live-verified exact CLI command surface for v2.1.201 (see "Live-Verified Claude Code CLI Mechanics" below); identified the local-marketplace-source content-freshness trap and the exact scripted command sequence + evidence artifact for D-02's smoke test |
| PKG-05 | Single canonical version source drives all version strings | Confirmed `plugin.json.version` is the only version field Claude Code itself reads; `lint_skill_md.py` provides the reusable LintResult/soft-append pattern for a new `check_version_drift.py` |
| QUAL-01 | Every OWASP version/edition/category ID cites an official source + retrieval date | Confirmed both `owasp-urls.json` files already carry verified URLs + retrieval dates; identified exact stale claims in README/CONTRIBUTING/docs/SKILL-STRUCTURE.md to fix for consistency |
| QUAL-02 | Coverage matrix documents covered vs. intentionally-not-covered | Confirmed exact edition/scope wording already locked in `asvs.md`/`kubernetes-top10.md` footnotes to mirror verbatim in the README matrix |
| QUAL-03 | Example secrets use a clear placeholder convention | Grepped and confirmed exact offending literals (API keys AND passwords) and the one already-good exemplar |
| ADPT-01 | LICENSE file added | Confirmed no LICENSE file exists at repo root; `plugin.json` already declares `"license": "MIT"` and author `"Security Education Community"` |
| ADPT-02 | README refreshed | Read current README in full; catalogued every stale claim requiring a fix |
| ADPT-03 | CONTRIBUTING + maintenance/versioning story documented | Read current CONTRIBUTING.md; it is also stale (references deleted `examples/` and `owasp-comprehensive-security-skills.md`) and needs its own refresh, not just an addition |
| ADPT-04 | Discoverability metadata set | Live-verified the exact plugin.json vs. marketplace.json schema split for `keywords` vs `category`/`tags` — this is a real, closed schema, not an invented field set |

</phase_requirements>

## Summary

This phase has two distinct research surfaces: (1) an external, fast-moving one — the current Claude Code CLI's plugin/marketplace mechanics — where training-data recall is explicitly untrustworthy and had to be replaced with live verification; and (2) an internal, fully-inspectable one — the repo's own stale docs, citation sources, and example-secret literals — where the answer is simply "read the files and grep."

**Live verification confirmed `claude --version` in this environment is 2.1.201.** The official Claude Code docs (code.claude.com, fetched 2026-07-27) give an exact, current command surface for everything D-01/D-02 need: `claude plugin validate <path>` (non-interactive, supports `--strict`), `claude plugin marketplace add <source> [--scope local|project|user]`, `claude plugin install <name>@<marketplace> [--scope ...]`, and — critically — `claude plugin details <name>` and `claude plugin list --json`, both of which print a **component inventory including a Skills count and names**, giving a clean, non-interactive, machine-parseable activation smoke test that satisfies D-02 far better than a manual prompt walkthrough.

**The most important non-obvious finding:** this repo's `marketplace.json` lists its one plugin entry with a **`github` source** (`mfkocalar/OWASP-Security-Skills`), not a relative path. Running `claude plugin marketplace add .` only re-reads the local `marketplace.json` catalog file — it does **not** make the plugin's own `install` pull from local disk. `claude plugin install owasp-security-skills@owasp-security-skills` would still clone from the **GitHub remote**, which is 116 commits behind local HEAD. **D-01's "true local-source test before push" therefore requires temporarily rewriting the plugin entry's `source` field to a relative path (e.g. `"."`) in the *uncommitted, on-disk* `marketplace.json` for the duration of the gate check, then reverting it before any commit** — the committed file must keep its `github` source per Phase 1 D-04 and D-11's ship-time intent. This is a genuine execution-order hazard the plan must handle explicitly, not an incidental detail.

**Regression re-check (STATE.md §Blockers/Concerns):** a GitHub issue matching the "marketplace 0 skills" description exists (`anthropics/claude-code#54967`, reported at CLI v2.1.123, closed as duplicate, workaround = pre-symlinking the local marketplace directory into `~/.claude/plugins/marketplaces/` before `add`). **No maintainer confirmation was found that this is fixed by v2.1.201** (the installed version here, which is newer than the reported version). Status: **unknown, not confirmed-fixed** — the plan must budget for the symlink workaround as a fallback and verify empirically via `claude plugin details`/`claude plugin list --json` skill counts during execution, not assume either way. Windows path-collapse and rename-race issues were also found (`#52435`, `#58241`), both Windows-only and both without confirmed fix — not applicable to this macOS execution environment but worth one documentation caveat since the repo ships Linux/Windows install instructions too.

**Primary recommendation:** Treat PKG-04 as two literally separate, sequenced checkpoints exactly as D-01 specifies — a temporary-source local gate now (captured to a phase artifact) and a github-source gate at ship, after push — and use `claude plugin details`/`claude plugin list --json` (not prompt-based testing) as D-02's scripted, capturable smoke test. Treat PKG-05, QUAL-01–03, and ADPT-01–04 as bounded, fully-scoped documentation/manifest edits against already-known-stale targets; no external research is needed for those beyond citation-source reuse.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Plugin/marketplace schema validity (PKG-04) | Claude Code CLI (external tool) | Repo manifests (`.claude-plugin/*.json`) | `claude plugin validate` is the authoritative validator; the repo only supplies conformant input |
| Version single-source-of-truth (PKG-05) | Repo manifest (`plugin.json`) | Repo tooling (`scripts/` drift-check) | Claude Code itself only ever reads `plugin.json.version` (or falls back to marketplace entry, then git SHA) — the repo's own drift-check is the only enforcement of "nothing else disagrees" |
| Citation accuracy (QUAL-01) | Per-skill `references/owasp-urls.json` | README / SKILL.md prose | JSON files are the data source of truth; prose surfaces (README, SKILL.md, docs/SKILL-STRUCTURE.md) must agree with them, not vice versa |
| Coverage honesty (QUAL-02) | README.md | `references/*.md` edition-note footnotes | README is the public-facing summary; the per-standard reference files already contain the verbatim edition/scope language to mirror |
| Secret placeholder convention (QUAL-03) | `skills/*/assets/examples/*` | CONTRIBUTING.md (documents the convention) | Example files are the enforcement surface; CONTRIBUTING is where the convention is written down once |
| License/legal identity (ADPT-01) | Repo root (`LICENSE`) | `plugin.json` (`license` field, already MIT) | LICENSE file is the legal artifact; plugin.json's field is metadata that must agree with it |
| Discoverability metadata (ADPT-04) | `.claude-plugin/plugin.json` (`keywords`) + `.claude-plugin/marketplace.json` (plugin-entry `category`/`tags`/`keywords`) | GitHub repo topics (external, user-applied) | Claude Code only reads the two manifest files; GitHub topics are a separate, human-controlled surface per D-11 |
| Doc retirement (DEPLOYMENT.md/TESTING.md) | Repo root markdown files | README.md (must drop the now-dead links) | Deleting the files is only "done" once every surviving cross-reference (README) is also fixed in the same commit boundary |

## Standard Stack

### Core
No new external libraries are introduced by this phase. All tooling is either an existing repo script (`scripts/lint_skill_md.py`, stdlib Python) or the `claude` CLI itself (already present, v2.1.201 verified in this environment).

| Tool | Version (verified in this environment) | Purpose | Why Standard |
|------|------------------------------------------|---------|---------------|
| `claude` CLI | 2.1.201 [VERIFIED: `claude --version` run in this environment, 2026-07-27] | Plugin/marketplace validate, install, discovery smoke test (PKG-04) | The only tool that can authoritatively validate this repo's packaging — no alternative exists |
| Python 3 (stdlib only) | 3.14.6 [VERIFIED: `python3 --version` run in this environment] | Extend `scripts/lint_skill_md.py`-style drift check (PKG-05) | Matches repo's existing stdlib-only tooling constraint (no PyYAML, no requests) |
| `git` | 2.53.0 [VERIFIED: `git --version` run in this environment] | Commit sequencing across the local→github checkpoint boundary (D-01) | Already the repo's only VCS dependency |
| `gh` CLI | 2.89.0 [VERIFIED: `gh --version` run in this environment] | Producing the exact `gh repo edit --add-topic ...` command list for the user to run manually (D-11) — NOT executed automatically | Standard GitHub CLI; already assumed available per D-11's phrasing |

### Supporting
| Tool | Purpose | When to Use |
|------|---------|-------------|
| `claude plugin details <name>` | Prints component inventory (Skills count + names, Agents, Hooks, MCP, LSP) and token-cost estimate | Primary scripted evidence for D-02's activation/discovery smoke test — confirms both skills were discovered post-install without needing a prompt-based test |
| `claude plugin list --json` | Machine-readable listing of installed plugins with version/source/enable-status | Secondary/cross-check evidence artifact; also useful for `--available` (marketplace-listed but not-yet-installed plugins) |
| `claude --debug` | Verbose plugin-loading trace (manifest errors, skill/agent/hook registration) | Diagnostic fallback if `claude plugin details` shows 0 skills or an install error — surfaces the root cause before falling back to the symlink workaround |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `claude plugin details`/`plugin list --json` as smoke-test evidence | A scripted prompt sent to a live Claude Code session asking it to use each skill | Prompt-based testing is closer to true end-user experience but is non-deterministic (model behavior varies) and harder to capture as a clean reproducible transcript; the CLI inventory commands are deterministic and exactly what D-02 asks for ("scripted + captured transcript") |
| Extending `scripts/lint_skill_md.py` in place | A brand-new standalone `scripts/check_version_drift.py` | Both are valid (Claude's discretion, D-04); a new file keeps lint_skill_md.py's FMT-0x scope clean, but reusing the same LintResult dataclass/soft-append pattern keeps the tooling style consistent either way |

**Installation:** None — no new packages. If Claude's discretion favors a new script, it is created directly in `scripts/` (stdlib only, no `pip install`).

**Version verification:** `claude --version` returns `2.1.201 (Claude Code)` in this environment (confirmed 2026-07-27). No package registry lookup applies — the CLI is a locally installed binary, not a project dependency declared in a manifest.

## Package Legitimacy Audit

**Not applicable this phase.** No new npm/PyPI/crates packages are installed. All work is repo-local Markdown/JSON edits and stdlib-only Python tooling extension (consistent with `.claude/CLAUDE.md`'s "no heavy runtime dependencies" constraint). The Package Legitimacy Gate protocol is skipped per its own scope condition (no external packages introduced).

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────┐
                    │   Local filesystem (repo)    │
                    │  .claude-plugin/plugin.json  │──(version=1.0.0, canonical)
                    │  .claude-plugin/marketplace.json │
                    └───────────────┬───────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │  CHECKPOINT 1 (Phase 5 gate,   │
                    │  now — D-01):                  │
                    │  claude plugin validate .      │
                    │  claude plugin marketplace     │
                    │    add . --scope local          │
                    │  [TEMP: rewrite plugin entry's  │
                    │   source -> "." on disk only,   │
                    │   never committed]              │
                    │  claude plugin install          │
                    │    owasp-security-skills@…       │
                    │    --scope local                │
                    │  claude plugin details …         │
                    │  claude plugin list --json       │
                    │  [REVERT temp source edit]       │
                    └───────────────┬───────────────┘
                                    │  capture stdout → phase artifact
                                    ▼
                    ┌───────────────────────────────┐
                    │  git commit + push (all Phase 5│
                    │  polish lands; remote catches  │
                    │  up to local HEAD)              │
                    └───────────────┬───────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │  CHECKPOINT 2 (ship step,       │
                    │  after push — D-01):            │
                    │  claude plugin marketplace add   │
                    │    mfkocalar/OWASP-Security-Skills│
                    │  claude plugin install           │
                    │    owasp-security-skills@…        │
                    │  claude plugin details …          │
                    └───────────────────────────────┘
```

### Recommended Project Structure
No new directories. Edits land in-place:
```
.claude-plugin/
├── plugin.json          # version 0.1.0 -> 1.0.0; keywords extended (ADPT-04)
└── marketplace.json      # add plugin-entry category + keywords/tags (ADPT-04)
LICENSE                   # new file (ADPT-01)
README.md                 # full refresh (ADPT-02)
CONTRIBUTING.md           # extend with maintenance/versioning story (ADPT-03); also fix its own stale content
scripts/
└── check_version_drift.py  # new OR extend lint_skill_md.py (Claude's discretion, D-04)
skills/*/assets/examples/*  # secret-literal normalization (QUAL-03)
DEPLOYMENT.md, TESTING.md    # salvage useful bits -> README/CONTRIBUTING, then delete (D-09)
docs/SKILL-STRUCTURE.md      # worked-example tree is stale (see Pitfall below) — QUAL-01 consistency sweep candidate
```

### Pattern 1: Two-checkpoint install validation with a reversible local-source override
**What:** A phase-gate validation that runs entirely against local disk content (not the stale GitHub remote), by temporarily pointing the marketplace's plugin `source` at a relative path, then reverting before commit.
**When to use:** Any time a repo's `marketplace.json` plugin entries use a `github`/`url`/`npm` source (i.e., the "ship" source type) and a local-content check is still needed before push.
**Example (scripted, non-interactive CLI — captures cleanly to a transcript file):**
```bash
# Source: code.claude.com/docs/en/plugin-marketplaces (fetched 2026-07-27) +
# code.claude.com/docs/en/plugins-reference (fetched 2026-07-27)

# 1. Schema/frontmatter validation (safe — no source rewrite needed)
claude plugin validate . | tee /tmp/phase5-validate.log

# 2. TEMPORARY local-source override for the true content test.
#    Do NOT commit this edit — revert it before any git add/commit.
#    (jq or a one-line python3 -c edit works; keep the diff minimal)
python3 -c "
import json, pathlib
p = pathlib.Path('.claude-plugin/marketplace.json')
d = json.loads(p.read_text())
d['plugins'][0]['_original_source'] = d['plugins'][0]['source']
d['plugins'][0]['source'] = '.'
p.write_text(json.dumps(d, indent=2) + '\n')
"

claude plugin marketplace add . --scope local | tee -a /tmp/phase5-validate.log
claude plugin install owasp-security-skills@owasp-security-skills --scope local \
  | tee -a /tmp/phase5-validate.log
claude plugin details owasp-security-skills@owasp-security-skills \
  | tee -a /tmp/phase5-validate.log
claude plugin list --json | tee -a /tmp/phase5-validate.log

# 3. REVERT the temporary source edit before touching git.
python3 -c "
import json, pathlib
p = pathlib.Path('.claude-plugin/marketplace.json')
d = json.loads(p.read_text())
d['plugins'][0]['source'] = d['plugins'][0].pop('_original_source')
p.write_text(json.dumps(d, indent=2) + '\n')
"
git diff --stat .claude-plugin/marketplace.json   # MUST show no diff
```

### Pattern 2: `claude plugin details` as deterministic activation-discovery evidence (D-02)
**What:** Use the CLI's own component-inventory command instead of a prompt-based "ask Claude to use the skill" test.
**When to use:** Whenever the smoke test needs to be scripted and reproducible rather than dependent on model behavior.
**Example:**
```bash
# Source: code.claude.com/docs/en/plugins-reference#plugin-details (fetched 2026-07-27)
claude plugin details owasp-security-skills@owasp-security-skills
# Expected shape (illustrative — capture the REAL output as the artifact):
#   owasp-security-skills 1.0.0
#     Source: owasp-security-skills@owasp-security-skills
#   Component inventory
#     Skills (2)  owasp-security-audit, secure-coding-practices
#     Agents (0)
#     Hooks (0)
#     MCP servers (0)
#     LSP servers (0)
```
If the Skills count is not `2` with both names present, treat it as a Checkpoint-1 failure and consult `claude --debug` before falling back to the symlink workaround from `anthropics/claude-code#54967`.

### Anti-Patterns to Avoid
- **Assuming a "local marketplace add" installs local content:** it only re-reads the local `marketplace.json` catalog file. If the plugin entry's `source` is still `github`, install pulls from the remote regardless of how the marketplace was added. Always check what `source` type the plugin entry actually uses before trusting a "local" test.
- **Leaving the temporary source override uncommitted-but-dirty:** if Checkpoint 1's on-disk edit to `marketplace.json` is not reverted before the next `git commit`, the shipped manifest would (temporarily or permanently) point at a relative path instead of the intended `github` source, breaking every real user's install.
- **Treating `claude plugin validate` success as proof of runtime activation:** validate only checks JSON schema + frontmatter syntax. It does not confirm skills were actually discovered/loaded — that requires the install + `plugin details` step.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Plugin manifest / marketplace JSON schema validation | A custom JSON-schema checker for `plugin.json`/`marketplace.json` | `claude plugin validate <path>` (with `--strict` to catch unrecognized-field typos) | It is the authoritative, first-party validator; a hand-rolled schema check would drift from the real (evolving) schema |
| Confirming skills were discovered after install | A prompt-engineering "please confirm you have skill X" test | `claude plugin details <name>` / `claude plugin list --json` | Deterministic, scriptable, and exactly matches what Claude Code itself resolved — no model-behavior variance |
| Version-drift detection | A new general-purpose config-linting framework | A small, targeted stdlib script (extending `lint_skill_md.py`'s LintResult pattern) that greps for version-looking strings across README/docs and asserts they equal `plugin.json.version` | The problem is narrow (one field, few files); a framework would be over-engineering for a Markdown-first, dependency-free repo |

**Key insight:** every capability this phase touches already has a first-party, authoritative tool (the `claude` CLI itself for packaging; the existing `owasp-urls.json` files for citations). The work is almost entirely "point the existing tool/data at the right target and reconcile the prose," not building new verification machinery.

## Runtime State Inventory

This phase is not a rename/refactor, but it does delete two files with surviving cross-references and bump a version string read by an external tool (Claude Code's plugin cache), so a lightweight inventory is warranted.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — this repo has no database/datastore. | None. |
| Live service config | None found in a UI/DB outside git. `marketplace.json`'s plugin entry currently points at a `github` source that is 116 commits behind local `HEAD` (`git status -sb` shows `ahead 116`) — this is git-tracked state, not out-of-git config, but it means "the github source" is currently stale content until Phase 5's commits are pushed. | Push after Phase 5 lands, before Checkpoint 2 (ship-time github install), per D-01. |
| OS-registered state | `claude plugin install` (when actually pulling local content per Pattern 1 above) writes to `~/.claude/plugins/cache` and, with `--scope local`, to `.claude/settings.local.json` (not currently gitignored — see Pitfall below). | Uninstall/clean up test-scope plugin state after the Checkpoint-1 evidence capture; add `.claude/settings.local.json` to `.gitignore` if the test run creates it. |
| Secrets/env vars | The example "secrets" being normalized (QUAL-03) are all fake/illustrative strings inside example code, never real credentials or `.env` values. No real secret exists in this repo. | Code edit only (string literal replacement in example files) — no rotation, no real-secret handling. |
| Build artifacts | `scripts/__pycache__/`, `skills/*/scripts/__pycache__/`, `skills/*/assets/examples/__pycache__/` exist on disk but are `.gitignore`d (`__pycache__/`, `*.pyc` already present per Phase 2's fix). `~/.claude/plugins/cache/` (outside repo) will gain a new versioned copy on every `claude plugin install` test run; the CLI auto-orphans old versions after 14 days [CITED: code.claude.com/docs/en/plugin-marketplaces, fetched 2026-07-27]. | None required in-repo (already gitignored); no action needed on the external cache (self-cleaning). |

**Nothing found in category:** Stored data — verified by inspection; this repo has no database or datastore of any kind.

## Common Pitfalls

### Pitfall 1: Local marketplace add ≠ local content install
**What goes wrong:** The team runs `claude plugin marketplace add .` and `claude plugin install owasp-security-skills@owasp-security-skills`, believes they tested local (possibly unpushed) content, but the plugin entry's `source` is `{"source": "github", "repo": "mfkocalar/OWASP-Security-Skills"}` — so the install actually clones from GitHub's default branch, which is 116 commits behind.
**Why it happens:** "Marketplace source" (where the catalog file comes from) and "plugin source" (where the plugin's files come from) are two independent fields, easy to conflate. [VERIFIED: code.claude.com/docs/en/plugin-marketplaces §"Marketplace sources vs plugin sources", fetched 2026-07-27]
**How to avoid:** Use Pattern 1 above — temporarily override the plugin entry's `source` to a relative path for the Checkpoint-1 test only, and revert before any commit.
**Warning signs:** `claude plugin details` after "local" install shows content/version that doesn't match what's on disk (e.g., missing a file you just added locally).

### Pitfall 2: Unconfirmed "0 skills" regression at the exact installed version
**What goes wrong:** Assuming either (a) the historically-documented "0 skills" bug still applies and building unnecessary workaround complexity into every install step, or (b) assuming it's fixed and being surprised by a silent 0-skills install.
**Why it happens:** `anthropics/claude-code#54967` was reported at CLI v2.1.123 and closed as a duplicate of an earlier issue; no changelog entry or maintainer comment confirming a fix was found by v2.1.201 (this environment's version, which postdates the report).
**How to avoid:** Run the real Checkpoint-1 sequence and read the actual `claude plugin details` output. If skills count is 0, apply the documented workaround (pre-create `~/.claude/plugins/marketplaces/<name>` as a symlink to the local repo path before `add`) and note in phase artifacts whether the regression reproduced at v2.1.201.
**Warning signs:** `claude plugin install` reports success but `claude plugin details`/`claude plugin list --json` shows `Skills (0)`.

### Pitfall 3: `.claude/settings.local.json` created by `--scope local` testing is not gitignored
**What goes wrong:** Running the Checkpoint-1 sequence with `--scope local` (recommended, to avoid touching the checked-in `.claude/settings.json` or the global `~/.claude/settings.json`) writes `enabledPlugins`/marketplace-add state into `.claude/settings.local.json` at the repo root. This file is not currently covered by `.gitignore` (only `.claude/skills/` is listed) and could get accidentally committed as test-scope noise.
**Why it happens:** The repo's `.gitignore` predates plugin-scope testing and was written for the symlink-install era.
**How to avoid:** Add `.claude/settings.local.json` to `.gitignore` in the same commit that performs the Checkpoint-1 test (mirrors Phase 2's precedent of fixing an untracked-file gap discovered during a verification step — see STATE.md Phase 02 decision log), or explicitly clean up the file after capturing evidence.
**Warning signs:** `git status` shows an untracked `.claude/settings.local.json` after running the validation sequence.

### Pitfall 4: `docs/SKILL-STRUCTURE.md`'s "worked example" tree has drifted from the real repo
**What goes wrong:** The locked convention doc's own worked-example section (lines ~85-124) still shows `references/llm-agentic.md` (one combined file) and an `owasp-security-audit.md` supplementary doc — both of which Phase 4 changed (split into `llm.md`+`agentic.md`; deleted the duplicate `.md`). A reader following this doc as "the authority on the target layout" (per this phase's own canonical_refs) would be pointed at stale filenames.
**Why it happens:** The doc was locked in Phase 1 and not revisited when Phase 4 executed its own approved restructuring.
**How to avoid:** Since QUAL-01 is explicitly framed as a cross-surface consistency sweep ("confirm completeness and consistency across README ↔ references ↔ manifests"), extend that sweep to include this doc's worked example, even though it isn't named in canonical_refs as an edit target. This is a fast, low-risk fix (two filenames + one deleted line) that closes a real drift the phase would otherwise miss.
**Warning signs:** `find skills -name '*.md' -o -name '*.json' | sort` vs. the tree printed in `docs/SKILL-STRUCTURE.md` disagree.

### Pitfall 5: Password-like literals outside the API-key convention (CONTEXT.md's D-10 examples are API-key-only)
**What goes wrong:** D-10's explicit offender list covers only `sk-...` API-key literals. A repo-wide grep also found plausible-looking password literals: `database_password: "MySecurePassword123!"` (k8s-rbac.yaml), `DB_PASSWORD = "MySecurePassword123"` (SCP vulnerable-examples.py), `const DB_PASSWORD = "MyDatabasePassword123"` and `password: 'admin123'` (SCP vulnerable-examples.js). These are exactly the kind of "looks like a real, valid secret" value QUAL-01's success criterion ("nothing that looks like a real, valid secret") targets, and CONTEXT.md's own endorsed exemplar list includes `PLACEHOLDER_PASSWORD` — but the plan needs to decide explicitly whether to extend D-10's literal-by-literal normalization to these password strings too, since they were not enumerated in CONTEXT.md's "current offenders" list.
**Why it happens:** CONTEXT.md's offender enumeration focused on the API-key pattern that inspired the whole convention; the grep for this research covered a broader credential-literal regex and surfaced adjacent cases in the same files.
**How to avoid:** Flag this explicitly for planner/user confirmation rather than silently in-scoping or silently ignoring it — it is a natural extension of D-10's intent but technically outside its literal offender list.
**Warning signs:** A secret scanner (GitGuardian, GitHub push protection) flags a password literal in an example file even after the API-key normalization lands.

## Code Examples

### Non-interactive CLI validate/install/detail sequence (all commands live-verified against current docs)
```bash
# Source: code.claude.com/docs/en/plugin-marketplaces §"Manage marketplaces from the CLI"
# and code.claude.com/docs/en/plugins-reference §"CLI commands reference" (both fetched 2026-07-27)

claude plugin validate .                       # schema + frontmatter check (marketplace dir)
claude plugin validate ./                       # equivalent; validates marketplace.json + all local-source plugin.json entries
claude plugin marketplace add . --scope local   # register the local directory as a marketplace, local scope only
claude plugin marketplace list --json           # confirm registration, inspect installLocation
claude plugin install owasp-security-skills@owasp-security-skills --scope local
claude plugin details owasp-security-skills@owasp-security-skills   # component inventory (Skills count/names)
claude plugin list --json                       # cross-check: version/source/enable status
claude --debug                                  # only if details/list show an unexpected 0-skills or error state
```

### marketplace.json plugin-entry schema (ADPT-04 target fields)
```json
// Source: code.claude.com/docs/en/plugin-marketplaces §"Plugin entries" (fetched 2026-07-27)
{
  "name": "owasp-security-skills",
  "source": { "source": "github", "repo": "mfkocalar/OWASP-Security-Skills" },
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "category": "security",
  "keywords": ["security", "owasp", "top-10", "asvs", "masvs", "secure-coding"],
  "tags": ["security-audit", "code-review", "compliance"]
}
```
Note: `category` and `tags` are **marketplace-entry-only** fields — they do not exist in the `plugin.json` manifest schema. `keywords` is valid in both places (plugin.json's own metadata field, and optionally repeated/extended on the marketplace entry). [VERIFIED: code.claude.com/docs/en/plugins-reference §"Metadata fields" (no `category`/`tags` field listed) vs. code.claude.com/docs/en/plugin-marketplaces §"Plugin entries" (`category`, `tags` listed as "marketplace-specific fields"), both fetched 2026-07-27]

## State of the Art

| Old Approach (Phase 1-era assumption) | Current Approach (verified 2026-07-27, CLI v2.1.201) | When Changed | Impact |
|--------------------------------------|--------------------------------------------------------|--------------|--------|
| Manual prompt-based activation testing ("paste an example, see if the skill responds") | `claude plugin details <name>` / `claude plugin list --json` give a deterministic, scriptable component inventory | Documented as of the current CLI reference; exact version this landed is not stated in the docs, but it is present and stable at v2.1.201 | D-02's "scripted + captured transcript" requirement can be satisfied with a CLI command, not a model-behavior-dependent prompt test |
| `keywords`-only discoverability metadata assumption | `marketplace.json` plugin entries additionally support `category`, `tags`, `relevance` (org-only), and `defaultEnabled` | `category`/`tags`: general availability; `relevance` requires v2.1.152+; `defaultEnabled` requires v2.1.154+ (both satisfied by v2.1.201) | ADPT-04 can set a real `category` field, not just extend `keywords` |
| Renaming/removing a marketplace plugin entry with no migration path | `renames` top-level field maps old name -> new name or `null`, requires v2.1.193+ | v2.1.193 | Not directly used this phase (no rename planned), but relevant if the plugin's `name` ever changes post-1.0.0 |

**Deprecated/outdated:** None directly deprecated by this phase's scope; the repo's own `install.sh`/symlink-based install path predates the plugin/marketplace mechanism entirely and its disposition (keep as documented alternative vs. retire) is explicitly Claude's discretion.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The "0 skills" regression (`#54967`) status at CLI v2.1.201 specifically is unconfirmed — the issue was reported at v2.1.123 and closed as a duplicate with no visible fix-version comment. | Common Pitfalls #2, Summary | If actually still present, Checkpoint 1 must apply the symlink workaround; if actually fixed, no action needed either way — but the plan should not assume the answer without running the real command sequence and reading the output |
| A2 | Windows path-collapse (`#52435`) and clone-rename-race (`#58241`) issues remain open/unconfirmed-fixed at any version, but are not applicable to this (macOS/Darwin) execution environment. | Summary | Low risk this phase (macOS-only execution), but if the repo's README/DEPLOYMENT-salvage content promises Windows support without a caveat, a Windows user could hit an EPERM install failure the docs don't warn about |
| A3 | Extending D-10's secret-placeholder normalization to the password-like literals found in Pitfall #5 is a reasonable in-scope extension of QUAL-03's success criterion, even though CONTEXT.md's offender list only names API-key literals. | Common Pitfalls #5 | If out of scope, those password literals remain as a residual credibility gap the phase claims to have closed but did not fully close |

## Open Questions

1. **Does the "0 skills" local-marketplace regression reproduce at CLI v2.1.201?**
   - What we know: it was reported and reproduced at v2.1.123; closed as a duplicate of an earlier tracked issue; no fix-version confirmation found via WebSearch/WebFetch.
   - What's unclear: whether the underlying symlink-preservation logic changed between v2.1.123 and v2.1.201 (multiple unrelated fixes shipped in that range per the docs' inline version-gated notes, but none specifically reference this bug).
   - Recommendation: Run the actual Checkpoint-1 sequence during execution and record the real `claude plugin details` skill count as the authoritative answer; don't gate planning on a guess.

2. **Should the password-like literals (Pitfall #5) be normalized in this phase or flagged as a v1.0.1 follow-up?**
   - What we know: they satisfy QUAL-03's plain-language success criterion ("nothing that looks like a real, valid secret") just as much as the API-key literals do; `PLACEHOLDER_PASSWORD` is already an endorsed exemplar in CONTEXT.md.
   - What's unclear: whether the user's D-10 offender enumeration was meant to be exhaustive (closed list) or illustrative (open list, "current offenders to normalize include...").
   - Recommendation: Default to including them (low cost, same mechanical edit, directly serves the stated success criterion), but surface this explicitly at plan-review/discuss time rather than silently expanding scope.

3. **Should `docs/SKILL-STRUCTURE.md`'s stale worked-example tree (Pitfall #4) be fixed in this phase?**
   - What we know: it's a two-line drift (filename split, one deleted duplicate file) in a doc explicitly named as "the authority on the target layout" in this phase's own canonical_refs.
   - What's unclear: whether touching a "locked convention" doc from Phase 1 needs separate sign-off versus being folded into this phase's general consistency sweep.
   - Recommendation: Fix it as a minimal, mechanical correction (matches QUAL-01's "confirm completeness and consistency" framing) rather than leaving a known-stale canonical doc uncorrected at ship time.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `claude` CLI | PKG-04 (validate/install/smoke-test) | ✓ | 2.1.201 [VERIFIED: `claude --version` run 2026-07-27] | — (no fallback; this phase's core gate requires it) |
| `python3` | PKG-05 drift-check script, QUAL-03 literal edits | ✓ | 3.14.6 [VERIFIED] | — |
| `git` | Commit sequencing, checkpoint ordering (D-01) | ✓ | 2.53.0 [VERIFIED] | — |
| `gh` CLI | Producing (not executing) the `gh repo edit --add-topic` command list (D-11) | ✓ | 2.89.0 [VERIFIED] | Commands can be handed to the user as plain text even without `gh` installed locally, since they are never auto-executed |
| `node` | Not required by this phase (no JS example changes need runtime execution; `node --check` syntax-only checks were used historically in TESTING.md, now being retired) | ✓ | v26.3.1 [VERIFIED] | N/A |
| Internet access to `code.claude.com` / GitHub (for the ship-time Checkpoint 2 install) | PKG-04 Checkpoint 2 (github-source install, at ship, after push) | Not tested this session (out of scope for Phase 5 research; assumed available at ship time) | — | If unavailable at ship time, Checkpoint 2 is deferred until connectivity is restored — it is explicitly a separate, later step per D-01 |

**Missing dependencies with no fallback:** None — every tool this phase's gate depends on is confirmed present.

**Missing dependencies with fallback:** None currently missing.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | None (no pytest/jest/etc.) — this repo uses ad-hoc `python3 -m py_compile` / `node --check` syntax checks (documented in the now-being-retired TESTING.md) plus the custom `scripts/lint_skill_md.py` linter |
| Config file | none |
| Quick run command | `python3 scripts/lint_skill_md.py skills --format text` |
| Full suite command | `python3 scripts/lint_skill_md.py skills --format text && claude plugin validate .` (proposed — combines existing lint with the new packaging gate) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PKG-04 | Plugin validates, installs, both skills discoverable | integration (CLI) | `claude plugin validate . && claude plugin details owasp-security-skills@owasp-security-skills` | ❌ Wave 0 — no existing script wraps this; plan should add a small shell/Python wrapper that captures output to a phase artifact |
| PKG-05 | No version-string drift across manifest/README/skills | unit (stdlib script) | `python3 scripts/check_version_drift.py` (proposed, does not yet exist) | ❌ Wave 0 |
| QUAL-01 | Every OWASP ID cites URL + retrieval date, consistently | manual/documentation review (not automatable — requires human judgment on prose accuracy) | N/A — cross-reference `owasp-urls.json` against README/SKILL.md/docs by inspection | N/A (manual-only, justified: citation *accuracy* is a semantic judgment, not a syntax check) |
| QUAL-02 | Coverage matrix present and honest | manual/documentation review | N/A | N/A (manual-only, justified) |
| QUAL-03 | No plausible-looking real secrets in examples | unit (regex script) | `grep -rnE "sk-[A-Za-z0-9]{10,}[^-]|password\s*=\s*['\"][A-Za-z][A-Za-z0-9]{6,}['\"]" skills/*/assets/examples` (ad-hoc; could be formalized as a small stdlib check) | ❌ Wave 0 (currently a manual grep, not a committed script) |
| ADPT-01 | LICENSE file exists, matches plugin.json | unit (file existence + string check) | `test -f LICENSE && grep -q "MIT" LICENSE` | ❌ Wave 0 |
| ADPT-02/03 | README/CONTRIBUTING refreshed, no dead links to deleted files | unit (grep) | `! grep -rl "owasp-comprehensive-security-skills.md\|owasp-css.instructions.md" README.md CONTRIBUTING.md` | ❌ Wave 0 |
| ADPT-04 | plugin.json/marketplace.json carry discoverability fields | unit (JSON field presence) | `python3 -c "import json; d=json.load(open('.claude-plugin/marketplace.json')); assert 'category' in d['plugins'][0]"` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** the relevant grep/JSON-field check for that task's specific requirement (fast, <5s each)
- **Per wave merge:** `python3 scripts/lint_skill_md.py skills --format text` (existing) + `claude plugin validate .` (new)
- **Phase gate:** Full Checkpoint-1 sequence (Pattern 1/2 above) captured to a phase artifact, plus every unit-level grep/JSON check green, before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] A small wrapper script or documented command block that runs the full Checkpoint-1 sequence and tees output to a phase artifact file (satisfies D-02's "captured transcript" requirement)
- [ ] `scripts/check_version_drift.py` (or an extension of `lint_skill_md.py`) — covers PKG-05
- [ ] No pytest/jest framework install needed — this repo intentionally has none, consistent with its "no heavy runtime dependencies" constraint; the Nyquist gaps above are all shell/stdlib-script-shaped, not framework-shaped

## Security Domain

### Applicable ASVS Categories

This is a packaging/documentation phase with essentially no application code surface (no auth, no sessions, no network-facing endpoints are introduced or modified). Most ASVS categories are not applicable; the two below are the only ones with real bearing.

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | No | No authentication code is touched this phase |
| V3 Session Management | No | N/A |
| V4 Access Control | No | N/A |
| V5 Input Validation | Marginal | `claude plugin validate` itself performs the only "input validation" relevant here (validating repo-authored JSON/YAML against Claude Code's schema) — no custom parsing is written |
| V6 Cryptography | No | The example-secret placeholder work (QUAL-03) is about *illustrative* strings, not real cryptographic material — no hand-rolled crypto is introduced |
| V14 Configuration | Yes | `plugin.json`/`marketplace.json` are configuration manifests; the standard control is "single source of truth, no drift" (exactly what D-04/PKG-05 already mandates) — no additional control needed beyond what's already locked |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Example code that looks like a real, exfiltratable secret gets accidentally treated as real by a downstream scanner or copy-pasted into a real config by a careless reader | Information Disclosure (indirect — a documentation-credibility risk, not a code vulnerability) | D-10's self-labeling placeholder convention (`sk-EXAMPLE-not-a-real-key`, `PLACEHOLDER_PASSWORD`) — structurally recognizable as fake to both humans and automated secret scanners |
| A public plugin manifest overclaims capability (e.g., a CI/coverage badge with no CI) | Repudiation / trust erosion (not a STRIDE-technical threat, but the exact "credibility" risk this phase's goal names) | D-08's static, honest-only badge policy |
| Marketplace/plugin source confusion leading to installing stale or wrong content silently | Tampering (installing unintended content without the user noticing) | Explicit two-checkpoint sequencing (D-01) + the Pattern 1 revert discipline documented above, so the shipped `marketplace.json` never silently retains a test-time source override |

## Sources

### Primary (HIGH confidence)
- code.claude.com/docs/en/plugin-marketplaces — fetched 2026-07-27 (full marketplace.json schema, plugin sources, CLI marketplace subcommands, validation/troubleshooting)
- code.claude.com/docs/en/plugins-reference — fetched 2026-07-27 (plugin.json schema, CLI plugin subcommands including `details`/`list`/`install`, caching/symlink behavior, debugging tools)
- `claude --version` executed directly in this environment — 2026-07-27 (`2.1.201 (Claude Code)`)
- `python3 --version`, `node --version`, `git --version`, `gh --version` executed directly in this environment — 2026-07-27
- Direct file reads: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `README.md`, `DEPLOYMENT.md`, `TESTING.md`, `CONTRIBUTING.md`, `install.sh`, `scripts/lint_skill_md.py`, `docs/SKILL-STRUCTURE.md`, both `owasp-urls.json` files, both `SKILL.md` files
- `git status -sb`, `git log origin/main..HEAD` executed directly — confirmed 116 commits ahead of `origin/main` (2026-07-27)
- Repo-wide grep for secret-literal offenders and dead cross-references to deleted legacy files — executed directly, 2026-07-27

### Secondary (MEDIUM confidence)
- github.com/anthropics/claude-code/issues/54967 ("0 skills" local marketplace bug) — fetched 2026-07-27; reported v2.1.123, closed as duplicate, no fix-version confirmation
- github.com/anthropics/claude-code/issues/52435 (Windows path collapse) — fetched 2026-07-27; reported v2.1.117, closed as not-planned/stale
- github.com/anthropics/claude-code/issues/58241 (Windows EPERM rename race) — fetched 2026-07-27; reported v2.1.139, closed as duplicate

### Tertiary (LOW confidence)
- None used as a basis for any recommendation in this document — all WebSearch-only leads were cross-verified against either the official docs or a directly-fetched GitHub issue before being cited.

## Metadata

**Confidence breakdown:**
- Standard stack / CLI mechanics: HIGH — verified live against official docs + direct version checks in this exact environment
- Regression status (0-skills, Windows issues): MEDIUM — issues located and read directly, but no maintainer statement confirms fixed/unfixed at the exact installed version; plan must verify empirically
- Repo-local facts (stale README/CONTRIBUTING/DEPLOYMENT/TESTING content, secret-literal offenders, citation-source completeness): HIGH — confirmed by direct file reads and grep, not inference

**Research date:** 2026-07-27
**Valid until:** Claude Code CLI mechanics: ~14 days (fast-moving — this is an actively-developed CLI with version-gated behavior changes noted throughout its own docs); repo-local facts: valid until the next commit touching these files
