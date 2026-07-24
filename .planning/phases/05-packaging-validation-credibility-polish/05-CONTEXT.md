# Phase 5: Packaging Validation & Credibility Polish - Context

**Gathered:** 2026-07-24
**Status:** Ready for planning

<domain>
## Phase Boundary

A new user can discover, install, and trust the plugin end-to-end on a clean
environment. This is the final public-release phase. Covers **PKG-04, PKG-05,
QUAL-01, QUAL-02, QUAL-03, ADPT-01, ADPT-02, ADPT-03, ADPT-04**.

**In scope:**
- PKG-04: end-to-end install validation (`claude plugin validate`, marketplace
  add, install, activation smoke test) — via a **local marketplace source now**
  as the phase gate, with the true **github-source** install run at ship.
- PKG-05: a single canonical version source (`plugin.json`) driving every version
  string, with a drift check.
- QUAL-01: final sweep confirming every OWASP version/edition/category-ID claim
  cites an official source URL + retrieval date (re-verify Phase 2–3 hardening is
  complete and consistent; **not** a re-verification of the editions themselves).
- QUAL-02: honest coverage matrix (covered vs. intentionally-not-covered).
- QUAL-03: self-labeling placeholder convention for example secrets.
- ADPT-01: add the missing LICENSE.
- ADPT-02: README refresh (fix stale content, matrix, badges, install/usage).
- ADPT-03: CONTRIBUTING + maintenance/versioning/update story.
- ADPT-04: discoverability metadata (manifests now, GitHub topics documented).
- Doc cleanup: retire the stale `DEPLOYMENT.md` / `TESTING.md` (Phase 1 carry-over).

**Out of scope (deferred / owned elsewhere):**
- Authoring new example files for uncovered 2025 categories (A03/A04/A06/A08/A10)
  — v2 / future example-coverage phase; the matrix DISCLOSES the gap, does not fill it.
- Re-verifying OWASP editions/IDs (Phases 2–3 own that; QUAL-01 here is a
  consistency/citation-completeness sweep only).
- Any CI/coverage/eval tooling (v2 EVAL-01/02/03).
- Adopting the Kubernetes Top 10 2025 draft (v2 EXP-02).

</domain>

<decisions>
## Implementation Decisions

### Install validation depth (PKG-04)
- **D-01:** **Two-checkpoint validation — local now, github at ship.** Run
  `claude plugin validate` + add a **local marketplace source** (the repo
  directory) + install + smoke test **in this environment now** as the Phase 5
  gate, capturing real command output. Defer the true **github-source**
  marketplace add + install to the ship/release step, after all Phase 5 polish
  commits land and are pushed (the GitHub remote is currently behind local HEAD,
  so a github install today would pull stale content). `claude` CLI v2.1.201 is
  present, so the local validation is genuinely runnable here.
  (Chosen over "local only + document github" and "push first then github".)
- **D-02:** **Activation smoke test = scripted + captured transcript.** A small,
  repeatable check (script or documented command sequence, stdlib-only to match
  repo tooling style) that confirms **both** skills are discoverable/loadable
  post-install, with the actual output captured into the phase artifacts as
  reproducible evidence. (Chosen over manual prompt walkthrough and
  structural-only verification.)
- **Re-check before relying on install mechanics:** per STATE.md
  §Blockers/Concerns, verify current Claude Code (v2.1.201) status for documented
  packaging regressions (symlink-to-cache, Windows path collapse, marketplace
  "0 skills" bug) rather than assuming they still apply.

### Version & release identity (PKG-05, ADPT-01)
- **D-03:** **Ship at 1.0.0.** First credible public release of the modernized
  plugin. Phase 1 deliberately reset to 0.1.0 to break the legacy 1.1.0 lineage,
  so 1.0.0 is a fresh, honest v1 — not a continuation of the old versioning.
- **D-04:** **`plugin.json` `version` is the single canonical source (PKG-05).**
  README/docs reference it without hardcoding a competing copy where avoidable; a
  tiny stdlib check (extend `scripts/` tooling) asserts no conflicting version
  string exists elsewhere. Skills do **not** carry their own version — the
  `SKILL.md` frontmatter spec has no version field. Consistent with Phase 1's
  "marketplace.json carries no version key; plugin.json is authoritative."
- **D-05:** **MIT LICENSE at repo root, holder = "Security Education Community"
  (matches `plugin.json` author), current year.** Zero new claims — aligns with
  the already-declared `plugin.json` `"license": "MIT"`. (Chosen over a different
  holder and over Apache-2.0.)

### README & honest coverage matrix (ADPT-02, QUAL-02, QUAL-01)
- **D-06:** **Two-column coverage matrix + "What this is NOT" note.** One matrix
  row per standard with an explicit **"Edition covered"** column AND a
  **"Scope / caveat"** column stating limits inline (K8s **2022** not the
  2025 draft; ASVS **4.0.3-body numbering** under a verified 5.0.0 current
  edition; LLM/Agentic as two separate standards). Plus a short **"What this is
  NOT"** section: guidance/reference — **not a runtime scanner**; and example
  files do **not** yet cover every 2025 category (A03 Supply Chain, A04 Insecure
  Design, A06 Vulnerable & Outdated Components, A08 Software & Data Integrity,
  A10 Exceptional Conditions). Caveats must be impossible to miss.
- **D-07:** **Every matrix/edition/ID claim cites an official source URL +
  retrieval date (QUAL-01).** Source the citations from the already-hardened
  per-skill `owasp-urls.json` files (Phases 2–3) — do not re-derive or
  re-verify editions; confirm completeness and consistency across README ↔
  references ↔ manifests.
- **D-08:** **Static, honest badge set only.** License (MIT), version (1.0.0),
  "Claude Code plugin", and OWASP-aligned — static shields reflecting true facts.
  **No** CI/coverage/build badges (there is no CI pipeline; deferred to v2
  EVAL-01). Badges must never misrepresent capability.
- **README is currently stale** and must be corrected: it links the deleted
  `owasp-comprehensive-security-skills.md`, says "six OWASP standards", "ASVS 5.0",
  and "SCP Quick Reference Guide" — all superseded by Phase 3–4 reframes.

### Legacy docs & example secrets (QUAL-03, ADPT-03)
- **D-09:** **Fold useful bits, then delete `DEPLOYMENT.md` + `TESTING.md`.**
  Salvage anything still accurate into README (install/usage) and CONTIBUTING
  (the maintenance/versioning/update story — this also satisfies **ADPT-03**),
  then delete both stale files (they still reference the removed root `skill.json`
  / `examples/` and describe the pre-plugin symlink-install era). Matches Phase 4's
  "retire superseded files" pattern. (Chosen over full rewrite and over the
  split rewrite-TESTING/delete-DEPLOYMENT option.)
- **D-10:** **Self-labeling placeholder convention for example secrets (QUAL-03).**
  Standardize on obviously-fake, self-documenting values across ALL examples:
  e.g. `sk-EXAMPLE-not-a-real-key`, `sk-your-api-key-here`, `PLACEHOLDER_PASSWORD`.
  Structurally recognizable enough to still teach the hardcoded-secret
  anti-pattern, but unmistakably fake to a human AND to secret scanners (GitHub
  push protection, GitGuardian). Document the convention once (CONTRIBUTING or a
  comment banner). Current offenders to normalize include `sk-abc123xyz789`
  (k8s-rbac.yaml, prompt-injection.txt, cryptographic-failures.js),
  `sk-abcd1234efgh5678ijkl9012` (SCP vulnerable-examples.py), and
  `sk-1234567890abcdefghijklmnop` (SCP vulnerable-examples.js). (Chosen over
  angle-bracket redaction and RFC-2606/documented-fake conventions.)

### Claude's Discretion
- Exact drift-check implementation for D-04 (script vs. lint-extension), where it
  lives in `scripts/`, and precisely which files it scans.
- Exact CONTRIBUTING structure and wording of the maintenance/versioning story.
- Precise matrix layout/column headers and badge shield styling.
- The exact `gh repo edit --add-topic` topic list content (see D-11) and the
  final `plugin.json` keyword / `marketplace.json` category+keyword values.
- `install.sh` disposition — keep as a documented alternative install path vs.
  slim/retire now that plugin/marketplace is the primary path (planner's call;
  it was patched to per-skill canonical paths in Phase 1 and is currently
  functional).

### Discoverability handling (ADPT-04)
- **D-11:** **In-repo metadata now + documented GitHub topics for user to apply.**
  Set/align `plugin.json` keywords and add a `marketplace.json` category +
  keywords during execution. Provide the exact `gh repo edit --add-topic ...`
  command list in the deliverable for the user to apply/approve — GitHub repo
  topics are an outward-facing change to the live public repo and stay
  user-controlled (do NOT run `gh repo edit` automatically). (Chosen over
  auto-applying via gh and over in-repo-manifests-only.)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` §"Phase 5: Packaging Validation & Credibility Polish" — goal + 5 success criteria
- `.planning/REQUIREMENTS.md` — PKG-04, PKG-05, QUAL-01, QUAL-02, QUAL-03, ADPT-01, ADPT-02, ADPT-03, ADPT-04 (this phase)
- `.planning/PROJECT.md` §Constraints (Accuracy #1, Format, Distribution), §Key Decisions, §Requirements/Active
- `.planning/STATE.md` §Blockers/Concerns — Claude Code packaging-regression re-check note; `DEPLOYMENT.md`/`TESTING.md` staleness (carried from Phase 1)

### Packaging & manifests (edit targets / canonical source)
- `.claude-plugin/plugin.json` — canonical version source (D-04); currently `0.1.0` → `1.0.0`; declares `"license": "MIT"`; holds keywords
- `.claude-plugin/marketplace.json` — github source entry; add category + keywords (D-11)
- `docs/SKILL-STRUCTURE.md` — locked skill-directory convention (Phase 1 D-07); the authority on the target layout

### Citation sources for QUAL-01 (do NOT re-verify editions — reuse hardened data)
- `skills/owasp-security-audit/references/owasp-urls.json` — verified Top 10 2025 / ASVS / MASVS / API 2023 / LLM 2025 / Agentic 2026 / K8s 2022 URLs + retrieval dates
- `skills/secure-coding-practices/references/owasp-urls.json` — SCP living-source crosswalk provenance
- `skills/owasp-security-audit/references/top10.md`, `asvs.md`, `masvs.md`, `api-top10.md`, `kubernetes-top10.md`, `llm.md`, `agentic.md` — edition notes to mirror in the README matrix

### Prior-phase context (decisions that constrain this phase)
- `.planning/phases/01-plugin-marketplace-foundation/01-CONTEXT.md` — plugin.json 0.1.0 reset (D-02), marketplace no-version-key, install.sh patched to per-skill paths; DEPLOYMENT.md/TESTING.md staleness deferred here
- `.planning/phases/04-skill-md-conversion-legacy-retirement/04-CONTEXT.md` §deferred — install.sh removal + full README/coverage/LICENSE/CONTRIBUTING + DEPLOYMENT.md/TESTING.md staleness all explicitly deferred to Phase 5; example-coverage gaps (A03/A04/A06/A08/A10) declined for Phase 4

### Public-facing docs to refresh/retire
- `README.md` — stale (links deleted comprehensive file; "six OWASP standards"; "ASVS 5.0"; "SCP Quick Reference Guide") → refresh (D-06/D-07/D-08)
- `CONTRIBUTING.md` — extend with maintenance/versioning/update story (D-09, ADPT-03)
- `DEPLOYMENT.md`, `TESTING.md` — salvage-then-delete (D-09)
- `install.sh` — disposition is Claude's discretion; currently functional
- `skills/*/assets/examples/*` — normalize secret placeholders (D-10)

### External (verify live during research — do NOT rely on training recall)
- Claude Code plugin/marketplace install + `claude plugin validate` mechanics for the current CLI (v2.1.201), and status of the documented packaging regressions (symlink-to-cache, Windows path collapse, marketplace "0 skills").

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `.claude-plugin/plugin.json` / `marketplace.json` already valid (Phase 1) — this
  phase bumps version and adds discoverability metadata, not a rebuild.
- Per-skill `owasp-urls.json` already carry verified URLs + retrieval dates — the
  QUAL-01 sweep and README matrix source citations from these, not fresh research.
- `scripts/lint_skill_md.py` (repo-root, stdlib-only, Phase 4) — the model/home for
  the D-04 version-drift check; reuse its LintResult/soft-append style and stdlib-only constraint.
- `install.sh` already patched to per-skill canonical paths (Phase 1) and functional.
- One good placeholder already exists in-repo: `API_KEY=sk-your-api-key-here`
  (`cryptographic-failures.js`) — use as the convention exemplar (D-10).

### Established Patterns
- kebab-case filenames; per-skill self-contained directories; plain codes + prose
  edition notes; topic-first (not literal-number) relabeling.
- "main stays installable at every commit boundary" discipline (Phases 1–4) — order
  deletes/edits so validation passes at each commit.
- Edition notes use verified source URL + retrieval date; no draft-as-final.

### Integration Points
- README matrix ↔ `owasp-urls.json` ↔ SKILL.md descriptions must agree on editions
  (Top 10 2025, ASVS 4.0.3-body/5.0.0, K8s 2022, LLM 2025, Agentic 2026) — a QUAL-01
  consistency surface.
- Version string appears in `plugin.json` (canonical) and may be referenced in README
  badge — the D-04 drift check guards this pair.
- Deleting DEPLOYMENT.md/TESTING.md must not break surviving cross-references (grep first).

</code_context>

<specifics>
## Specific Ideas

- Placeholder exemplars the user endorsed: `sk-EXAMPLE-not-a-real-key`,
  `sk-your-api-key-here`, `PLACEHOLDER_PASSWORD`.
- Badge set: License (MIT) · Version (1.0.0) · Claude Code plugin · OWASP-aligned —
  static shields only, no CI/coverage badges.
- Matrix must foreground: guidance-not-scanner, example-coverage gaps
  (A03/A04/A06/A08/A10), K8s 2022 (not 2025 draft), ASVS 4.0.3-body numbering.
- Two install-validation checkpoints: local-source now (gate) + github-source at ship.

</specifics>

<deferred>
## Deferred Ideas

- **New-category example files** (A03 Supply Chain, A04 Insecure Design, A06
  Vulnerable & Outdated Components, A08 Software & Data Integrity, A10 Exceptional
  Conditions) — the coverage matrix discloses the gap; authoring them is a future
  example-coverage phase / v2, explicitly declined for Phase 4 and not invented here.
- **CI / eval tooling** — v2 EVAL-01 (`evals/` correctness tests), EVAL-02 (OpenSSF
  badge), EVAL-03 (awesome-list submissions). Out of this milestone; badges here stay
  static/honest because there is no CI.
- **Kubernetes Top 10 2025 adoption** — v2 EXP-02, once final/stable.
- **Auto-applying GitHub repo topics** — kept as a user-controlled manual step (D-11);
  not automated in this phase.

None of these expand Phase 5 scope — all are pre-existing v2/future-phase items.

</deferred>

---

*Phase: 5-packaging-validation-credibility-polish*
*Context gathered: 2026-07-24*
