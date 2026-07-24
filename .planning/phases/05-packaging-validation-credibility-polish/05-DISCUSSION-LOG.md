# Phase 5: Packaging Validation & Credibility Polish - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-24
**Phase:** 5-packaging-validation-credibility-polish
**Areas discussed:** Install validation depth, Version & release identity, README & coverage matrix, Legacy docs & secrets

---

## Install validation depth (PKG-04)

### Q1 — Install source given github remote is behind local HEAD

| Option | Description | Selected |
|--------|-------------|----------|
| Local-source now, document github | Local validate/add/install/smoke now; document github as release-time equivalent | |
| Push first, then github install | Push main, run real github-sourced install; publishes mid-polish work | |
| Both: local now + github at ship | Local validation now as gate; github install deferred to ship after push | ✓ |

**User's choice:** Both — local now + github at ship
**Notes:** `claude` CLI v2.1.201 confirmed present locally; github remote is behind local HEAD so a github install today would pull stale content.

### Q2 — Activation smoke-test evidence

| Option | Description | Selected |
|--------|-------------|----------|
| Scripted + captured transcript | Repeatable check confirming both skills loadable post-install; output captured | ✓ |
| Manual prompt walkthrough | Documented example prompts run by a human with pass/fail note | |
| Structural verification only | Verify files land correctly without asserting live activation | |

**User's choice:** Scripted + captured transcript
**Notes:** Matches the repo's stdlib-only tooling style; reproducible evidence into phase artifacts.

---

## Version & release identity (PKG-05, ADPT-01, ADPT-04)

### Q1 — Public release version

| Option | Description | Selected |
|--------|-------------|----------|
| 1.0.0 | First credible public release of the modernized plugin | ✓ |
| 0.1.0 (stay) | Keep Phase 1's intentional early-stage version | |
| 0.2.0 | Minor bump marking progress without full 1.0 claim | |

**User's choice:** 1.0.0
**Notes:** Phase 1 reset to 0.1.0 to break the legacy 1.1.0 lineage, so 1.0.0 is a fresh honest v1.

### Q2 — Canonical version source (PKG-05)

| Option | Description | Selected |
|--------|-------------|----------|
| plugin.json canonical + check | plugin.json authoritative + stdlib drift check; no per-skill version | ✓ |
| plugin.json canonical, doc-only | Authoritative + documented rule, no automated check | |
| Add VERSION file | Repo-root VERSION file as source | |

**User's choice:** plugin.json canonical + check
**Notes:** Consistent with Phase 1 "marketplace.json no version key, plugin.json authoritative"; SKILL.md spec has no version field.

### Q3 — LICENSE type + holder

| Option | Description | Selected |
|--------|-------------|----------|
| MIT, holder = author name | MIT, holder "Security Education Community", current year | ✓ |
| MIT, different holder | MIT with a specific alternate name/handle | |
| Apache-2.0 | Switch to Apache-2.0 (patent grant + NOTICE) | |

**User's choice:** MIT, holder = author name
**Notes:** Aligns with plugin.json's already-declared `"license": "MIT"` — zero new claims.

### Q4 — ADPT-04 GitHub topics handling

| Option | Description | Selected |
|--------|-------------|----------|
| In-repo + documented topics | Set manifest metadata now; document `gh repo edit --add-topic` for user | ✓ |
| I apply topics via gh too | Also run `gh repo edit` during execution | |
| In-repo manifests only | Only touch plugin.json/marketplace.json | |

**User's choice:** In-repo + documented topics
**Notes:** GitHub repo topics are an outward-facing change to the live repo; user stays in control.

---

## README & coverage matrix (ADPT-02, QUAL-02)

### Q1 — Coverage matrix representation

| Option | Description | Selected |
|--------|-------------|----------|
| Two-column: covered + caveat | Edition-covered + scope/caveat columns inline + "What this is NOT" note | ✓ |
| Matrix + separate limitations | Clean matrix, then a distinct limitations section | |
| Matrix only, minimal caveats | Matrix with editions + sources, caveats footnoted | |

**User's choice:** Two-column: covered + caveat
**Notes:** Caveats impossible to miss — K8s 2022, ASVS 4.0.3-body, example-coverage gaps, guidance-not-scanner.

### Q2 — Status badges

| Option | Description | Selected |
|--------|-------------|----------|
| Static, honest set | License, version, Claude Code plugin, OWASP-aligned; no CI/coverage badges | ✓ |
| Minimal (license + version) | Just License and Version | |
| No badges | Prose + matrix only | |

**User's choice:** Static, honest set
**Notes:** No CI pipeline exists (deferred to v2 EVAL-01); badges must not misrepresent capability.

---

## Legacy docs & secrets (QUAL-03, ADPT-03)

### Q1 — Stale DEPLOYMENT.md / TESTING.md disposition

| Option | Description | Selected |
|--------|-------------|----------|
| Fold useful bits, delete originals | Salvage into README + CONTRIBUTING, then delete both | ✓ |
| Rewrite both to plugin model | Keep both, fully rewrite | |
| Rewrite TESTING, delete DEPLOYMENT | Split decision | |

**User's choice:** Fold useful bits, delete originals
**Notes:** CONTRIBUTING absorbs the maintenance/versioning/update story (also serves ADPT-03); matches Phase 4 retire-superseded-files pattern.

### Q2 — Example secret placeholder convention (QUAL-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Self-labeling placeholders | `sk-EXAMPLE-not-a-real-key`, `sk-your-api-key-here`, `PLACEHOLDER_PASSWORD` | ✓ |
| Angle-bracket redaction | `<REPLACE_ME>` / `<YOUR_API_KEY>` style | |
| RFC-2606 / documented-fake | example.com + AWS `EXAMPLE`-suffixed keys | |

**User's choice:** Self-labeling placeholders
**Notes:** Plausible enough to teach the anti-pattern, unmistakably fake to humans and secret scanners. One good exemplar already in-repo (`sk-your-api-key-here`).

---

## Claude's Discretion

- Drift-check implementation (script vs. lint-extension), location, scanned files.
- CONTRIBUTING structure + maintenance/versioning wording.
- Matrix layout/column headers and badge shield styling.
- Exact `gh repo edit --add-topic` list and final plugin.json keyword / marketplace.json category+keyword values.
- `install.sh` disposition (keep documented alt-path vs. slim/retire).

## Deferred Ideas

- New-category example files (A03/A04/A06/A08/A10) — matrix discloses the gap; authoring deferred to a future example-coverage phase / v2.
- CI / eval tooling — v2 EVAL-01/02/03.
- Kubernetes Top 10 2025 adoption — v2 EXP-02.
- Auto-applying GitHub repo topics — kept as a user-controlled manual step.
