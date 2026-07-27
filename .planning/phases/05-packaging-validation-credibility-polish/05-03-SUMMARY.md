---
phase: 05-packaging-validation-credibility-polish
plan: 03
subsystem: docs
tags: [readme, credibility, coverage-matrix, honesty, drift-fix]
status: complete
dependency-graph:
  requires: [05-01]
  provides: [refreshed-readme, honest-coverage-matrix, skill-structure-drift-fix]
  affects: [README.md, docs/SKILL-STRUCTURE.md]
tech-stack:
  added: []
  patterns: [static-badge-only, cite-from-owasp-urls-json, two-column-coverage-matrix]
key-files:
  created: []
  modified:
    - README.md
    - docs/SKILL-STRUCTURE.md
decisions:
  - "Combined Task 1 (structural refresh) and Task 2 (coverage matrix + What this is NOT) into a single README.md commit, since both tasks edit overlapping sections of the same file and were authored as one coherent Write pass"
  - "Coverage-matrix source citations quoted verbatim from skills/owasp-security-audit/references/owasp-urls.json and skills/secure-coding-practices/references/owasp-urls.json — no editions re-derived"
  - "Secure Coding Practices matrix row cites the living Cheat Sheet Series (retrieved 2026-07-22) and explicitly labels the original SCP Quick Reference Guide as archived/historical-origin only"
metrics:
  duration: 25min
  completed: 2026-07-27
---

# Phase 05 Plan 03: README credibility refresh + SKILL-STRUCTURE.md drift fix Summary

Refreshed the stale public-facing README into an honest trust surface — static
badges, a two-column coverage matrix with per-standard source URLs and
retrieval dates, a prominent "What this is NOT" disclosure, a primary
plugin/marketplace install path, and zero dead links — then closed a small
worked-example drift in `docs/SKILL-STRUCTURE.md` left over from Phase 4's
`llm.md`/`agentic.md` split.

## What Was Built

**README.md refresh (Tasks 1 + 2, one commit `803f592`):**
- Added a static badge block (License MIT / Version 1.0.0 / Claude Code
  plugin / OWASP-aligned) — no CI/coverage badge, per D-08. The version
  badge uses the shields.io `version-1.0.0` token so `check_version_drift.py`
  recognizes and validates it against `plugin.json`.
- Corrected the intro to state the honest structure: two skills, seven OWASP
  standards (Top 10, ASVS, MASVS, API Security, Kubernetes, LLM, Agentic
  Applications — LLM and Agentic counted separately per D-06) plus the
  secure-coding-practices skill.
- Replaced the dead link to the Phase-4-deleted
  `owasp-comprehensive-security-skills.md` with links into
  `skills/owasp-security-audit/SKILL.md` and `skills/secure-coding-practices/SKILL.md`.
- Rewrote Installation: `claude plugin marketplace add` /
  `claude plugin install` (the verified CLI command surface from
  05-RESEARCH.md) is now primary; `install.sh` is documented as a secondary,
  symlink-based alternative for non-plugin assistants.
- Regenerated the "Repository structure" tree against the real on-disk
  layout (`.claude-plugin/`, `skills/*/`, `docs/`, `scripts/`, `LICENSE`,
  `README.md`, `CONTRIBUTING.md`, `install.sh`).
- Removed dead links to `DEPLOYMENT.md`/`TESTING.md` from the Documentation
  list (both retired elsewhere this phase) and replaced them with links to
  each skill's `SKILL.md` + `references/` and `docs/SKILL-STRUCTURE.md`.
- Linked the new root `LICENSE` file in place of the old plain-text
  "Released under the MIT License." line.
- Replaced the single-column Coverage table with a two-column matrix
  (Standard | Edition covered | Scope / caveat), one row per standard —
  Top 10 (2025 Final), ASVS (5.0.0 current edition, 4.0.3-body numbering
  called out inline), MASVS (2.1.0), API Security Top 10 (2023), Kubernetes
  Top 10 (2022 stable, 2025 draft explicitly excluded), LLM Top 10 (2025),
  Agentic Applications Top 10 (2026, its own row), and a Secure Coding
  Practices row (living-source derivation, QRG named as archived-only).
  Every row's edition + source URL + retrieval date is quoted verbatim from
  the hardened `owasp-urls.json` files.
- Added a "What this is NOT" section immediately after the matrix: states
  guidance/reference (not a runtime scanner), and names the five uncovered
  2025 Top 10 example categories (A03 Supply Chain, A04 Insecure Design,
  A06 Vulnerable & Outdated Components, A08 Software or Data Integrity
  Failures, A10 Mishandling of Exceptional Conditions) as a disclosed gap,
  not a fixed one.
- Updated the per-file Examples table's OWASP category labels to match
  Phase 4's topic-first relabeling actually present in the example file
  headers (A01/A02/A04/A05/A09, API Security, Kubernetes, LLM/Agentic).

**docs/SKILL-STRUCTURE.md drift fix (Task 3, commit `bfdca9e`):**
- Replaced the stale worked-example reference to the pre-Phase-4 combined
  `references/llm-agentic.md` with the two real split files `llm.md` and
  `agentic.md`.
- Removed the worked-example line referencing the deleted in-skill
  supplementary `owasp-security-audit.md` doc.
- Confirmed via `find skills -name '*.md' -o -name '*.json'` that no other
  filename in the doc's worked-example tree disagrees with the real on-disk
  layout (the `secure-coding-practices.md` and `README.md` entries under
  `secure-coding-practices/` were verified still accurate — those files
  still exist and were never part of the drift).

## Deviations from Plan

### Auto-fixed Issues

None — no bugs, missing functionality, or blocking issues were encountered.

### Process note (not a Rule 1-4 deviation)

Task 1 and Task 2 both edit `README.md` and were authored as a single
coherent `Write` pass (badges/intro/install/structure-tree in the same file
sections as the coverage matrix and "What this is NOT" note, produced
together for internal consistency). They landed as one commit (`803f592`)
rather than two, since splitting a single-file rewrite into two partial
commits would have required manual hunk-splitting with no verification
benefit — both tasks' automated `<verify>` checks pass against the
committed state. Task 3 (a distinct file, `docs/SKILL-STRUCTURE.md`) is its
own commit as planned.

## Verification Results

All automated checks from the plan's `<verification>` block pass:

```
! grep -qE "owasp-comprehensive-security-skills\.md|owasp-css\.instructions\.md" README.md   → PASS (no dead links)
! grep -qE "\]\(DEPLOYMENT\.md\)|\]\(TESTING\.md\)" README.md                                  → PASS
grep -qiE "what this is not" README.md                                                          → PASS
grep -q "2022" README.md && grep -q "2025" README.md                                            → PASS
grep -qiE "5.0.0|4.0.3" README.md                                                                → PASS
! grep -qE "llm-agentic\.md|owasp-security-audit\.md" docs/SKILL-STRUCTURE.md                  → PASS
python3 scripts/check_version_drift.py                                                          → exit 0, all 4 checks PASS
```

`check_version_drift.py --format text` output (captured):
```
Scanned 1 target file(s) for version drift.
  [PASS] .claude-plugin/plugin.json :: plugin-json-has-version — canonical version is 1.0.0
  [PASS] .claude-plugin/marketplace.json :: marketplace-top-level-version — no top-level 'version' key (plugin.json is authoritative)
  [PASS] .claude-plugin/marketplace.json :: marketplace-plugin-version[owasp-security-skills] — plugin entry 'owasp-security-skills' carries no 'version' key
  [PASS] README.md :: badge-version-token — found version 1.0.0 matches canonical 1.0.0

RESULT: PASS — all checks passed.
```

**HUMAN-CHECK (QUAL-01/QUAL-02 semantic, self-verified during execution):**
Cross-referenced the README matrix against both `owasp-urls.json` files, both
`SKILL.md` descriptions, and `asvs.md`/`kubernetes-top10.md` edition notes —
every edition (Top 10 2025, ASVS 4.0.3-body/5.0.0, MASVS 2.1.0, API 2023,
LLM 2025, Agentic 2026, K8s 2022) matches and carries a source URL +
retrieval date consistent across all surfaces. The matrix and "What this is
NOT" note read as honest; no badge overclaims capability (all four are
static facts: license, version, plugin format, and standard-alignment —
none imply CI, test coverage, or runtime scanning).

## Known Stubs

None — this plan only edits existing documentation prose; no new
components, empty-state props, or placeholder data paths were introduced.

## Threat Flags

None — both edits stay within the trust boundaries already registered in
this plan's `<threat_model>` (T-05-02, T-05-06, T-05-04). No new network
endpoint, auth path, file-access pattern, or schema change was introduced.

## Self-Check: PASSED

- `test -f README.md` → FOUND
- `test -f docs/SKILL-STRUCTURE.md` → FOUND
- `git log --oneline --all | grep -q 803f592` → FOUND
- `git log --oneline --all | grep -q bfdca9e` → FOUND
- `python3 scripts/check_version_drift.py` → exit 0 (verified above)
