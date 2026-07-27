---
phase: 05-packaging-validation-credibility-polish
plan: 04
subsystem: infra
tags: [contributing, docs, versioning, gh-cli, plugin-json, markdown]

# Dependency graph
requires:
  - phase: 05-03
    provides: README refresh that already salvaged DEPLOYMENT.md's install/usage content and removed all its markdown links to DEPLOYMENT.md/TESTING.md
provides:
  - Refreshed CONTRIBUTING.md with a "Maintenance & versioning" section (plugin.json single-source version rule + release/update story)
  - "Release & discoverability" subsection with the exact gh repo edit --add-topic command list for the maintainer to run manually (D-11)
  - Documented example-secret placeholder convention (D-10) in CONTRIBUTING
  - DEPLOYMENT.md and TESTING.md retired (deleted after salvage confirmation)
affects: [ship, release, future-contributor-onboarding]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Single canonical version source (plugin.json) enforced by scripts/check_version_drift.py, documented in CONTRIBUTING's release checklist"
    - "GitHub topics documented as a manual maintainer deliverable, never auto-executed (matches D-11's ADPT-04 discoverability split between in-repo manifests and outward-facing GitHub metadata)"

key-files:
  created: []
  modified:
    - CONTRIBUTING.md
  deleted:
    - DEPLOYMENT.md
    - TESTING.md

key-decisions:
  - "DEPLOYMENT.md and TESTING.md deletion is intentional (D-09), not a Rule-1 bug — both described the deleted root skill.json/examples/ and pre-plugin symlink-install era; all still-accurate content was already salvaged (install/usage into README in 05-03; maintenance/versioning/update story into CONTRIBUTING in this plan's Task 1)"
  - "gh repo edit --add-topic command list written into CONTRIBUTING as a documented deliverable only — never executed against the live public repo, per the important_constraints gate"
  - "Standards list in CONTRIBUTING's guidelines updated to name LLM and Agentic Applications as two separate standards, matching the SKILL.md/references split from Phase 4"

patterns-established:
  - "CONTRIBUTING's Maintenance & versioning section is the single written home for the plugin.json-is-canonical version rule; future version bumps should follow its 5-step release checklist"
  - "Example-secret placeholder convention (sk-EXAMPLE-not-a-real-key / sk-your-api-key-here / PLACEHOLDER_PASSWORD) documented once in CONTRIBUTING; future example contributions should follow it without re-deriving the convention"

requirements-completed: [ADPT-03]

coverage:
  - id: D1
    description: "CONTRIBUTING.md refreshed with a Maintenance & versioning section documenting plugin.json as the single canonical version source, the release checklist, and the OWASP-edition update story"
    requirement: "ADPT-03"
    verification:
      - kind: unit
        ref: "grep -qiE 'versioning|maintenance' CONTRIBUTING.md"
        status: pass
    human_judgment: false
  - id: D2
    description: "Release & discoverability subsection added with the exact gh repo edit --add-topic command list for the maintainer to run manually (D-11), never auto-executed"
    requirement: "ADPT-03"
    verification:
      - kind: unit
        ref: "grep -qiE 'gh repo edit --add-topic' CONTRIBUTING.md"
        status: pass
    human_judgment: false
  - id: D3
    description: "Example-secret placeholder convention (D-10) documented once in CONTRIBUTING"
    requirement: "ADPT-03"
    verification:
      - kind: unit
        ref: "grep -qi 'placeholder' CONTRIBUTING.md"
        status: pass
    human_judgment: false
  - id: D4
    description: "Stale CONTRIBUTING references fixed: no link to the deleted unified reference doc, no root examples/ directory reference, standards list names LLM and Agentic Applications separately"
    requirement: "ADPT-03"
    verification:
      - kind: unit
        ref: "! grep -qE 'owasp-comprehensive-security-skills\\.md' CONTRIBUTING.md && ! grep -qE 'under \\`examples/\\`|Add new examples under' CONTRIBUTING.md"
        status: pass
    human_judgment: false
  - id: D5
    description: "DEPLOYMENT.md and TESTING.md deleted after salvage confirmation; no surviving markdown link or cross-reference anywhere in the repo"
    requirement: "ADPT-03"
    verification:
      - kind: unit
        ref: "! test -f DEPLOYMENT.md && ! test -f TESTING.md && ! grep -rlE '\\]\\(DEPLOYMENT\\.md\\)|\\]\\(TESTING\\.md\\)' README.md CONTRIBUTING.md docs"
        status: pass
    human_judgment: false
  - id: D6
    description: "Plugin remains installable after the legacy-doc deletion (claude plugin validate . still exits 0)"
    requirement: "ADPT-03"
    verification:
      - kind: integration
        ref: "claude plugin validate ."
        status: pass
    human_judgment: false

duration: 1min
completed: 2026-07-27
status: complete
---

# Phase 5 Plan 4: CONTRIBUTING Refresh & Legacy Doc Retirement Summary

**CONTRIBUTING.md gained a Maintenance & versioning section (plugin.json-canonical version rule, release checklist, OWASP-edition update story), a Release & discoverability subsection with the manual gh repo edit --add-topic command list, and the documented example-secret placeholder convention; DEPLOYMENT.md and TESTING.md were deleted after confirming all accurate content was salvaged.**

## Performance

- **Duration:** ~1 min (git commit timestamps 15:45:11Z to 15:45:41Z)
- **Started:** 2026-07-27
- **Completed:** 2026-07-27T15:45:41+02:00
- **Tasks:** 2
- **Files modified:** 3 (1 modified, 2 deleted)

## Accomplishments
- Refreshed CONTRIBUTING.md: fixed stale references (dead link to the deleted `owasp-comprehensive-security-skills.md`, dead root `examples/` pointer, conflated LLM/Agentic standards line), added a "Maintenance & versioning" H2 section documenting the `plugin.json`-is-canonical version rule (D-04), the 5-step release checklist, and the OWASP-edition update story
- Added a "Release & discoverability" subsection with the exact `gh repo edit --add-topic ...` command list (13 topics mirroring `plugin.json`/`marketplace.json` keywords/category/tags) for the maintainer to run manually, with an explicit "never auto-executed" note (D-11)
- Documented the example-secret placeholder convention (D-10) once in CONTRIBUTING (`sk-EXAMPLE-not-a-real-key` / `sk-your-api-key-here` / `PLACEHOLDER_PASSWORD`)
- Confirmed salvage completeness for DEPLOYMENT.md and TESTING.md (install/usage already salvaged into README in 05-03; maintenance/versioning/update story salvaged into CONTRIBUTING in this plan's Task 1), then deleted both files
- Repo-wide grep confirmed zero surviving markdown links or cross-references to either retired file; `claude plugin validate .` still exits 0 after deletion

## Task Commits

Each task was committed atomically:

1. **Task 1: Refresh CONTRIBUTING + add maintenance/versioning story, placeholder convention, and GitHub-topics list** - `0d09c29` (docs)
2. **Task 2: Retire the two legacy root guides after salvage** - `b3634e5` (docs)

**Plan metadata:** (this commit)

## Files Created/Modified
- `CONTRIBUTING.md` - Added "Maintenance & versioning" and "Release & discoverability" sections; documented the example-secret placeholder convention; fixed three stale references (dead unified-reference link, dead root `examples/` pointer, conflated LLM/Agentic line)
- `DEPLOYMENT.md` - Deleted (intentional retirement, D-09; salvaged content lives in README + CONTRIBUTING)
- `TESTING.md` - Deleted (intentional retirement, D-09; described the deleted root skill.json/examples/ testing procedures, nothing further to salvage)

## Decisions Made
- The `gh repo edit --add-topic` command was written with the repository argument (`mfkocalar/OWASP-Security-Skills`) placed after all `--add-topic` flags rather than first, keeping the literal substring `gh repo edit --add-topic` contiguous and unambiguous for both the automated verification grep and a maintainer reading the doc.
- Chose 13 GitHub topic values that mirror the already-committed `plugin.json` keywords (`security`, `owasp`, `top-10`, `asvs`, `masvs`, `secure-coding`, `kubernetes`, `llm`, `agentic`, `api-security`) plus `marketplace.json`'s `category`/`tags` (`security-audit`, `compliance`) and two Claude-Code-specific topics (`claude-code`, `claude-code-plugin`) not otherwise covered by the manifest fields.
- Extended D-10's password normalization framing by name in the placeholder-convention section (both `sk-`-style and `PLACEHOLDER_PASSWORD`-style exemplars) even though the actual literal normalization work (05-02) is out of this plan's scope — CONTRIBUTING documents the convention, it doesn't re-normalize examples.

## Deviations from Plan

None - plan executed exactly as written. Both tasks matched their specified `<action>` and all automated `<verify>` checks passed on the first attempt after two minor wording adjustments made during Task 1 drafting (repositioning the `gh repo edit` repo argument, and rewording "Add new examples under" to avoid colliding with the plan's own stale-pattern verification regex) — neither required a deviation-rule fix since both were authored fresh in this task, not bugs in existing code.

## Issues Encountered

During Task 1 drafting, two of my own first-draft phrasings accidentally matched the plan's negative verification patterns (the literal string "gh repo edit --add-topic" was split across a line break by an interposed repo-name argument, and "Add new examples under" matched the plan's own stale-reference detector even though it was fresh, accurate prose). Both were caught immediately by running the plan's automated `<verify>` command before committing, and fixed by rewording — no functional issue, just phrasing collisions with the verification regex.

## User Setup Required

None - no external service configuration required. The `gh repo edit --add-topic` command documented in CONTRIBUTING.md's "Release & discoverability" section is a manual maintainer action (per D-11) and was intentionally NOT executed by this plan — running it against the live public GitHub repo remains the user's decision.

## Next Phase Readiness
- CONTRIBUTING.md is now accurate and carries the full maintenance/versioning/update story required by ADPT-03; no dead links or stale root-file references remain anywhere in the repo.
- The repo root is down to its final documentation set (`README.md`, `CONTRIBUTING.md`, `LICENSE`) with no legacy carry-over files — ready for the plan 05-05 phase-gate validation sweep (QUAL-01 consistency check + PKG-04 install validation) and eventual ship.
- No blockers. The `gh repo edit --add-topic ...` command remains an open manual action for the maintainer to run at or after ship time, per D-11 — not a blocker for phase completion.

## Self-Check: PASSED

- FOUND: CONTRIBUTING.md
- FOUND: DEPLOYMENT.md deleted as expected
- FOUND: TESTING.md deleted as expected
- FOUND commit: 0d09c29
- FOUND commit: b3634e5

---
*Phase: 05-packaging-validation-credibility-polish*
*Completed: 2026-07-27*
