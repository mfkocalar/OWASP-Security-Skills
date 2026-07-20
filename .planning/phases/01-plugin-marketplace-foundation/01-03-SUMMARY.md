---
phase: 01-plugin-marketplace-foundation
plan: 03
subsystem: infra
tags: [install-sh, readme, plugin-packaging, cleanup, bash]

# Dependency graph
requires:
  - phase: 01-plugin-marketplace-foundation (plan 01)
    provides: ".claude-plugin/plugin.json superseding manifest, required as a guard before skill.json removal"
provides:
  - "install.sh patched to verify only surviving files/paths (no root skill.json, examples-count repointed to per-skill path)"
  - "README.md example links and repository-structure diagram repointed to per-skill assets/examples/ paths"
  - "root skill.json and root examples/ removed; canonical examples remain under skills/owasp-security-audit/assets/examples/"
  - "DEPLOYMENT.md/TESTING.md staleness gap tracked in STATE.md for Phase 5"
affects: [phase-04-legacy-retirement, phase-05-doc-polish]

# Tech tracking
tech-stack:
  added: []
  patterns: ["patch-then-delete ordering to keep main installable at every commit"]

key-files:
  created: []
  modified:
    - install.sh
    - README.md
    - .planning/STATE.md

key-decisions:
  - "Removed the stale skill.json row from README's repository-structure diagram (beyond the plan's literal 'examples row' instruction) to keep the diagram consistent with this same plan's skill.json deletion, rather than leave a known-false structure line unaddressed until Phase 5"

patterns-established:
  - "Patch-then-delete: files referencing a doomed artifact are repointed to their surviving location first, then the artifact is deleted, with an explicit safety diff/guard check gating the deletion — guarantees no commit in the sequence leaves main in a broken/uninstallable state"

requirements-completed: [PKG-03]

coverage:
  - id: D1
    description: "install.sh required_files array, examples-count check, and cosmetic echo repointed to survive skill.json/examples removal"
    requirement: "PKG-03"
    verification:
      - kind: unit
        ref: "bash -n install.sh && grep -q 'skills/owasp-security-audit/assets/examples' install.sh"
        status: pass
      - kind: manual_procedural
        ref: "printf '4\\n' | bash install.sh — exits 0 after removals"
        status: pass
    human_judgment: false
  - id: D2
    description: "README.md example links (11 spots) repointed to skills/owasp-security-audit/assets/examples/<file>"
    requirement: "PKG-03"
    verification:
      - kind: unit
        ref: "existence loop over 9 filenames under skills/owasp-security-audit/assets/examples/ + grep -c count >= 9 in README.md"
        status: pass
    human_judgment: false
  - id: D3
    description: "Root skill.json and root examples/ removed; canonical examples retained per-skill; DEPLOYMENT/TESTING staleness recorded in STATE.md"
    requirement: "PKG-03"
    verification:
      - kind: unit
        ref: "test ! -e examples && test ! -e skill.json && test -f .claude-plugin/plugin.json && ls skills/owasp-security-audit/assets/examples | wc -l >= 9 && grep -q DEPLOYMENT.md .planning/STATE.md"
        status: pass
    human_judgment: false

duration: 1min
completed: 2026-07-20
status: complete
---

# Phase 01 Plan 03: Retire skill.json and root examples/ Summary

**install.sh and README.md repointed to per-skill canonical paths, then root skill.json and duplicate examples/ deleted with a byte-identical safety check gating the removal — main stays installable at every commit.**

## Performance

- **Duration:** 1 min
- **Started:** 2026-07-20T10:59:00Z
- **Completed:** 2026-07-20T11:01:37Z
- **Tasks:** 3
- **Files modified:** 3 (install.sh, README.md, .planning/STATE.md) + 10 files removed (examples/*9, skill.json)

## Accomplishments
- `install.sh` no longer checks for the retired root `skill.json`; its examples-count check and cosmetic next-steps echo now point at `skills/owasp-security-audit/assets/examples/`, the surviving canonical location
- `README.md`'s repository-structure diagram, "Examples" intro, and all 9 file links now resolve to `skills/owasp-security-audit/assets/examples/<file>` — zero broken links after the deletions
- Root `skill.json` (D-08) and root `examples/` (D-05, 9 files) removed after a byte-identical `diff -rq` safety check and a `.claude-plugin/plugin.json` presence guard both passed
- DEPLOYMENT.md/TESTING.md staleness (they still reference the removed root manifest and root examples/) recorded as a tracked deferral in `.planning/STATE.md` Blockers/Concerns for Phase 5 doc-polish
- `printf '4\n' | bash install.sh` (test-only option) verified exiting 0 after all removals, proving the patch-then-delete ordering kept `main` installable at every commit

## Task Commits

Each task was committed atomically:

1. **Task 1: Patch install.sh** - `a484531` (fix)
2. **Task 2: Repoint README.md example links** - `39d9809` (docs)
3. **Task 3: Retire root skill.json/examples/, record deferral** - `088df58` (chore)

**Plan metadata:** (final commit recorded below)

## Files Created/Modified
- `install.sh` - Removed `skill.json` from `required_files`; repointed examples-count check and cosmetic echo to `skills/owasp-security-audit/assets/examples/`
- `README.md` - Repository-structure diagram, Examples intro, and 9 file links repointed to per-skill canonical paths; stale `skill.json` row dropped
- `.planning/STATE.md` - Appended DEPLOYMENT.md/TESTING.md staleness deferral bullet to Blockers/Concerns
- `examples/*` (9 files) - Removed (D-05, canonical copies retained under `skills/owasp-security-audit/assets/examples/`)
- `skill.json` - Removed (D-08, superseded by `.claude-plugin/plugin.json`)

## Decisions Made
- Dropped the stale `skill.json` row from README's repository-structure diagram, beyond the plan's literally-scoped "examples row" instruction — leaving a diagram line describing a file this very plan deletes would create an immediately-false statement in the same commit sequence, which is a stronger consistency violation than the DEPLOYMENT.md/TESTING.md deferral (those files aren't touched by this plan at all, so their staleness is a genuine cross-plan deferral; the README diagram is touched by this plan, so its skill.json line becoming false a task later was avoidable in-scope).

## Deviations from Plan

None (Rule 1-3) - plan executed exactly as written for all three tasks and their verification steps. One in-scope judgment call is documented above under Decisions Made (removing the stale skill.json diagram row); this is not a deviation from a task's `<action>` — it falls within Task 2's own "repository-structure diagram row" instruction, interpreted to keep the diagram internally consistent with Task 3's deletions in the same plan.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Phase 01 (plugin-marketplace-foundation) plans 01-03 are all complete: `.claude-plugin/plugin.json` + `marketplace.json` exist (01-01), `docs/SKILL-STRUCTURE.md` locks the skill-directory convention (01-02), and now `install.sh`/`README.md` are consistent with the retired root `skill.json`/`examples/` (01-03).
- Root `skill.json` and root `examples/` are gone; the only remaining root-level legacy files are `owasp-css.instructions.md`, `owasp-comprehensive-security-skills.md`, and `install.sh` itself — all explicitly deferred to Phase 4/5 per D-09.
- DEPLOYMENT.md/TESTING.md staleness is tracked in STATE.md and ready for Phase 5 doc-polish to pick up.
- No blockers for Phase 2.

---
*Phase: 01-plugin-marketplace-foundation*
*Completed: 2026-07-20*

## Self-Check: PASSED

- FOUND: install.sh
- FOUND: README.md
- FOUND: .planning/STATE.md
- CONFIRMED ABSENT: skill.json (removed per D-08)
- CONFIRMED ABSENT: examples/ (removed per D-05)
- FOUND commit: a484531 (Task 1)
- FOUND commit: 39d9809 (Task 2)
- FOUND commit: 088df58 (Task 3)
