---
phase: 05-packaging-validation-credibility-polish
plan: 05
subsystem: infra
tags: [claude-plugin, marketplace, install-validation, checkpoint, bash]

# Dependency graph
requires:
  - phase: 05-01
    provides: plugin.json 1.0.0 as canonical version source, marketplace.json discoverability metadata
  - phase: 05-02
    provides: secret-normalized example content (nothing left that would fail a real install/activation smoke test)
  - phase: 05-03
    provides: refreshed README with honest coverage matrix (public trust surface the install gate implicitly validates)
  - phase: 05-04
    provides: refreshed CONTRIBUTING with release/versioning story (paired with the install gate as the "is it shippable" evidence)
provides:
  - Reusable Checkpoint-1/Checkpoint-2 install-validation capture wrapper (scripts/checkpoint1_install_validate.sh)
  - Captured, human-verified transcript proving end-to-end install + 2-skill discovery against final committed content
  - Proof that the test-time marketplace.json source override never reaches the committed manifest (byte-exact revert via EXIT trap)
affects: [ship, release]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Reversible-override capture wrapper: temp-edit a manifest field, run the real CLI sequence, revert via `trap ... EXIT` (fires even on failure), assert `git diff --quiet` before declaring PASS"
    - "Transcript-as-evidence: full command output teed to a phase-directory .md artifact rather than trusted from memory/summary"

key-files:
  created:
    - scripts/checkpoint1_install_validate.sh
    - .planning/phases/05-packaging-validation-credibility-polish/05-checkpoint1-transcript.md
  modified:
    - .gitignore

key-decisions:
  - "Checkpoint 2 (true github-source install) deliberately deferred to the ship step after Phase 5 is pushed, since the remote is currently behind local HEAD — documented explicitly in the transcript rather than attempted against a stale remote"
  - "The 0-skills v2.1.201 regression (Pitfall #2) did not reproduce: real run showed Skills (2) with both correct names on the first pass, so the symlink workaround was not needed"

requirements-completed: [PKG-04]

coverage:
  - id: D1
    description: "End-to-end install validated on this environment against final committed content: claude plugin validate, local-source marketplace add, install, and a scripted discovery smoke test all pass, with both skills (owasp-security-audit, secure-coding-practices) discoverable"
    requirement: "PKG-04"
    verification:
      - kind: manual_procedural
        ref: ".planning/phases/05-packaging-validation-credibility-polish/05-checkpoint1-transcript.md"
        status: pass
    human_judgment: true
    rationale: "PKG-04 requires human confirmation that the captured transcript is legitimate evidence of a real install (not fabricated output) and that the marketplace.json revert is truly clean before this gate can be trusted as shipped proof; the human approved via the blocking checkpoint."
  - id: D2
    description: "The shipped marketplace.json never retains the test-time local-source override; committed manifest keeps its github source unchanged"
    requirement: "PKG-04"
    verification:
      - kind: other
        ref: "git diff --quiet .claude-plugin/marketplace.json (re-confirmed clean during finalization)"
        status: pass
    human_judgment: false

# Metrics
duration: 3min
completed: 2026-07-27
status: complete
---

# Phase 5 Plan 5: Checkpoint-1 Install-Validation Gate Summary

**End-to-end `claude plugin validate` -> local-source marketplace add -> install -> discovery smoke test proved both skills load, with a byte-exact revert of the temporary marketplace.json source override enforced by an EXIT trap.**

## Performance

- **Duration:** 3 min (continuation finalization; Tasks 1-2 executed in a prior session)
- **Started:** 2026-07-27T13:46:57Z
- **Completed:** 2026-07-27T13:55:14Z (transcript timestamp)
- **Tasks:** 3 (2 automated + 1 human-verify checkpoint)
- **Files modified:** 3 (scripts/checkpoint1_install_validate.sh, .gitignore, transcript artifact)

## Accomplishments
- Built a reusable, stdlib-only capture wrapper (`scripts/checkpoint1_install_validate.sh`) implementing the full validated command sequence: `claude plugin validate .` -> temp source override -> `marketplace add ./ --scope local` -> `install --scope local` -> `plugin details` / `plugin list --json` -> revert -> `git diff --quiet` assertion, with per-step PASS/FAIL echo and a `trap ... EXIT` guaranteeing the revert runs even on failure.
- Ran the gate against final, committed Phase 5 content: `claude plugin validate` passed, install succeeded, and `claude plugin details` reported `Skills (2)  owasp-security-audit, secure-coding-practices` — the real, authoritative result (the documented v2.1.201 "0 skills" regression did not reproduce).
- Captured the full run to `05-checkpoint1-transcript.md` as reproducible phase evidence, including an explicit note that Checkpoint 2 (true github-source install) is deferred to the ship step after Phase 5 is pushed.
- Confirmed and human-verified that the committed `.claude-plugin/marketplace.json` was never left with the test-time source override (`git diff --quiet` succeeds) and that `.claude/settings.local.json` is gitignored, not tracked.

## Task Commits

Each task was committed atomically:

1. **Task 1: Create the Checkpoint-1 capture wrapper + gitignore hardening** - `630cb22` (feat) + `2e28fed` (fix: `.` -> `./` for `claude plugin marketplace add` source)
2. **Task 2: Run the gate, capture the transcript, record the real skills count** - `4c8b451` (feat)
3. **Task 3: Human-verify the Checkpoint-1 gate** - checkpoint (no code); human responded "approved" after reviewing the transcript and re-confirmed invariants

**Plan metadata:** committed as part of this finalization step (docs commit, see below)

## Files Created/Modified
- `scripts/checkpoint1_install_validate.sh` - Reusable install-validation capture wrapper for Checkpoint 1 (and reusable for ship-time Checkpoint 2)
- `.gitignore` - Added `.claude/settings.local.json` (the `--scope local` install writes this test-scope file)
- `.planning/phases/05-packaging-validation-credibility-polish/05-checkpoint1-transcript.md` - Captured transcript evidence of the full gate run

## Decisions Made
- Checkpoint 2 (github-source install) deliberately deferred to the ship step after Phase 5 is pushed — the remote is behind local HEAD, so testing the github source now would test stale content, not this phase's final state.
- The unconfirmed v2.1.201 "0 skills" regression (Pitfall #2 / T-05-10) did not reproduce on this environment; the real, authoritative `claude plugin details` output showed both skills on the first attempt, so no symlink workaround was needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `claude plugin marketplace add .` failed to resolve; switched to `./`**
- **Found during:** Task 1 (wrapper authoring, discovered when Task 2 first executed it)
- **Issue:** The bare `.` path argument to `claude plugin marketplace add` did not resolve reliably as a local-source path.
- **Fix:** Changed the wrapper to use `./` explicitly.
- **Files modified:** scripts/checkpoint1_install_validate.sh
- **Verification:** Re-ran the wrapper; `marketplace add` step passed.
- **Committed in:** 2e28fed

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Minor CLI-argument fix necessary for the gate to run at all. No scope creep; no architectural change.

## Issues Encountered
None beyond the auto-fixed CLI argument issue above.

## User Setup Required
None - no external service configuration required. This plan required a human-verify checkpoint (Task 3), which the user approved after independently reviewing the transcript and confirming the invariants (marketplace.json unchanged, settings.local.json untracked, Skills (2) present).

## Next Phase Readiness
- Phase 5 (and the v1.0 milestone) is now fully executed: packaging, secret hygiene, README/CONTRIBUTING refresh, and this final install-validation gate all landed.
- Checkpoint 2 (true github-source install) remains as an explicit, documented ship-time follow-up to run once Phase 5's commits are pushed to the remote — not a blocker for this plan or phase completion.
- No blockers carried forward.

---
*Phase: 05-packaging-validation-credibility-polish*
*Completed: 2026-07-27*

## Self-Check: PASSED

All claimed files found on disk (scripts/checkpoint1_install_validate.sh, 05-checkpoint1-transcript.md, 05-05-SUMMARY.md). All claimed commits found in git log (630cb22, 2e28fed, 4c8b451).
