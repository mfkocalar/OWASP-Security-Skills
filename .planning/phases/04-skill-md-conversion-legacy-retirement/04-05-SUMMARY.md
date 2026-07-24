---
phase: 04-skill-md-conversion-legacy-retirement
plan: 05
subsystem: docs
tags: [markdown, install.sh, agent-skills, legacy-retirement]

# Dependency graph
requires:
  - phase: 04-skill-md-conversion-legacy-retirement
    provides: "04-04 repointed all in-skill example headers away from the legacy comprehensive guide, leaving the loaded path clean of references before this plan's delete"
provides:
  - "Repo-root owasp-css.instructions.md deleted (legacy Copilot-style routing file)"
  - "Repo-root owasp-comprehensive-security-skills.md deleted (~900-line legacy monolith)"
  - "skills/owasp-security-audit/owasp-security-audit.md deleted (in-skill duplicate of SKILL.md)"
  - "install.sh minimally patched: sentinel repointed to .claude-plugin/plugin.json; required_files trimmed to README.md only"
affects: [phase-05-packaging-polish]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Delete + installer patch shipped in the SAME commit so main stays installable at every commit boundary (Phase 1/2/3 discipline continued)"

key-files:
  created: []
  modified:
    - install.sh

key-decisions:
  - "Salvage-check confirmed both legacy files are fully superseded (D-02) — safe to delete with no content loss"
  - "In-skill duplicate owasp-security-audit.md had actually DIVERGED from SKILL.md (not byte-identical as originally verified during context-gathering) because Phases 04-02/03/04 patched SKILL.md but never touched the duplicate — divergence strengthens rather than weakens the case for deletion since the duplicate now carries strictly stale content (old ASVS 5.0 phrasing, unsplit llm-agentic.md reference)"
  - "install.sh sentinel repointed to .claude-plugin/plugin.json (recommended target, confirmed present) rather than any other surviving file"

requirements-completed: [FMT-04]

coverage:
  - id: D1
    description: "Three legacy files (owasp-css.instructions.md, owasp-comprehensive-security-skills.md, skills/owasp-security-audit/owasp-security-audit.md) removed from the git-tracked/loaded path"
    requirement: "FMT-04"
    verification:
      - kind: other
        ref: "git ls-files | grep -E '^owasp-css\\.instructions\\.md$|^owasp-comprehensive-security-skills\\.md$|^skills/owasp-security-audit/owasp-security-audit\\.md$' → empty"
        status: pass
    human_judgment: false
  - id: D2
    description: "install.sh remains installable after the delete — sentinel repoints to .claude-plugin/plugin.json, required_files trimmed, syntactically valid, no dangling references"
    requirement: "FMT-04"
    verification:
      - kind: other
        ref: "bash -n install.sh; grep -cE 'owasp-comprehensive-security-skills|owasp-css' install.sh == 0; grep -c plugin.json install.sh >= 1"
        status: pass
      - kind: manual_procedural
        ref: "echo 4 | bash install.sh (test-only path) — verified README.md + 12 example files, no false directory error; also exercised option 3 (custom path install) against a scratch directory to confirm the sentinel fix works on the real install path, not just test-only"
        status: pass
    human_judgment: false
  - id: D3
    description: "Salvage-check gate: confirmed no unique still-current content exists only in the deleted 900-line file, and the loaded path (skills/) was already clean of references before deletion"
    verification:
      - kind: manual_procedural
        ref: "Section-by-section skim of owasp-comprehensive-security-skills.md against skills/owasp-security-audit/references/*.md — all six sections (Top 10 2021, ASVS, MASVS, API Security, Kubernetes, Agentic 2026) confirmed superseded by refreshed per-skill reference files; grep -rl skills/ for both doomed filenames returned clean"
        status: pass
    human_judgment: false

duration: 5min
completed: 2026-07-24
status: complete
---

# Phase 4 Plan 5: Legacy File Retirement & Installer Patch Summary

**Deleted the three FMT-04 legacy files (owasp-css.instructions.md, the 900-line comprehensive guide, and its in-skill duplicate) and minimally patched install.sh's sentinel/required_files in the same commit so main stays installable.**

## Performance

- **Duration:** 5 min
- **Started:** 2026-07-24T14:19:16Z
- **Completed:** 2026-07-24T14:23:48Z
- **Tasks:** 2 completed
- **Files modified:** 4 (3 deletions, 1 edit)

## Accomplishments
- Salvage-check gate run before any deletion: confirmed the ~900-line comprehensive guide's six sections (Top 10 2021, ASVS, MASVS, API Security, Kubernetes, Agentic Applications 2026) are all superseded by the refreshed per-skill `references/` tree built in Phases 2–3 and 04-02; no unique still-current content found.
- Deleted `owasp-css.instructions.md` (repo root, 114 lines), `owasp-comprehensive-security-skills.md` (repo root, ~900 lines), and `skills/owasp-security-audit/owasp-security-audit.md` (in-skill duplicate) in a single commit.
- Patched `install.sh` in the same commit: repointed the `install_skill()` directory sentinel from the now-deleted comprehensive file to `.claude-plugin/plugin.json`, and trimmed `verify_installation()`'s `required_files` array down to `README.md`.
- Verified `install.sh` stays installable: `bash -n` passes, zero remaining references to either deleted filename, sentinel confirmed present via both the test-only path and a real custom-path install against a scratch directory.

## Task Commits

Each task was committed atomically:

1. **Task 1: Salvage-check gate (no deletion)** — no commit (verification-only task; no files changed, per plan instruction "Do NOT delete anything in this task")
2. **Task 2: Delete the three legacy files + minimal install.sh patch** - `563aad2` (chore)

**Plan metadata:** (final docs commit recorded below)

## Files Created/Modified
- `install.sh` - Directory sentinel repointed from the deleted `owasp-comprehensive-security-skills.md` to `.claude-plugin/plugin.json`; `required_files` array in `verify_installation()` trimmed from 3 entries to just `README.md`
- `owasp-css.instructions.md` - Deleted (legacy Copilot-style routing file, fully subsumed by SKILL.md descriptions)
- `owasp-comprehensive-security-skills.md` - Deleted (~900-line legacy monolith, superseded by per-skill references/ tree)
- `skills/owasp-security-audit/owasp-security-audit.md` - Deleted (in-skill duplicate of SKILL.md)

## Decisions Made
- Confirmed via salvage-check that all content in the deleted 900-line file is superseded — no salvage needed, clean delete proceeded as the plan's expected default path.
- Deviation noted (see below): the in-skill duplicate had diverged from SKILL.md since the original context-gathering verification, but the divergence only confirms staleness (not uniqueness), so the delete decision (D-02) stands unchanged.
- install.sh patch scoped strictly to the sentinel line and the `required_files` array, per plan's "do NOT rewrite install.sh beyond these two regions" instruction — full install.sh rework remains Phase 5 scope.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug/stale finding, not a functional bug] Duplicate file diff was not byte-identical as the plan assumed**
- **Found during:** Task 1 (Salvage-check gate)
- **Issue:** The plan's acceptance criteria assumed `diff -q skills/owasp-security-audit/SKILL.md skills/owasp-security-audit/owasp-security-audit.md` would report the files identical (verified true during 04-CONTEXT gathering on 2026-07-23). By execution time, the diff showed 4 hunks of difference: the ASVS phrasing ("ASVS 5.0" vs. the 04-03-hardened "ASVS (4.0.3-numbered verification requirements; 5.0.0 is the current edition)"), the routing table's llm-agentic.md single-row entry vs. the 04-04-split llm.md/agentic.md two-row entry, and the corresponding reference-list prose. This is because Phases 04-02/03/04 patched only the authoritative `SKILL.md`, never the secondary in-skill duplicate.
- **Fix:** Re-verified the intent of the salvage-check (does the duplicate carry any unique, still-current content?) rather than the literal byte-identical acceptance line. Confirmed the duplicate carries strictly *older, now-superseded* content and nothing unique/current — the divergence makes the case for deletion stronger, not weaker, since keeping it around would reintroduce stale ASVS/llm-agentic phrasing into the loaded path. Proceeded with the planned delete.
- **Files modified:** None beyond the planned deletion.
- **Verification:** `diff` output manually reviewed line-by-line; confirmed every difference is SKILL.md having been updated (never the reverse) by Phases 04-02/03/04.
- **Committed in:** 563aad2 (Task 2 commit — the delete itself; Task 1 was verification-only, no commit)

---

**Total deviations:** 1 auto-fixed (0 functional bugs — a finding that refined the salvage-check's literal acceptance criterion without changing its outcome)
**Impact on plan:** No scope creep. The plan's delete decision (D-02) and outcome are unchanged; only the salvage-check's supporting evidence differs from what was assumed at context-gathering time.

## Issues Encountered
None beyond the salvage-check finding documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- FMT-04 fully satisfied: all three legacy files are out of the tracked/loaded path, and `install.sh` remains functional (verified via both the test-only path and a real custom-path install).
- **Known, tracked gap (by explicit scope decision, not an oversight):** `README.md`, `DEPLOYMENT.md`, `TESTING.md`, `CONTRIBUTING.md`, and this repo's own `.claude/CLAUDE.md` still reference the now-deleted legacy filenames. This is deferred to Phase 5 (PKG/QUAL/ADPT doc-polish) per the plan's `<deferred_and_known_gaps>` section — record this in the eventual PR description so a reviewer does not flag it as a missed cross-reference.
- Phase 4 plans 1–5 are now all complete; phase-level completion and verification remain the orchestrator's responsibility (not marked here per this execution's scope guard).

## Known Stubs
None.

## Threat Flags
None — this plan only deletes files and patches install.sh's existing sentinel/required_files logic; no new network endpoints, auth paths, or trust-boundary surface introduced.

---
*Phase: 04-skill-md-conversion-legacy-retirement*
*Completed: 2026-07-24*

## Self-Check: PASSED

- FOUND: .planning/phases/04-skill-md-conversion-legacy-retirement/04-05-SUMMARY.md
- CONFIRMED DELETED: owasp-css.instructions.md
- CONFIRMED DELETED: owasp-comprehensive-security-skills.md
- CONFIRMED DELETED: skills/owasp-security-audit/owasp-security-audit.md
- FOUND commit: 563aad2
