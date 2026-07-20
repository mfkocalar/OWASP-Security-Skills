---
phase: 01-plugin-marketplace-foundation
fixed_at: 2026-07-20T13:05:00Z
review_path: .planning/phases/01-plugin-marketplace-foundation/01-REVIEW.md
iteration: 1
findings_in_scope: 2
fixed: 2
skipped: 1
status: partial
---

# Phase 1: Code Review Fix Report

**Fixed at:** 2026-07-20T13:05:00Z
**Source review:** .planning/phases/01-plugin-marketplace-foundation/01-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope (critical + warning, per `fix_scope: critical_warning`): 2 (WR-01, WR-02)
- Fixed: 2
- Skipped: 1 (WR-03, noted below though outside declared fix scope for completeness)

Note: `fix_scope` for this run is `critical_warning`, which includes all `WR-*` findings. `01-REVIEW.md`
reported 0 critical findings and 3 warnings (WR-01, WR-02, WR-03). WR-01 and WR-02 were fixed. WR-03
was assessed and skipped because it is already formally deferred to Phase 5 in `.planning/STATE.md`
(see reasoning below) rather than left unaddressed by omission.

## Fixed Issues

### WR-01: `install.sh`'s post-call `if [ $? -eq 0 ]` checks are dead code under `set -e`

**Files modified:** `install.sh`
**Commit:** `0dc113d`
**Applied fix:** Replaced the `install_skill ...; if [ $? -eq 0 ]; then ... fi` pattern in all three
menu branches (choice 1 "Claude Desktop", choice 2 "GitHub Copilot", choice 3 "Custom path") with
`if install_skill ...; then ... fi`. This makes `install_skill`'s exit status participate directly in
the `if` conditional, which is exempt from `set -e`'s implicit-exit rule, so the failure branch (or,
here, simply skipping the success-path echo block) now actually executes when `install_skill` returns
non-zero, instead of being unreachable dead code.

Verified: `bash -n install.sh` passes; `printf '4\n' | bash install.sh` (happy path, verification-only
menu choice) still exits 0 with all checks passing.

### WR-02: Custom install path (menu option 3) allows directory-traversal outside `$SKILLS_BASE`

**Files modified:** `install.sh`
**Commit:** `64c3782`
**Applied fix:** Added a guard immediately after the existing empty-path check in the choice-3 branch
that rejects any `custom_path` containing a `..` substring:
```bash
if [[ "$custom_path" == *".."* ]]; then
    echo -e "${RED}Error: Custom path must not contain '..'${NC}"
    exit 1
fi
```
This blocks traversal segments (e.g. `../../../../tmp/evil`) before `install_skill` builds
`install_dir` and performs `mkdir -p` / `ln -s`, so a malicious or malformed custom path can no longer
escape `$SKILLS_BASE`.

Verified: `bash -n install.sh` passes; happy path (`printf '4\n' | bash install.sh`) still exits 0;
traversal repro (`printf '3\n../../../../tmp/evil\n' | bash install.sh`) now exits 1 with the new error
message instead of proceeding to create directories/symlinks outside the intended base.

## Skipped Issues

### WR-03: `README.md`'s "Documentation" section links to stale `DEPLOYMENT.md`/`TESTING.md`

**File:** `README.md:124-129`
**Reason:** This finding is already formally deferred to Phase 5 in `.planning/STATE.md` (line 77:
"DEPLOYMENT.md/TESTING.md staleness tracked for Phase 5"; line 88: full deferral entry citing
`01-RESEARCH.md` Open Question #1). The review's own suggested fix explicitly frames a full correction
as "out of this phase's declared scope." Rather than perform an out-of-scope rewrite of
`DEPLOYMENT.md`/`TESTING.md` (which still reference the deleted root `skill.json` and root `examples/`
directory in numerous places) as a side effect of this fix pass, the finding is left to the already-
scheduled Phase 5 doc-polish work. No code or doc change was made for this finding in this run.
**Original issue:** `README.md`'s Documentation section links to `DEPLOYMENT.md` and `TESTING.md`
without qualification, but both target files still describe the removed `skill.json` and `examples/`
paths, so a reader following those links would run commands against paths that no longer exist.

---

_Fixed: 2026-07-20T13:05:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
