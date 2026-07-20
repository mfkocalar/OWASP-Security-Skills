---
phase: 01-plugin-marketplace-foundation
reviewed: 2026-07-20T11:27:18Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - .claude-plugin/marketplace.json
  - .claude-plugin/plugin.json
  - README.md
  - docs/SKILL-STRUCTURE.md
  - install.sh
findings:
  critical: 0
  warning: 3
  info: 3
  total: 6
status: issues_found
---

# Phase 1: Code Review Report

**Reviewed:** 2026-07-20T11:27:18Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

Reviewed the two Claude Code packaging manifests (`.claude-plugin/plugin.json`,
`.claude-plugin/marketplace.json`), the patched `install.sh`, the repointed `README.md`, and the new
`docs/SKILL-STRUCTURE.md`.

Both JSON manifests are schema-correct: I ran `claude plugin validate .claude-plugin/plugin.json
--strict` and `claude plugin validate . --strict` (which resolves to the marketplace manifest when
both files are present at repo root) — both exit 0 with no warnings. Field sets match the official
closed schema exactly (no ported `skill.json` custom fields), the GitHub source object is well-formed
and points at the correct, git-remote-confirmed `mfkocalar/OWASP-Security-Skills` repo, and the
marketplace `name` is not on Anthropic's reserved-names list. `docs/SKILL-STRUCTURE.md`'s worked
example directory trees were checked against the live filesystem (`find skills -type f`, `find
skills -type l`) and match exactly — no drift, no symlinks. All 11 README example links (9 in
`owasp-security-audit`, 2 in `secure-coding-practices`) resolve to real files.

No blockers found. The findings below are quality/robustness issues in `install.sh`'s control flow
and one accuracy gap in `README.md`'s "Documentation" section — none of these break plugin
installation or validation, but they degrade the reliability of the legacy installer and the
accuracy of user-facing docs.

## Warnings

### WR-01: `install.sh`'s post-call `if [ $? -eq 0 ]` checks are dead code under `set -e` — the failure branch can never run

**File:** `install.sh:140-146` (choice 1), `install.sh:150-155` (choice 2), `install.sh:169-171` (choice 3)

**Issue:** The script sets `set -euo pipefail` (line 5), then in each menu branch calls
`install_skill ...` as a bare statement and checks its result on the *next* line:

```bash
install_skill "Claude Desktop" ".claude/skills/owasp-security"
if [ $? -eq 0 ]; then
    verify_installation "${SKILLS_BASE}/.claude/skills/owasp-security"
    ...
fi
```

Under `set -e`, a plain (non-conditional) command that returns non-zero terminates the script
immediately — the `if [ $? -eq 0 ]` line is never reached when `install_skill` fails, because bash's
`errexit` only exempts commands that are themselves part of an `if`/`while`/`until` test, a `&&`/`||`
list, or negated with `!`. A bare function-call statement followed by a separate `$?` check does not
qualify for the exemption.

I confirmed this exact pattern with an isolated repro (`set -euo pipefail; myfunc() { return 1; };
myfunc; if [ $? -eq 0 ]; then echo success; else echo failure; fi; echo after`) — the script exits at
`myfunc` with status 1, printing neither `failure` nor `after`. The net effect on this script's
success path is not currently observable as broken (install failure already halts the script via the
`EXIT` trap's generic "Installation interrupted or failed" message), but the `if` block is dead code
for the failure path and misleads any future maintainer who assumes it will run (e.g. if someone adds
an `else` branch with cleanup logic, that branch would never execute).

**Fix:** Either capture the status explicitly to defeat `errexit`'s implicit-exit rule, or restructure
as a proper conditional:

```bash
if install_skill "Claude Desktop" ".claude/skills/owasp-security"; then
    verify_installation "${SKILLS_BASE}/.claude/skills/owasp-security"
    echo -e "\n${GREEN}Next steps:${NC}"
    ...
fi
```

Apply the same fix to the choice-2 and choice-3 branches.

### WR-02: Custom install path (menu option 3) allows directory-traversal outside `$SKILLS_BASE`

**File:** `install.sh:157-171`

**Issue:** `custom_path` is read directly from user input with no validation beyond "non-empty":

```bash
if ! read -r -p "Enter custom installation path: " custom_path; then
    ...
fi
if [ -z "$custom_path" ]; then
    echo -e "${RED}Error: Custom path cannot be empty${NC}"
    exit 1
fi
install_skill "Custom" "$custom_path"
```

`install_skill` builds `install_dir="${SKILLS_BASE}/${skill_path}"` and then does
`mkdir -p "$(dirname "$install_dir")"` followed by `ln -s "$(pwd)" "$install_dir"`. If a user (or a
script driving this installer non-interactively) supplies a value containing `../` segments (e.g.
`../../../../tmp/evil`), the resulting path escapes `$SKILLS_BASE` entirely and the installer will
create directories and a symlink anywhere on the filesystem the invoking user has write access to.
This is a self-directed local action (the script only runs with the input the same user provides), so
impact is limited, but it's still a missing input-validation gap worth closing given the installer
also runs unattended in some workflows (e.g. CI verification with option 4).

**Fix:** Reject paths containing `..` segments or resolve/validate the final path stays under
`$SKILLS_BASE` before proceeding:

```bash
if [[ "$custom_path" == *".."* ]]; then
    echo -e "${RED}Error: Custom path must not contain '..'${NC}"
    exit 1
fi
```

### WR-03: `README.md`'s "Documentation" section links to `DEPLOYMENT.md`/`TESTING.md`, which still describe deleted `skill.json`/`examples/`

**File:** `README.md:124-129`

**Issue:** The patched README correctly repoints all 9 example links to
`skills/owasp-security-audit/assets/examples/` and `skills/secure-coding-practices/assets/examples/`,
but its "Documentation" section still links to `DEPLOYMENT.md` and `TESTING.md` without qualification:

```markdown
- [DEPLOYMENT.md](DEPLOYMENT.md) — installation and deployment options.
- [TESTING.md](TESTING.md) — how to verify the skill is installed and working.
```

Both target files still reference the now-deleted root `skill.json` (e.g. `TESTING.md:409` "Test 7.2:
skill.json Completeness", `DEPLOYMENT.md:126` "Edit `skill.json` for activation trigger
configuration") and the deleted root `examples/` directory (e.g. `TESTING.md:65`
`for file in examples/*.py examples/*.js ...`, `DEPLOYMENT.md:82-85` bare `examples/*.py` paths). A
user following the README to TESTING.md would run commands against paths that no longer exist. Per
`01-RESEARCH.md`'s Open Question 1, this staleness was explicitly flagged and deferred to a later
phase's full README/docs rewrite — noting it here so the gap is not silently lost, since the deferral
was recorded in planning artifacts but no forward-pointer to it exists in the shipped README itself.

**Fix (out of this phase's declared scope, but worth a one-line mitigation now):** Add a brief caveat
next to the two links, e.g. "(being updated for the new plugin packaging — see Phase 5)", or track the
gap explicitly in `STATE.md`'s blockers list per the research doc's own recommendation.

## Info

### IN-01: `install.sh:48` creates target directories before verifying the script is run from the repo root

**File:** `install.sh:39-54`

**Issue:** `install_skill()` runs `mkdir -p "$(dirname "$install_dir")"` (line 48) before the
repo-root check at line 51 (`if [ ! -f "owasp-comprehensive-security-skills.md" ]`). If the script is
invoked from the wrong directory, it will have already created (possibly nested) directories under
`$SKILLS_BASE` before erroring out, leaving stray empty directories behind.

**Fix:** Move the repo-root file check above the `mkdir -p` call.

### IN-02: `case $choice in` uses an unquoted variable

**File:** `install.sh:137`

**Issue:** `case $choice in` is unquoted. In this specific instance `$choice` has already been
validated against `^[1-5]$` (line 132), so there's no practical word-splitting risk today, but it's
inconsistent with the rest of the script's otherwise-careful quoting (`"$install_dir"`,
`"$custom_path"`, etc.) and is worth matching for consistency.

**Fix:** `case "$choice" in`

### IN-03: `install.sh:182-185` `*)` catch-all case is unreachable

**File:** `install.sh:137-186`

**Issue:** The `case $choice in ... *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;; esac` catch-all
branch can never execute, because `choice` is already validated against `^[1-5]$` at line 132 before
the `case` statement is reached, and cases `1`–`5` are all explicitly handled. This is harmless dead
code, not a bug, but worth trimming for clarity.

**Fix:** Remove the redundant `*)` branch, or remove the earlier regex validation if the `case`
statement is meant to be the sole validation point (not recommended, since removing it would also
remove the friendlier pre-`case` error message).

---

_Reviewed: 2026-07-20T11:27:18Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
