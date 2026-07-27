---
phase: 05-packaging-validation-credibility-polish
reviewed: 2026-07-27T00:00:00Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - .claude-plugin/marketplace.json
  - .claude-plugin/plugin.json
  - docs/SKILL-STRUCTURE.md
  - scripts/check_version_drift.py
  - scripts/checkpoint1_install_validate.sh
  - skills/owasp-security-audit/assets/examples/cryptographic-failures.js
  - skills/owasp-security-audit/assets/examples/k8s-rbac.yaml
  - skills/owasp-security-audit/assets/examples/prompt-injection.txt
  - skills/secure-coding-practices/assets/examples/vulnerable-examples.js
  - skills/secure-coding-practices/assets/examples/vulnerable-examples.py
findings:
  critical: 0
  warning: 6
  info: 3
  total: 9
status: issues_found
---

# Phase 05: Code Review Report

**Reviewed:** 2026-07-27
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

Reviewed the Phase 5 packaging/validation artifacts: the two plugin manifests, the structure doc, the version-drift checker, the checkpoint install-validation script, and five OWASP example files. Per the review brief, the deliberately-vulnerable teaching code and self-labeling placeholder secrets in the example files were treated as intentional and not flagged.

Both scripts pass syntax checks (`python3 -m py_compile`, `bash -n`). `check_version_drift.py` is well-constructed and its narrow-matcher design correctly avoids flagging OWASP edition numbers. No Critical/Blocker defects were found. The substantive concerns are in `checkpoint1_install_validate.sh` (a revert-safety window, a false-fail gate condition, missing teardown, and undocumented step status), a documentation-accuracy drift in `SKILL-STRUCTURE.md` where quoted "verbatim" frontmatter no longer matches the on-disk `SKILL.md` files (and still cites the superseded "OWASP Top 10 (2021)" edition), and a version-number regression between `plugin.json` (1.0.0) and the project's documented 1.1.0 history. Findings in the SECURE-labeled example blocks are noted separately because a security-education repo's *secure* exemplars must not mis-teach.

## Narrative Findings (AI reviewer)

## Warnings

### WR-01: SKILL-STRUCTURE.md quotes stale frontmatter and a superseded OWASP edition

**File:** `docs/SKILL-STRUCTURE.md:36` and `docs/SKILL-STRUCTURE.md:45`
**Issue:** The doc presents these as verbatim quotes ("Real example ... first 3 lines" and "Second confirming example ... first 3 lines"), but neither matches the current on-disk `SKILL.md`:
- Line 36 quotes `OWASP Top 10 (2021), ASVS 5.0`. The live `skills/owasp-security-audit/SKILL.md` now reads `OWASP Top 10 (2025), ASVS (4.0.3-numbered verification requirements; 5.0.0 is the current edition)`.
- Line 45 quotes the SCP description as `Audit code against the OWASP Secure Coding Practices Quick Reference Guide checklist. Covers 14 critical domains ...`. The live `skills/secure-coding-practices/SKILL.md` has been rewritten to `Audit code against a 14-domain secure coding checklist derived from OWASP's living sources — the Developer Guide, Cheat Sheet Series, and Proactive Controls — with the original ... Quick Reference Guide noted only as the archived historical origin.`

This directly touches the repo's stated CRITICAL accuracy constraint (every OWASP version/edition must be correct): the doc still advertises the superseded "OWASP Top 10 (2021)" as the canonical structure example, and a contributor copying this template would reintroduce the outdated edition.
**Fix:** Replace both quoted blocks with the current frontmatter copied verbatim from the two `SKILL.md` files, or mark them as illustrative-only and add a note that the authoritative text lives in the skills. Best: derive the quote programmatically (or add a doc-drift check) so the two cannot desync again.

### WR-02: Revert safety window — OVERRIDE_APPLIED set after the mutation, not before

**File:** `scripts/checkpoint1_install_validate.sh:90-99`
**Issue:** The byte-exact backup is taken at line 90, the JSON mutation runs at lines 91-98, and `OVERRIDE_APPLIED=1` is only set at line 99. `revert_override()` is gated on `OVERRIDE_APPLIED -eq 1`. If the inline `python3` write partially writes / truncates `marketplace.json` and then fails (`set -e` aborts), the EXIT trap fires but skips the restore because the flag is still `0` — leaving a corrupted `marketplace.json` on disk despite a valid backup existing. The flag should guard on "backup exists and file may be mutated," which becomes true the moment the mutation is attempted.
**Fix:**
```bash
cp "$MARKETPLACE_JSON" "$BACKUP_FILE"
OVERRIDE_APPLIED=1   # arm the revert BEFORE mutating, so a failed write is still restored
python3 -c "..."
```

### WR-03: Clean-revert gate false-fails when marketplace.json has pre-existing uncommitted edits

**File:** `scripts/checkpoint1_install_validate.sh:146-152`
**Issue:** Step 6 asserts success via `git diff --quiet "$MARKETPLACE_JSON"`. The revert restores the byte-exact backup captured at *script start* (line 90), i.e. the on-disk state — which may already contain staged/unstaged edits. If the working tree was not clean for this file when the script started, the revert is correct (restores start state) yet `git diff --quiet` still reports a diff and the gate prints `[FAIL] ... still shows a diff after revert`. The gate conflates "my override was reverted" with "file matches HEAD."
**Fix:** Either assert a clean tree for the file at startup (`git diff --quiet "$MARKETPLACE_JSON"` before Step 2, abort if dirty), or verify the revert by comparing against the backup (`cmp -s "$BACKUP_FILE" "$MARKETPLACE_JSON"`) instead of against HEAD.

### WR-04: No teardown of the local marketplace / installed plugin — breaks the documented reusability

**File:** `scripts/checkpoint1_install_validate.sh:106-121`
**Issue:** The script registers a local marketplace (`claude plugin marketplace add ./ --scope local`, line 107) and installs the plugin (line 116) but never removes/uninstalls them; only the `marketplace.json` file edit is reverted. The header (lines 18-20) claims the sequence is "Reusable ... intended to be re-run." On a second run, `claude plugin marketplace add ./ --scope local` is likely to fail with an "already exists" error (or install a duplicate), so under `set -e` the re-run aborts at Step 3 — contradicting the reusability claim and leaving stale local state after every run.
**Fix:** Add an EXIT-trap teardown (`claude plugin uninstall ... --scope local`; `claude plugin marketplace remove ... --scope local`), or make Step 3 idempotent (detect an existing registration and skip/refresh). At minimum, document that manual cleanup is required between runs.

### WR-05: Steps 5a/5b emit no [PASS]/[FAIL] line, contradicting the stated design rule

**File:** `scripts/checkpoint1_install_validate.sh:124-140`
**Issue:** The header design rules (line 26) state "Every step prints a clear [PASS]/[FAIL] line to the transcript," but the discovery smoke-test steps (5a `plugin details`, 5b `plugin list --json`) only tee raw output — no explicit status line. Because `set -euo pipefail` is active, a failure aborts the script, but the committed transcript (public phase evidence) then contains no pass/fail marker for the D-02 discovery check, weakening the evidence trail and diverging from every other step's format.
**Fix:** Wrap 5a/5b in `if ...; then echo "[PASS] ..."; else echo "[FAIL] ..."; exit 1; fi` like Steps 1/3/4, so each discovery check records an explicit status line.

### WR-06: plugin.json version 1.0.0 regresses from the documented 1.1.0

**File:** `.claude-plugin/plugin.json:5`
**Issue:** `version` is `1.0.0`. The project record (CLAUDE.md → Version Management) documents `1.1.0` as the current production version whose scope was "Added Secure Coding Practices skill, organized packaged skills with references/assets" — exactly the content this plugin now bundles (both `owasp-security-audit` and `secure-coding-practices`). Publishing the public plugin as `1.0.0` is a backward version step that can confuse users who already have 1.1.0 and undermines the "worth sharing" credibility goal. `check_version_drift.py` will not catch this — it treats `plugin.json` as canonical and does not scan CLAUDE.md or historical manifests. (README badge is consistent at 1.0.0; `skill.json` no longer exists, so drift within scanned files is clean.)
**Fix:** Confirm whether a deliberate version reset for the new plugin-format identity is intended. If not, bump `plugin.json` `version` (and the README badge) to `1.1.0` or higher so the public artifact does not regress below the documented release.

## Info

### IN-01: check_version_drift.py Version-label matcher misses heading-prefixed lines

**File:** `scripts/check_version_drift.py:55-57`
**Issue:** `LABEL_VERSION_RE` anchors on `^\s*\**version` — a line must begin with optional whitespace/asterisks then `version`. A Markdown heading such as `## Version: 1.2.3`, or any `Foo version: x.y.z`, is not scanned (the `#`/prefix chars break the anchor). This is a deliberate narrow scope, but it is a genuine blind spot: a drifted version written as a heading in README would pass silently.
**Fix:** If heading-style version lines are expected in README, extend the anchor to tolerate a leading `#+\s*` (e.g. `^\s*#*\s*\**version...`). Otherwise, document the blind spot in the module docstring alongside the existing OWASP-edition rationale.

### IN-02: prompt-injection.txt "EVEN MORE SECURE" block contradicts its own lesson

**File:** `skills/owasp-security-audit/assets/examples/prompt-injection.txt:69-77`
**Issue:** In a SECURE-labeled block (not the intentionally-vulnerable teaching half), the "EVEN MORE SECURE" example builds `ConversationChain(prompt_template="Helpful assistant. Answer {user_input}", ...)`, re-embedding user input into a template string. That re-introduces the string-interpolation pattern the immediately-preceding SECURE example (lines 48-67) teaches readers to avoid via message/role separation. As a *secure* exemplar in a security-education reference, it mis-teaches.
**Fix:** Replace the `prompt_template` interpolation with a genuinely parameter-separated construction, or drop the "EVEN MORE SECURE" block, so the secure exemplar does not demonstrate the anti-pattern it warns against.

### IN-03: cryptographic-failures.js SECURE encryption uses a hardcoded scrypt salt

**File:** `skills/owasp-security-audit/assets/examples/cryptographic-failures.js:123,144`
**Issue:** In the SECURE-labeled `secure_encrypt_data`/`secure_decrypt_data`, key derivation uses `crypto.scryptSync(process.env.DATABASE_ENCRYPTION_KEY, 'salt', 32)` — a constant literal salt `'salt'`. A fixed salt defeats the purpose of salting the KDF; the correct lesson is a per-key random salt persisted alongside the ciphertext. Since this is the "secure" reference a reader will copy, the constant salt teaches a subtly weak pattern.
**Fix:** Generate a random salt (`crypto.randomBytes(16)`), derive the key from it, and store the salt with the `{iv, ciphertext, auth_tag}` payload; read it back for decryption. Note in a comment why a static salt is wrong.

---

_Reviewed: 2026-07-27_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
