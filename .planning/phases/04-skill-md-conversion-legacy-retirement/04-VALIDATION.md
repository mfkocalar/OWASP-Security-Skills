---
phase: 04
slug: skill-md-conversion-legacy-retirement
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-24
---

# Phase 04 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> This is a **documentation/file-restructuring** phase — validation is
> mechanical lint/grep/git checks plus a manual code re-read for CONT-06,
> not an application test suite. Derived from 04-RESEARCH.md § Validation
> Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | None — docs-only phase; no test runner in this repo (a stated project constraint: no heavy runtime deps) |
| **Config file** | none |
| **Quick run command** | `python3 scripts/lint_skill_md.py` (stdlib-only FMT-01/02/05 lint — Wave 0 artifact; exact path is planner's call) |
| **Full suite command** | Full sweep: lint script + `wc -l skills/*/SKILL.md` + FMT-04 `git ls-files` check + FMT-05 bundled-dir check + cross-reference grep (all commands in 04-RESEARCH.md § Code Examples) |
| **Estimated runtime** | ~5 seconds (pure lint/grep/git — no build, no network) |

---

## Sampling Rate

- **After every task commit:** Run the relevant grep/wc/lint check for the file(s) just touched
- **After every plan wave:** Run the full Code Examples command block (FMT-04 + FMT-05 + cross-reference sweep) once
- **Before `/gsd-verify-work`:** All five FMT + CONT-06 checks green; manual read-through confirming `prompt-injection.txt`'s four AG-codes are individually corrected and `install.sh`'s sentinel patch is in place
- **Max feedback latency:** ~5 seconds

---

## Per-Task Verification Map

> Task IDs are assigned by the planner. This table is populated per plan/task
> during planning; the requirement→check mapping below is the authoritative
> source the planner lifts `<verify>` blocks and `must_haves` from.

| Req ID | Behavior | Test Type | Automated Command | File Exists |
|--------|----------|-----------|-------------------|-------------|
| FMT-01 | `name` (≤64, folder-match, no reserved words) + non-empty `description` (≤1024) on both SKILL.md | script | `python3 scripts/lint_skill_md.py` (regex extraction, no PyYAML) | ❌ W0 |
| FMT-02 | Both SKILL.md bodies ≤~500 lines (guidance, flag don't hard-fail) | shell | `wc -l skills/*/SKILL.md` | ✅ |
| FMT-03 | Description carries routing/activation load (no legacy trigger file needed) | grep + manual | `grep -c "Use this skill\|Use when" skills/*/SKILL.md` (non-zero) + manual read | ✅ |
| FMT-04 | Legacy files gone from git-tracked/loaded path | shell | `git ls-files \| grep -E '^owasp-css\.instructions\.md$\|^owasp-comprehensive-security-skills\.md$\|^skills/owasp-security-audit/owasp-security-audit\.md$'` → empty | ✅ |
| FMT-05 | Frontmatter lint: byte-0 start, no `<`/`>` in `description`, only `references/`\|`scripts/`\|`assets/` bundled dirs | script + shell | lint script (byte-0 + angle-bracket) + `find skills -mindepth 2 -maxdepth 2 -type d \| grep -vE "/(references\|scripts\|assets)$"` → empty | ❌ W0 (same script as FMT-01) |
| CONT-06 | Every example relabeled to correct 2025 ID **by topic** + code re-validated + dead cross-refs repointed | grep + **manual** | `grep -rn "AG0[0-9]\|A05: Security Misconfiguration\|2017 edition\|owasp-comprehensive-security-skills" skills/owasp-security-audit/assets/examples/` → empty, **plus** manual code re-read against `top10.md`/`llm.md`/`agentic.md` | ✅ (manual review required — code correctness is not grep-provable) |

---

## Wave 0 Requirements

- [ ] `scripts/lint_skill_md.py` — small **stdlib-only** (no PyYAML — it is unavailable in-env) Python lint script covering FMT-01/FMT-02/FMT-05, matching `quick_scan.py`'s single-file dependency-free style (~40 lines). Path is planner's discretion (repo-root `scripts/` can lint both skills from one place, vs. per-skill `scripts/`).
- [ ] No conftest/fixtures needed — documentation repo, no application test suite.

*Everything else uses existing `git`/`grep`/`wc`/`find` — no new infrastructure.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Each example's vulnerable/secure **code** still correctly demonstrates its (newly-relabeled) category against the 2025 requirement text | CONT-06 | Code semantic correctness is not grep-provable; e.g. SSRF now folds into A01 (CWE-918), old-A05 misconfig→new-A02, old-A03 injection→new-A05 | Read each example; confirm the demonstrated behavior matches the topic of its new ID (per `top10.md`/`llm.md`/`agentic.md`), not just that the label string changed |
| `prompt-injection.txt`'s four AG-codes corrected **individually** (AG01→LLM01, AG03→LLM05, AG05→LLM10, AG06→LLM06/ASI02-03), not a blanket find-replace; stale "Preview/Draft" status line fixed | CONT-06 | The 4 codes map to *different* real items — a single regex substitution would be wrong | Read the file; confirm each header maps per 04-RESEARCH.md § AG-code remediation map; confirm no "Preview"/"Draft" survives |
| D-02 salvage-check: no unique still-current content exists **only** in the 900-line file before deleting | FMT-04 | Judgement call — "unique + still current" is not mechanically decidable | Run the cross-reference sweep + skim the 900-line file against the `references/` tree; confirm content is superseded before the delete commit |
| `install.sh` still installs after the delete (minimal sentinel + required_files patch) | (integration integrity, not a FMT/CONT req) | Requires running the installer's test path | `./install.sh` option 4 (test-only) from repo root succeeds — no "run from the OWASP-Security-Skills directory" false error |

---

## Validation Sign-Off

- [ ] All tasks have an `<automated>` verify or a Wave 0 dependency (lint script), except the CONT-06 code-correctness + D-02 salvage checks, which are declared Manual-Only above
- [ ] Sampling continuity: no 3 consecutive tasks without an automated check
- [ ] Wave 0 covers the MISSING reference (the lint script)
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter (by validator after planning)

**Approval:** pending
