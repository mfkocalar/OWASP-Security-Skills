---
phase: 1
slug: plugin-marketplace-foundation
status: final
nyquist_compliant: true
wave_0_complete: false
created: 2026-07-19
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Finalized 2026-07-19 after plan-checker VERIFICATION PASSED (Nyquist checks 8a–8d green).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | None — pure Markdown/JSON/shell repo; verification is CLI + inline shell assertions |
| **Config file** | none — no test-runner infrastructure is needed (see Wave 0) |
| **Quick run command** | `claude plugin validate . --strict` (CLI confirmed present at v2.1.201 during planning) |
| **Full suite command** | `claude plugin validate . --strict && printf '4\n' | bash install.sh` (option 4, test-only) |
| **Estimated runtime** | ~5 seconds |

> **CLI fallback (from RESEARCH.md):** if the `claude plugin` subcommand is ever unavailable, fall back to per-task JSON-validity + allowlist assertions (`python3 -m json.tool` + field-set checks) plus manual field-set review against `01-RESEARCH.md`'s confirmed schema tables. Every task's `<verify>` block already encodes this fallback.

---

## Sampling Rate

- **After every task commit:** Run `claude plugin validate . --strict` (once `.claude-plugin/` exists) — else the task's inline `python3`/`find`/`grep` assertion
- **After every plan wave:** Run `claude plugin validate . --strict && printf '4\n' | bash install.sh` (option 4)
- **Before `/gsd-verify-work`:** Full suite green; all 9 README example links resolve; `docs/SKILL-STRUCTURE.md` matches the real skill layout
- **Max feedback latency:** ~5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | Tooling Ready | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|---------------|--------|
| 01-01-T1 | 01-01 | 1 | PKG-01 | T-01-02 / T-01-03 | `plugin.json` carries only official-schema fields; identity `owasp-security-skills` / `0.1.0` (D-01/02/03) | smoke | `python3 -m json.tool` + top-key allowlist assert (+ `claude plugin validate . --strict`) | ✅ | ⬜ pending |
| 01-01-T2 | 01-01 | 1 | PKG-02 | T-01-01 | `marketplace.json` lists exactly 1 plugin via a github source object; name not reserved (D-04) | smoke | `python3` source/owner/reserved-name assert (+ `claude plugin validate . --strict`) | ✅ | ⬜ pending |
| 01-02-T1 | 01-02 | 1 | PKG-03 / SC4 | T-01-04 | `docs/SKILL-STRUCTURE.md` documents the SKILL.md+references/+scripts/+assets/ convention unambiguously (D-07) | manual + grep | `test -f` + grep four convention elements + CONVENTIONS.md xref (+ human-check) | ✅ | ⬜ pending |
| 01-02-T2 | 01-02 | 1 | PKG-03 | T-01-04 | no symlinks in skills tree; both skills at plugin root; per-skill `assets/examples/` | scripted | `find skills -type l` == 0 + dir-exists + example-count checks | ✅ | ⬜ pending |
| 01-03-T1 | 01-03 | 2 | PKG-03 / D-06 | T-01-05 | `install.sh` patched (drop skill.json from `required_files`; repoint examples-count path) | smoke | `bash -n install.sh` + grep per-skill examples path | ✅ | ⬜ pending |
| 01-03-T2 | 01-03 | 2 | PKG-03 / D-06 | T-01-05 | all README example links repoint to per-skill canonical paths (no broken root link) | smoke | file-exists loop over 9 targets + `grep -c` ≥ 9 (+ human-check) | ✅ | ⬜ pending |
| 01-03-T3 | 01-03 | 2 | PKG-03 / D-05, D-08 | T-01-06 / T-01-07 | root `skill.json` + `examples/` removed behind byte-identical guard; deferral tracked; install.sh option 4 exits 0 | smoke | `test ! -e` guards + `printf '4\n' \| bash install.sh` exit 0 | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*
*Tooling Ready: all verify commands use already-present tools (python3, find, grep, bash, and the `claude` CLI); no test framework needs installing.*

---

## Wave 0 Requirements

*No test-infrastructure Wave 0 is required.* This repo is intentionally test-runner-free (Markdown/JSON/shell only); `claude plugin validate` plus inline shell assertions ARE the verification mechanism for this phase's domain. The three deliverable files below are authored by their owning tasks (not test stubs):

- [ ] `.claude-plugin/plugin.json` — core deliverable of PKG-01 (task 01-01-T1)
- [ ] `.claude-plugin/marketplace.json` — core deliverable of PKG-02 (task 01-01-T2)
- [ ] `docs/SKILL-STRUCTURE.md` — core deliverable of D-07/SC4 (task 01-02-T1)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `docs/SKILL-STRUCTURE.md` documents the convention unambiguously | SC4 | Doc-content correctness is not machine-assertable | Plan-checker/human review against the confirmed directory-convention facts in `01-RESEARCH.md` |
| README "Examples" section + structure diagram show no bare root `examples/` link | PKG-03 / D-06 | Prose/link-context correctness beyond a target-exists grep | Skim the README Examples section; confirm every listed sample resolves to a per-skill path |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or documented fallback (plan-checker Dimension 8a: PASS)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (Dimension 8c: PASS)
- [x] Wave 0 covers all MISSING references (none exist — Dimension 8d: PASS)
- [x] No watch-mode flags (Dimension 8b: PASS)
- [x] Feedback latency < 10s (~5s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-19 (plan-checker VERIFICATION PASSED; `wave_0_complete` flips true during execution)
