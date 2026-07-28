---
phase: 5
slug: packaging-validation-credibility-polish
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-27
updated: 2026-07-28
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from 05-RESEARCH.md §Validation Architecture. This repo intentionally
> has no pytest/jest framework ("no heavy runtime dependencies" constraint) —
> all checks are shell/stdlib-script-shaped.
>
> **Post-execution audit (2026-07-28):** all Wave-0 artifacts exist; all 7 automatable
> requirements verify green; the 2 semantic requirements (QUAL-01, QUAL-02) are
> legitimate manual-only checks and were independently confirmed by the phase
> verifier (05-VERIFICATION.md, status: passed, 16/16 must-haves).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | None — stdlib `python3` scripts + the custom `scripts/lint_skill_md.py` linter (Phase 4) and `scripts/check_version_drift.py` (Phase 5) |
| **Config file** | none |
| **Quick run command** | `python3 scripts/lint_skill_md.py skills --format text` |
| **Full suite command** | `python3 scripts/lint_skill_md.py skills --format text && python3 scripts/check_version_drift.py && claude plugin validate .` |
| **Estimated runtime** | ~5–15 seconds (lint + drift are sub-second; `claude plugin validate` dominates) |

---

## Sampling Rate

- **After every task commit:** Run the grep/JSON-field check for that task's specific requirement (fast, <5s each)
- **After every plan wave:** Run `python3 scripts/lint_skill_md.py skills --format text && python3 scripts/check_version_drift.py && claude plugin validate .`
- **Before `/gsd-verify-work`:** Full Checkpoint-1 sequence (validate + local-source override install + `claude plugin details`) captured to a phase artifact, AND every unit-level grep/JSON check green
- **Max feedback latency:** ~15 seconds

---

## Per-Task Verification Map

> Audited post-execution against the real repo. All commands below were re-run on 2026-07-28.

| Requirement | Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|----------|-----------|-------------------|-------------|--------|
| PKG-04 | Plugin validates, installs, both skills discoverable | integration (CLI) | `claude plugin validate .` + `scripts/checkpoint1_install_validate.sh` (validate → local-source override → install → `claude plugin details`) captured to transcript | ✅ wrapper + transcript | ✅ green |
| PKG-05 | No version-string drift across manifest/README/skills | unit (stdlib script) | `python3 scripts/check_version_drift.py` (exit 0, 4/4 checks) | ✅ script exists | ✅ green |
| QUAL-01 | Every OWASP ID cites URL + retrieval date, consistently | manual (semantic) | see Manual-Only Verifications — confirmed by gsd-verifier (16/16); gap closed in 05-06 | N/A | ✅ manual-only (verified) |
| QUAL-02 | Coverage matrix present and honest | manual (semantic) | see Manual-Only Verifications — confirmed by gsd-verifier (16/16) | N/A | ✅ manual-only (verified) |
| QUAL-03 | No plausible-looking real secrets in examples | unit (regex/grep) | `grep -rnE "sk-[A-Za-z0-9]{10,}[^-]\|password[[:space:]]*=[[:space:]]*['\"][A-Za-z][A-Za-z0-9]{6,}['\"]" skills/*/assets/examples` returns no matches | ✅ | ✅ green |
| ADPT-01 | LICENSE exists, matches plugin.json (MIT) | unit (file + string) | `test -f LICENSE && grep -q "MIT" LICENSE` | ✅ | ✅ green |
| ADPT-02 | README refreshed, no dead links to deleted files | unit (grep) | `! grep -rlE "owasp-comprehensive-security-skills\.md\|owasp-css\.instructions\.md" README.md` | ✅ | ✅ green |
| ADPT-03 | CONTRIBUTING carries maintenance/versioning/update story | unit (grep headings) | `grep -qiE "versioning\|maintenance" CONTRIBUTING.md` | ✅ | ✅ green |
| ADPT-04 | Manifests carry discoverability fields | unit (JSON field presence) | `python3 -c "import json; d=json.load(open('.claude-plugin/marketplace.json')); assert {'category','keywords','tags'} <= d['plugins'][0].keys()"` | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*
*7/9 requirements have green automated verification; QUAL-01 & QUAL-02 are documented manual-only semantic checks (both independently verified by the phase verifier).*

---

## Wave 0 Requirements

- [x] A wrapper script that runs the full Checkpoint-1 sequence (`claude plugin validate` → reversible local-source override → install → `claude plugin details`) and tees output to a phase artifact — **done: `scripts/checkpoint1_install_validate.sh` + `05-checkpoint1-transcript.md`** (PKG-04 / D-02)
- [x] `scripts/check_version_drift.py` — stdlib-only, asserts `plugin.json` `version` is the single source of truth and no conflicting version string exists elsewhere — **done, green** (PKG-05 / D-04)
- [x] No pytest/jest framework install needed — repo intentionally has none; every check is shell/stdlib-script-shaped, consistent with the "no heavy runtime dependencies" constraint

*Existing `scripts/lint_skill_md.py` covers the SKILL.md lint surface and is reused as the per-wave check.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions | Outcome |
|----------|-------------|------------|-------------------|---------|
| Every OWASP version/edition/category-ID claim cites an official source URL + retrieval date, consistent across README ↔ references ↔ manifests ↔ docs | QUAL-01 | Citation *accuracy* is a semantic judgment on prose, not a syntax check | Cross-reference both `owasp-urls.json` files against README matrix, SKILL.md descriptions, docs/SKILL-STRUCTURE.md excerpts, and reference edition-notes; confirm each edition (Top 10 2025, ASVS 4.0.3-body/5.0.0, MASVS 2.1.0, API 2023, LLM 2025, Agentic 2026, K8s 2022) matches and carries a URL + retrieval date | ✅ Verified by gsd-verifier (05-VERIFICATION.md passed); the SKILL-STRUCTURE.md drift was found and closed in gap plan 05-06 |
| Coverage matrix is honest (covered vs. intentionally-not-covered), foregrounds guidance-not-scanner + example-coverage gaps (A03/A04/A06/A08/A10) + K8s 2022-not-2025-draft + ASVS 4.0.3-body numbering | QUAL-02 | "Honest" is a semantic judgment — a matrix can be syntactically present but misleading | Read README matrix + "What this is NOT" note; verify each caveat from D-06 is present and impossible to miss; verify no badge overclaims capability (D-08) | ✅ Verified by gsd-verifier (05-VERIFICATION.md passed) |

---

## Validation Audit 2026-07-28

| Metric | Count |
|--------|-------|
| Requirements total | 9 |
| Automated (green) | 7 |
| Manual-only (documented + verified) | 2 |
| Missing (need generated tests) | 0 |
| Gaps escalated | 0 |

No MISSING gaps — all Wave-0 artifacts exist and every automatable command re-ran green; the nyquist-auditor was not needed (nothing to generate). The two manual-only items are inherent semantic judgments, both independently confirmed by the phase verifier.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or a documented Manual-Only entry
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (Checkpoint-1 capture wrapper, `check_version_drift.py`) — both delivered
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter (7 automated-green + 2 documented manual-only; 0 MISSING)

**Approval:** verified 2026-07-28
