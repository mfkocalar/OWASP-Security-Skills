---
phase: 5
slug: packaging-validation-credibility-polish
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-27
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from 05-RESEARCH.md §Validation Architecture. This repo intentionally
> has no pytest/jest framework ("no heavy runtime dependencies" constraint) —
> all checks are shell/stdlib-script-shaped.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | None — stdlib `python3` scripts + the custom `scripts/lint_skill_md.py` linter (Phase 4) |
| **Config file** | none |
| **Quick run command** | `python3 scripts/lint_skill_md.py skills --format text` |
| **Full suite command** | `python3 scripts/lint_skill_md.py skills --format text && claude plugin validate .` |
| **Estimated runtime** | ~5–15 seconds (lint is sub-second; `claude plugin validate` dominates) |

---

## Sampling Rate

- **After every task commit:** Run the grep/JSON-field check for that task's specific requirement (fast, <5s each)
- **After every plan wave:** Run `python3 scripts/lint_skill_md.py skills --format text && claude plugin validate .`
- **Before `/gsd-verify-work`:** Full Checkpoint-1 sequence (validate + local-source override install + `claude plugin details`) captured to a phase artifact, AND every unit-level grep/JSON check green
- **Max feedback latency:** ~15 seconds

---

## Per-Task Verification Map

> Task IDs are assigned by the planner (PLAN.md files do not exist yet at
> validation-strategy time). This map is completed/refined once plans exist;
> the requirement→command mapping below is the authoritative source the
> planner must wire each task's `<verify>` block to.

| Requirement | Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|----------|-----------|-------------------|-------------|--------|
| PKG-04 | Plugin validates, installs, both skills discoverable | integration (CLI) | `claude plugin validate . && claude plugin details owasp-security-skills@owasp-security-skills` | ❌ W0 (needs capture wrapper) | ⬜ pending |
| PKG-05 | No version-string drift across manifest/README/skills | unit (stdlib script) | `python3 scripts/check_version_drift.py` | ❌ W0 (script to create) | ⬜ pending |
| QUAL-01 | Every OWASP ID cites URL + retrieval date, consistently | manual (semantic) | see Manual-Only Verifications | N/A | ⬜ pending |
| QUAL-02 | Coverage matrix present and honest | manual (semantic) | see Manual-Only Verifications | N/A | ⬜ pending |
| QUAL-03 | No plausible-looking real secrets in examples | unit (regex/grep) | `grep -rnE "sk-[A-Za-z0-9]{10,}[^-]\|password\s*=\s*['\"][A-Za-z][A-Za-z0-9]{6,}['\"]" skills/*/assets/examples` returns no matches | ❌ W0 | ⬜ pending |
| ADPT-01 | LICENSE exists, matches plugin.json (MIT) | unit (file + string) | `test -f LICENSE && grep -q "MIT" LICENSE` | ❌ W0 | ⬜ pending |
| ADPT-02 | README refreshed, no dead links to deleted files | unit (grep) | `! grep -rlE "owasp-comprehensive-security-skills\.md\|owasp-css\.instructions\.md" README.md` | ❌ W0 | ⬜ pending |
| ADPT-03 | CONTRIBUTING carries maintenance/versioning/update story | unit (grep headings) | `grep -qiE "versioning\|maintenance" CONTRIBUTING.md` | ❌ W0 | ⬜ pending |
| ADPT-04 | Manifests carry discoverability fields | unit (JSON field presence) | `python3 -c "import json; d=json.load(open('.claude-plugin/marketplace.json')); assert 'category' in d['plugins'][0]"` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] A small wrapper script (or documented command block) that runs the full Checkpoint-1 sequence (`claude plugin validate` → reversible local-source override → install → `claude plugin details`) and tees output to a phase artifact — satisfies D-02's "captured transcript" requirement for PKG-04
- [ ] `scripts/check_version_drift.py` — stdlib-only, asserts `plugin.json` `version` is the single source of truth and no conflicting version string exists elsewhere (PKG-05 / D-04); model on `scripts/lint_skill_md.py` style
- [ ] No pytest/jest framework install needed — repo intentionally has none; every gap above is shell/stdlib-script-shaped, consistent with the "no heavy runtime dependencies" constraint

*Existing `scripts/lint_skill_md.py` covers the SKILL.md lint surface and is reused as the per-wave check.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Every OWASP version/edition/category-ID claim cites an official source URL + retrieval date, consistent across README ↔ references ↔ manifests | QUAL-01 | Citation *accuracy* is a semantic judgment on prose, not a syntax check | Cross-reference both `owasp-urls.json` files against README matrix, SKILL.md descriptions, and reference edition-notes; confirm each edition (Top 10 2025, ASVS 4.0.3-body/5.0.0, MASVS 2.1.0, API 2023, LLM 2025, Agentic 2026, K8s 2022) matches and carries a URL + retrieval date |
| Coverage matrix is honest (covered vs. intentionally-not-covered), foregrounds guidance-not-scanner + example-coverage gaps (A03/A04/A06/A08/A10) + K8s 2022-not-2025-draft + ASVS 4.0.3-body numbering | QUAL-02 | "Honest" is a semantic judgment — a matrix can be syntactically present but misleading | Read README matrix + "What this is NOT" note; verify each caveat from D-06 is present and impossible to miss; verify no badge overclaims capability (D-08) |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (Checkpoint-1 capture wrapper, `check_version_drift.py`)
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
