---
phase: 1
slug: plugin-marketplace-foundation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-19
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | None — pure Markdown/JSON/shell repo; verification is CLI + manual review |
| **Config file** | none — Wave 0 authors the manifests being validated |
| **Quick run command** | `claude plugin validate . --strict` |
| **Full suite command** | `claude plugin validate . --strict && ./install.sh` (option 4, test-only) |
| **Estimated runtime** | ~5 seconds |

> **CLI availability caveat (from RESEARCH.md):** the `claude` plugin subcommands were not exercised in research. Confirm `claude --version` supports `plugin validate` before treating validation as machine-checkable; else fall back to manual JSON-schema review against the field tables in `01-RESEARCH.md`.

---

## Sampling Rate

- **After every task commit:** Run `claude plugin validate . --strict` (once `.claude-plugin/` exists)
- **After every plan wave:** Run `claude plugin validate . --strict && ./install.sh` (option 4)
- **Before `/gsd-verify-work`:** Full suite must be green; all 9 README example links resolve; `docs/SKILL-STRUCTURE.md` matches the real skill layout
- **Max feedback latency:** ~5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| _TBD — planner populates from task breakdown_ | | | | | | | | | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `.claude-plugin/plugin.json` — does not exist yet; core deliverable of PKG-01
- [ ] `.claude-plugin/marketplace.json` — does not exist yet; core deliverable of PKG-02
- [ ] `docs/SKILL-STRUCTURE.md` — does not exist yet; core deliverable of D-07/SC4
- [ ] No test framework to install — repo is intentionally test-runner-free; `claude plugin validate` IS the test framework for this phase's domain

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `docs/SKILL-STRUCTURE.md` documents the convention unambiguously | SC4 | Doc-content correctness is not machine-assertable | Plan-checker/human review against the confirmed directory-convention facts in `01-RESEARCH.md` |
| All 9 README example links resolve to per-skill canonical paths | PKG-03 / D-06 | Link-target existence after repoint | For each repointed link, confirm the target file exists under `skills/owasp-security-audit/assets/examples/` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
