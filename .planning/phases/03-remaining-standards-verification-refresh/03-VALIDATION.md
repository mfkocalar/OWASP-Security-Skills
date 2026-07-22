---
phase: 3
slug: remaining-standards-verification-refresh
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-22
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from 03-RESEARCH.md "## Validation Architecture". This phase's product is
> Markdown/JSON reference content (citation accuracy), so "tests" are deterministic
> grep + JSON-shape assertions runnable with Python's standard library — no test
> framework install required.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | None (Markdown/JSON reference content — no test runner in this repo) |
| **Config file** | none — no framework needed (Wave 0 has no gaps) |
| **Quick run command** | `python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json > /dev/null && python3 -m json.tool skills/secure-coding-practices/references/owasp-urls.json > /dev/null` |
| **Full suite command** | JSON-validity check above **plus** all grep/JSON-shape assertions in the Per-Task map below |
| **Estimated runtime** | ~2 seconds (each assertion < 1s) |

---

## Sampling Rate

- **After every task commit:** Run the grep/JSON assertion(s) for the file(s) just edited (each < 1s)
- **After every plan wave:** Run the full suite (JSON validity + all grep assertions)
- **Before `/gsd-verify-work`:** All requirement rows below must be green
- **Max feedback latency:** ~2 seconds

---

## Per-Task Verification Map

Task IDs (`03-NN-MM`) are assigned by the planner; rows below are keyed by requirement and
carry the concrete automated command each covering task must satisfy. The planner should attach
the matching command to each task's `<automated>` verify.

| Requirement | Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|----------|-----------|-------------------|-------------|--------|
| CONT-03 | Each of ASVS/MASVS/API/LLM/Agentic reference file carries an edition-verification note with a retrieval date (`llm-agentic.md` twice — LLM + Agentic) | grep assertion | `grep -l "Retrieved 2026-07-22" skills/owasp-security-audit/references/{asvs,masvs,api-top10,llm-agentic}.md \| wc -l` == 4 | ✅ exists | ⬜ pending |
| CONT-03 | `owasp-security-audit/.../owasp-urls.json` has `edition` + `retrieval_date` + `confidence: verified` for ASVS, MASVS, API1–10:2023, LLM01–10:2025, ASI01–10 | JSON-shape check | `python3 -c "import json; d=json.load(open('skills/owasp-security-audit/references/owasp-urls.json')); codes=['ASVS','MASVS']+[f'API{i}:2023' for i in range(1,11)]+[f'LLM{i:02d}:2025' for i in range(1,11)]+[f'ASI{i:02d}' for i in range(1,11)]; missing=[c for c in codes if 'retrieval_date' not in d.get(c,{})]; assert not missing, missing"` | ✅ exists | ⬜ pending |
| CONT-04 | `kubernetes-top10.md` cites 2022 as primary AND footnotes 2025 as in-progress (not final) | grep assertion | `grep -q "2022" skills/owasp-security-audit/references/kubernetes-top10.md && grep -qi "in progress\|not.*final\|feedback\|draft" skills/owasp-security-audit/references/kubernetes-top10.md` | ✅ exists | ⬜ pending |
| CONT-05 | `scp-checklist.md` contains a 14-domain crosswalk with per-domain living-source URLs | grep assertion (row count) | `grep -c "cheatsheetseries.owasp.org\|devguide.owasp.org\|top10proactive.owasp.org" skills/secure-coding-practices/references/scp-checklist.md` ≥ 14 | ✅ exists | ⬜ pending |
| CONT-05 | SCP QRG noted as archived/historical, not a current source | grep assertion | `grep -qi "archived\|historical" skills/secure-coding-practices/references/scp-checklist.md` | ✅ exists | ⬜ pending |
| CONT-05 | `secure-patterns.md` no longer implies the QRG is a live/current source | grep assertion | `grep -qi "historical\|archived" skills/secure-coding-practices/references/secure-patterns.md` | ✅ exists | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

*Existing infrastructure covers all phase requirements.* Every file this phase targets already
exists (confirmed in research by reading all six reference files + both `owasp-urls.json` files).
No test framework or fixture install is needed — assertions run on Python's standard library
(already a repo dependency via `quick_scan.py`).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Memory Management & File Management SCP crosswalk anchors are the correct living source | CONT-05 | Research flagged these two domains LOW confidence (Assumptions A2/A3) — automated grep only proves a URL is present, not that it is the *right* anchor | Before locking the crosswalk, open the chosen Cheat Sheet / Developer Guide page for each of these two domains and confirm it actually covers that domain's controls |
| Every edition/ID/status claim in a task's diff traces to a quoted source + retrieval date | CONT-03, CONT-04 | Citation-accuracy correctness is editorial, not mechanically checkable by grep | Per-task editorial self-check: each edition claim in the diff must have a matching quoted source + retrieval date in 03-RESEARCH.md (or a fresh live re-verify) |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (N/A — no Wave 0 gaps)
- [ ] No watch-mode flags
- [ ] Feedback latency < 2s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
