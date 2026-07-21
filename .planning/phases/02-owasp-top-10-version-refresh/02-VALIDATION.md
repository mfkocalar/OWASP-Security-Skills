---
phase: 2
slug: owasp-top-10-version-refresh
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-21
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> This is a Markdown/docs + Python-label content migration — verification is
> **grep-based**, not test-framework-based (no test runner exists in this repo, and
> the project constraint forbids heavy runtime dependencies). Derived from
> `02-RESEARCH.md` §Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | None — Markdown/docs repo with no test runner (confirmed: no `package.json`, `pytest.ini`, or `tests/` at repo root) |
| **Config file** | none — grep/JSON-parse checks are self-contained |
| **Quick run command** | `grep -rnE "A0[1-9]:2021\|A10:2021\|:2021" skills/owasp-security-audit/ README.md` (expect zero *unintended* matches; intentional "formerly A0x:2021" breadcrumb prose is the D-01 pattern and is allowed) |
| **Full suite command** | Quick grep above **plus** `python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json > /dev/null` (JSON stays valid after edits) |
| **Estimated runtime** | ~2 seconds |

---

## Sampling Rate

- **After every task commit:** Run the quick grep command
- **After every plan wave:** Run the full suite command (grep + JSON parse)
- **Before `/gsd-verify-work`:** Full suite green **and** manual diff of final `top10.md` category list against `02-RESEARCH.md`'s official mapping table (confirm no topic was mis-numbered — the topic-driven-not-number-driven landmine)
- **Max feedback latency:** ~2 seconds

---

## Per-Task Verification Map

> Requirement-level seed from research; the executor fills concrete `{N}-PP-TT` task IDs
> and status during execution once plans assign tasks.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 2-*-* | TBD | TBD | CONT-01 | — | `top10.md` lists 10 2025 categories, correct ID/name mapping | grep + manual diff | `grep -c "^## A" skills/owasp-security-audit/references/top10.md` (expect 10) | ❌ W0 | ⬜ pending |
| 2-*-* | TBD | TBD | CONT-01 | — | Edition recorded Final + source URL + retrieval date | grep | `grep -n "2025 (Final)" skills/owasp-security-audit/references/top10.md skills/owasp-security-audit/references/owasp-urls.json` | ❌ W0 | ⬜ pending |
| 2-*-* | TBD | TBD | CONT-02 | — | No stray 2021-era IDs in loaded path (breadcrumbs excepted) | grep | `grep -rnE "A0[1-9]:2021\|A10:2021" skills/ README.md` (expect only intended breadcrumbs) | ❌ W0 | ⬜ pending |
| 2-*-* | TBD | TBD | CONT-02 | — | `owasp-urls.json` stays valid JSON | automated | `python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] No new test files — the grep/JSON-parse commands above are ad-hoc verification, not a permanent harness (per the "no heavy runtime dependencies" constraint; not worth building a script for a one-time content migration)
- [ ] `python3 -m json.tool` (stdlib — always available; no install)

*Existing infrastructure (grep + Python stdlib) covers all phase requirements; no framework install needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Final `top10.md` category list matches the **official** 2021→2025 mapping topic-for-topic (not by number) | CONT-01 | Correctness of the topic→ID mapping cannot be asserted by grep; it requires a human/agent diff against the official source captured in `02-RESEARCH.md` | Open `02-RESEARCH.md` mapping table; confirm each 2025 ID in `top10.md` carries the correct topic (e.g., A02:2025 = Security Misconfiguration, NOT Cryptographic Failures) |
| Edition is genuinely **Final**, not RC, at ship time | CONT-01 | The Final-vs-RC gate (D-04) is a source-authority judgment, not a string check | Confirm `02-RESEARCH.md` FINAL verdict + the recorded official OWASP source URL resolves and says "2025 (Final)/Released" |

---

## Validation Sign-Off

- [ ] All tasks have an automated grep/parse verify or a documented manual verification
- [ ] Sampling continuity: no 3 consecutive tasks without a grep/parse check
- [ ] Wave 0 covers all MISSING references (none beyond stdlib)
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter (set by nyquist auditor / verifier)

**Approval:** pending
