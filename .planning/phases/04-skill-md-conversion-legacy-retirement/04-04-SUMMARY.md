---
phase: 04-skill-md-conversion-legacy-retirement
plan: 04
subsystem: docs
tags: [owasp, top10-2025, llm-top10, agentic-top10, examples, cross-reference]

requires:
  - phase: 04-02
    provides: "references/llm.md and references/agentic.md (split from llm-agentic.md), including the AG##-to-real-OWASP mapping table"
  - phase: 02
    provides: "references/top10.md rewritten topic-first against the OWASP Top 10 2025 mapping"
provides:
  - "All nine paired vulnerable/secure example files carry topic-correct OWASP 2025 category labels"
  - "Every example header now points at a surviving references/*.md file, none point at the legacy comprehensive guide slated for deletion in 04-05"
  - "prompt-injection.txt's four invented AG codes individually remapped to their correct real OWASP LLM items, with a corrected Final status line"
affects: ["04-05 (legacy file deletion — this plan's repoint work must land first)"]

tech-stack:
  added: []
  patterns: ["Topic-based category relabeling (not literal number substitution) applied to example files, mirroring the Phase 2 top10.md convention"]

key-files:
  created: []
  modified:
    - skills/owasp-security-audit/assets/examples/broken-access-control.py
    - skills/owasp-security-audit/assets/examples/security-misconfiguration.py
    - skills/owasp-security-audit/assets/examples/injection.js
    - skills/owasp-security-audit/assets/examples/cryptographic-failures.js
    - skills/owasp-security-audit/assets/examples/xss.html
    - skills/owasp-security-audit/assets/examples/logging-monitoring-failures.py
    - skills/owasp-security-audit/assets/examples/api-auth-bypass.js
    - skills/owasp-security-audit/assets/examples/k8s-rbac.yaml
    - skills/owasp-security-audit/assets/examples/prompt-injection.txt

key-decisions:
  - "Relabeled security-misconfiguration.py (old-A05 -> A02), cryptographic-failures.js (old-A02 -> A04), and injection.js (added missing A05 label) by TOPIC against top10.md, not literal number substitution, per Phase 2 precedent"
  - "xss.html's stale '2017 edition'/A03 note corrected to map XSS under A05: Injection (2025 edition)"
  - "prompt-injection.txt's four invented AG codes individually remapped per agentic.md's mapping table (AG01->LLM01:2025, AG03->LLM05:2025, AG05->LLM10:2025, AG06->LLM06:2025 with ASI02/ASI03 cross-ref) rather than a blanket substitution"
  - "broken-access-control.py kept its A01 label and gained an inline note that SSRF (CWE-918) now folds into A01 in 2025 — no code change needed since existing IDOR/authz-bypass demonstrations already fit A01's topic"

requirements-completed: [CONT-06]

coverage:
  - id: D1
    description: "broken-access-control.py, security-misconfiguration.py, injection.js relabeled to 2025 IDs (A01/A02/A05) by topic and repointed to references/top10.md"
    requirement: CONT-06
    verification:
      - kind: other
        ref: "grep -c owasp-comprehensive-security-skills / A05: Security Misconfiguration / A05.{0,3}Injection / SSRF|CWE-918 / references/top10.md checks (Task 1 verify block)"
        status: pass
    human_judgment: false
  - id: D2
    description: "cryptographic-failures.js, xss.html, logging-monitoring-failures.py relabeled to 2025 IDs (A04/A05/A09) by topic, stale 2017-edition note removed, repointed to references/top10.md"
    requirement: CONT-06
    verification:
      - kind: other
        ref: "grep -c A02: Cryptographic Failures / 2017 edition / A05 / Security Logging / owasp-comprehensive-security-skills checks (Task 2 verify block)"
        status: pass
    human_judgment: false
  - id: D3
    description: "api-auth-bypass.js and k8s-rbac.yaml headers repointed to references/api-top10.md and references/kubernetes-top10.md respectively"
    requirement: CONT-06
    verification:
      - kind: other
        ref: "grep -c references/api-top10.md api-auth-bypass.js; grep -c references/kubernetes-top10.md k8s-rbac.yaml"
        status: pass
    human_judgment: false
  - id: D4
    description: "prompt-injection.txt's four invented AG codes individually remapped to correct real OWASP LLM items, stale Preview/Draft status corrected to Final, header repointed to references/llm.md"
    requirement: CONT-06
    verification:
      - kind: other
        ref: "grep -cE AG0[0-9] (==0); grep -cE LLM(01|05|06|10) (>=1); grep -ciE Preview|Draft (==0) on prompt-injection.txt (Task 3 verify block)"
        status: pass
    human_judgment: true
    rationale: "Acceptance criteria explicitly require a MANUAL check confirming each of the four AG headers maps to its individual correct item (not a blanket AG01->ASI01 substitution) — a human/reviewer should visually confirm the four distinct mappings shown in the Accomplishments section below."

duration: 20min
completed: 2026-07-24
status: complete
---

# Phase 04 Plan 04: Example Relabel to OWASP Top 10 2025 Summary

**All nine paired vulnerable/secure example files carry topic-correct OWASP 2025 category IDs and point at surviving reference files instead of the soon-to-be-deleted legacy comprehensive guide.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-24T14:17:25Z
- **Tasks:** 3 completed
- **Files modified:** 9

## Accomplishments

- Relabeled `security-misconfiguration.py` from the old A05 slot to **A02** (2025), `cryptographic-failures.js` from old A02 to **A04** (2025), and added the previously-missing **A05: Injection** label to `injection.js` — all by topic per `references/top10.md`, not numeric substitution.
- Kept `broken-access-control.py` at **A01** and added an explicit note that SSRF (CWE-918) — formerly its own A10:2021 category — now folds into A01 in the 2025 edition.
- Corrected `xss.html`'s stale "XSS was A07 in the 2017 edition" note; XSS now maps under **A05: Injection** for 2025.
- Updated `logging-monitoring-failures.py`'s category name to the 2025 wording **"A09: Security Logging & Alerting Failures"**.
- Repointed all nine example headers away from the legacy `owasp-comprehensive-security-skills.md` (deleted in 04-05) to a surviving reference: `references/top10.md` (six web-app examples), `references/api-top10.md` (`api-auth-bypass.js`), `references/kubernetes-top10.md` (`k8s-rbac.yaml`), and `references/llm.md` (`prompt-injection.txt`).
- Individually remapped `prompt-injection.txt`'s four invented `AG0X` codes to their correct real OWASP items per `references/agentic.md`'s mapping table:
  - `AG01: Prompt Injection` → `LLM01:2025 Prompt Injection`
  - `AG03: Insecure Output Handling` → `LLM05:2025 Improper Output Handling`
  - `AG05: Denial of Service` → `LLM10:2025 Unbounded Consumption`
  - `AG06: Unauthorized Plugin/Tool Access` → `LLM06:2025 Excessive Agency` (with an ASI02 Tool Misuse / ASI03 Identity & Privilege Abuse cross-reference to `references/agentic.md`)
- Corrected `prompt-injection.txt`'s stale `Status: Preview/Draft` line to `Status: Final`, matching the verified-Final status of the Agentic Apps 2026 edition established in 04-02.
- Full examples-dir sweep for `owasp-comprehensive-security-skills|AG0[0-9]|2017 edition|A05: Security Misconfiguration|A02: Cryptographic Failures|Preview|Draft` returns clean (no matches).
- Validated syntax on all touched code files: `python3 -m py_compile` for the three `.py` files, `node --check` for the four `.js` files — all pass (one pre-existing, unrelated `SyntaxWarning` in an embedded NGINX config string literal inside `security-misconfiguration.py`, not introduced by this plan).

## Task Commits

Each task was committed atomically:

1. **Task 1: Relabel Top 10 group A (broken-access-control.py, security-misconfiguration.py, injection.js)** - `7880a5b` (docs)
2. **Task 2: Relabel Top 10 group B (cryptographic-failures.js, xss.html, logging-monitoring-failures.py)** - `8a6e539` (docs)
3. **Task 3: Repoint API/K8s examples + individually remap prompt-injection.txt AG codes** - `d65d43a` (docs)

_No TDD tasks in this plan — all edits are documentation/labeling changes to existing example files._

## Files Created/Modified

- `skills/owasp-security-audit/assets/examples/broken-access-control.py` - Kept A01, added SSRF/CWE-918 2025 fold-in note, repointed header to `references/top10.md`
- `skills/owasp-security-audit/assets/examples/security-misconfiguration.py` - Relabeled old-A05 → A02, repointed header to `references/top10.md`
- `skills/owasp-security-audit/assets/examples/injection.js` - Added missing "A05: Injection" label, repointed header to `references/top10.md`
- `skills/owasp-security-audit/assets/examples/cryptographic-failures.js` - Relabeled old-A02 → A04, repointed header to `references/top10.md`
- `skills/owasp-security-audit/assets/examples/xss.html` - Removed stale 2017-edition/A03 note, mapped XSS under A05: Injection, repointed to `references/top10.md`
- `skills/owasp-security-audit/assets/examples/logging-monitoring-failures.py` - Updated to 2025 wording "A09: Security Logging & Alerting Failures", repointed to `references/top10.md`
- `skills/owasp-security-audit/assets/examples/api-auth-bypass.js` - Repointed header to `references/api-top10.md`
- `skills/owasp-security-audit/assets/examples/k8s-rbac.yaml` - Repointed header to `references/kubernetes-top10.md`
- `skills/owasp-security-audit/assets/examples/prompt-injection.txt` - Individually remapped four AG codes to correct LLM items, fixed stale Preview/Draft status to Final, repointed header to `references/llm.md`

## Decisions Made

- Relabeled `security-misconfiguration.py`, `cryptographic-failures.js`, and `injection.js` strictly by TOPIC against `references/top10.md` — not literal number substitution — consistent with the Phase 2 `top10.md` precedent (six of ten categories changed number and/or topic between the 2021 and 2025 editions).
- `broken-access-control.py` required no code changes: its existing IDOR / missing-authorization demonstrations already match A01's topic in 2025; only an explanatory SSRF-fold-in note was added, since the file doesn't itself demonstrate SSRF and none was required.
- `prompt-injection.txt`'s four AG codes were remapped individually (not via a single blanket AG→ASI or AG→LLM substitution) per the project's T-04-12 threat mitigation and `04-RESEARCH.md`'s explicit warning that the four codes resolve to different real OWASP items.

## Deviations from Plan

None - plan executed exactly as written. All three tasks completed per their `<action>` and `<acceptance_criteria>` blocks with no auto-fixes, blockers, or architectural changes needed.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All nine example files are now safe for the legacy file deletion planned in 04-05 (`owasp-comprehensive-security-skills.md`, `owasp-css.instructions.md`) — no example header still targets the file being deleted.
- CONT-06 (example relabel/re-validation) is satisfied; the full examples-dir negative-grep sweep required by this plan's `<verification>` block passes with zero matches.
- 04-05 can proceed with legacy retirement without risk of leaving a dead cross-reference behind in `assets/examples/`.

---
*Phase: 04-skill-md-conversion-legacy-retirement*
*Completed: 2026-07-24*

## Self-Check: PASSED

All 9 modified example files and this SUMMARY.md confirmed present on disk. All 3 task commit hashes (7880a5b, 8a6e539, d65d43a) confirmed in git log.
