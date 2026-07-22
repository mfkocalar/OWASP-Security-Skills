---
phase: 03-remaining-standards-verification-refresh
plan: 02
subsystem: owasp-security-audit skill data layer
tags: [owasp, citation-hardening, kubernetes, provenance, json]
dependency-graph:
  requires: []
  provides:
    - "kubernetes-top10.md 2025-draft-status footnote (CONT-04)"
    - "owasp-urls.json verified provenance for ASVS/MASVS/API/LLM/ASI/K01-10 (CONT-03)"
  affects:
    - "skills/owasp-security-audit/SKILL.md (consumes owasp-urls.json for citation links)"
    - "Phase 5 QUAL-02 coverage matrix (consumes verified/retrieval_date fields)"
tech-stack:
  added: []
  patterns:
    - "Edition-verification note pattern (2-field: primary source + explicit not-final footnote) mirrored from Phase 2's top10.md"
    - "owasp-urls.json verified entry shape (title/edition/url/retrieval_date/confidence) extended to all remaining standard codes"
key-files:
  created: []
  modified:
    - skills/owasp-security-audit/references/kubernetes-top10.md
    - skills/owasp-security-audit/references/owasp-urls.json
decisions:
  - "Kubernetes 2025 edition kept as footnote only (not primary) — OWASP's own page states 'feedback welcome' with no version tag and no formal GitHub release as of 2026-07-22 (D-05/D-06 halt-and-flag did not fire; no formal release found)"
  - "LLM01-10:2025 confidence upgraded to 'verified' for all ten codes while leaving the shared index-fallback URLs (LLM03/06/09/10) unchanged — the shared page is a structural fact (no dedicated per-item page), not a confidence problem, per 03-RESEARCH.md Anti-Pattern guidance"
  - "ASI01-10 confidence upgraded to 'verified' with the shared resource-page URL kept as-is — names verified against the primary 2025-12-09 OWASP announcement (carried over from Phase 03-01)"
  - "K01-K10 received retrieval_date only; no 2025 K0x entry added as verified, preserving the Kubernetes exception explicitly"
metrics:
  duration: 6min
  completed: 2026-07-22
status: complete
---

# Phase 3 Plan 2: Kubernetes Footnote Tightening & owasp-urls.json Citation Hardening Summary

Tightened the Kubernetes 2025-draft footnote to explicitly flag it as in-progress/not-final and extended owasp-urls.json's verified-provenance shape (edition + retrieval_date + confidence) to every remaining standard code touched this phase, without upgrading Kubernetes past its 2022 edition.

## What Was Built

**Task 1 — Kubernetes footnote tightening** (`kubernetes-top10.md`): Replaced the single combined 2022/2025 paragraph with two parts: (1) a tightened "Source & edition" block keeping 2022 as primary with `Retrieved 2026-07-22`, and (2) a new "2025 edition status (footnote)" paragraph stating verbatim that OWASP's own page/README says only "2025 Top 10 Risks now available — Feedback welcome," with no version tag and no formal GitHub release as of 2026-07-22 — explicitly "in progress, not final." The existing `[?]` ambiguity markers elsewhere in the file (5 total, including the "2022 → 2025 cross-reference" appendix) were left untouched, per the plan's explicit instruction not to "clean up" them.

**Task 2 — owasp-urls.json citation hardening**: Upgraded every CONT-03 code to the verified entry shape already used for A01-A10:
- `ASVS`: edition `"5.0"` → `"5.0.0"`, added `retrieval_date: "2026-07-22"`, confidence → `"verified"`.
- `MASVS`: added `retrieval_date`, confidence → `"verified"`.
- `API1:2023`-`API10:2023` (10 entries): added `retrieval_date`, all upgraded to `"verified"`.
- `LLM01:2025`-`LLM10:2025` (10 entries): added `retrieval_date`; confidence for the four index-fallback entries (LLM03, LLM06, LLM09, LLM10) upgraded to `"verified"` while their shared `genai.owasp.org/llm-top-10/` URL was left unchanged (structural fact, not a confidence gap).
- `ASI01`-`ASI10` (10 entries): added `retrieval_date`, confidence upgraded to `"verified"`, shared resource-page URL unchanged.
- `K01`-`K10` (10 entries): added `retrieval_date` only — confidence was already `"verified"`; no 2025 K0x entry was added, and no Kubernetes edition value was touched.
- Added top-level `_meta.kubernetes_2025_status` field (verbatim string from 03-PATTERNS.md) recording the 2025 draft ambiguity in machine-readable form, cross-referencing the `kubernetes-top10.md` footnote.

## Verification

- `python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json` — passes (valid JSON) after every edit and at plan completion.
- Task 2 CONT-03 Python assertion (retrieval_date on ASVS/MASVS/all API1-10:2023/all LLM01-10:2025/all ASI01-10; `ASVS.edition == "5.0.0"`; `_meta.kubernetes_2025_status` present; `K01.retrieval_date` present) — passes.
- Task 1 CONT-04 grep assertion (`"2022"` present AND one of `in progress|not.*final|feedback|draft` present AND `"Retrieved 2026-07-22"` present) — passes.
- `git status --short` after both commits — clean, no untracked files.
- No file deletions in either commit (`git diff --diff-filter=D`).

## Deviations from Plan

None - plan executed exactly as written. No halt-and-flag conditions fired: a live check of OWASP's Kubernetes Top 10 project page (via 03-RESEARCH.md's already-captured live verification) shows no formal 2025 release tag, so the 2022-primary/2025-footnote structure specified by D-05/D-06 was applied without escalation.

## Known Stubs

None. This plan modifies reference/data files only; no UI or runtime code paths are affected.

## Threat Flags

None. This plan introduces no new network endpoints, auth paths, file access patterns, or trust-boundary schema changes — consistent with the plan's threat_model disposition (all three registered threats were `mitigate`, addressed via the provenance-tracing and Kubernetes halt-and-flag mechanisms described above).

## Self-Check: PASSED

- FOUND: skills/owasp-security-audit/references/kubernetes-top10.md
- FOUND: skills/owasp-security-audit/references/owasp-urls.json
- FOUND: e93b6e3 (docs(03-02): tighten Kubernetes 2025 footnote as in-progress/not-final)
- FOUND: 313b58a (docs(03-02): citation-harden owasp-urls.json with verified provenance)
