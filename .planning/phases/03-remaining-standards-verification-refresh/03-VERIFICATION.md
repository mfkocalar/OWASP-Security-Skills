---
phase: 03-remaining-standards-verification-refresh
verified: 2026-07-22T00:00:00Z
status: passed
score: 3/3 roadmap truths verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 2/3
  gaps_closed:

    - "ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Applications Top 10 (2026) each cite a verified official OWASP source URL and retrieval date in their reference file (roadmap SC1 / CONT-03) — ASVS sub-claim now honest"
  gaps_remaining: []
  regressions: []
human_verification:

  - test: "Open the File Upload Cheat Sheet (File Management row) and the Developer Guide index (Memory Management row) in the Living-Source Crosswalk"
    expected: "Confirm the File Upload Cheat Sheet genuinely covers File Management's checklist controls, and confirm whether a better dedicated Memory Management anchor exists beyond the bare Developer Guide index page"
    why_human: "Requires topical judgment of live external page content; carried forward unchanged from the prior verification (03-03-SUMMARY.md coverage item D4) and unaffected by plan 03-04"
---

# Phase 3: Remaining Standards Verification & Refresh Verification Report

**Phase Goal:** Every other OWASP standard cited by `owasp-security-audit`, and the checklist content of `secure-coding-practices`, is citation-hardened and traceable to a correctly-versioned, live OWASP source.
**Verified:** 2026-07-22
**Status:** human_needed
**Re-verification:** Yes — after gap closure (plan 03-04)

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Apps Top 10 (2026) each cite a verified official OWASP source URL + retrieval date (roadmap SC1 / CONT-03) | ✓ VERIFIED | MASVS/API/LLM/Agentic unchanged from initial verification (still each carry a verified edition-verification note whose stated edition matches the body content — no regression, confirmed by re-grep). ASVS's prior self-contradiction is now resolved: `asvs.md` (lines 12-26) still records "ASVS 5.0.0 confirmed as the current stable release" with the official URL, `Retrieved 2026-07-22`, and the 2025-05-30 Barcelona release fact (all preserved, `grep` confirms), and a new "Numbering disclosure" clause (lines 17-26) explicitly states the chapter numbers and requirement-ID examples in this reference follow **ASVS 4.0.3** taxonomy, names the 5.0.0 V-series remap (Auth→V6, Session→V7, Authz→V8, Crypto→V11, Config→V13, Validation split V1/V2), and marks the full 5.0.0 re-mapping as an intentionally deferred, documented limitation. The reporting exemplar (lines 248-254) no longer presents `V2.1.5` as a bare identifier — it is now explicitly labeled "a **4.0.3 identifier**" with a note that "under ASVS 5.0.0 the same control lives in the renumbered V6 (Authentication) series" and an instruction to "confirm the exact requirement ID against the edition you are auditing" before it lands in a compliance deliverable. A user can no longer be handed a wrong-for-the-declared-edition control ID: the file is now internally honest about which numbering it uses. |
| 2 | Kubernetes reference cites 2022 stable edition as primary, with 2025 draft explicitly footnoted as in-progress/not final (roadmap SC2 / CONT-04) | ✓ VERIFIED | Re-checked directly: `kubernetes-top10.md` lines 7-17 still pin 2022 as canonical (`Retrieved 2026-07-22`) with the "2025 edition status (footnote)" paragraph unchanged, still stating OWASP's page offers only "Feedback welcome," no formal release, "in progress, not final." Not touched by plan 03-04 (which modified only `asvs.md`) — no regression. |
| 3 | `secure-coding-practices` content re-derived against living OWASP Developer Guide / Cheat Sheet Series / Proactive Controls; archived SCP QRG noted as historical origin (roadmap SC3 / CONT-05) | ✓ VERIFIED | Re-checked directly: `scp-checklist.md` still carries the "Living-Source Crosswalk" section and the "Historical origin" blockquote pointing at the archived QRG page. Not touched by plan 03-04 — no regression. |

**Score:** 3/3 roadmap truths verified (up from 2/3 — the ASVS blocking gap from the prior verification is closed)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `skills/owasp-security-audit/references/asvs.md` | Edition-verification note for ASVS 5.0.0, consistent with body | ✓ VERIFIED | Note now discloses the reference's 4.0.3 numbering while retaining verified 5.0.0 provenance; exemplar edition-labeled. Internal contradiction from prior verification resolved. |
| `skills/owasp-security-audit/references/masvs.md` | Edition-verification note for MASVS 2.1.0 | ✓ VERIFIED | Unchanged since prior verification (not touched by 03-04); re-confirmed consistent |
| `skills/owasp-security-audit/references/api-top10.md` | Edition-verification note for API Security Top 10 2023 | ✓ VERIFIED | Unchanged; re-confirmed consistent |
| `skills/owasp-security-audit/references/llm-agentic.md` | Two edition-verification notes (LLM 2025 + Agentic 2026 Final) | ✓ VERIFIED | Unchanged; re-confirmed consistent |
| `skills/owasp-security-audit/references/kubernetes-top10.md` | 2022 primary + 2025 footnoted not-final | ✓ VERIFIED | Unchanged; re-confirmed |
| `skills/owasp-security-audit/references/owasp-urls.json` | Verified edition/retrieval_date/confidence for ASVS, MASVS, API1-10, LLM01-10, ASI01-10, K01-10 | ✓ VERIFIED (structurally) | Not touched by 03-04 (plan explicitly scoped this file out-of-scope — the `"ASVS": {"edition": "5.0.0"}` entry is not contradicted by disclosing that the markdown body summarizes ASVS using 4.0.3 numbering); prior verification's non-blocking warnings (WR-01/WR-03 confidence-tier precision) remain open as informational, non-gating items |
| `skills/secure-coding-practices/references/scp-checklist.md` | 14-row crosswalk + archived-QRG note; checklist unchanged | ✓ VERIFIED | Unchanged; re-confirmed |
| `skills/secure-coding-practices/references/owasp-urls.json` | `owasp_scp_guide.status=archived`; 14-entry `scp_domain_crosswalk` | ✓ VERIFIED | Unchanged; re-confirmed |
| `skills/secure-coding-practices/references/secure-patterns.md` | QRG line reworded to historical origin | ✓ VERIFIED | Unchanged; re-confirmed |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `asvs.md` edition-verification note | `asvs.md` body chapter/control-ID content | Edition claim must match cited requirement IDs | ✓ WIRED | Previously NOT WIRED — now resolved. The edition note (lines 12-26) and the body (chapter headings + `V2.1.5` exemplar at lines 248-254) now agree: both explicitly state the reference follows 4.0.3 numbering while 5.0.0 is the current stable edition. `grep -c '4.0.3'` returns 4 occurrences across the file (note + exemplar both label it), confirming the disclosure is present in both locations the prior gap identified as contradictory. |
| `scp-checklist.md` crosswalk table | `secure-coding-practices/owasp-urls.json` `scp_domain_crosswalk` | Domain-to-URL mapping agreement | ✓ WIRED | Unchanged from prior verification; not touched by 03-04 |
| `kubernetes-top10.md` 2025 footnote | `owasp-urls.json` `_meta.kubernetes_2025_status` | Consistent not-final wording | ✓ WIRED | Unchanged from prior verification; not touched by 03-04 |
| `llm-agentic.md` ASI01-ASI10 names | Primary 2025-12-09 OWASP announcement | No third-party suffix variants | ✓ WIRED | Unchanged from prior verification; not touched by 03-04 |

### Scope-Discipline Check (gap-closure plan 03-04)

Plan 03-04 was locked to a "source-free reframe, not a re-anchor." Verified directly:

- No chapter heading was renumbered: `grep -c '^## Chapter' asvs.md` still returns 8, and `grep -q '^## Chapter 2: Authentication'` still succeeds — chapters remain in their original 4.0.3 order/numbering.
- No externally-sourced 5.0.0 requirement ID was invented: the only 5.0.0 V-series references added are category names (V6, V7, V8, V11, V13, V1/V2) used to describe where the *category* moved, not specific fabricated requirement IDs.
- `owasp-urls.json` was correctly left untouched per the plan's own scope note — the `"ASVS": {"edition": "5.0.0"}` entry was never the source of the contradiction (it records the correct current edition; the contradiction was in the markdown body, now fixed).
- Git history confirms scope: commits `c95a9dc` (+11 lines, edition note) and `0ff26b9` (+6/-2 lines, exemplar) touch only `skills/owasp-security-audit/references/asvs.md`. No other file in the phase was modified by 03-04.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|---|---|---|---|---|
| CONT-03 | 03-01-PLAN, 03-02-PLAN, 03-04-PLAN (gap closure) | ASVS/MASVS/API/LLM/Agentic citation-hardened with verified edition, URL, retrieval date | ✓ SATISFIED | MASVS/API/LLM/Agentic satisfied since initial verification. ASVS's prior false internal claim (5.0.0 banner over unlabeled 4.0.3 body/exemplar) is now resolved via honest numbering disclosure — the reference no longer hands a wrong-for-the-declared-edition control ID. REQUIREMENTS.md marks this `[x]` complete; this now holds up under direct file inspection. |
| CONT-04 | 03-02-PLAN | Kubernetes 2022 primary, 2025 footnoted not-final | ✓ SATISFIED | Re-confirmed; unaffected by 03-04 |
| CONT-05 | 03-03-PLAN | secure-coding-practices re-derived against living sources, QRG noted historical | ✓ SATISFIED | Re-confirmed; unaffected by 03-04. One manual-only spot-check remains outstanding (see Human Verification, carried forward unchanged from prior verification) |

No orphaned requirements: REQUIREMENTS.md maps exactly CONT-03/CONT-04/CONT-05 to Phase 3, and all three appear in the plans' `requirements:` frontmatter (CONT-03 additionally claimed by 03-04-PLAN as `gap_closure: true`).

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `skills/owasp-security-audit/references/asvs.md` | — | (prior blocker resolved) | — | The 5.0.0-banner-over-4.0.3-body contradiction flagged in the prior verification is closed; no anti-pattern remains in this file. |
| `skills/owasp-security-audit/references/owasp-urls.json` | 51,56,59,60,62-71 | LLM03/06/09/10 and all ASI01-10 resolve only to an index/landing page yet carry identical `"confidence": "verified"` as per-item-URL entries | ⚠️ Warning (carried forward, non-blocking) | Pre-existing, not touched by 03-04. Worth fixing before Phase 5's coverage-matrix work (QUAL-02) but does not fail SC1's literal wording. |
| `skills/owasp-security-audit/references/owasp-urls.json` | 45-49 | K06/K07/K08 JSON titles abbreviated vs. md headers; K10 title diverges from official 2022 title | ⚠️ Warning (carried forward, non-blocking) | Pre-existing, not touched this phase; does not affect CONT-04. |
| `skills/owasp-security-audit/references/owasp-urls.json` | 4 | `_meta.confidence` documents a `"pattern"` tier with zero entries and omits `"index-fallback"` | ℹ️ Info (carried forward) | Pre-existing schema/data drift, not introduced this phase. |
| `skills/secure-coding-practices/references/secure-patterns.md` | multiple | WR-04/WR-05/IN-02/03/04 pre-existing example-code defects | ℹ️ Info (carried forward) | Not modified by 03-03 or 03-04; flagged for a future code-quality pass. |
| `skills/secure-coding-practices/references/owasp-urls.json` | 39-42, 54-58 | `related_owasp_projects` legacy URLs diverge from audit skill's canonical URLs | ℹ️ Info (carried forward) | Not touched by 03-03 or 03-04. |

No `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` markers found in `asvs.md` or any other phase-modified file.

### Human Verification Required

### 1. Spot-check the two LOW-confidence Living-Source Crosswalk anchors

**Test:** Open the File Upload Cheat Sheet (`https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html`, File Management row) and the Developer Guide index (`https://devguide.owasp.org/`, Memory Management row).
**Expected:** Confirm the File Upload Cheat Sheet genuinely covers File Management's checklist controls (it is explicitly flagged as covering upload validation only, not path-traversal/serving items), and confirm whether a better dedicated Memory Management anchor exists in the Developer Guide beyond the bare index page.
**Why human:** Carried forward unchanged from the prior verification — 03-03-SUMMARY.md explicitly defers this as a manual-only check (coverage item D4); it requires topical judgment of live external page content, which cannot be verified via grep/static analysis. Not affected by plan 03-04 (which only touched `asvs.md`).

## Gaps Summary

All three roadmap Success Criteria for Phase 3 now hold up under direct file inspection.

The single blocking gap from the prior verification (SC1/CONT-03's ASVS self-contradiction — a "5.0.0 confirmed" banner sitting over unlabeled ASVS 4.0.3 chapter taxonomy and a `V2.1.5` exemplar presented as if valid under 5.0.0) is closed by plan 03-04's source-free reframe. Verified directly against `asvs.md`:

- The edition-verification note (lines 12-26) retains every previously-verified fact (5.0.0 current stable, 2025-05-30 Barcelona release, official URL, `Retrieved 2026-07-22`) and adds a "Numbering disclosure" clause stating this reference's chapter/requirement numbering follows ASVS 4.0.3, naming the 5.0.0 V-series remap and marking a full re-mapping as an intentionally deferred, documented limitation.
- The reporting exemplar (lines 248-254) no longer hands `V2.1.5` as a bare identifier — it is edition-labeled "a 4.0.3 identifier," notes its 5.0.0 V6-series equivalent, and instructs the reader to confirm the exact requirement ID against the edition being audited before it lands in a compliance deliverable.
- No chapter was renumbered and no externally-sourced 5.0.0 requirement ID was invented (confirmed: `grep -c '^## Chapter'` still returns 8, `^## Chapter 2: Authentication` still matches) — the locked "reframe, not re-anchor" decision was honored exactly.
- Scope was disciplined: only `asvs.md` was modified (commits `c95a9dc`, `0ff26b9`); `owasp-urls.json` was correctly left untouched.

A user running this skill against ASVS can no longer be handed a wrong-for-the-declared-edition control ID — the reference is now internally honest about which numbering it summarizes, which satisfies the phase goal's "traceable to a correctly-versioned source" bar for the source-free-reframe approach the user locked in.

No regressions found in the SC2 (Kubernetes) or SC3 (secure-coding-practices) areas — both were untouched by plan 03-04 and re-confirmed directly.

All three roadmap Success Criteria (and all technical gaps) are resolved: every truth is VERIFIED and no artifact, key link, or scope-discipline check failed. The overall status is `human_needed` rather than `passed` solely because one human-verification item remains open from the prior verification (the File Management / Memory Management crosswalk spot-check, carried forward unchanged, unaffected by plan 03-04). Per the verification decision tree, any non-empty human-verification list means the phase cannot be marked `passed` even when every automated check succeeds — this item requires a human to open two live OWASP pages and judge topical coverage, which cannot be done via grep/static analysis.

---

_Verified: 2026-07-22_
_Verifier: Claude (gsd-verifier)_
