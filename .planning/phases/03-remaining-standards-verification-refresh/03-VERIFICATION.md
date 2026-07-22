---
phase: 03-remaining-standards-verification-refresh
verified: 2026-07-22T00:00:00Z
status: gaps_found
score: 2/3 roadmap truths verified
behavior_unverified: 0
overrides_applied: 0
gaps:
  - truth: "ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Applications Top 10 (2026) each cite a verified official OWASP source URL and retrieval date in their reference file (roadmap SC1 / CONT-03)"
    status: failed
    reason: "MASVS, API Security, LLM, and Agentic Apps all pass — each carries a verified edition-verification note whose stated edition matches the body content. ASVS fails: asvs.md's edition-verification note (added this phase) declares 'ASVS 5.0.0 confirmed as the current stable release', but the file's own chapter headings and its one concrete requirement-ID exemplar are ASVS 4.0.3 taxonomy, not 5.0.0. Specifically: chapters are numbered/titled per 4.0.3 (Ch.2 Authentication, Ch.3 Session Management, Ch.4 Access Control, Ch.5 Input Validation & Encoding, Ch.6 Cryptography, Ch.7 Error Handling & Logging, Ch.8 Data Protection, Ch.10 Malicious Code); under ASVS 5.0.0 the chapters were renumbered (Authentication=V6, Session Management=V7, Authorization=V8, Cryptography=V11, Configuration=V13, Validation split into V1/V2) so 'Chapter 2 = Authentication' is impossible in 5.0.0. The file's reporting exemplar at line 238 instructs citing 'requirement V2.1.5 (MFA for sensitive operations)' — V2.x is Authentication under 4.0.3 numbering; it is not a valid 5.0.0 identifier. A user running an ASVS 5.0.0 audit with this skill would be handed a wrong, edition-mismatched control ID in a real deliverable. This is a self-contradiction introduced/hardened by this phase's own diff (git show 6d7be18 confirms only the edition-verification banner was touched, strengthening the 5.0.0 claim without reconciling it against the pre-existing 4.0.3 body) and is precisely the accuracy failure this phase existed to eliminate (project constraint #1: 'Every OWASP version number, category, and control ID must be verified against official OWASP sources'). Confirmed independently by direct file read, not merely accepted from 03-REVIEW.md CR-01."
    artifacts:
      - path: "skills/owasp-security-audit/references/asvs.md"
        issue: "Lines 12-15 edition-verification note asserts ASVS 5.0.0 confirmed current; lines 47-224 chapter structure and line 238 exemplar control ID 'V2.1.5' are ASVS 4.0.3 taxonomy/numbering, not 5.0.0. Cosmetic secondary issue: chapters are also presented out of numerical order (2,4,6,5,3,8,7,10)."
    missing:
      - "Either (a) re-anchor the body to the ASVS 5.0.0 V-series taxonomy (renumber chapters to their correct 5.0.0 equivalents and replace V2.1.5 with a verified 5.0.0 requirement ID pulled from the published 5.0.0 requirements CSV), or (b) downgrade the edition-verification note to state the narrative summary follows 4.0.3 numbering while 5.0.0 is the current release, and remove V2.1.5 as a 5.0.0-labeled identifier"
---

# Phase 3: Remaining Standards Verification & Refresh Verification Report

**Phase Goal:** Every other OWASP standard cited by `owasp-security-audit`, and the checklist content of `secure-coding-practices`, is citation-hardened and traceable to a correctly-versioned, live OWASP source.
**Verified:** 2026-07-22
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Apps Top 10 (2026) each cite a verified official OWASP source URL + retrieval date (roadmap SC1 / CONT-03) | ✗ FAILED (partial) | MASVS/API/LLM/Agentic all correctly cite verified editions consistent with body content. ASVS's edition-verification note claims 5.0.0 but the body is ASVS 4.0.3 taxonomy, and the exemplar control ID `V2.1.5` is a 4.0.3 identifier presented as if valid under the declared 5.0.0 edition — see CR-01 below, independently re-confirmed by direct read of `asvs.md`. |
| 2 | Kubernetes reference cites 2022 stable edition as primary, with 2025 draft explicitly footnoted as in-progress/not final (roadmap SC2 / CONT-04) | ✓ VERIFIED | `kubernetes-top10.md` lines 7-17: "Source & edition" block pins 2022 as canonical with `Retrieved 2026-07-22`; a separate "2025 edition status (footnote)" paragraph states OWASP's page says only "Feedback welcome," no version tag, no formal GitHub release, explicitly "in progress, not final." `_meta.kubernetes_2025_status` in `owasp-urls.json` uses matching wording. K01-K10 entries unchanged in edition (still 2022); no 2025 K0x entry added. |
| 3 | `secure-coding-practices` content re-derived against living OWASP Developer Guide / Cheat Sheet Series / Proactive Controls; archived SCP QRG noted as historical origin, not current source (roadmap SC3 / CONT-05) | ✓ VERIFIED | `scp-checklist.md` carries a 14-row "Living-Source Crosswalk" table (confirmed all 14 rows present, URLs match `cheatsheetseries.owasp.org` / `devguide.owasp.org` / `top10proactive.owasp.org`), an archived-QRG blockquote with `Retrieved 2026-07-22`, and the top-of-file reference line reworded to "Historical origin." The pre-existing 14 domain headings and 219 checklist items are byte-for-byte unchanged (diff of commit `422cb6f` only removes the old `> **Reference:**` line and adds the crosswalk section). `secure-patterns.md` line 3 reworded to "Historical origin," pointing at the crosswalk. SCP's own `owasp-urls.json` marks `owasp_scp_guide.status = "archived"` with `retrieval_date` and adds a 14-entry `scp_domain_crosswalk` (confirmed valid JSON, 14 entries, File Management = `cited-weak`, Memory Management = `assumed`, matching the markdown table's weak-anchor flags one-for-one). |

**Score:** 2/3 roadmap truths fully verified (1 partially failed on the ASVS sub-claim)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `skills/owasp-security-audit/references/asvs.md` | Edition-verification note for ASVS 5.0.0, consistent with body | ⚠️ CONTRADICTORY | Note present, URL/date present, but body taxonomy + exemplar ID are 4.0.3, not 5.0.0 — see gap above |
| `skills/owasp-security-audit/references/masvs.md` | Edition-verification note for MASVS 2.1.0 | ✓ VERIFIED | Note present (lines 11-15); 8 MASVS-* control groups listed match 2.1.0 (includes MASVS-PRIVACY, added in 2.1.0); no version-specific control IDs cited that could mismatch |
| `skills/owasp-security-audit/references/api-top10.md` | Edition-verification note for API Security Top 10 2023 | ✓ VERIFIED | Note present (lines 11-14); body uses API1:2023-API10:2023 throughout, consistent |
| `skills/owasp-security-audit/references/llm-agentic.md` | Two edition-verification notes (LLM 2025 + Agentic 2026 Final) | ✓ VERIFIED | Both notes present (lines 15-18, 26-33); verbatim 2025-12-09 announcement quote present; LLM01:2025-LLM10:2025 and ASI01-ASI10 body content matches; AG## legacy-code mapping table untouched and accurate |
| `skills/owasp-security-audit/references/kubernetes-top10.md` | 2022 primary + 2025 footnoted not-final | ✓ VERIFIED | Confirmed above; existing `[?]` ambiguity markers and 2022→2025 cross-reference appendix preserved |
| `skills/owasp-security-audit/references/owasp-urls.json` | Verified edition/retrieval_date/confidence for ASVS, MASVS, API1-10, LLM01-10, ASI01-10, K01-10; `_meta.kubernetes_2025_status` | ✓ VERIFIED (structurally); ⚠️ see WR-01/WR-03 below | Valid JSON (`python3 -m json.tool` passes); all required fields present; `ASVS.edition == "5.0.0"`. Two review-flagged precision issues carried forward as warnings, not gates (see Anti-Patterns) |
| `skills/secure-coding-practices/references/scp-checklist.md` | 14-row crosswalk + archived-QRG note; checklist unchanged | ✓ VERIFIED | Confirmed above |
| `skills/secure-coding-practices/references/owasp-urls.json` | `owasp_scp_guide.status=archived`; 14-entry `scp_domain_crosswalk` | ✓ VERIFIED | Valid JSON; both conditions confirmed by direct read |
| `skills/secure-coding-practices/references/secure-patterns.md` | QRG line reworded to historical origin | ✓ VERIFIED | Line 3 confirmed reworded; body patterns below unchanged |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `scp-checklist.md` crosswalk table | `secure-coding-practices/owasp-urls.json` `scp_domain_crosswalk` | Domain-to-URL mapping agreement | ✓ WIRED | Compared all 14 rows — URLs and confidence tiers agree (File Management: table "CITED — weaker anchor" / JSON "cited-weak"; Memory Management: table "ASSUMED — weak anchor" / JSON "assumed") |
| `kubernetes-top10.md` 2025 footnote | `owasp-urls.json` `_meta.kubernetes_2025_status` | Consistent not-final wording | ✓ WIRED | Both state 2025 is available for feedback only, no formal release/version tag |
| `llm-agentic.md` ASI01-ASI10 names | Primary 2025-12-09 OWASP announcement | No third-party suffix variants | ✓ WIRED | Names confirmed plain (e.g., "Tool Misuse" not "Tool Misuse & Exploitation") |
| `asvs.md` edition-verification note | `asvs.md` body chapter/control-ID content | Edition claim must match cited requirement IDs | ✗ NOT WIRED | Edition note says 5.0.0; body uses 4.0.3 chapter numbers and cites `V2.1.5` as if it were a 5.0.0 ID — see gap |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|---|---|---|---|---|
| CONT-03 | 03-01-PLAN, 03-02-PLAN | ASVS/MASVS/API/LLM/Agentic citation-hardened with verified edition, URL, retrieval date | ✗ BLOCKED (partial) | MASVS/API/LLM/Agentic satisfied; ASVS's "verified edition" claim is false in the sense that the accompanying body content does not match the declared edition — a real audit-report control-ID would be wrong. REQUIREMENTS.md marks this `[x]` complete; that checkbox does not hold up under direct file inspection. |
| CONT-04 | 03-02-PLAN | Kubernetes 2022 primary, 2025 footnoted not-final | ✓ SATISFIED | Confirmed above |
| CONT-05 | 03-03-PLAN | secure-coding-practices re-derived against living sources, QRG noted historical | ✓ SATISFIED | Confirmed above; one manual-only spot-check remains outstanding (see Human Verification) |

No orphaned requirements: REQUIREMENTS.md maps exactly CONT-03/CONT-04/CONT-05 to Phase 3, and all three appear in the three plans' `requirements:` frontmatter.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `skills/owasp-security-audit/references/asvs.md` | 12-15, 47-224, 238 | Edition banner (5.0.0) contradicts body taxonomy/control ID (4.0.3) | 🛑 Blocker | See gap above — undermines the phase's core accuracy goal |
| `skills/owasp-security-audit/references/owasp-urls.json` | 51,56,59,60,62-71 | LLM03/06/09/10 and all ASI01-10 resolve only to an index/landing page yet carry identical `"confidence": "verified"` as per-item-URL entries | ⚠️ Warning | Weaker anchor mislabeled at the same confidence tier as stronger per-item citations; inconsistent with the file's own honest treatment of MASVS-* sub-entries (`"index-fallback"`). Does not misstate any edition/ID, so it does not fail SC1's literal wording, but it is a citation-honesty regression worth fixing before Phase 5's coverage-matrix work (QUAL-02) |
| `skills/owasp-security-audit/references/owasp-urls.json` | 45-49 | K06/K07/K08 JSON titles are abbreviated vs. the file's own md headers; K10 title diverges from the official 2022 title ("Vulnerable Components" vs. "Outdated and Vulnerable Kubernetes Components") — all marked `"verified"` | ⚠️ Warning | Pre-existing content (not modified substantively this phase — 03-02-PLAN only added `retrieval_date` to K01-K10, confidence was already "verified" beforehand). Does not affect CONT-04's 2022-primary/2025-footnote requirement, but the "verified" label overstates precision |
| `skills/owasp-security-audit/references/owasp-urls.json` | 4 | `_meta.confidence` documents a `"pattern"` tier that has zero entries and omits the `"index-fallback"` tier that is actually used | ℹ️ Info | Pre-existing schema/data drift, not introduced this phase |
| `skills/secure-coding-practices/references/secure-patterns.md` | multiple | WR-04 (broken `PBKDF2` import/undershooting iteration count), WR-05 (non-existent `CharField(regex=...)` kwarg), IN-02/03/04 (ineffective memory-clear, no-op cert pinning, deprecated header) | ℹ️ Info / pre-existing | Pre-existing example-code defects, not modified by this phase's re-anchoring work (which only touched the top provenance line) and not gating per this phase's success criteria — flagged for a future code-quality pass, not a Phase 3 gap |
| `skills/secure-coding-practices/references/owasp-urls.json` | 39-42, 54-58 | `related_owasp_projects.masvs`/`llm_top_10` use legacy URLs diverging from the audit skill's canonical URLs | ℹ️ Info / pre-existing | `related_owasp_projects` block was not touched by 03-03-PLAN (only `owasp_scp_guide` and the new `scp_domain_crosswalk` key were edited) |

No `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` markers found in any of the 9 phase-modified files.

### Human Verification Required

### 1. Spot-check the two LOW-confidence Living-Source Crosswalk anchors

**Test:** Open the File Upload Cheat Sheet (`https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html`, File Management row) and the Developer Guide index (`https://devguide.owasp.org/`, Memory Management row).
**Expected:** Confirm the File Upload Cheat Sheet genuinely covers File Management's checklist controls (it is explicitly flagged as covering upload validation only, not path-traversal/serving items), and confirm whether a better dedicated Memory Management anchor exists in the Developer Guide beyond the bare index page.
**Why human:** 03-03-SUMMARY.md explicitly defers this as a manual-only check (coverage item D4); it requires topical judgment of live external page content, which cannot be verified via grep/static analysis. These two rows are marked `weak`/`ASSUMED` and must not be silently upgraded to "verified" without this check.

## Gaps Summary

Two of three roadmap Success Criteria for this phase are solidly achieved: the Kubernetes 2022-primary/2025-footnote structure (SC2/CONT-04) and the secure-coding-practices living-source re-anchoring (SC3/CONT-05) both hold up under direct file inspection, including cross-file JSON/markdown consistency checks.

The remaining criterion (SC1/CONT-03) fails on its ASVS component. This phase's own diff (commit `6d7be18`) hardened the ASVS edition-verification note from a vague "Version 5.0 is the current release as of this writing" to an explicit, confident claim: "ASVS 5.0.0 confirmed as the current stable release (not a release candidate)." That stronger claim was never reconciled against the file's pre-existing body, which retains the ASVS 4.0.3 chapter taxonomy and cites `V2.1.5` — a 4.0.3-only identifier — as the reporting exemplar. The result is a reference file that now asserts a verified, hardened 5.0.0 edition while handing out a wrong control ID for that edition. This is exactly the class of defect the phase's D-06 halt-and-flag mechanism was designed to catch, but the halt-and-flag logic in 03-01-PLAN only checked for edition drift (has OWASP released something newer?), not internal consistency between the new edition claim and the pre-existing body content — so it did not fire.

This is not deferred to a later phase: Phase 4's example-remapping criterion (CONT-06) covers `examples/` code, not this reference file's own chapter/control-ID content, and Phase 5's coverage-matrix criterion only asks that a citation URL + retrieval date exist, not that the citation be internally consistent with the body. REQUIREMENTS.md currently shows CONT-03 checked off `[x]`; that status does not hold up against direct inspection of `asvs.md` and should be reopened.

Recommended fix path: either renumber `asvs.md`'s chapters to the ASVS 5.0.0 V-series (Authentication→V6, Session Management→V7, Authorization→V8, Cryptography→V11, Configuration→V13, Validation split V1/V2) and replace `V2.1.5` with a verified 5.0.0 requirement ID, or soften the edition-verification note to state that the narrative summary intentionally follows 4.0.3 numbering while 5.0.0 remains the current release, and stop presenting `V2.1.5` as though it were valid under 5.0.0.

---

_Verified: 2026-07-22_
_Verifier: Claude (gsd-verifier)_
