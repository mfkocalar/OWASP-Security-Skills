---
phase: 02-owasp-top-10-version-refresh
verified: 2026-07-21T14:12:26Z
status: gaps_found
score: 9/10 must-haves verified
behavior_unverified: 0
overrides_applied: 0
gaps:
  - truth: "top10.md 'What changed: 2021 to 2025' section is internally consistent and factually accurate about how many categories moved rank / carried over"
    status: failed
    reason: >
      top10.md line 20-21 states "Six of the eight categories that carried
      over both moved rank *and* several were renamed" — this contradicts the
      document's own mapping table two lines below and its own line-40
      restatement. Per the mapping table: only FIVE categories changed rank
      (A02 #5->2, A03 #6->3, A04 #2->4, A05 #3->5, A06 #4->6); A01/A07/A08/A09
      kept their numeric slot. And NINE categories (A01-A09) carry over to a
      distinct 2021 origin per the table — only A10 is genuinely net-new — so
      "eight" undercounts the carry-over set by one. Line 40 itself says "Only
      A01, A07, A08, and A09 keep the same numeric slot" which directly implies
      5 moved, not 6. This is a self-contradiction within the single most
      credibility-sensitive paragraph of the phase's primary deliverable (the
      plan's own objective calls the topic-to-ID mapping "the single highest
      credibility risk of the phase"). It was flagged by 02-REVIEW.md (WR-01)
      as a warning that "should be treated as high priority" for a public
      reference whose #1 project constraint (CLAUDE.md) is accuracy, and it
      remains unfixed as of this verification.
    artifacts:
      - path: "skills/owasp-security-audit/references/top10.md"
        issue: "Lines 20-21 prose ('Six of the eight...') contradicts the mapping table (lines 26-38) and the line-40 restatement ('Only A01, A07, A08, and A09 keep the same numeric slot')"
    missing:
      - "Rewrite the line-20/21 summary sentence to match the table: five categories moved rank (A02-A06), nine categories carried over from a 2021 origin (A01-A09), only A10 is net-new. 02-REVIEW.md WR-01 provides a ready-to-use replacement sentence."
deferred:
  - truth: "Every place a Top 10 category ID or name appears — including the paired vulnerable/secure example source files (.py/.js/.html) — uses the 2025 label"
    addressed_in: "Phase 4"
    evidence: "Phase 4 success criteria #4: 'Paired vulnerable/secure examples are re-validated against the updated standard requirement text (especially Top 10 2025) and mapped to the correct new category IDs.' REQUIREMENTS.md maps CONT-06 (example re-labeling) explicitly to Phase 4, and 02-CONTEXT.md/02-RESEARCH.md/both PLAN.md files document this as an explicit, deliberate scope split (D-02/D-03), not an oversight. Confirmed: skills/owasp-security-audit/assets/examples/security-misconfiguration.py:1 still says 'A05: Security Misconfiguration', cryptographic-failures.js:1 still says 'A02: Cryptographic Failures', xss.html:19 still says 'A03: Injection' — all 2021-era labels inside the example files themselves, but README.md's own example-table prose labels (the only 'examples' surface this phase's plans claim) were correctly updated to 2025 IDs."
---

# Phase 2: OWASP Top 10 Version Refresh Verification Report

**Phase Goal:** Rewrite the OWASP Top 10 reference from the 2021 edition to the 2025 (Final) edition with correct category IDs (topic-mapped, not numeric substitution), and make that edition consistent everywhere it is cited across the loaded skill path.
**Verified:** 2026-07-21T14:12:26Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | top10.md lists all 10 2025 categories, topic-mapped (not numeric substitution) from the official OWASP mapping | ✓ VERIFIED | `grep -cE '^## A(0[1-9]|10):'` = 10; all 10 headers present with topic-correct names (A02 Security Misconfiguration, A03 Software Supply Chain Failures [net-new], A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A10 Mishandling of Exceptional Conditions [net-new]) matching 02-RESEARCH.md's mapping table |
| 2 | SSRF is folded into A01 as a labeled sub-section citing CWE-918 | ✓ VERIFIED | `### Sub-section: Server-Side Request Forgery (SSRF) — CWE-918` present under `## A01`; `CWE-918` appears twice in top10.md |
| 3 | A "What changed: 2021 to 2025" mapping table appears near the top with per-category "formerly A0x in the 2021 edition" breadcrumbs | ✓ VERIFIED | Table present at lines 26-38 (topic-correct, cross-checked against 02-RESEARCH.md); breadcrumb prose present in each category body (e.g. "Formerly A05 in the 2021 edition", "Formerly A02 in the 2021 edition") |
| 4 | The "What changed" section is internally consistent (no self-contradicting counts) | ✗ FAILED | Lines 20-21 claim "Six of the eight categories... moved rank" — contradicts the table (5 moved: A02-A06) and line 40 ("Only A01, A07, A08, and A09 keep the same numeric slot"). See gap below. |
| 5 | Edition recorded as "2025 (Final)" with official source URL and retrieval date 2026-07-21 in top10.md and owasp-urls.json | ✓ VERIFIED | top10.md: `OWASP Top 10 2025 (Final)`, `https://owasp.org/Top10/2025/`, `2026-07-21` all present; owasp-urls.json: all 10 A01-A10 entries carry `"edition": "2025"`, matching URLs, and `"retrieval_date": "2026-07-21"` |
| 6 | owasp-urls.json A01-A10 entries are topic-correct 2025 IDs/URLs and the file remains valid JSON | ✓ VERIFIED | `python3 -m json.tool` exits 0; zero `"edition": "2021"` occurrences; all 10 entries verified topic-correct via direct JSON parse; `_indexes.top10_2025` key present (renamed from `top10_2021`) |
| 7 | No stale 2021-era Top 10 IDs/names/edition labels/URLs remain anywhere in the loaded skill path (skills/ + README.md) | ✓ VERIFIED | `grep -rnE "A0[1-9]_2021\|A10_2021\|\(2021\)" skills/ README.md` returns zero matches (exit 1/no output) — the CONT-02 gate |
| 8 | SKILL.md and owasp-security-audit.md mirror pair are byte-identical and both cite the 2025 Top 10 with 2025 A01 citation URLs | ✓ VERIFIED | `diff` reports no differences; both contain `OWASP Top 10 (2025)` and `Top10/2025/A01_2025-Broken_Access_Control`; zero occurrences of the 2021 label or 2021 A01 URL |
| 9 | vulnerable-patterns.md index/section headers renumbered to 2025 IDs (topic-mapped, in place); llm-agentic.md unaffected | ✓ VERIFIED | Headers confirmed: `## A04 — Cryptographic Failures`, `## A05 — Injection`, `## A02 — Security Misconfiguration`, `## A01 (SSRF, CWE-918) / API7 — SSRF`; llm-agentic.md:536 still correctly references web A09 (unchanged slot) |
| 10 | quick_scan.py Top10 labels match the 2025 taxonomy with regex logic unchanged; README coverage row and example-table labels read 2025 | ✓ VERIFIED | Label counts: A04=8, A05=6, A02=4, A01=1, A07=2 (all match plan spec); zero A03/A10 stray labels; `python3 -m py_compile` exits 0; README contains `OWASP Top 10 (2025)`, zero `(2021)`, and per-example labels (A04)/(A05)/(A02) correctly applied |

**Score:** 9/10 truths verified (0 present, behavior-unverified)

### Deferred Items

Items not yet met but explicitly addressed in a later milestone phase.

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | Paired vulnerable/secure example source files (.py/.js/.html) still contain 2021-era Top 10 IDs in their own text (e.g. `security-misconfiguration.py:1` says "A05", `cryptographic-failures.js:1` says "A02", `xss.html:19` says "A03") | Phase 4 | Phase 4 SC #4 explicitly covers re-validating and remapping example category IDs; REQUIREMENTS.md maps CONT-06 to Phase 4; both 02-01-PLAN.md and 02-02-PLAN.md explicitly prohibit touching example files in this phase (D-02/D-03), and README.md's own example-table prose labels (the "examples" surface these plans actually claim) were correctly updated to 2025 IDs |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `skills/owasp-security-audit/references/top10.md` | 2025 Final rewrite, topic-mapped, mapping table, breadcrumbs, SSRF+CWE-918 in A01, net-new A03/A10 | ✓ VERIFIED (with prose defect) | All structural/data must-haves pass; one internally-inconsistent summary sentence (see gap) |
| `skills/owasp-security-audit/references/owasp-urls.json` | 2025 A01-A10 block, valid JSON, retrieval_date, top10_2025 index | ✓ VERIFIED | All checks pass |
| `skills/owasp-security-audit/SKILL.md` | 2025 edition label + citation URLs | ✓ VERIFIED | All checks pass |
| `skills/owasp-security-audit/owasp-security-audit.md` | Byte-identical mirror of SKILL.md | ✓ VERIFIED | `diff` empty |
| `skills/owasp-security-audit/references/vulnerable-patterns.md` | 2025 IDs, topic-mapped, in place | ✓ VERIFIED | Headers confirmed |
| `skills/owasp-security-audit/scripts/quick_scan.py` | 2025 Top10:Axx labels, regex unchanged | ✓ VERIFIED | Label counts + py_compile pass |
| `README.md` | 2025 coverage row + example labels | ✓ VERIFIED | Grep checks pass |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| top10.md category IDs/names | owasp-urls.json A01-A10 keys | Identical 2025 IDs, names, URLs | ✓ WIRED | All 10 titles match between top10.md headers and owasp-urls.json entries |
| top10.md edition-note source URL | owasp-urls.json `_indexes.top10_2025` | Both `https://owasp.org/Top10/2025/` | ✓ WIRED | Confirmed identical |
| SKILL.md Top 10 citation URLs | owasp-urls.json A01 2025 URL | Citation URL matches JSON entry | ✓ WIRED | `Top10/2025/A01_2025-Broken_Access_Control` present in both |
| quick_scan.py category labels | top10.md 2025 taxonomy | Label-to-category correspondence | ✓ WIRED | crypto=A04(8), injection=A05(6), misconfig=A02(4), SSRF=A01(1), auth=A07(2) — matches top10.md's taxonomy |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| CONT-01 | 02-01-PLAN.md | Top 10 reference updated 2021→2025 (Final) using official category mapping | ✓ SATISFIED | top10.md rewritten with 10 topic-correct categories, mapping table, SSRF/A01 fold-in, net-new A03/A10 — verified above (one prose-accuracy defect noted as gap) |
| CONT-02 | 02-01-PLAN.md, 02-02-PLAN.md | Top 10 IDs/names/cross-references consistent everywhere they appear (skill body, references, examples, README, manifest) | ✓ SATISFIED (loaded path); ⚠ example-file scope deferred | CONT-02 grep clean across skills/ + README.md; example *source file* re-labeling is separately tracked as CONT-06 and explicitly deferred to Phase 4 per REQUIREMENTS.md — not an orphaned or missed requirement |

No orphaned requirements: REQUIREMENTS.md maps only CONT-01 and CONT-02 to Phase 2, and both plans declare exactly these two IDs in frontmatter.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `skills/owasp-security-audit/references/top10.md` | 20-21 | Self-contradicting factual claim ("Six of the eight... moved rank") vs. the document's own table and line-40 restatement | 🛑 Content-accuracy defect (see gap) | Undermines the credibility of the single paragraph whose job is to explain the edition migration; already flagged by 02-REVIEW.md WR-01 and left unresolved |
| `skills/owasp-security-audit/references/top10.md` (A09) vs `owasp-urls.json` (A09) | 36, 526 / 25 | "&" vs "and" in A09 title ("Security Logging & Alerting Failures" vs "Security Logging and Alerting Failures") | ℹ️ Info (pre-existing, non-blocking) | Cosmetic label mismatch between prose heading and citation-link text (02-REVIEW.md IN-01); does not affect any must-have |
| `skills/owasp-security-audit/SKILL.md` / `owasp-security-audit.md` | whole file | Duplicated files with no automated sync guard | ℹ️ Info (pre-existing, non-blocking) | Currently byte-identical (verified); no CI/pre-commit guard exists yet to prevent future drift (02-REVIEW.md WR-02) — informational, not a phase-2 must-have |

No `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` debt markers found in any of the seven phase-2-modified files.

### Behavioral Spot-Checks

Step 7b: SKIPPED (no runnable entry points beyond `quick_scan.py`, which is exercised via `py_compile` above; this is a documentation-migration phase, not a service/CLI with meaningful runtime behavior to probe beyond the syntax check already performed)

### Probe Execution

No `scripts/*/tests/probe-*.sh` files exist in this repository and no PLAN/SUMMARY references any probe script — Step 7c not applicable.

### Human Verification Required

None. All must-haves and the flagged content-accuracy issue are deterministically verifiable by reading the file (no runtime, visual, or UX judgment required).

### Gaps Summary

Phase 2's structural and data-correctness work is genuinely complete and accurate: all 10 categories are topic-mapped correctly, SSRF/CWE-918 is folded into A01, A03 and A10 are freshly written net-new categories, the edition is recorded as Final with source URL and retrieval date, `owasp-urls.json` is valid and consistent, and the CONT-02 consistency sweep is clean across the entire loaded skill path (SKILL.md mirror, vulnerable-patterns.md, quick_scan.py, README.md) — the code review's own adversarial pass confirmed "no incorrect OWASP ID, invalid data, or broken citation was found."

The one gap is a single self-contradicting sentence in top10.md's "What changed" intro (lines 20-21), which claims "six of the eight" categories moved rank/carried over when the document's own mapping table and its own line-40 restatement both say five moved rank and nine carried over. This was already caught by 02-REVIEW.md (WR-01) and rated high-priority for a public reference whose top project constraint is accuracy, but it was not fixed before this phase was marked complete. It is a one-sentence, mechanical fix (a ready replacement sentence is provided in 02-REVIEW.md WR-01) and does not require re-touching any other must-have artifact.

The paired-example-file relabeling item is correctly out of scope for this phase (tracked separately as CONT-06, explicitly deferred to Phase 4 in REQUIREMENTS.md and in both plan documents) and is recorded above as `deferred`, not a gap.

---

_Verified: 2026-07-21T14:12:26Z_
_Verifier: Claude (gsd-verifier)_
