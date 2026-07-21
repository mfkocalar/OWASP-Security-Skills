---
phase: 02-owasp-top-10-version-refresh
reviewed: 2026-07-21T00:00:00Z
depth: standard
files_reviewed: 6
files_reviewed_list:
  - skills/owasp-security-audit/SKILL.md
  - skills/owasp-security-audit/owasp-security-audit.md
  - skills/owasp-security-audit/references/owasp-urls.json
  - skills/owasp-security-audit/references/top10.md
  - skills/owasp-security-audit/references/vulnerable-patterns.md
  - skills/owasp-security-audit/scripts/quick_scan.py
findings:
  critical: 0
  warning: 2
  info: 4
  total: 6
status: issues_found
---

# Phase 02: Code Review Report

**Reviewed:** 2026-07-21
**Depth:** standard
**Files Reviewed:** 6
**Status:** issues_found

## Summary

Adversarial content-integrity review of the OWASP Top 10 reference content
migrated from the 2021 edition to the 2025 Final edition. Six source files
were reviewed against the phase's stated primary risks: correct OWASP IDs,
valid JSON, no broken citations, and internal consistency.

**The core migration is sound.** All ten 2025 category IDs/names/ordering
match the known 2025 Final structure; SSRF is correctly folded from A10:2021
into A01:2025 (including the `quick_scan.py` label renumbering — `requests.get`
SSRF hint moved to `Top10:A01`); every crypto/injection/misconfig/auth label
in the scanner was correctly renumbered to the 2025 scheme; `owasp-urls.json`
is valid JSON with no duplicate keys, and all ten Top-10 URL slugs match their
titles. The 2021-origin names in the mapping table are all correct, and the
statistical claims (100% misconfig, 30k+/14k+ CVEs, 723 CVEs, 36 CWEs, 24
CWEs) are backed verbatim by `02-RESEARCH.md`. All referenced reference files
and the nine `assets/examples/` files exist — no broken citations.

**No blockers.** No incorrect OWASP ID, invalid data, or broken citation was
found. The findings below are one factual-consistency error in prose, one
maintainability defect (duplicated files), and four minor completeness/
cosmetic items. Note the WR-01 count error is prose-only and self-corrected by
the doc's own mapping table two lines later — but for a public reference whose
prime directive is accuracy, it should be treated as high priority.

## Structural Findings (fallow)

No `<structural_findings>` block was provided with this review. None to report.

## Narrative Findings (AI reviewer)

## Warnings

### WR-01: Intro summary counts contradict the authoritative mapping table

**File:** `skills/owasp-security-audit/references/top10.md:20`
**Issue:** The "What changed" intro states: *"Six of the eight categories that
carried over both moved rank and several were renamed."* Both numbers conflict
with the doc's own mapping table (lines 26-38) and its line-40 statement:
- **Rank moves:** only **five** categories changed rank — A02 (#5→2), A03
  (#6→3), A04 (#2→4), A05 (#3→5), A06 (#4→6). A01/A07/A08/A09 kept their slot.
  "Six ... moved rank" overstates by one under every interpretation (max is 5).
- **Carried over:** **nine** categories trace to a distinct 2021 origin
  (A01–A09 all map back in the table); only A10:2025 is net-new. "Eight" is an
  undercount (or an undocumented special-casing of A01 for the SSRF fold-in).
- Line 40 correctly says *"Only A01, A07, A08, and A09 keep the same numeric
  slot,"* which implies 5 moved — directly contradicting the intro's "six."

For a public OWASP reference where accuracy is the #1 project constraint
(`CLAUDE.md`), a wrong count in the opening summary undercuts credibility even
though the machine-checkable table below it is correct.
**Fix:** Reconcile the sentence to the table. Suggested:
```
Of the nine categories that carried over from 2021, five moved rank (A02–A06)
and four were renamed (A03, A07, A08, A09) — this is not a simple renumbering.
```
Alternative considered: keep "eight" by explicitly excluding A01 as a special
case ("eight carried-over categories besides A01, which absorbed SSRF"), but
that still leaves "six moved rank" wrong, so a full rewrite is cleaner.

### WR-02: Byte-identical guidance files duplicated with no sync mechanism

**File:** `skills/owasp-security-audit/SKILL.md` and
`skills/owasp-security-audit/owasp-security-audit.md`
**Issue:** The two files are byte-identical (confirmed via `diff`) and both are
regular files (confirmed via `file` — not symlinks). This duplication is noted
as intentional in the phase brief, but there is no automated guard keeping them
in sync. The next edit to either file (a new OWASP edition, a routing-table
tweak) will silently drift them apart, and the skill has two "sources of truth"
for 416 lines of guidance. Since the content must stay identical, copying is
strictly worse than a mechanism that enforces identity.
**Fix:** Replace the copy with a symlink (`owasp-security-audit.md ->
SKILL.md`) if the packaging tolerates symlinks, or add a CI/pre-commit check
that fails when the two diverge:
```bash
diff -q skills/owasp-security-audit/SKILL.md \
        skills/owasp-security-audit/owasp-security-audit.md \
  || { echo "SKILL.md and owasp-security-audit.md have drifted"; exit 1; }
```
*Tradeoff:* a symlink is zero-maintenance but some marketplace packagers
dereference or reject symlinks; the CI check keeps two real files but adds a
gate. Pick per distribution constraints. Either beats an unguarded copy.

## Info

### IN-01: A09 title differs between reference files ("&" vs "and")

**File:** `skills/owasp-security-audit/references/top10.md:36,526` vs
`skills/owasp-security-audit/references/owasp-urls.json:25`
**Issue:** `top10.md` renders A09 as "Security Logging **&** Alerting Failures"
(ampersand), while `owasp-urls.json` uses "Security Logging **and** Alerting
Failures". Since the skill emits the JSON `title` as the visible text of the
markdown citation link, the link label will not match the prose heading a
reader just saw. Purely cosmetic; the URL slug (`..._and_...`) is unaffected.
**Fix:** Pick one form and apply it in both files. The URL slug uses `and`, so
standardizing on "and" in `top10.md` keeps label and slug aligned.

### IN-02: A03 section omits mapped-CWE list that peer sections include

**File:** `skills/owasp-security-audit/references/top10.md:234-303`
**Issue:** A04, A06, A09, and A10 each enumerate their mapped CWEs inline, and
`02-RESEARCH.md:191` captured A03's CWEs (CWE-447, 1035, 1104, 1329, 1357,
1395). The A03 section lists none, creating uneven depth across sections.
Not an accuracy error — a completeness gap.
**Fix:** Add a CWE line to A03 mirroring the peer sections, e.g. "Relevant
CWEs: CWE-1104 (unmaintained third-party components), CWE-1357 (reliance on
insufficiently trustworthy component), …".

### IN-03: A03 header prose reads "New category for 2025" like the genuinely net-new A10

**File:** `skills/owasp-security-audit/references/top10.md:236`
**Issue:** A03 opens with *"New category for 2025 — expands on what was
A06:2021,"* the same "New category for 2025" lead-in used by A10 (line 569),
which is genuinely net-new with no 2021 equivalent. The mapping table (line 30)
correctly treats A03 as a rename/rescope of A06:2021, not net-new. The
qualifier that follows keeps it technically accurate, but the parallel phrasing
can imply A03 is net-new to a skimming reader.
**Fix:** Reword to "Expanded and renamed for 2025 — grows A06:2021 (Vulnerable
and Outdated Components) into the full software supply chain," reserving "New
category for 2025 — no 2021 equivalent" for A10 only.

### IN-04: quick_scan.py `standard` field namespacing is inconsistent

**File:** `skills/owasp-security-audit/scripts/quick_scan.py:171-179`
**Issue:** Emitted `standard` values are namespaced for Top 10 (`Top10:A04`)
and Kubernetes (`K8s:K01`) but bare for LLM patterns (`LLM01`, `LLM05`). The
bare LLM codes also don't match the `owasp-urls.json` keys (`LLM01:2025`),
so a reviewer resolving a scanner lead to a citation must know to reattach the
`:2025` suffix. Pre-existing and cosmetic (the field is a human hint, not a
lookup key), and tangential to the Top-10 focus of this phase.
**Fix:** Normalize to a consistent scheme, e.g. `LLM:LLM01` / `LLM:LLM05`, or
document that `standard` is a display hint and the JSON key is derived by
stripping the namespace prefix.

---

_Reviewed: 2026-07-21_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
