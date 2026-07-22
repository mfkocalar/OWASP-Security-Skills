---
phase: 03-remaining-standards-verification-refresh
reviewed: 2026-07-22T00:00:00Z
depth: standard
files_reviewed: 9
files_reviewed_list:
  - skills/owasp-security-audit/references/api-top10.md
  - skills/owasp-security-audit/references/asvs.md
  - skills/owasp-security-audit/references/kubernetes-top10.md
  - skills/owasp-security-audit/references/llm-agentic.md
  - skills/owasp-security-audit/references/masvs.md
  - skills/owasp-security-audit/references/owasp-urls.json
  - skills/secure-coding-practices/references/owasp-urls.json
  - skills/secure-coding-practices/references/scp-checklist.md
  - skills/secure-coding-practices/references/secure-patterns.md
findings:
  critical: 1
  warning: 6
  info: 5
  total: 12
status: issues_found
---

# Phase 3: Code Review Report

**Reviewed:** 2026-07-22
**Depth:** standard
**Files Reviewed:** 9
**Status:** issues_found

## Summary

Phase 03 is a citation-hardening + living-source re-anchoring pass over six OWASP
reference documents and two `owasp-urls.json` citation maps. Review prioritized the
project's #1 constraint (accuracy of editions, category IDs, and control identifiers),
internal consistency between the markdown notes and the JSON entries, JSON
well-formedness, and honesty of "verified" confidence labels.

**Strong points.** Both `owasp-urls.json` files parse as valid JSON with no duplicate
keys. Retrieval dates are internally consistent between every markdown file and its JSON
counterpart (A01–A10 dated 2026-07-21 per the Phase 2 re-verification; all Phase 3
standards dated 2026-07-22). The SCP crosswalk confidence tiers match one-for-one
between `scp-checklist.md` and the SCP `owasp-urls.json`, including the honestly-labeled
weaker anchors (File Management "cited-weak", Memory Management "assumed"). The
Kubernetes 2022-vs-2025 edition status is consistently hedged across the footnote, the
`_meta` block, and the appendix. The LLM/Agentic `AG##`→real-code mapping and the
"invented codes are not OWASP" warnings are accurate and well-guarded.

**Key concern.** One BLOCKER: `asvs.md` had its edition claim *hardened* this phase to
"ASVS 5.0.0 confirmed as the current stable release," yet the entire body still uses the
ASVS **4.0.3** chapter taxonomy and cites a 4.0-style requirement ID (`V2.1.5`). This is
the precise self-contradiction this phase existed to eliminate, and it directly violates
the accuracy constraint on control identifiers. Six warnings cover weaker "verified"
labels, md/JSON title mismatches, a schema-documentation drift, a cross-file MASVS URL
divergence, and two broken/weak code samples in `secure-patterns.md` that are labeled
SECURE.

## Critical Issues

### CR-01: `asvs.md` declares edition 5.0.0 but its content is the ASVS 4.0.3 taxonomy

**File:** `skills/owasp-security-audit/references/asvs.md:12-14`, body `47-224`, example `238-239`

**Issue:** The Phase 3 diff added a strengthened claim:

> "**Edition verification:** ASVS 5.0.0 confirmed as the current stable release … released 2025-05-30 at Global AppSec EU Barcelona."

The edition string, date, and venue are correct for ASVS 5.0.0. But every chapter heading
and the one concrete requirement ID in the file belong to **ASVS 4.0.3**, not 5.0.0:

- The file's chapters are numbered "Chapter 2: Authentication", "Chapter 3: Session
  Management", "Chapter 4: Access Control", "Chapter 5: Input Validation & Encoding",
  "Chapter 6: Cryptography", "Chapter 7: Error Handling & Logging", "Chapter 8: Data
  Protection", "Chapter 10: Malicious Code" (lines 47, 70, 93, 117, 145, 168, 190, 211).
  This is the 4.0.3 chapter map.
- In ASVS **5.0.0**, the chapters were renumbered: Authentication is **V6**, Session
  Management **V7**, Authorization **V8**, Cryptography **V11**, Configuration **V13**,
  Validation is split into V1 (Encoding & Sanitization) / V2 (Validation & Business
  Logic). The "Chapter 2 = Authentication" mapping is impossible under 5.0.0.
- Line 238-239 cites a specific control ID as the reporting exemplar: *"Ch. 2 L2 —
  requirement V2.1.5 (MFA for sensitive operations)"*. `V2.x` is Authentication in 4.0.3;
  under 5.0.0 that content lives under the V6 series. The skill will emit a wrong,
  non-existent-for-the-declared-edition control ID in real audit reports.

Because the skill instructs the reviewer to "cite the chapter + level" and hands `V2.1.5`
as the template, this defect propagates directly into deliverables — the exact failure the
accuracy constraint forbids.

**Fix:** Either (a) re-anchor the body to the 5.0.0 taxonomy (renumber the chapters to
their V-series equivalents and replace `V2.1.5` with the correct 5.0.0 authentication
requirement ID after verifying it against the published 5.0.0 requirements CSV), or
(b) if the intent is to keep 4.0.3-structured guidance, change the edition claim to state
that the *narrative summary follows 4.0.3 numbering* while 5.0.0 is the current release,
and stop presenting `V2.1.5` as a 5.0.0 identifier. Do not leave a 5.0.0 edition banner
over 4.0.3 chapter/requirement numbering.

## Warnings

### WR-01: LLM03/06/09/10 (and all ASI entries) marked "verified" resolve only to an index/landing page

**File:** `skills/owasp-security-audit/references/owasp-urls.json:53,56,59,60,62-71`

**Issue:** `LLM01/02/04/05/07/08` carry per-item `llmrisk/…` URLs, but `LLM03`, `LLM06`,
`LLM09`, `LLM10` all point to the index `https://genai.owasp.org/llm-top-10/` — yet every
entry carries the identical `"confidence": "verified"`. Similarly, `ASI01`–`ASI10` all
resolve to the single resource-page URL. A citation that only reaches an index page is a
strictly weaker anchor than a per-item page, and `llm-agentic.md:326` itself hedges the
ASI per-item definitions with `[?]` ("the downloadable PDF … carries the canonical
definitions"). Labeling the weaker anchors "verified" identically to the per-item ones
overstates the strength of the citation and is inconsistent with the file's own honesty
elsewhere (the MASVS sub-entries correctly use `"index-fallback"`).

**Fix:** Downgrade the index-only LLM entries and the ASI entries to a distinct tier
(e.g., `"index-fallback"` or `"verified-index"`) so the confidence label reflects that the
per-item page was not the resolved target, matching the treatment already given to the
MASVS-* sub-entries.

### WR-02: `_meta.confidence` documents tiers that don't exist and omits the ones that do

**File:** `skills/owasp-security-audit/references/owasp-urls.json:4,18-82`

**Issue:** The `_meta.confidence` description defines only two tiers — entries "marked
'verified'" and "'pattern' entries … inferred from the project's URL scheme." In the
actual data there are **zero** `pattern` entries, while `index-fallback` (lines 75-82) is
used but never documented. The schema description and the data have drifted apart, which
undercuts the file's role as the authoritative confidence legend.

**Fix:** Update the `_meta.confidence` text to describe the tiers actually in use
(`verified`, `index-fallback`, and whatever tier WR-01 introduces), and drop or restore the
`pattern` tier so the legend matches the payload.

### WR-03: Kubernetes titles in `owasp-urls.json` don't match the markdown headers or the official 2022 titles, yet are "verified"

**File:** `skills/owasp-security-audit/references/owasp-urls.json:45-49`; cross-ref `kubernetes-top10.md:245,309,389,525`

**Issue:** Three K-series titles disagree between the JSON and the file's own markdown
headers, and one disagrees with the official OWASP 2022 title — all while marked
`"confidence": "verified"`:

- `K06` JSON "Broken Authentication" vs md header "K06: Broken Authentication **Mechanisms**".
- `K07` JSON "Network Segmentation" vs md header "K07: **Missing** Network Segmentation **Controls**".
- `K08` JSON "Secrets Management" vs md header "K08: Secrets Management **Failures**".
- `K10` JSON and md both say "Vulnerable Components"; the official 2022 title is
  "**Outdated and Vulnerable Kubernetes** Components".

A "verified" label should mean the title was checked against source; these abbreviations
were not.

**Fix:** Normalize the JSON `title` fields to the official 2022 titles (and align the md
headers), or, if intentional shorthand, drop the `"verified"` claim on the affected entries.

### WR-04: `secure-patterns.md` PBKDF2 example is broken and uses an iteration count its own repo contradicts

**File:** `skills/secure-coding-practices/references/secure-patterns.md:416,423-427`

**Issue:** The block labeled "✓ SECURE: Key derivation from password" has two defects:

1. `from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2` and `kdf = PBKDF2(...)` —
   the `cryptography` library exposes the class as **`PBKDF2HMAC`**, not `PBKDF2`. As
   written this raises `ImportError`, so the "secure" template does not run.
2. `iterations=100000` contradicts this repo's own `asvs.md:106`, which requires
   "PBKDF2-SHA256 with ≥ 310,000 iterations," and is below current OWASP guidance. A SECURE
   pattern that undershoots the standard the same skill enforces is an internal
   inconsistency a reviewer copying the template would inherit.

**Fix:**
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
...
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
```
Align the iteration count with `asvs.md` (≥ 310,000; OWASP currently recommends 600,000 for
PBKDF2-HMAC-SHA256).

### WR-05: `secure-patterns.md` Django validation example uses a non-existent `CharField(regex=...)` kwarg

**File:** `skills/secure-coding-practices/references/secure-patterns.md:38-42`

**Issue:** The "✓ SECURE: Django input validation" block does:
```python
username = forms.CharField(max_length=20, min_length=3, regex=r'^[a-zA-Z0-9_-]+$')
```
`django.forms.CharField` does not accept a `regex` argument — this raises `TypeError` at
class definition. Regex-constrained fields use `forms.RegexField`. The example is offered
as a copy-ready secure template but will not import.

**Fix:** Use `username = forms.RegexField(regex=r'^[a-zA-Z0-9_-]+$', max_length=20,
min_length=3)`, or attach a `RegexValidator` to `CharField`.

### WR-06: MASVS canonical URL diverges between the two `owasp-urls.json` files

**File:** `skills/owasp-security-audit/references/owasp-urls.json:74` vs `skills/secure-coding-practices/references/owasp-urls.json:39-42`

**Issue:** The audit map uses `https://mas.owasp.org/MASVS/` (matching `masvs.md:9`, the
canonical MASVS home), while the SCP map's `related_owasp_projects.masvs.url` points to the
older `https://owasp.org/www-project-mobile-app-security/`. Two citation maps in the same
distribution give two different "official" MASVS URLs. The SCP map's `llm_top_10` entry
(line 55) similarly uses the legacy `www-project-llm-top-10/` slug rather than the
`genai.owasp.org` home the audit side treats as canonical.

**Fix:** Standardize the SCP `related_owasp_projects` URLs on the same canonical anchors the
audit map uses (`mas.owasp.org/MASVS/`, `genai.owasp.org/llm-top-10/`), or add a note that
the SCP list intentionally points at project landing pages.

## Info

### IN-01: Injection-scan flag on `llm-agentic.md` is a false positive

**File:** `skills/owasp-security-audit/references/llm-agentic.md:85,240-241`

**Issue:** The PostToolUse hook flagged "ignore previous instructions" and "repeat your
instructions" patterns. These are legitimate documentation content — an adversarial test
corpus example (LLM01) and a red-team probe example (LLM07), not an injection payload. No
action needed; recorded for transparency.

### IN-02: `secure-patterns.md` "clear sensitive data from memory" pattern is ineffective in Python

**File:** `skills/secure-coding-practices/references/secure-patterns.md:531-545`

**Issue:** `password = "x" * len(password); del password; gc.collect()` does not overwrite
the original secret — Python `str` objects are immutable, so the reassignment creates a new
object and leaves the original in memory until GC. Labeled SECURE, it teaches a
misconception. `asvs.md:179` correctly scopes zeroing to "where language permits"; Python
`str` does not. Consider a `bytearray` example or a note that Python cannot reliably zero
`str` secrets.

### IN-03: `secure-patterns.md` "certificate pinning" example is a no-op

**File:** `skills/secure-coding-practices/references/secure-patterns.md:574-578`

**Issue:** The `# Certificate pinning (for sensitive APIs)` comment sits over a
`create_urllib3_context(...)` call whose return value is discarded and never attached to any
session/adapter. The code performs no pinning; the comment overstates what it does. Either
implement pinning (custom `HTTPAdapter` + `assert_fingerprint`) or relabel the comment.

### IN-04: `secure-patterns.md` recommends the deprecated `X-XSS-Protection` header

**File:** `skills/secure-coding-practices/references/secure-patterns.md:588`

**Issue:** `X-XSS-Protection: 1; mode=block` is deprecated; current OWASP guidance is to set
`X-XSS-Protection: 0` and rely on Content-Security-Policy (already set on line 590). Minor
freshness gap in a SECURE example.

### IN-05: `asvs.md` chapters are presented out of numerical order

**File:** `skills/owasp-security-audit/references/asvs.md:47,70,93,117,145,168,190,211`

**Issue:** Chapters appear as 2, 4, 6, 5, 3, 8, 7, 10 rather than in sequence. Cosmetic,
but it compounds CR-01's numbering confusion; worth ordering sequentially when the
edition/numbering is reconciled.

---

_Reviewed: 2026-07-22_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
