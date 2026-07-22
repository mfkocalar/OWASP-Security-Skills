# Phase 3: Remaining Standards Verification & Refresh - Pattern Map

**Mapped:** 2026-07-22
**Files analyzed:** 9 (all modify-in-place, no new files)
**Analogs found:** 9 / 9 (all analogs are Phase 2's already-hardened files)

## File Classification

| File to Modify | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `skills/owasp-security-audit/references/asvs.md` | reference doc (config-like) | request-response (loaded on demand by SKILL.md) | `skills/owasp-security-audit/references/top10.md` (edition-note block) | exact |
| `skills/owasp-security-audit/references/masvs.md` | reference doc | request-response | `top10.md` (edition-note block) | exact |
| `skills/owasp-security-audit/references/api-top10.md` | reference doc | request-response | `top10.md` (edition-note block) | exact |
| `skills/owasp-security-audit/references/llm-agentic.md` | reference doc | request-response | `top10.md` (edition-note block) — needs TWO notes | exact |
| `skills/owasp-security-audit/references/kubernetes-top10.md` | reference doc | request-response | `top10.md` (edition-note block) + own existing `[?]` footnote convention | exact (self-analog for footnote) |
| `skills/owasp-security-audit/references/owasp-urls.json` | config/data (URL index) | CRUD (key lookup) | its own existing `A01`–`A10` verified entries (Phase 2) | exact |
| `skills/secure-coding-practices/references/scp-checklist.md` | reference doc | request-response | `top10.md` "What changed" table style (markdown table w/ URL column) | role-match |
| `skills/secure-coding-practices/references/owasp-urls.json` | config/data (URL index) | CRUD | `owasp-security-audit/references/owasp-urls.json` entry shape | role-match (different file, same shape) |
| `skills/secure-coding-practices/references/secure-patterns.md` | reference doc | request-response | its own top-line `> Reference:` header (self-analog, single-line fix) | exact |

## Pattern Assignments

### `skills/owasp-security-audit/references/asvs.md` (reference doc)

**Analog:** `skills/owasp-security-audit/references/top10.md`, lines 8-17

**Current file top** (`asvs.md` lines 9-11 — the line to replace/extend):
```markdown
**Source:** OWASP Application Security Verification Standard —
<https://owasp.org/www-project-application-security-verification-standard/>.
Version 5.0 is the current release as of this writing.
```

**Edition-verification note pattern to insert (mirror `top10.md` lines 8-17 exactly in structure):**
```markdown
**Source:** OWASP Application Security Verification Standard —
<https://owasp.org/www-project-application-security-verification-standard/>.

**Edition verification:** ASVS 5.0.0 confirmed as the current stable release
(not a release candidate), released 2025-05-30 at Global AppSec EU Barcelona.
Source: <https://owasp.org/www-project-application-security-verification-standard/>.
Retrieved 2026-07-22. No newer stable edition found as of this date.
```
Note: replace the vague "Version 5.0 is the current release as of this writing" with the exact "5.0.0" + verified/retrieved-date language per D-03/D-06 — this file currently under-specifies the patch version and has no retrieval date, exactly the gap `top10.md` closed in Phase 2.

---

### `skills/owasp-security-audit/references/masvs.md` (reference doc)

**Analog:** `top10.md` lines 8-17; existing `masvs.md` lines 8-11 (to be tightened)

**Current text to replace:**
```markdown
**Source:** OWASP Mobile Application Security Verification Standard —
<https://mas.owasp.org/MASVS/>. Version 2.1.0 is the current release as
of this writing; confirm against the MAS site if citing version
text verbatim.
```

**Edition-verification note to insert (same shape as ASVS above):**
```markdown
**Edition verification:** MASVS 2.1.0 confirmed current — GitHub release tag
`v2.1.0`, published 2024-01-18, added the MASVS-PRIVACY category.
Source: <https://mas.owasp.org/MASVS/> (also see
<https://github.com/OWASP/masvs/releases/tag/v2.1.0>). Retrieved 2026-07-22.
No newer tag found.
```
This removes the current "confirm against the MAS site" hedge language — the point of this phase is to replace that hedge with an actual verified note.

---

### `skills/owasp-security-audit/references/api-top10.md` (reference doc)

**Analog:** `top10.md` lines 8-17; existing `api-top10.md` line 8

**Current text:**
```markdown
**Source:** OWASP API Security Project 2023 edition —
<https://owasp.org/API-Security/editions/2023/en/0x11-t10/>.
```

**Edition-verification note to append directly after:**
```markdown
**Edition verification:** API Security Top 10 2023 confirmed current — no
newer edition found; `API1:2023`–`API10:2023` match this file item-for-item.
Source: <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>.
Retrieved 2026-07-22.
```

---

### `skills/owasp-security-audit/references/llm-agentic.md` (reference doc — TWO notes required)

**Analog:** `top10.md` lines 8-17 (structure), applied twice since this file covers two standards.

**Existing structure** (lines 1-24) already has a numbered two-project intro (LLM 2025 / Agentic 2026) with an announcement/resource-page link and a callout box warning against invented `AG01-10` codes (lines 21-24) — insert the edition-verification prose directly under each of the two numbered project bullets (after line 13 for LLM, after line 19 for Agentic), not as one combined note.

**LLM 2025 note** (insert after line 13, `PDF: ...` line):
```markdown
   **Edition verification:** LLM Top 10 2025 confirmed current — live index
   lists exactly `LLM01:2025`–`LLM10:2025`, matching this file. No 2026
   LLM-specific edition found (2026 work is the separate Agentic project).
   Source: <https://genai.owasp.org/llm-top-10/>. Retrieved 2026-07-22.
```

**Agentic 2026 note** (insert after line 19, `Resource page: ...` line):
```markdown
   **Edition verification:** Agentic Apps Top 10 2026 confirmed **Final**,
   not RC/draft — the official 2025-12-09 announcement states verbatim:
   "Today, with immense pride, we release the OWASP Top 10 for Agentic AI
   Applications." `ASI01`–`ASI10` names below match the primary source
   exactly (verified against goteleport.com-style third-party paraphrases
   and rejected those variants — see Pitfall 3 in RESEARCH.md).
   Source: <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>.
   Retrieved 2026-07-22.
```
Do not touch the existing `AG01-10` warning callout (lines 21-24) — it's already correct.

---

### `skills/owasp-security-audit/references/kubernetes-top10.md` (reference doc — self-analog, tighten only)

**Analog:** the file's own existing lines 7-13 (already the right shape, per D-05 needs wording tightened, not rewritten) + the "Anti-Patterns to Avoid" guardrail in RESEARCH.md.

**Current text** (lines 7-13):
```markdown
**Source & edition.** Content below is pinned to the **2022 edition**
of the OWASP Kubernetes Top 10, which remains the canonical project
page: <https://owasp.org/www-project-kubernetes-top-ten/> (2022 index
at `/2022/en/src/`). OWASP has published a 2025 edition that renumbers
several items (secrets → K03, network segmentation → K05, auth → K09);
if you review a cluster against 2025 requirements, verify each mapping
against the 2025 per-item pages before citing codes [?].
```

**Tightened replacement (adds retrieval date + explicit not-final status per CONT-04/D-05 — do not enumerate 2025 categories as authoritative, keep the existing `[?]` markers as-is elsewhere in the file):**
```markdown
**Source & edition.** Content below is pinned to the **2022 edition**
of the OWASP Kubernetes Top 10, which remains the canonical project
page: <https://owasp.org/www-project-kubernetes-top-ten/> (2022 index
at `/2022/en/src/`). Retrieved 2026-07-22.

**2025 edition status (footnote):** OWASP's own project page/GitHub
README states only "2025 Top 10 Risks now available — Feedback welcome,"
with no version tag and no formal GitHub release published as of
2026-07-22 — this is **in progress, not final**. Do not cite 2025 K0x
codes as authoritative; if reviewing against 2025 draft content, verify
each mapping against the 2025 per-item pages first [?].
```
Test harness expects both `"2022 edition"` and one of `in progress|not.*final|feedback` to be present (see RESEARCH.md CONT-04 grep assertion) — the replacement above satisfies both literally.

---

### `skills/owasp-security-audit/references/owasp-urls.json` (config/data)

**Analog:** its own existing `A01`–`A10` entries (lines 17-26) — the verified entry shape established in Phase 2.

**Entry shape to replicate (exact fields: `title`, `edition`, `url`, `retrieval_date`, `confidence`):**
```json
"A01": {"title": "Broken Access Control", "edition": "2025", "url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/", "retrieval_date": "2026-07-21", "confidence": "verified"}
```

**Apply this shape to upgrade the current entries below (currently missing `retrieval_date` and/or stuck at `"pattern"`/`"index-fallback"` confidence per RESEARCH.md's Live Verification table):**
- `ASVS` (line 72, currently `edition: "5.0"`, `confidence: "pattern"`) → `edition: "5.0.0"`, add `retrieval_date: "2026-07-22"`, `confidence: "verified"`, url unchanged.
- `MASVS` (line 73, `confidence: "pattern"`) → add `retrieval_date: "2026-07-22"`, `confidence: "verified"`.
- All `API1:2023`–`API10:2023` (lines 28-37, several still `"pattern"`) → add `retrieval_date: "2026-07-22"`, upgrade every entry to `"verified"`.
- All `LLM01:2025`–`LLM10:2025` (lines 50-59) → add `retrieval_date: "2026-07-22"`; per RESEARCH.md Anti-Pattern guidance, keep `"index-fallback"` URLs as-is (shared page is a structural fact, not a confidence problem) but the *ID/name* confidence field may move to `"verified"` since primary-source-confirmed.
- All `ASI01`–`ASI10` (lines 61-70) → add `retrieval_date: "2026-07-22"`, upgrade confidence to `"verified"` (ID/name verified against primary 2025-12-09 announcement per RESEARCH.md), keep the shared `index-fallback` URL unchanged.
- `K01`–`K10` (lines 39-48, already `"verified"`) → add `retrieval_date: "2026-07-22"` only. Do **NOT** add any 2025 K0x entries as verified (D-06/Kubernetes exception in RESEARCH.md Pattern 2).
- Add a top-level `_meta` field per RESEARCH.md Pattern 2 Kubernetes exception:
```json
"kubernetes_2025_status": "2025 edition available for community feedback as of 2026-07-22; no formal release/version tag; not cited as primary — see kubernetes-top10.md footnote."
```

---

### `skills/secure-coding-practices/references/scp-checklist.md` (reference doc)

**Analog:** `top10.md`'s "What changed: 2021 to 2025" table (lines 19-44) — closest existing markdown-table-with-URL-column style in the repo; also the file's own existing header block (lines 1-5).

**Current header** (lines 1-5, to be updated — QRG reference needs archived-status framing):
```markdown
# OWASP Secure Coding Practices — Comprehensive Checklist

> **Reference:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist.html

This is the complete OWASP Secure Coding Practices checklist organized by domain. Use this for audits, compliance reviews, and to validate code against each requirement.
```

**14-domain crosswalk table to add (new section, additive only — do not touch the 100+ checklist items below, per D-01). Full table content from RESEARCH.md Architecture Patterns "Pattern 3":**
```markdown
## Living-Source Crosswalk

> The OWASP Secure Coding Practices Quick Reference Guide (QRG) linked above
> is the **archived historical origin** of this checklist — OWASP's own
> project page states the QRG project "has now been archived... migrated to
> various sections within the OWASP Developer Guide." The checklist items
> below remain valid guidance; the table maps each domain to its current
> **living** source for anyone who wants deeper/updated reading.
> Retrieved 2026-07-22.

| # | SCP Domain | Living-source anchor | URL | Confidence |
|---|---|---|---|---|
| 1 | Input Validation | Input Validation Cheat Sheet + Proactive Control C3 | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html | VERIFIED |
| 2 | Output Encoding | XSS Prevention Cheat Sheet + Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html | CITED |
| 3 | Authentication and Password Management | Authentication Cheat Sheet + Password Storage Cheat Sheet + MFA Cheat Sheet + Proactive Control C7 | https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html | CITED |
| 4 | Session Management | Session Management Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html | CITED |
| 5 | Access Control | Authorization Cheat Sheet + Proactive Control C1 | https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html | CITED |
| 6 | Cryptographic Practices | Cryptographic Storage Cheat Sheet + Proactive Control C2 | https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html | CITED |
| 7 | Error Handling and Logging | Error Handling Cheat Sheet + Logging Cheat Sheet + Proactive Control C9 | https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html | VERIFIED |
| 8 | Data Protection | Developer Guide "Protect Data Everywhere" + Cryptographic Storage Cheat Sheet | https://devguide.owasp.org/en/04-design/02-web-app-checklist/08-protect-data/ | CITED |
| 9 | Communication Security | Transport Layer Security Cheat Sheet + HSTS Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html | CITED |
| 10 | System Configuration | Docker Security Cheat Sheet + Proactive Control C5 | https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html | CITED |
| 11 | Database Security | Database Security Cheat Sheet + SQL Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html | VERIFIED |
| 12 | File Management | File Upload Cheat Sheet (partial anchor — covers upload validation, not path-traversal/serving items) | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | CITED — weaker anchor |
| 13 | Memory Management | OWASP Developer Guide (no dedicated language-agnostic page located — flagged for spot-check) | https://devguide.owasp.org/ | ASSUMED — weak anchor |
| 14 | General Coding Practices | OWASP Top 10 Proactive Controls (2024, current stable) + Proactive Control C6 | https://top10proactive.owasp.org/archive/2024/the-top-10/ | VERIFIED |
```
Test harness requires the string `"archived"` to appear (case-insensitive) and ≥14 matches of the three crosswalk domains (`cheatsheetseries.owasp.org|devguide.owasp.org|top10proactive.owasp.org`) per RESEARCH.md's CONT-05 grep assertions — the table above satisfies both.

---

### `skills/secure-coding-practices/references/owasp-urls.json` (config/data)

**Analog:** `skills/owasp-security-audit/references/owasp-urls.json`'s entry shape (see above) — same `edition`/`retrieval_date`/`confidence` fields, applied here as a new top-level `scp_domain_crosswalk` key per RESEARCH.md Open Question 2's recommendation.

**Current `owasp_scp_guide` block (lines 2-9) needs a `status: "archived"` field added:**
```json
"owasp_scp_guide": {
  "name": "OWASP Secure Coding Practices Quick Reference Guide",
  "url": "https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/",
  "stable_version": "https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/",
  "checklist": "https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist.html",
  "introduction": "https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction",
  "github": "https://github.com/OWASP/www-project-secure-coding-practices-quick-reference-guide",
  "status": "archived",
  "retrieval_date": "2026-07-22"
}
```

**New top-level key to add (machine-readable mirror of the scp-checklist.md table, one entry per domain, matching the audit-skill JSON shape):**
```json
"scp_domain_crosswalk": {
  "1_input_validation": {"domain": "Input Validation", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html", "retrieval_date": "2026-07-22", "confidence": "verified"},
  "2_output_encoding": {"domain": "Output Encoding", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html", "retrieval_date": "2026-07-22", "confidence": "cited"}
  /* ... continue for all 14 domains, same fields, mirroring the scp-checklist.md table rows exactly ... */
}
```

---

### `skills/secure-coding-practices/references/secure-patterns.md` (reference doc)

**Analog:** the file's own top line (self-analog, single-line reword).

**Current line 3:**
```markdown
> **Reference:** OWASP Secure Coding Practices Quick Reference Guide
```

**Replacement (per RESEARCH.md Pitfall/Anti-Pattern — reword to "historical origin", per CONT-05 grep assertion requiring `historical|archived`):**
```markdown
> **Historical origin:** These patterns derive from the OWASP Secure Coding
> Practices Quick Reference Guide, now archived by OWASP; see
> `scp-checklist.md`'s crosswalk table for current living sources.
```
No other changes needed in this file — RESEARCH.md confirms (Open Question 3) no other QRG citations exist in the body, only implementation patterns with no source-attribution language.

## Shared Patterns

### Edition-Verification Note (cross-cutting: asvs.md, masvs.md, api-top10.md, llm-agentic.md ×2)
**Source:** `skills/owasp-security-audit/references/top10.md` lines 8-17 (Phase 2 precedent)
**Shape:** `**Edition verification:** <standard> <edition> confirmed <status> ... Source: <url>. Retrieved <date>. <drift-or-no-drift statement>.`
**Apply to:** every one of the 5 already-versioned standards, twice for llm-agentic.md.

### `owasp-urls.json` Entry Shape (cross-cutting: both owasp-urls.json files)
**Source:** `skills/owasp-security-audit/references/owasp-urls.json` lines 17-26 (`A01`-`A10`)
**Shape:** `{"title": "...", "edition": "...", "url": "...", "retrieval_date": "YYYY-MM-DD", "confidence": "verified"}`
**Apply to:** every code touched in this phase across both per-skill JSON files (they are NOT shared — update each independently).

### Halt-and-Flag / Draft-as-Final Prohibition (cross-cutting governance, not code)
**Source:** Phase 2 D-04, carried forward as D-06 in `03-CONTEXT.md`
**Apply to:** Kubernetes 2025 footnote wording (the one place it fires this phase) — never present the 2025 K8s edition or its category numbers as final/authoritative.

## No Analog Found

None — every file in scope has a direct or near-direct analog in Phase 2's already-hardened `top10.md` / `owasp-urls.json` work, or is a self-analog (tightening its own existing text).

## Metadata

**Analog search scope:** `skills/owasp-security-audit/references/`, `skills/secure-coding-practices/references/`
**Files scanned:** 9 target files + 2 owasp-urls.json + top10.md analog (12 total reads)
**Pattern extraction date:** 2026-07-22
