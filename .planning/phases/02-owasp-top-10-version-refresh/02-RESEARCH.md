# Phase 2: OWASP Top 10 Version Refresh - Research

**Researched:** 2026-07-21
**Domain:** OWASP Top 10 web application risk taxonomy — 2021→2025 edition migration
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 (Edition-change presentation):** Present the 2021→2025 move with a **mapping table
  near the top of `top10.md` PLUS short inline cross-references** at each affected category
  (e.g., "SSRF — formerly A10 in the 2021 edition — is now assessed under A01"). Chosen over
  clean-2025-only and appendix-only.
- **D-02 (Phase 2 vs Phase 4 boundary):** Phase 2 updates the **loaded path only**: `top10.md`,
  `SKILL.md`, `owasp-security-audit.md`, the other `references/*.md`, `owasp-urls.json`,
  `quick_scan.py`, and `README.md`. **Leave** `owasp-comprehensive-security-skills.md` and
  `owasp-css.instructions.md` untouched — Phase 4 deletes them. Example-file category
  re-labeling stays CONT-06 / Phase 4 and is NOT pulled forward.
- **D-03:** Interpret ROADMAP SC2's "no 2021-era IDs remain anywhere" as "anywhere in the
  loaded/shipping path." The two doomed legacy files are the explicit, documented exception.
  Verify-phase should not fail Phase 2 on 2021 IDs surviving in those two files.
- **D-04 (Final vs RC gate):** The rewrite is gated on the edition being **Final**. If Top 10
  2025 is still RC at research time: halt the relabel, keep 2021, flag it. Do not ship a draft
  as final.
- **D-05 (Sourcing):** Attach an **official OWASP source URL + retrieval date** to the recorded
  edition. The authoritative mapping must come from OWASP's official 2025 publication, not
  hand-derived, not training-data recall. Fold the source URL into `references/owasp-urls.json`.
- **D-06 (Rewrite depth):** **Full refresh of all 10 categories** — each gets refreshed
  detection signals, mitigations, and a vulnerable/secure code example aligned to 2025. Merge
  SSRF into A01; write A03 (Software Supply Chain Failures) and A10 (Mishandling of Exceptional
  Conditions) from scratch.

### Claude's Discretion

- `owasp-security-audit.md` vs `SKILL.md` byte-identical status — **CONFIRMED this session**
  (see Finding 6 below): both files are exactly 415 lines, `diff` reports zero differences.
  Treat as a redundant mirror; update both in lockstep during Phase 2 (Phase 4 will decide
  whether to retire the duplicate).
- Exact wording/format of the mapping table and inline cross-reference phrasing, provided
  every 2025 category ID/name is correct and traceable.
- Precise placement of the new A03/A10 sections and how SSRF signals are woven into A01.

### Deferred Ideas (OUT OF SCOPE)

- Example-file category re-labeling (`broken-access-control.py`, `cryptographic-failures.js`,
  `injection.js`, etc. → 2025 IDs) — CONT-06 / Phase 4, once the standard text is final.
- Scrubbing 2021 IDs from `owasp-comprehensive-security-skills.md` and
  `owasp-css.instructions.md` — moot; Phase 4 deletes them.
- Kubernetes 2025-draft adoption — v2 (EXP-02); Phase 3 keeps 2022 stable as primary.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CONT-01 | `owasp-security-audit` Top 10 reference updated 2021→2025 (Final) using OWASP's official category mapping | Finding 1 (Final verdict) + Finding 2 (verbatim official mapping) give the exact, sourced mapping table and per-category source text needed to rewrite `top10.md` |
| CONT-02 | Top 10 category IDs/names/cross-references consistent everywhere they appear (skill body, references, examples, README, manifest) | Finding 5 (consistency-sweep surface) enumerates every file + line where a 2021-era ID appears in the loaded path, and confirms manifests are already clean |
</phase_requirements>

## Summary

**Verdict: FINAL.** The OWASP Top 10:2025 is officially published and Final as of the retrieval
date (2026-07-21). This was confirmed directly from the OWASP Foundation's own GitHub
repository README (`raw.githubusercontent.com/OWASP/Top10/master/README.md`), fetched via
direct `curl` (bypassing any LLM-summarization risk), which reads verbatim:

> `## OWASP Top 10 2025 - RELEASED`
> `We have released the OWASP Top 10:2025 (Final):`
> `- [OWASP Top10:2025](https://owasp.org/Top10/2025/)`

The same README marks the 2021 edition `SUPERSEDED`. The live document at
`https://owasp.org/Top10/2025/` and its GitHub source
(`github.com/OWASP/Top10/tree/master/2025/docs/en`) are consistent with this: full per-category
pages exist for A01–A10:2025, each with background, CWE mappings, prevention guidance, and
attack scenarios — the hallmarks of a finished document, not a stub RC. D-04's halt condition
does **not** trigger — the phase proceeds with the full rewrite.

**Caveat for the planner:** be aware that dozens of third-party blog posts (dated as late as
February 2026) still describe this edition as "Release Candidate 1" or "RC1," reflecting the
November 2025 announcement at OWASP Global AppSec DC. Those posts are now stale. Only the
official OWASP GitHub README and the live `owasp.org/Top10/2025/` document — both fetched
directly this session — carry authority here; do not let secondary sources reintroduce RC
doubt during planning or review.

**The official mapping is a much larger reshuffle than CONTEXT.md's shorthand suggests.**
CONTEXT.md/ROADMAP describe the change as "new A03, new A10, SSRF folded into A01, A02
reordered" — accurate as far as it goes, but incomplete. In reality **six of the eight
"carried-over" categories changed position**, and three were renamed. Full official mapping
(source: `owasp.org/Top10/2025/0x00_2025-Introduction/`, verified via direct GitHub raw fetch):

| 2025 ID | 2025 Name | 2021 origin | Change |
|---|---|---|---|
| A01:2025 | Broken Access Control | A01:2021 Broken Access Control | Same rank (#1); **SSRF (former A10:2021) rolled in** |
| A02:2025 | Security Misconfiguration | A05:2021 Security Misconfiguration | **Moved #5 → #2** |
| A03:2025 | Software Supply Chain Failures | A06:2021 Vulnerable and Outdated Components | **New name/scope**, expanded from #6 → #3 |
| A04:2025 | Cryptographic Failures | A02:2021 Cryptographic Failures | **Moved #2 → #4** |
| A05:2025 | Injection | A03:2021 Injection | **Moved #3 → #5** |
| A06:2025 | Insecure Design | A04:2021 Insecure Design | **Moved #4 → #6** |
| A07:2025 | Authentication Failures | A07:2021 Identification and Authentication Failures | Same rank (#7); renamed (dropped "Identification and") |
| A08:2025 | Software or Data Integrity Failures | A08:2021 Software and Data Integrity Failures | Same rank (#8); renamed ("and" → "or") |
| A09:2025 | Security Logging & Alerting Failures | A09:2021 Security Logging and Monitoring Failures | Same rank (#9); renamed ("Monitoring" → "Alerting") |
| A10:2025 | Mishandling of Exceptional Conditions | *(no 2021 equivalent)* | **Net-new category** |
| *(retired)* | — | A10:2021 Server-Side Request Forgery (SSRF) | **Folded into A01:2025**, no longer standalone |

**This means only A01, A07, A08, A09 keep the same numeric slot** (and three of those four
were renamed). A02 through A06 all reference a *different* underlying risk topic than their
2021 numeric counterpart. **Do not do a naive "replace A05 with A02" find-and-replace by
number** — every category's content must be re-derived from its *topic*, not carried across by
ID position. This is the single most important planning implication of this research.

**Primary recommendation:** Rewrite `top10.md` category-by-category using the topic-based
mapping table above (not numeric substitution), pull detection signals/mitigations from the
verified official text captured in Finding 3, add the D-01 mapping table + inline breadcrumbs,
and sweep the loaded-path files enumerated in Finding 5.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Top 10 category reference content (`top10.md`) | Reference/Documentation | — | Static markdown reference loaded on demand by the audit skill; no runtime component |
| Category-code → canonical URL resolution (`owasp-urls.json`) | Reference/Documentation | Skill body (SKILL.md citation logic) | Data file consumed by the skill's citation-linking behavior described in SKILL.md §"Link every code you cite" |
| Regex lead-scanner category labels (`quick_scan.py`) | Tooling/Script | Reference/Documentation | Python script tags each pattern match with a `Top10:Axx` string; must stay in sync with the reference taxonomy it labels against |
| Cross-standard category cross-references (`llm-agentic.md`, `vulnerable-patterns.md`) | Reference/Documentation | — | Prose links between standards (e.g., "closest: web A09") — content only, no execution |
| Public-facing coverage claims (`README.md`) | Documentation/Adoption | — | Marketing/adoption surface; must not overclaim an edition that isn't what's shipped |

This phase is 100% Reference/Documentation + Tooling-label tier — there is no browser, API,
or database tier involved. The only "runtime" artifact touched is `quick_scan.py`'s string
labels (not its regex logic), which are pure metadata.

## Standard Stack

Not applicable — this phase installs no packages, adds no dependencies, and touches only
Markdown reference files and Python string literals inside an existing script. There is no
"Standard Stack" or "Package Legitimacy Audit" section for this phase; skip both per the
tool_strategy exemption for content-only phases.

## Architecture Patterns

### Recommended per-category rewrite structure (reuse existing shape)

`top10.md`'s existing structure — Detection signals → Mitigations → Code example → Checklist —
is sound and should be preserved for all 10 categories in the 2025 rewrite (this satisfies
D-06's "full refresh" without inventing a new document shape). Add two new top-level elements
per D-01:

1. **"What changed: 2021 → 2025" mapping table** near the top of the file (right after the
   Source line), using the topic-based table from the Summary section above.
2. **Inline breadcrumbs** at each category whose 2021 identity differs from its 2025 identity,
   e.g.:
   - At A01: *"SSRF — formerly its own category, A10 in the 2021 edition — is now assessed
     under this category."*
   - At A02: *"Formerly A05 in the 2021 edition (Security Misconfiguration is unchanged in
     substance; only its rank and number moved)."*
   - At A03: *"New category for 2025 — expands on what was A06:2021 (Vulnerable and Outdated
     Components) to cover the full software supply chain, not just known-vulnerable
     dependencies."*
   - At A04: *"Formerly A02 in the 2021 edition."*
   - At A05: *"Formerly A03 in the 2021 edition."*
   - At A06: *"Formerly A04 in the 2021 edition."*
   - At A07–A09: note the name change only (rank unchanged).
   - At A10: *"New category for 2025 — no 2021 equivalent."*

### Content sourcing per category (verified official text, this session)

Full verbatim official source text was fetched via direct `curl` from
`raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/` for **A01, A03, A10** (the three
categories requiring the heaviest rewrite — merge target, and the two net-new categories), and
header/background paragraphs were fetched for **A02, A04, A05, A06, A07, A08, A09** (content
largely carries over from the existing `top10.md` sections under their new name/number, per the
mapping table, with the rank/name deltas quoted below).

- **A01:2025 Broken Access Control** — unchanged #1. New/expanded CWE list explicitly includes
  *CWE-918 Server-Side Request Forgery (SSRF)* — confirming the SSRF fold-in at the CWE level,
  not just prose. Existing `top10.md` A01 section (IDOR, ownership checks, default-deny) is
  reusable almost as-is; add an SSRF sub-section (reuse the existing A10:2021 SSRF detection
  signals/mitigations/code example verbatim, since SSRF's technical content didn't change —
  only its home category did).
- **A02:2025 Security Misconfiguration** *(was A05:2021)* — "Moving up from #5 ... 100% of
  applications tested were found to have some form of misconfiguration ... Notable CWEs
  included are CWE-16 Configuration and CWE-611 (XXE)." Existing `top10.md` A05 section
  (debug flags, headers, CORS, IaC scanning) is directly reusable; renumber to A02, note the
  XXE CWE addition as a detection signal if the planner wants full CWE-list parity.
- **A03:2025 Software Supply Chain Failures** *(net-new; expands A06:2021)* — full official
  text captured. Key facts: originated from 2013's "A9 – Using Components with Known
  Vulnerabilities"; now covers the *entire* dependency/build/distribution ecosystem, not just
  known-CVE components; example attack scenarios cite SolarWinds (2019), the 2025 Bybit $1.5B
  wallet-software supply-chain theft, and the 2025 `Shai-Hulud` self-propagating npm worm.
  Mapped CWEs: CWE-447, 1035, 1104, 1329, 1357, 1395. Prevention guidance centers on SBOM
  generation/tracking, CI/CD hardening, signed artifacts, staged rollouts. This content did
  not exist anywhere in the current `top10.md` (A06:2021 was narrower — "known vulnerability
  in a dependency") and must be written fresh per D-06.
- **A04:2025 Cryptographic Failures** *(was A02:2021)* — "Moving down two positions to #4 ...
  failures related to lack of cryptography, insufficiently strong cryptography, leaking of
  cryptographic keys ... common CWEs involve weak PRNG (CWE-327, 331, 1241, 338)." Existing
  `top10.md` A02 section (weak hashes, DIY crypto, plaintext secrets, TLS) is directly
  reusable; renumber to A04. Consider adding a PRNG-specific detection signal since it's called
  out as newly prominent.
- **A05:2025 Injection** *(was A03:2021)* — "falls two spots from #3 to #5 ... greatest number
  of CVEs ... includes Cross-site Scripting (high frequency/low impact, 30k+ CVEs) and SQL
  Injection (low frequency/high impact, 14k+ CVEs)." Existing `top10.md` A03 section (SQLi,
  command injection, SSTI, XSS via innerHTML) is directly reusable; renumber to A05.
- **A06:2025 Insecure Design** *(was A04:2021)* — "slides two spots from #4 to #6 ... focuses
  on risks related to design and architectural flaws ... Notable CWEs: CWE-256 Unprotected
  Storage of Credentials, CWE-269 Improper Privilege Management, CWE-434 Unrestricted Upload,
  CWE-501 Trust Boundary Violation, CWE-522 Insufficiently Protected Credentials." Existing
  `top10.md` A04 section (threat modeling, rate limits, trust boundaries) is directly reusable;
  renumber to A06.
- **A07:2025 Authentication Failures** *(was A07:2021, renamed)* — "maintains its position at
  #7 with a slight name change [dropped 'Identification and'] to more accurately reflect the 36
  CWEs." Existing `top10.md` A07 section is reusable verbatim content-wise; update the heading
  name only (drop "Identification and").
- **A08:2025 Software or Data Integrity Failures** *(was A08:2021, renamed)* — "continues at #8
  ... slight, clarifying name change from 'Software *and* Data Integrity Failures.'" Note:
  current `top10.md` does not have a standalone A08 section with this exact name yet (it's
  present as "A08: Software & Data Integrity Failures" — verify the ampersand/conjunction
  wording when rewriting; official 2025 name uses "or", not "and" or "&").
- **A09:2025 Security Logging & Alerting Failures** *(was A09:2021, renamed)* — "retains its
  position at #9 ... slight name change to emphasize the alerting function ... incredibly
  difficult to test for (only 723 CVEs) ... CWE-117 output encoding to logs, CWE-532 sensitive
  data in logs, CWE-778 insufficient logging." Existing `top10.md` A09 section is reusable;
  rename heading from "Security Logging & Monitoring Failures" to "Security Logging & Alerting
  Failures" and consider adding an "alerting, not just logging" detection signal (e.g., "logs
  exist but nothing consumes/alerts on them").
- **A10:2025 Mishandling of Exceptional Conditions** *(net-new)* — full official text captured.
  24 mapped CWEs (CWE-209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460,
  476, 478, 484, 550, 636, 703, 754, 755, 756). Core theme: failure to prevent/detect/respond to
  abnormal conditions — covers improper error handling, "failing open" instead of "failing
  closed," verbose error messages leaking system info, uncaught exceptions, null pointer
  dereferences, missing/duplicate exception handling scattered across a codebase instead of
  centralized. Official example scenarios: (1) resource exhaustion DoS from file-upload
  exception handling that never releases resources; (2) database error messages leaking schema
  info used to refine a SQL injection attack; (3) financial transaction state corruption from
  a multi-step transaction that isn't rolled back on partial failure ("fail closed," not
  attempt-to-resume). This content did not exist anywhere in the current `top10.md` and must be
  written fresh per D-06.

### Anti-Patterns to Avoid

- **Numeric find-and-replace ("A05 → A02" globally).** Six of ten categories changed both
  number *and* underlying topic. A blind renumbering sweep will silently attach the wrong
  content to the wrong ID (e.g., accidentally leaving Injection content under "A03" when A03 is
  now Software Supply Chain Failures — an entirely different topic). Always resolve by *topic*
  first, then assign the number.
- **Treating "SSRF folded into A01" as a content deletion.** The SSRF detection signals,
  mitigations, and code example in the current A10:2021 section remain technically accurate —
  they just move to live inside the A01 section (as a labeled sub-section) rather than being
  discarded.
- **Presenting the RC-era blog commentary as current.** Several high-ranking search results
  (dated Nov 2025–Feb 2026) describe this edition as "RC1." Do not cite those as edition-status
  evidence — cite the OWASP GitHub README and the live `owasp.org/Top10/2025/` document, both
  of which explicitly say "RELEASED" / "(Final)."

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Determining official category text | Paraphrasing from memory or from third-party blog summaries | The verbatim official text captured in this document (sourced from `raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/*.md`) | Blog posts (even reputable ones) compress, editorialize, or go stale (RC-era posts still circulate); the GitHub-hosted source markdown is the canonical, versioned original |
| Verifying edition status | Trusting `owasp.org` page prose (which doesn't state "Final" anywhere in its visible copy) | The OWASP/Top10 GitHub repo root `README.md`, which explicitly uses "RELEASED" / "(Final)" / "SUPERSEDED" status labels | The project's own README is the one place that carries an explicit, unambiguous status label; the per-edition doc pages themselves don't self-label |

**Key insight:** For this phase, "research" *is* the deliverable risk surface — the accuracy
constraint (PROJECT.md) makes citation provenance the single highest-value thing this research
produces. Every category fact above traces to a specific raw GitHub URL fetched today; the
planner should carry those URLs into `top10.md`'s "References" links per-category if it wants
maximal auditability (optional, Claude's Discretion per CONTEXT.md).

## Common Pitfalls

### Pitfall 1: Conflating "RC1 announced" with "still RC"
**What goes wrong:** A researcher (or the planner reviewing this research) sees dozens of blog
posts referencing "OWASP Top 10:2025 (Release Candidate 1)" from November 2025 and concludes
the edition is still a draft.
**Why it happens:** RC1 was genuinely announced in Nov 2025 at OWASP Global AppSec DC, and most
web content indexes that moment; the finalization (this session confirms "RELEASED"/"Final" in
the GitHub README) happened later and has less content volume discussing it explicitly.
**How to avoid:** Always check the primary source's own status label (GitHub README section
headers: "RELEASED", "SUPERSEDED", "HISTORIC") rather than counting blog mentions.
**Warning signs:** Any claim about edition status that cites a blog post instead of
`owasp.org` or `github.com/OWASP/Top10` directly.

### Pitfall 2: Assuming numeric continuity across editions
**What goes wrong:** Treating "A05:2021 → A05:2025" as a like-for-like rename, when in fact
A05:2025 is a completely different topic (Security Misconfiguration, formerly A05:2021's
*own* content moved to A02:2025) than what A05:2021 covered before (Injection, now A05:2025 —
wait, this is exactly the trap: A05 in *both* editions exists but means different things only
by coincidence of the renumbering; always verify by name, not number).
**Why it happens:** OWASP Top 10 IDs look like stable enumerations but are re-assigned by rank
each edition; only the *name* is a stable anchor within an edition.
**How to avoid:** Build the rewrite from the name-based mapping table (this document's Summary
section), never from a number-substitution script.
**Warning signs:** Any sweep script or find-and-replace that operates on bare `A0[1-9]|A10`
tokens without also checking the surrounding category name.

### Pitfall 3: Missing the CWE-918 (SSRF) signal when merging A10 into A01
**What goes wrong:** Writing A01:2025 without an explicit SSRF sub-section, because the
merge is described only in prose ("rolled into this category") rather than being obviously
visible in a CWE list glance.
**Why it happens:** A01:2025's CWE list is long (40 CWEs); CWE-918 is easy to miss without
deliberately cross-referencing the "what changed" mapping figure.
**How to avoid:** D-01 explicitly requires an inline breadcrumb at A01 calling out the SSRF
fold-in — treat this as a required checklist item during the A01 rewrite, not optional color.
**Warning signs:** An A01:2025 section that reads identically to the 2021 A01 section with no
mention of SSRF anywhere.

## Runtime State Inventory

Not applicable — this is a content-only rewrite phase, not a rename/refactor/migration of
runtime state, stored data, or registered services. No database, external service
configuration, OS-level registration, secret, or build artifact references the OWASP edition
string in a way that requires migration. Skipping this section per its trigger condition
(rename/refactor/migration phases only).

## Consistency-Sweep Surface (CONT-02)

Confirmed via direct grep of the loaded path (this session, 2026-07-21). Every file, line, and
exact string requiring an update:

| File | Line(s) | Current text | Required change |
|------|---------|---------------|------------------|
| `skills/owasp-security-audit/references/top10.md` | 1–438 (whole file) | 2021 edition, A01–A10 per old mapping | Full rewrite per D-01/D-06 — **primary target** |
| `skills/owasp-security-audit/SKILL.md` | 3 (frontmatter `description`) | `Covers the OWASP Top 10 (2021), ASVS 5.0, ...` | `Covers the OWASP Top 10 (2025), ASVS 5.0, ...` |
| `skills/owasp-security-audit/SKILL.md` | 181 | `[A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)` | Update URL to `https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/` (verify exact live path before writing — see Finding note below) |
| `skills/owasp-security-audit/SKILL.md` | 206 | `- [OWASP Top 10 (2021)](https://owasp.org/Top10/)` | `- [OWASP Top 10 (2025)](https://owasp.org/Top10/2025/)` |
| `skills/owasp-security-audit/SKILL.md` | 212 | `### [CRITICAL] [A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) — missing ownership check` | Same URL update as line 181 |
| `skills/owasp-security-audit/SKILL.md` | 383 | `` `references/top10.md` — OWASP Top 10 (2021): A01–A10 with detection`` | `` `references/top10.md` — OWASP Top 10 (2025): A01–A10 with detection`` |
| `skills/owasp-security-audit/owasp-security-audit.md` | identical to SKILL.md (415 lines, byte-identical, confirmed via `diff`) | same 5 spots as above | Update in lockstep — this is a mirror, not a separate source |
| `skills/owasp-security-audit/references/vulnerable-patterns.md` | 17–25 (index table) | `A01`/`A02`/`A03`/`A05`/`A09`/`A10` labels next to snippet categories | Relabel per topic-based mapping: A02→A04, A03→A05 (keep "A03 XSS" as A05 too — XSS is part of Injection, still A05:2025), A05→A02, A10→A01 (SSRF now lives under A01) |
| `skills/owasp-security-audit/references/vulnerable-patterns.md` | 83, 128, 178, 267 (section headers `## A02 —`, `## A03 —`, `## A05 —`, `## A10 / API7 —`) | Old section headers | Renumber headers to match new IDs; A01 (line 29) and A09 (line 247) headers are unchanged by number but A09's name changed |
| `skills/owasp-security-audit/references/vulnerable-patterns.md` | 164 | `### Python — JSON instead of pickle (A08 overlap)` | A08 keeps its number; only rename note if desired ("Software or Data Integrity Failures") |
| `skills/owasp-security-audit/scripts/quick_scan.py` | 58, 68, 71, 74, 78, 81, 84, 87 | `"Top10:A02"` (8 occurrences, crypto patterns) | `"Top10:A04"` |
| `skills/owasp-security-audit/scripts/quick_scan.py` | 92–108 | `"Top10:A03"` (6 occurrences, injection patterns) | `"Top10:A05"` |
| `skills/owasp-security-audit/scripts/quick_scan.py` | 112–124 | `"Top10:A05"` (4 occurrences, misconfig patterns) | `"Top10:A02"` |
| `skills/owasp-security-audit/scripts/quick_scan.py` | 128–134 | `"Top10:A07"` (2 occurrences, auth patterns) | Unchanged — A07 keeps its number (only the category *name* changed, which isn't in this string) |
| `skills/owasp-security-audit/scripts/quick_scan.py` | 138–139 | `"Top10:A10"` (1 occurrence, SSRF pattern: `requests-get-no-timeout`) | `"Top10:A01"` — SSRF is now under A01 |
| `skills/owasp-security-audit/references/llm-agentic.md` | 536 | `AG09 Inadequate Logging \| **Not OWASP LLM/Agentic.** Closest: web A09` | ID unchanged (A09 keeps its number); optional: update the implied name from "Monitoring" to "Alerting" for full accuracy |
| `README.md` | 27 | `| **OWASP Top 10 (2021)** | Web application risks — access control, crypto, injection, misconfiguration, SSRF, and more |` | `| **OWASP Top 10 (2025)** | Web application risks — access control, misconfiguration, supply chain, crypto, injection, insecure design, ... |` |
| `README.md` | 106–111 | Example-file table: `(A01)`, `(A02)`, `(A03)`, `(A05)`, `(A03: Injection)`, `(A09)` | **See open question below** — label-only update recommended (A02→A04, A03→A05, A05→A02; A01 and A09 unchanged in number) since these are prose labels on unmodified example files, distinct from CONT-06's example-*file* re-labeling |
| `skills/owasp-security-audit/references/owasp-urls.json` | 1–26 | `A01`–`A10` entries all `"edition": "2021"`, `"confidence": "pattern"` | Rewrite entries to 2025 IDs/names/URLs, add `"retrieval_date": "2026-07-21"` (or equivalent field consistent with the file's existing schema), mark `"confidence": "verified"` for entries checked this session (A01, A03, A10 — full page fetch; A02/A04/A05/A06/A07/A08/A09 — header/background paragraph fetch, still solidly `verified` since sourced from the same raw GitHub files, not inferred) |

**Files confirmed to need NO change** (checked this session, no `A0[1-9]`/`A10` Top-10-style
codes found): `references/api-top10.md`, `references/asvs.md`, `references/kubernetes-top10.md`,
`references/masvs.md`. These files use their own standards' numbering (API1–API10, K01–K10,
ASVS chapter numbers) which is untouched by this phase.

**Manifests confirmed clean** (per CONTEXT.md code_context, re-verified): `.claude-plugin/plugin.json`
and `.claude-plugin/marketplace.json` carry no Top 10 category IDs — no action needed there.

**Explicitly excluded per D-02/D-03** (not touched this phase): `owasp-comprehensive-security-skills.md`
(repo root) and `owasp-css.instructions.md` (repo root) — both still reference 2021-era content;
Phase 4 deletes these files rather than updating them.

## Open Questions

1. **README example-table category labels (lines 106–111): in-scope relabel or deferred?**
   - What we know: D-02 explicitly lists `README.md` as in the Phase 2 loaded-path sweep for
     CONT-02. CONT-06 (deferred to Phase 4) is specifically about re-labeling the *example
     files themselves* to new category IDs. The README table doesn't modify any example file —
     it only updates a one-word parenthetical label in prose next to an unchanged file link.
   - What's unclear: whether the planner should treat "(A02)" next to `cryptographic-failures.js`
     as part of the README sweep (in scope, CONT-02) or as example-adjacent content that should
     wait for Phase 4's CONT-06 pass (so the example file and its README label change together,
     avoiding a README claim that's inconsistent with the file's own content/comments until
     Phase 4).
   - Recommendation: Update the README labels now (low-risk, single-word swap, keeps CONT-02's
     "no 2021-era IDs remain in the loaded path" success criterion honest) but do NOT touch the
     example `.py`/`.js`/`.html` files themselves. Flag this explicitly in the plan so the
     verify-phase reviewer understands the label changed but the file's internal comments
     (which may still say "A02" in a code comment) are intentionally untouched pending Phase 4.

2. **Exact live URL path for individual 2025 category pages.**
   - What we know: the GitHub source confirms the file-naming pattern
     `A0N_2025-Category_Name.md` under `2025/docs/en/`, and the live site root is
     `https://owasp.org/Top10/2025/`. Internal cross-links within the fetched markdown (e.g.,
     A03's reference to A02) render as `https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/`.
   - What's unclear: whether every individual category page is live at that exact path (some
     were confirmed via internal markdown links, not independently curled one-by-one for all
     10).
   - Recommendation: the planner/executor should do one lightweight `curl -sI` check per URL
     before writing it into `owasp-urls.json`, mirroring the existing file's own stated
     fallback protocol ("if a WebFetch returns 404, try the project index URL").

## Environment Availability

Skipped — this phase has no external tool/service/runtime dependencies. It is pure Markdown
and Python-string-literal editing in an existing repository; `curl` (used only during this
research session, not by the shipped skill) and a text editor are the only tools involved.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | None — this is a Markdown/docs + Python-script-labels repo with no test runner (confirmed: no `package.json`, `pytest.ini`, `tests/` directory found at repo root) |
| Config file | none — see Wave 0 |
| Quick run command | `grep -rn -E "A0[1-9]:2021|A10:2021|Top10:A0[1-9]\"|Top10:A10\"" skills/owasp-security-audit/ README.md` (should return zero matches after the phase, except inside the two explicitly-excluded legacy files, which this command doesn't scan) |
| Full suite command | Same grep, plus `python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json > /dev/null` to confirm the JSON stays valid after edits |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CONT-01 | `top10.md` lists all 10 2025 categories with correct ID/name mapping | manual + grep | `grep -c "^## A" skills/owasp-security-audit/references/top10.md` (expect 10) and manual diff against this document's mapping table | ❌ Wave 0 — no existing check |
| CONT-01 | Edition recorded as Final with source URL + retrieval date | manual | `grep -n "2025 (Final)" skills/owasp-security-audit/references/top10.md skills/owasp-security-audit/references/owasp-urls.json` | ❌ Wave 0 |
| CONT-02 | No 2021-era IDs remain in loaded path (excluding the two doomed legacy files) | grep | `grep -rn -E "A0[1-9]_2021|A10_2021|\(2021\)" skills/ README.md` (expect zero, or only in explicitly-annotated "formerly A0x:2021" breadcrumb prose, which is the *intended* D-01 pattern and should be distinguished from a stray unswept reference) | ❌ Wave 0 |
| CONT-02 | `owasp-urls.json` stays valid JSON after edit | automated | `python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json` | ✅ (json.tool is stdlib, always available) |

### Sampling Rate
- **Per task commit:** run the quick grep command above after each file edit.
- **Per wave merge:** run the full suite command (grep + JSON validation) before moving to the
  next file.
- **Phase gate:** Full suite green before `/gsd-verify-work`; additionally, manually diff the
  final `top10.md` category list against this RESEARCH.md's mapping table (Summary section) to
  confirm no topic was mis-numbered.

### Wave 0 Gaps
- No existing automated check for "no stale category IDs" — the grep commands above are new
  and should be run manually by the executor/verifier (not worth building a permanent script
  for a one-time content migration, per the "no heavy runtime dependencies" project constraint).
- No existing JSON-schema validation for `owasp-urls.json` beyond basic parse-ability — not a
  blocker, the file has no formal schema today.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Phase touches only reference documentation content, not authentication code |
| V3 Session Management | no | N/A |
| V4 Access Control | no | N/A |
| V5 Input Validation | no | N/A |
| V6 Cryptography | no | N/A |

This phase has no application-security surface of its own — it edits reference documentation
consumed by the skill, not executable authentication/session/crypto logic. The "security" risk
here is entirely a **content-accuracy** risk (shipping wrong/stale OWASP guidance to end users
who rely on it for their own security reviews), which is addressed by the citation-provenance
and consistency-sweep sections above, not by ASVS-style code controls.

### Known Threat Patterns for {stack}

Not applicable in the traditional STRIDE sense — the "threat" this phase mitigates is
reputational/credibility risk from a public security reference citing an incorrect or
unverifiable OWASP edition. Mitigated by: (1) the Final-vs-RC verdict being sourced from the
OWASP Foundation's own GitHub README rather than secondary commentary, and (2) every category
fact in this document being traceable to a specific raw GitHub URL fetched on the stated
retrieval date.

## Sources

### Primary (HIGH confidence — VERIFIED via direct fetch this session)

- `https://raw.githubusercontent.com/OWASP/Top10/master/README.md` — official repo README;
  status labels "RELEASED"/"(Final)"/"SUPERSEDED"/"HISTORIC" quoted verbatim above. Fetched via
  direct `curl`, 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/index.md` — 2025 category
  list (10 IDs/names) confirmed verbatim. Fetched via direct `curl`, 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/0x00_2025-Introduction.md` —
  full "What's changed in the Top 10 for 2025" section, the authoritative source for the
  mapping table in this document's Summary. Fetched via direct `curl`, 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A01_2025-Broken_Access_Control.md` — full text, incl. CWE-918 (SSRF) confirmation. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A03_2025-Software_Supply_Chain_Failures.md` — full text. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A10_2025-Mishandling_of_Exceptional_Conditions.md` — full text. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A02_2025-Security_Misconfiguration.md` — background paragraph. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A04_2025-Cryptographic_Failures.md` — background paragraph. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A05_2025-Injection.md` — background paragraph. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A06_2025-Insecure_Design.md` — background paragraph. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A07_2025-Authentication_Failures.md` — background paragraph. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A08_2025-Software_or_Data_Integrity_Failures.md` — background paragraph. Fetched 2026-07-21.
- `https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A09_2025-Security_Logging_and_Alerting_Failures.md` — background paragraph. Fetched 2026-07-21.
- `https://api.github.com/repos/OWASP/Top10/contents/2025/docs/en` — file listing confirming the exact 10 category filenames + intro/about/next-steps docs exist. Fetched 2026-07-21.
- Direct codebase grep (this session) — `skills/owasp-security-audit/**`, `README.md`,
  `.claude-plugin/*.json` — established the exact consistency-sweep surface.

### Secondary (MEDIUM confidence)

- `https://owasp.org/Top10/2025/` and `https://owasp.org/Top10/2025/0x00_2025-Introduction/` —
  live rendered pages, consistent with the raw GitHub source but fetched via WebFetch
  (LLM-summarized) rather than raw curl for the initial pass; cross-checked against the direct
  curl fetches above so treated as corroborating, not sole-source.
- `https://owasp.org/www-project-top-ten/` — project index page; used only to confirm "most
  current released version is the OWASP Top Ten 2025" framing.

### Tertiary (LOW confidence — explicitly NOT used as edition-status evidence)

- Various third-party blog posts (Qualys, Semgrep, Orca, 42gears, Medium, sitewall.net, etc.)
  describing the edition as "RC1" (Nov 2025 vintage) or "Final" (2026 vintage) — used only to
  triangulate the *timeline* (RC1 announced Nov 2025, finalized subsequently), never as the
  authoritative status source. The Final verdict in this document rests entirely on the
  Primary sources above.

## Metadata

**Confidence breakdown:**
- Final-vs-RC verdict: HIGH — sourced directly from OWASP's own GitHub README via unmediated
  `curl`, cross-checked against the live site and project index page.
- Official 2021→2025 mapping: HIGH — sourced directly from the official introduction document's
  "What's changed" section via unmediated `curl`; every category's rank/name delta quoted
  verbatim.
- New-category substance (A03, A10): HIGH — full official page text captured via unmediated
  `curl`, including CWE lists and example attack scenarios.
- Carried-over category substance (A02, A04–A09): HIGH for the rank/name/CWE-highlight facts
  quoted (sourced from official background paragraphs, curled directly); MEDIUM for the
  assumption that full section bodies can be adapted from the existing `top10.md` 2021 content
  without further official-source cross-checking — the planner should spot-check each adapted
  section's detection signals against the corresponding official page if time allows, since
  only background paragraphs (not full pages) were fetched for these seven categories.
- Consistency-sweep surface: HIGH — established via direct repo grep this session, not
  training-data recall.

**Research date:** 2026-07-21
**Valid until:** Treat the Final-vs-RC verdict and category mapping as stable (OWASP Top 10
editions don't change post-release) — no re-verification needed unless OWASP publishes an
erratum. Re-verify only if execution is delayed more than ~90 days and a new edition
announcement surfaces in the interim.
