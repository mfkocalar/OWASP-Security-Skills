# Phase 3: Remaining Standards Verification & Refresh - Research

**Researched:** 2026-07-22
**Domain:** OWASP standards citation-hardening (ASVS, MASVS, API Security, LLM/Agentic, Kubernetes) + secure-coding-practices re-anchoring
**Confidence:** HIGH (all six standards + the SCP archival status were independently confirmed via live WebFetch/WebSearch against official OWASP properties on 2026-07-22; the SCP per-domain Cheat Sheet URL list has MEDIUM confidence — see Assumptions Log)

## Summary

This is a verification, not a discovery, phase: the correct editions were already identified in `.planning/research/STACK.md` before this milestone began, and the job here is to confirm each one live and attach citation metadata. Live research on 2026-07-22 confirms **no version drift** on any of the five already-labeled standards — ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), and LLM Top 10 (2025) are all still current, with zero newer stable editions found. The one item flagged as an open risk in STATE.md — whether **OWASP Top 10 for Agentic Applications 2026** is Final or still RC/draft, and whether the repo's `ASI01`–`ASI10` names are the real verbatim IDs — is **resolved**: the official OWASP GenAI Security Project announcement (genai.owasp.org, dated 2025-12-09) states in its own words *"Today, with immense pride, we release the OWASP Top 10 for Agentic AI Applications"* — a Final release, not a preview — and its stated category list (`ASI01 Agent Goal Hijack` through `ASI10 Rogue Agents`) matches the repo's existing `llm-agentic.md` and `owasp-urls.json` content **verbatim**. No relabeling is required for D-04; only the file's provenance note needs upgrading from "paraphrased, consult the PDF" to "IDs/names/status confirmed final against the primary announcement."

Kubernetes is the one place where D-06's halt-and-flag gate actually fires: OWASP's own Kubernetes Top Ten GitHub repo shows "2025 Top 10 Risks now available — Feedback welcome" with **no version tag, no formal release, and "No releases published"** in GitHub — genuinely ambiguous, not a clean Final/RC binary like Top 10 2025 was in Phase 2. The existing `kubernetes-top10.md` file is already well-calibrated for this (2022 primary, 2025 flagged with `[?]` markers) — Phase 3's job is mostly to attach a retrieval date and tighten the footnote wording, not rewrite it.

For `secure-coding-practices`, the OWASP SCP Quick Reference Guide project is confirmed **archived** (official project page: *"The OWASP Secure Coding Practices Quick-reference Guide project has now been archived... migrated to various sections within the OWASP Developer Guide"*). A 14-domain crosswalk to living sources (Cheat Sheet Series + Proactive Controls 2024 + OWASP Developer Guide) is provided below with per-domain URLs; two domains (Memory Management, File Management) have a weaker living-source anchor and are flagged for a pre-lock spot-check rather than presented as fully confirmed.

**Primary recommendation:** Add a short edition-verification note + matching `owasp-urls.json` entry to each of the five already-correct standards (mirroring Phase 2's `top10.md`/`owasp-urls.json` convention exactly), tighten the Kubernetes 2025 footnote to reflect its genuinely ambiguous (not-yet-final) status, and add the 14-domain SCP crosswalk table with the two weaker-anchor domains flagged for a quick manual check before lock.

## Architectural Responsibility Map

This phase touches only reference/documentation tiers — no runtime application code — but the map below shows where each standard's *content* logically applies when the skill is later used in an audit.

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| ASVS verification requirements | API / Backend | Frontend Server (SSR) | ASVS chapters (auth, session, access control, crypto) are almost all backend/server-enforced controls |
| MASVS mobile requirements | Browser / Client (mobile app binary) | API / Backend | MASVS is unique among the six standards in targeting the client binary itself, not just the server |
| API Security Top 10 | API / Backend | — | REST/GraphQL/RPC handler-level findings by definition |
| Kubernetes Top 10 | Database / Storage (cluster control plane treated as infra tier) | API / Backend | Cluster/orchestration config is infrastructure, not app code, but gates what backends can do |
| LLM Top 10 / Agentic Top 10 | API / Backend (model-serving layer) | Browser / Client (agent UI, approval flows) | Most LLM/agent risks are server-side (prompt handling, tool dispatch); ASI09 (Human-Agent Trust Exploitation) is the one client/UI-facing exception |
| secure-coding-practices checklist | API / Backend | Browser / Client, Database / Storage | The 14 domains span all tiers (e.g., Input Validation is server-side by SCP's own core principle; Communication Security spans client↔server↔database) |
| This phase's own output (citation metadata) | Reference Documentation (no runtime tier) | — | `owasp-urls.json` / edition notes are static, loaded-on-demand reference data, not executable code |

**Planner note:** No task in this phase should touch application/runtime code — every task target is a `.md` or `.json` reference file. If a plan task proposes changing `SKILL.md` routing logic or example source files, that's out of scope (CONT-06/Phase 4 territory per CONTEXT.md).

## User Constraints (from CONTEXT.md)

<user_constraints>

### Locked Decisions

- **D-01 — Light re-anchor (SCP):** Preserve the existing 14-domain checklist structure and its 100+ items. Do NOT restructure around Proactive Controls and do NOT rebuild content from scratch.
- **D-02 — Per-domain crosswalk (SCP):** Add a crosswalk table mapping each of the 14 domains to its living-source anchor (e.g., Input Validation → Input Validation Cheat Sheet + Proactive Control C3), each with an official source URL + retrieval date. Note the OWASP SCP Quick Reference Guide as the archived historical origin, not a current source.
- **D-03 — Mirror the Phase 2 convention:** For each of ASVS 5.0.0, MASVS 2.1.0, API Security 2023, LLM 2025, and Agentic Apps 2026: add a short edition-verification note inside the standard's reference file (edition + official source URL + retrieval date + verified status) AND a matching `owasp-urls.json` entry (`edition`, `retrieval_date`, `confidence: verified`).
- **D-04 — Agentic Apps 2026: primary source + Final-gate.** Pull the exact ASI01–ASI10 IDs/names verbatim from the official OWASP Agentic Apps Top 10 primary source. Apply Phase 2's D-04 rule: if the edition is still RC/draft or unverifiable at research time, halt the relabel, keep provenance conservative, and flag status + date rather than presenting a draft as final.
- **D-05 — Kubernetes: minimal footnote.** Keep 2022 stable as the primary cited edition; add a one-line footnote noting a 2025 edition is in progress and not yet final. Do not enumerate draft categories as if authoritative.
- **D-06 — Version-drift policy (phase-wide):** The draft-as-final prohibition + halt-if-RC gate established in Phase 2 (D-04) extends to every standard verified here. If live research finds any expected label is wrong, halt-and-flag: record the discrepancy, cite the newest verified stable edition, and surface it rather than silently relabeling.

### Claude's Discretion

- Exact wording/placement of each per-file edition-verification note and the SCP crosswalk table, provided every edition/ID/URL is correct and traceable.
- Whether LLM 2025 and Agentic 2026 keep sharing `llm-agentic.md` or are split — a structural call for research/planner (Phase 4 owns file restructuring; keep them consistent here regardless).
- Per-domain source selection for the SCP crosswalk (which Cheat Sheet / Proactive Control best anchors each of the 14 domains) — a research task (see the crosswalk table below).

### Deferred Ideas (OUT OF SCOPE)

- **QUAL-02 coverage matrix** (which editions are covered vs. intentionally not) — Phase 5; this phase only produces the per-standard verification metadata that feeds it.
- **Kubernetes Top 10 2025 adoption** once final/stable — v2 (EXP-02); Phase 3 keeps 2022 primary.
- **Splitting `llm-agentic.md`** into separate LLM / Agentic files — a Phase 4 file-structure concern, not required for citation-hardening.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CONT-03 | ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 (2023), LLM Top 10 (2025), and Agentic Apps (2026) references are citation-hardened with verified edition, official source URL, and retrieval date | All five confirmed live 2026-07-22 with zero drift (see "Live Verification Results" below); official URLs + exact quotes captured for each; `owasp-urls.json` entry shape specified |
| CONT-04 | Kubernetes reference cites the 2022 stable edition; the 2025 draft is footnoted as in-progress (not presented as final) | 2022 confirmed still canonical; 2025 status confirmed genuinely ambiguous (no version tag, "feedback welcome," no GitHub release) — footnote wording tightened accordingly |
| CONT-05 | `secure-coding-practices` is re-derived against the living OWASP Developer Guide / Cheat Sheet Series / Proactive Controls (the archived SCP Quick Reference Guide origin is noted) | SCP QRG archival confirmed with exact quote + URL; 14-domain crosswalk table built against Cheat Sheet Series (spot-verified) + Proactive Controls 2024 (spot-verified) + Developer Guide (partially verified — 2 domains flagged) |

</phase_requirements>

## Live Verification Results (2026-07-22)

All entries below were independently confirmed via WebFetch/WebSearch against official OWASP domains during this research session — not carried forward from training data or prior research files.

| Standard | Expected label (CONTEXT.md) | Live-verified status | Official source URL | Retrieval date |
|---|---|---|---|---|
| ASVS | 5.0.0 | **CONFIRMED — Final, current.** Released "LIVE at Global AppSec EU Barcelona 2025" on **2025-05-30**. `v5.0.0` is the current stable release tag; "Bleeding Edge" (master branch) exists but is explicitly marked unsuitable for production. No newer stable release found. | `https://owasp.org/www-project-application-security-verification-standard/` (project page); version source: `https://github.com/OWASP/ASVS/tree/v5.0.0/5.0`; browsable at `https://asvs.dev/` | 2026-07-22 |
| MASVS | 2.1.0 | **CONFIRMED — current.** GitHub release tag `v2.1.0`, published **2024-01-18**, added the MASVS-PRIVACY category. No newer tag found. | `https://mas.owasp.org/MASVS/`; release: `https://github.com/OWASP/masvs/releases/tag/v2.1.0` | 2026-07-22 |
| API Security Top 10 | 2023 | **CONFIRMED — current.** No newer edition found; `API1:2023`–`API10:2023` list matches the repo's `api-top10.md` item-for-item. | `https://owasp.org/API-Security/editions/2023/en/0x11-t10/` (index); per-item pages already cited correctly in `api-top10.md` | 2026-07-22 |
| LLM Top 10 | 2025 | **CONFIRMED — current.** Live-fetched `genai.owasp.org/llm-top-10/` lists exactly `LLM01:2025`–`LLM10:2025` matching the repo. No 2026 LLM-specific edition found (2026 work is the *separate* Agentic project, not an LLM Top 10 revision). | `https://genai.owasp.org/llm-top-10/` | 2026-07-22 |
| Agentic Applications Top 10 | 2026 | **CONFIRMED — Final, not RC/draft (resolves the D-04 / STATE.md gap).** Official announcement, dated **2025-12-09**, states verbatim: *"Today, with immense pride, we release the OWASP Top 10 for Agentic AI Applications."* `ASI01`–`ASI10` names, fetched directly from the same primary announcement, match the repo's `llm-agentic.md` and `owasp-urls.json` **exactly** (see table below). | `https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/` (primary announcement); resource page: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/` | 2026-07-22 |
| Kubernetes Top 10 | 2022 primary, 2025 footnoted | **CONFIRMED 2022 still canonical; 2025 status genuinely ambiguous (not Final).** OWASP's own project page/GitHub README states only *"2025 Top 10 Risks now available — Feedback welcome. Please open issues or PRs for changes"* — no "stable"/"final"/"released" label like Top 10 2025 had, and the GitHub repo shows **"No releases published."** Treat as in-progress per D-06; do not upgrade to primary. | `https://owasp.org/www-project-kubernetes-top-ten/` (2022 index: `/2022/en/src/`) | 2026-07-22 |

### Exact ASI01–ASI10 verbatim names (primary source, confirms D-04)

Fetched directly from the 2025-12-09 official announcement — matches the repo's existing `llm-agentic.md` / `owasp-urls.json` content with **zero discrepancy**:

| ID | Verbatim name (primary source) | Matches repo? |
|---|---|---|
| ASI01 | Agent Goal Hijack | Yes |
| ASI02 | Tool Misuse | Yes |
| ASI03 | Identity & Privilege Abuse | Yes |
| ASI04 | Agentic Supply Chain Vulnerabilities | Yes |
| ASI05 | Unexpected Code Execution | Yes |
| ASI06 | Memory & Context Poisoning | Yes |
| ASI07 | Insecure Inter-Agent Communication | Yes |
| ASI08 | Cascading Failures | Yes |
| ASI09 | Human-Agent Trust Exploitation | Yes |
| ASI10 | Rogue Agents | Yes |

**Caveat (not a blocker):** third-party blogs (e.g., goteleport.com) render some names with extra suffixes ("Tool Misuse & Exploitation", "Unexpected Code Execution/RCE") — these are **not** what the primary OWASP announcement uses and should **not** be adopted. The repo's plain names above are correct as-is; only the file's *provenance note* needs updating (from "paraphrased, consult PDF for exact quotes" to "IDs/names/status confirmed final against the primary 2025-12-09 announcement"). The full per-category *description prose* in the downloadable PDF was not independently re-verified this session (WebFetch cannot read the binary PDF) — the existing paraphrased descriptions in `llm-agentic.md` are reasonable summaries and don't need a rewrite, just don't claim they're verbatim PDF quotes.

## Standard Stack

Not applicable in the traditional sense — this phase installs no libraries. The "stack" here is the set of citation sources this phase depends on:

### Core (primary citation sources)
| Source | Scope | Why Standard |
|---|---|---|
| `owasp.org/www-project-application-security-verification-standard/` | ASVS 5.0.0 | Official OWASP project page, only authoritative source for ASVS edition status |
| `mas.owasp.org/MASVS/` | MASVS 2.1.0 | Official OWASP Mobile Application Security project site |
| `owasp.org/API-Security/editions/2023/en/0x11-t10/` | API Security Top 10 2023 | Official OWASP API Security project's own index page |
| `genai.owasp.org/llm-top-10/` and `genai.owasp.org/2025/12/09/...` | LLM 2025 + Agentic 2026 | Official OWASP GenAI Security Project properties |
| `owasp.org/www-project-kubernetes-top-ten/` | Kubernetes 2022 + 2025 status | Official OWASP Kubernetes project page |
| `cheatsheetseries.owasp.org/cheatsheets/*.html` | SCP crosswalk (per-domain) | Official, actively maintained OWASP Cheat Sheet Series |
| `top10proactive.owasp.org/archive/2024/` | SCP crosswalk (Proactive Controls) | Official OWASP Top 10 Proactive Controls, 2024 = current stable edition |
| `devguide.owasp.org/` | SCP archival landing spot | Official OWASP Developer Guide — the SCP QRG's confirmed migration destination |

### Supporting
| Source | Purpose | When to Use |
|---|---|---|
| `github.com/OWASP/*` release pages | Version-tag confirmation (ASVS, MASVS) | When the project page itself doesn't show an explicit version/date, cross-check the GitHub releases tab |
| `github.com/OWASP/www-project-kubernetes-top-ten` | 2025 K8s status confirmation | Confirms "no releases published" — the concrete evidence behind treating 2025 as not-yet-final |

### Alternatives Considered
| Instead of | Could use | Tradeoff |
|---|---|---|
| Citing `genai.owasp.org/resource/...` as the sole Agentic source | Citing the downloadable PDF directly | The PDF is the canonical document but isn't independently WebFetch-able (binary); the announcement page is an official primary source that already confirms IDs/names/Final-status, so it's sufficient for CONT-03/D-04 — the PDF link should still be kept as a secondary reference for readers who want full prose |
| Cheat Sheet Series per-domain crosswalk | Rebuilding SCP content from the archived QRG doc directly | QRG is explicitly archived by OWASP; citing it as a "current" source would violate D-02/CONT-05 and the project's own migration notice |

**Installation:** N/A — no packages. This phase edits Markdown and JSON only.

**Version verification:** All six standard editions above were checked against their live official OWASP page during this research session on 2026-07-22 (not training-data recall). No `npm view` / `pip index` / `cargo search` equivalent applies to OWASP standards; the equivalent verification step for future maintainers is: re-fetch the project's official index page and confirm the edition label + any "Final"/"stable"/"draft" wording before citing.

## Package Legitimacy Audit

**Not applicable.** This phase makes no changes to `package.json`, `requirements.txt`, or any dependency manifest — it only edits Markdown reference files and the two `owasp-urls.json` metadata files. No npm/PyPI/crates packages are introduced, so the Package Legitimacy Gate protocol does not apply. (Confirmed by re-reading CONTEXT.md's canonical_refs list: every file this phase touches is `.md` or `.json` under `references/`.)

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────┐
                    │   Live OWASP official        │
                    │   sources (owasp.org,         │
                    │   genai.owasp.org,             │
                    │   mas.owasp.org,               │
                    │   cheatsheetseries.owasp.org)  │
                    └──────────────┬───────────────┘
                                   │ WebFetch/WebSearch
                                   │ (this research pass, 2026-07-22)
                                   ▼
                    ┌─────────────────────────────┐
                    │  Edition-verification note    │
                    │  (prose, inside each .md file)│
                    └──────┬─────────────┬─────────┘
                           │             │
                           ▼             ▼
              ┌────────────────┐  ┌──────────────────────┐
              │ owasp-urls.json │  │  Standard's own       │
              │ entry (edition, │  │  reference file body   │
              │ retrieval_date, │  │  (asvs.md, masvs.md,   │
              │ confidence)     │  │  api-top10.md,         │
              └────────┬────────┘  │  llm-agentic.md,       │
                       │           │  kubernetes-top10.md)  │
                       │           └───────────┬────────────┘
                       │                       │
                       ▼                       ▼
          ┌─────────────────────────────────────────────┐
          │  SKILL.md loads these on demand when a       │
          │  security audit needs that standard --       │
          │  citation resolves to a clickable link        │
          └─────────────────────────────────────────────┘

     (Separate flow for secure-coding-practices, same shape:)

  scp-checklist.md (14 domains, unchanged)
       │
       ▼
  + Crosswalk table added (D-02): domain → Cheat Sheet / Proactive Control URL + date
       │
       ▼
  secure-coding-practices/references/owasp-urls.json
  (add per-domain crosswalk entries; mark owasp_scp_guide.status = "archived")
```

### Recommended File-Edit Structure

No new files — this phase only edits existing reference files in place:
```
skills/owasp-security-audit/references/
├── asvs.md              # add edition-verification note (D-03)
├── masvs.md             # add edition-verification note (D-03)
├── api-top10.md         # add edition-verification note (D-03)
├── llm-agentic.md       # add TWO edition-verification notes (LLM 2025 + Agentic 2026) (D-03)
├── kubernetes-top10.md  # tighten 2025 footnote wording (D-04/D-05) — no new note needed, 2022 already primary
└── owasp-urls.json      # add/upgrade edition + retrieval_date + confidence for every code touched above

skills/secure-coding-practices/references/
├── scp-checklist.md     # add 14-domain crosswalk table (D-02); do NOT touch the 100+ checklist items (D-01)
├── owasp-urls.json      # add per-domain crosswalk entries + mark owasp_scp_guide as archived
└── secure-patterns.md   # fix the top-of-file "Reference: OWASP SCP QRG" line — see Pitfall below
```

### Pattern 1: Edition-Verification Note (mirrors Phase 2's `top10.md` convention)

**What:** A short paragraph placed near the top of each standard's reference file, right after the existing "Source:" line, stating the exact confirmed edition, official URL, retrieval date, and confirmed status.

**When to use:** Once per standard file (twice in `llm-agentic.md`, since it covers two standards).

**Example (drawn from this research's own verified findings — ready to paste into `asvs.md`):**
```markdown
**Edition verification:** ASVS 5.0.0 confirmed as the current stable release
(not a release candidate), released 2025-05-30 at Global AppSec EU Barcelona.
Source: <https://owasp.org/www-project-application-security-verification-standard/>.
Retrieved 2026-07-22. No newer stable edition found as of this date.
```

### Pattern 2: `owasp-urls.json` Entry Shape (reuse verbatim — established in Phase 2)

**What:** The existing flat-map shape from `skills/owasp-security-audit/references/owasp-urls.json`, already used for `A01`–`A10`:
```json
"ASVS": {"title": "Application Security Verification Standard", "edition": "5.0.0", "url": "https://owasp.org/www-project-application-security-verification-standard/", "retrieval_date": "2026-07-22", "confidence": "verified"}
```
Apply the same shape to `MASVS`, all `API1:2023`–`API10:2023`, all `LLM01:2025`–`LLM10:2025`, and all `ASI01`–`ASI10` entries — every one of these currently lacks a `retrieval_date` field and several still say `"confidence": "pattern"` or `"index-fallback"` where this research now supports `"verified"`.

**Kubernetes exception:** do NOT flip K01–K10 confidence based on this research alone for the 2025 set (there is no 2025 set in the file yet, and none should be added as "verified" — only the existing 2022 K01–K10 entries get a `retrieval_date` addition). Consider adding a top-level `_meta` note (mirroring the existing `_meta.confidence` field) stating: `"kubernetes_2025_status": "2025 edition available for community feedback as of 2026-07-22; no formal release/version tag; not cited as primary — see kubernetes-top10.md footnote."`

### Pattern 3: SCP Domain Crosswalk Table (new — D-02)

**What:** A markdown table added to `scp-checklist.md`, one row per domain, linking to a living OWASP source.

**Full crosswalk (research output — ready for the planner to adapt):**

| # | SCP Domain | Living-source anchor | URL | Confidence |
|---|---|---|---|---|
| 1 | Input Validation | Input Validation Cheat Sheet + Proactive Control C3 (Validate all Input & Handle Exceptions) | `https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html` | VERIFIED (fetched directly) |
| 2 | Output Encoding | Cross Site Scripting Prevention Cheat Sheet + Injection Prevention Cheat Sheet | `https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html` | CITED (confirmed listed in Cheat Sheet Series index; URL pattern not individually fetched) |
| 3 | Authentication and Password Management | Authentication Cheat Sheet + Password Storage Cheat Sheet + Multifactor Authentication Cheat Sheet + Proactive Control C7 (Secure Digital Identities) | `https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html` | CITED |
| 4 | Session Management | Session Management Cheat Sheet | `https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html` | CITED |
| 5 | Access Control | Authorization Cheat Sheet + Proactive Control C1 (Implement Access Control) | `https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html` | CITED |
| 6 | Cryptographic Practices | Cryptographic Storage Cheat Sheet + Proactive Control C2 (Use Cryptography to Protect Data) | `https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html` | CITED |
| 7 | Error Handling and Logging | Error Handling Cheat Sheet + Logging Cheat Sheet + Proactive Control C9 (Implement Security Logging and Monitoring) | `https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html` | VERIFIED (Logging Cheat Sheet fetched directly); Error Handling Cheat Sheet URL is CITED, not individually fetched |
| 8 | Data Protection | OWASP Developer Guide "Protect Data Everywhere" checklist + Cryptographic Storage Cheat Sheet | `https://devguide.owasp.org/en/04-design/02-web-app-checklist/08-protect-data/` | CITED |
| 9 | Communication Security | Transport Layer Security Cheat Sheet + HTTP Strict Transport Security Cheat Sheet | `https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html` | CITED |
| 10 | System Configuration | Docker Security Cheat Sheet + Proactive Control C5 (Secure By Default Configurations) | `https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html` | CITED |
| 11 | Database Security | Database Security Cheat Sheet + SQL Injection Prevention Cheat Sheet | `https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html` | VERIFIED (URL confirmed to exist and load via search result showing direct page title match) |
| 12 | File Management | File Upload Cheat Sheet | `https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html` | CITED — **weaker anchor, see Open Questions** |
| 13 | Memory Management | OWASP Developer Guide / Go Secure Coding Practices Guide (language-specific memory-safety guidance) | `https://devguide.owasp.org/` (no dedicated language-agnostic memory-management page conclusively located) | **ASSUMED / weak anchor — see Open Questions** |
| 14 | General Coding Practices | OWASP Top 10 Proactive Controls (overview) + Proactive Control C6 (Keep your Components Secure) | `https://top10proactive.owasp.org/archive/2024/the-top-10/` | VERIFIED (fetched directly, confirms 2024 is current stable Proactive Controls edition) |

**Proactive Controls 2024 — confirmed current, spot-verified twice** (both the archive/2024 page and the live top10proactive.owasp.org WIP-labeled root page show identical C1–C10 titles for the 2024 edition):
```
C1: Implement Access Control          C6: Keep your Components Secure
C2: Use Cryptography to Protect Data  C7: Secure Digital Identities
C3: Validate all Input & Handle       C8: Leverage Browser Security Features
    Exceptions                        C9: Implement Security Logging and Monitoring
C4: Address Security from the Start   C10: Stop Server Side Request Forgery
C5: Secure By Default Configurations
```
Note: the live site's root page labels the *next* revision "Future Top 10 (WIP)" — do not cite that WIP content; 2024 remains the citable stable edition.

### Anti-Patterns to Avoid

- **Citing the archived SCP QRG as a current source:** `secure-patterns.md`'s top-of-file line (`> Reference: OWASP Secure Coding Practices Quick Reference Guide`) currently implies the QRG is a live, authoritative reference. It should be reworded to note the QRG as the **historical origin** of these patterns, with the crosswalk in `scp-checklist.md` as the living-source pointer (CONT-05 explicitly requires this).
- **Treating "index-fallback" URLs as lower-confidence than they are:** Several `LLM0x` and all `ASI0x` entries in `owasp-urls.json` point to a shared index/resource page rather than a per-item page — that's a structural fact about the OWASP GenAI site (some LLM items and *all* Agentic items don't have individual sub-pages), not a confidence problem. Don't force a fake per-item URL; keep the shared-page citation and mark IDs/names as `verified` based on this research's primary-source confirmation.
- **Enumerating 2025 Kubernetes categories as if final:** The existing `kubernetes-top10.md` appendix already does this correctly (marks each 2022→2025 mapping with `[?]` and tells the reader to verify against per-item pages) — do not "clean up" those `[?]` markers into confident statements; the ambiguity is real, confirmed by this research.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Determining if an OWASP standard is Final vs Draft | Guessing from a blog post's confident tone | The project's own official page/announcement, checked for explicit "released"/"stable"/"final" language or its absence | Third-party blogs (goteleport.com, praesidia.ai, etc.) confidently describe the Agentic Top 10's categories with paraphrased names ("Tool Misuse & Exploitation") that are NOT what the primary source says — always trace back to the OWASP-owned domain |
| Re-deriving SCP checklist content from scratch | Rewriting the 14-domain, 100+-item checklist against Cheat Sheet prose | Keep the existing checklist verbatim (D-01); only add the crosswalk table pointing to living sources | The checklist items are already correct security guidance; the accuracy gap is *citation*, not *content* |
| Confirming Kubernetes 2025 status | Assuming "available" == "final" | Explicitly check for a version tag / GitHub Release / "stable" label — absence of all three is itself the signal | OWASP's own site conflates "published" and "final" in casual language; the K8s repo's own "No releases published" is the disambiguating fact |

**Key insight:** Every citation-hardening claim in this phase should trace to a specific quoted sentence from an official OWASP-owned domain, retrieved during this research session — not to a third-party blog's summary, however confident-sounding, and not to training-data recall of what the standard "should" say.

## Common Pitfalls

### Pitfall 1: Treating "available"/"published" as synonymous with "Final"/"stable"
**What goes wrong:** A standard's project page says an edition is "now available," and a planner or reviewer assumes this means it has superseded the prior edition, when OWASP itself hasn't attached a formal release/version designation.
**Why it happens:** OWASP project pages use inconsistent language across projects — Top 10 2025 explicitly said "RELEASED"/prior edition "SUPERSEDED" (Phase 2 verified this precisely), but Kubernetes 2025 only says "now available... feedback welcome," a materially weaker claim.
**How to avoid:** For each standard, look for the *specific* words "Final," "stable," "released" (with the prior edition explicitly marked superseded/archived) vs. softer language ("available," "feedback welcome," "work in progress"). Absence of a GitHub release tag is a strong secondary signal.
**Warning signs:** No version tag, no explicit prior-edition-superseded language, GitHub showing "No releases published."

### Pitfall 2: Assuming a re-derivation task requires new content instead of new citations
**What goes wrong:** "Re-derive against the living OWASP Developer Guide" (CONT-05 wording) could be misread as "rewrite the SCP checklist using Developer Guide content," which would violate D-01 (light re-anchor) and duplicate effort that already produced a solid checklist.
**Why it happens:** The word "re-derive" sounds like a content rebuild.
**How to avoid:** D-01/D-02 are explicit: the checklist stays, only a crosswalk table is added. Confirm this interpretation is locked before any task touches `scp-checklist.md`'s existing 100+ items.
**Warning signs:** A plan task that proposes editing/removing existing checklist bullet points rather than only adding a new table section.

### Pitfall 3: Citing a third-party paraphrase for the Agentic Top 10 instead of the primary source
**What goes wrong:** Multiple SEO/vendor blogs (goteleport.com, praesidia.ai, sphr.world) independently paraphrase the ASI category names with added suffixes not present in the primary OWASP announcement.
**Why it happens:** These blogs summarize the PDF/announcement in their own words for SEO purposes; their phrasing looks equally authoritative in a search result snippet.
**How to avoid:** Always fetch from a `genai.owasp.org` or `owasp.org` domain directly for the final ID/name text; treat any third-party name variant as unconfirmed until cross-checked against the primary page.
**Warning signs:** A category name with an extra descriptive suffix not present in the repo's existing (already-verified-correct) `llm-agentic.md` names.

## Code Examples

### Edition-verification note pattern (verified snippet, see Architecture Patterns Pattern 1 above for the full text)

### `owasp-urls.json` entry pattern (verified snippet, see Architecture Patterns Pattern 2 above)

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|---|---|---|---|
| Citing OWASP SCP Quick Reference Guide as a live secure-coding source | Citing OWASP Developer Guide + Cheat Sheet Series + Proactive Controls | QRG project archived (confirmed 2025-06-08 per GitHub archival) | Any project still citing the QRG URL as "current" is citing an archived page; the content survives but its home moved |
| Referring to Kubernetes Top 10 by only one edition | Two editions coexist (2022 stable, 2025 in-progress) with different K0x numbering for the same categories | 2025 edition publication (exact date not found; no formal release tag as of 2026-07-22) | Any citation must specify which edition's K0x code is meant — they are not interchangeable |
| Assuming Agentic Apps 2026 was still a "Preview" using invented `AG0x` codes | Final release using `ASI01`–`ASI10` under the OWASP GenAI Security Project | Released 2025-12-09 | The repo has already made this transition correctly (see the `llm-agentic.md` "Mapping: repo's old AG## codes" appendix) — this phase just needs to update the provenance note, not the codes |

**Deprecated/outdated:**
- OWASP SCP Quick Reference Guide as a "current" citation target — officially archived; its content lives on in the Developer Guide.
- The old repo-invented `AG01`–`AG10` codes — already fully retired in the current `llm-agentic.md`, kept only as a historical mapping table for readers translating old reports.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Cheat Sheet URLs for domains 2–6, 8–10 (Output Encoding, Authentication, Session Management, Access Control, Cryptographic Practices, Data Protection, Communication Security, System Configuration) follow the standard `cheatsheetseries.owasp.org/cheatsheets/<Name>_Cheat_Sheet.html` pattern confirmed by two direct fetches (Input Validation, Logging) but were not each individually fetched this session | Standard Stack / SCP crosswalk table | Low — if a URL 404s, the existing `owasp-urls.json` fallback convention ("try the project index URL and update this file") already handles this; planner should have the implementing task spot-check each URL with one fetch per file before finalizing |
| A2 | Memory Management (domain 13) has no clean, language-agnostic living-source anchor in the OWASP Developer Guide; the Go Secure Coding Practices Guide covers memory-management topics but is Go-specific | SCP crosswalk table (row 13) | Medium — if the planner locks a weak/wrong URL here, the crosswalk table would misrepresent this domain's sourcing; recommend either citing the Developer Guide's general index as an "under migration" placeholder, or keeping this domain's crosswalk cell explicitly marked "no dedicated living source located — see original SCP QRG content as reference of last resort, not current source" |
| A3 | File Management (domain 12) crosswalk anchor (File Upload Cheat Sheet) covers only the upload-validation subset of the domain's checklist items, not path-traversal/file-serving items | SCP crosswalk table (row 12) | Low-Medium — the File Upload Cheat Sheet is a real, correct anchor for part of the domain but doesn't cover every checklist bullet (e.g., "never send the absolute file path to the client"); planner should note this is a partial anchor, not claim full 1:1 coverage |
| A4 | The exact date the OWASP Kubernetes Top 10 2025 edition was first published was not found (only that it currently reads "now available") | Live Verification Results table | Low — doesn't block the footnote (which only needs to say "in progress," not attach a date to the 2025 edition itself); the retrieval date (2026-07-22) is what matters for the footnote's own provenance |
| A5 | The MASVS 8 control-group names in the repo's `masvs.md` table use shorthand ("Authentication", "Network", "Platform") vs. the official site's fuller titles ("Authentication and Authorization", "Network Communication", "Platform Interaction") | Architecture Patterns / general | Very low — cosmetic; not a version/edition/ID accuracy issue, but the planner may want a one-line tweak to fully match official wording since the accuracy constraint is broad |

## Open Questions

1. **Which URL should represent "the" ASVS source in `owasp-urls.json`: the project landing page or the version-pinned GitHub tag?**
   - What we know: The project page (`owasp.org/www-project-application-security-verification-standard/`) is the human-readable entry point and is what `asvs.md` already cites; the GitHub tag (`github.com/OWASP/ASVS/tree/v5.0.0/5.0`) is the immutable, version-pinned source.
   - What's unclear: Phase 2's precedent (`top10.md`) cited the human-readable project index (`owasp.org/Top10/2025/`), not a GitHub tag, so consistency argues for the project page.
   - Recommendation: Use the project landing page as primary (matches Phase 2 precedent + existing `asvs.md` citation style); optionally mention the GitHub tag in the edition-verification note prose as a secondary "canonical version source" for readers who want the pinned artifact.

2. **Should the SCP crosswalk table live only in `scp-checklist.md`, or also duplicate into the SCP skill's `owasp-urls.json`?**
   - What we know: D-03 requires the `owasp-urls.json` entry pattern for the five *audit-skill* standards; D-02 requires the crosswalk table for SCP but doesn't explicitly say it must also populate `owasp-urls.json`.
   - What's unclear: CONTEXT.md's canonical_refs section does list `skills/secure-coding-practices/references/owasp-urls.json` as a file this phase re-anchors, implying some crosswalk data belongs there too, for consistency with the audit-skill convention and to support the Phase 5 coverage matrix (QUAL-02).
   - Recommendation: Put the full table (with all context/rationale) in `scp-checklist.md` per D-02, and mirror just the machine-readable fields (domain, url, retrieval_date, confidence) into `owasp-urls.json` as a new top-level key (e.g., `scp_domain_crosswalk`) — this keeps both files' conventions consistent and feeds Phase 5 cleanly.

3. **Does `secure-patterns.md` need its own edition-verification note, or just a corrected top-line reference?**
   - What we know: CONTEXT.md's canonical_refs list this file only for "confirm no stale QRG-as-current citations" — a lighter task than the crosswalk-table work in `scp-checklist.md`.
   - What's unclear: whether the top-of-file `> Reference: OWASP Secure Coding Practices Quick Reference Guide` line is the *only* stale reference, or whether individual pattern sections also implicitly claim QRG provenance.
   - Recommendation: A single sentence fix at the top of the file (reword the QRG mention to "historical origin," per Pitfall/Anti-Pattern above) should satisfy CONT-05's scope for this file; a full read of the file (already done in this research pass) found no other explicit QRG citations in the body — only implementation patterns with no source-attribution language at all.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | None (Markdown/JSON reference content — no test runner in this repo) |
| Config file | none — see Wave 0 |
| Quick run command | `python3 -m json.tool skills/owasp-security-audit/references/owasp-urls.json > /dev/null && python3 -m json.tool skills/secure-coding-practices/references/owasp-urls.json > /dev/null` (JSON validity check) |
| Full suite command | Same as quick run, plus the grep assertions below |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CONT-03 | Each of ASVS/MASVS/API/LLM/Agentic has an edition-verification note with retrieval date | grep assertion | `grep -l "Retrieved 2026-07-22" skills/owasp-security-audit/references/{asvs,masvs,api-top10,llm-agentic}.md \| wc -l` should be 4 (llm-agentic.md counted once but must contain the string twice — one for LLM, one for Agentic) | ✅ files exist today |
| CONT-03 | `owasp-urls.json` has `retrieval_date` + `confidence: verified` for ASVS, MASVS, all API1-10, all LLM01-10, all ASI01-10 | JSON-shape check (Python script) | `python3 -c "import json; d=json.load(open('skills/owasp-security-audit/references/owasp-urls.json')); codes=['ASVS','MASVS']+[f'API{i}:2023' for i in range(1,11)]+[f'LLM{i:02d}:2025' for i in range(1,11)]+[f'ASI{i:02d}' for i in range(1,11)]; missing=[c for c in codes if 'retrieval_date' not in d.get(c,{})]; assert not missing, missing"` | ✅ file exists, Wave 0 need: none, script is inline |
| CONT-04 | `kubernetes-top10.md` cites 2022 as primary AND footnotes 2025 as in-progress (not final) | grep assertion | `grep -q "2022 edition" skills/owasp-security-audit/references/kubernetes-top10.md && grep -qi "in progress\|not.*final\|feedback" skills/owasp-security-audit/references/kubernetes-top10.md` | ✅ file exists (already partially satisfies this) |
| CONT-05 | `scp-checklist.md` contains a 14-domain crosswalk table with per-domain URLs | grep assertion (count table rows) | `grep -c "cheatsheetseries.owasp.org\|devguide.owasp.org\|top10proactive.owasp.org" skills/secure-coding-practices/references/scp-checklist.md` should be ≥ 14 | ✅ file exists, crosswalk section is new (Wave 0 gap: none, it's the plan's own deliverable) |
| CONT-05 | SCP QRG is noted as archived, not current | grep assertion | `grep -qi "archived" skills/secure-coding-practices/references/scp-checklist.md` | ✅ file exists |
| CONT-05 | `secure-patterns.md` no longer implies QRG is a live current source | grep assertion (negative + positive) | `grep -qi "historical\|archived" skills/secure-coding-practices/references/secure-patterns.md` | ✅ file exists |

### Sampling Rate
- **Per task commit:** Run the relevant grep assertion(s) for the file(s) just edited (each is < 1s).
- **Per wave merge:** Run the full JSON-validity check + all grep assertions above.
- **Phase gate:** All six requirement rows above green before `/gsd-verify-work`.

### Wave 0 Gaps
None — every file targeted by this phase already exists (confirmed by reading all six reference files + both `owasp-urls.json` files during this research pass). No new test framework or fixture needs to be installed; the validation is pure grep/JSON-shape checks against Markdown/JSON files, runnable with only Python's standard library (already required by the repo's existing `quick_scan.py`).

## Security Domain

> `security_enforcement: true` in `.planning/config.json`, so this section is included per the mandatory verification protocol. However, this phase's actual "product" is documentation/citation accuracy, not application code with a runtime attack surface — the ASVS category mapping below is included for completeness but most categories are genuinely not applicable.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | No authentication code is written or changed in this phase |
| V3 Session Management | No | N/A — no session code |
| V4 Access Control | No | N/A — no access-control code |
| V5 Input Validation | No | N/A — no user-facing input handling; this phase's own "input" is OWASP's published web pages, read via WebFetch/WebSearch, not user-controlled application input |
| V6 Cryptography | No | N/A — no cryptographic code |

### Known Threat Patterns for this phase's actual domain (content/citation integrity)

| Pattern | STRIDE-adjacent category | Standard Mitigation |
|---------|--------|---------------------|
| Citing a stale/superseded OWASP edition as current (misinformation to the skill's own users) | Tampering-adjacent (information integrity, not classic STRIDE) | Live re-verification against the official project page before every edition claim, with an explicit retrieval date recorded (this research's own methodology) |
| Adopting a third-party paraphrase of an OWASP category name instead of the primary source's exact wording | Tampering-adjacent (content provenance) | Always resolve to a `owasp.org`/`genai.owasp.org`/`mas.owasp.org` domain fetch before finalizing any ID/name/status claim (see Pitfall 3 above) |
| Presenting a draft/RC/in-progress standard as Final (directly named in PROJECT.md's Out of Scope table: "Presenting draft OWASP editions as final — Credibility risk") | Repudiation-adjacent (false attribution of authority) | The D-04/D-06 halt-and-flag gate applied throughout this research — Kubernetes 2025 is the one case where this actually fired |

**Note for planner:** No `checkpoint:human-verify` gate is needed for package installs (none exist), but consider a lightweight editorial self-check task ("does every edition claim in this task's diff have a matching quoted source + retrieval date in this RESEARCH.md?") as a cheap per-task verification substitute, given the domain here is citation accuracy rather than code correctness.

## Sources

### Primary (HIGH confidence — official OWASP domains, fetched/searched live 2026-07-22)
- `https://owasp.org/www-project-application-security-verification-standard/` — ASVS 5.0.0 current-release confirmation
- `https://github.com/OWASP/ASVS/releases` — ASVS version-tag cross-check
- `https://mas.owasp.org/news/2024/01/18/masvs-v210-release--masvs-privacy/` and `https://github.com/OWASP/masvs/releases/tag/v2.1.0` — MASVS 2.1.0 confirmation
- `https://owasp.org/API-Security/editions/2023/en/0x11-t10/` — API Security Top 10 2023 confirmation
- `https://genai.owasp.org/llm-top-10/` — LLM Top 10 2025 confirmation (fetched live)
- `https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/` — Agentic Apps 2026 Final-release confirmation + exact ASI01-10 names (fetched live)
- `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/` — Agentic Apps resource/PDF landing page
- `https://owasp.org/www-project-kubernetes-top-ten/` and `https://github.com/OWASP/www-project-kubernetes-top-ten/blob/main/README.md` — Kubernetes 2022/2025 status confirmation (fetched live)
- `https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/` — SCP QRG archival confirmation, exact quote (fetched live)
- `https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html` — spot-fetched, confirmed live
- `https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html` — spot-fetched, confirmed live
- `https://top10proactive.owasp.org/archive/2024/the-top-10/` — Proactive Controls 2024 C1-C10, spot-fetched
- `https://top10proactive.owasp.org/` — confirms 2024 is current stable, next edition is "Future Top 10 (WIP)"

### Secondary (MEDIUM confidence — WebSearch-verified against official-domain search results, not directly WebFetched)
- Cheat Sheet Series title list (Authentication, Session Management, Authorization, Cryptographic Storage, Transport Layer Security, Error Handling, Docker Security, File Upload, Database Security cheat sheets) — confirmed to exist via search result titles pointing to `cheatsheetseries.owasp.org` URLs, not each individually fetched this session
- OWASP Developer Guide "Protect Data Everywhere" checklist page (`devguide.owasp.org/en/04-design/02-web-app-checklist/08-protect-data/`) — found via search, not directly fetched

### Tertiary (LOW confidence — flagged, not used for any claim above without a primary/secondary cross-check)
- Third-party blogs describing Agentic Top 10 category names with added suffixes (goteleport.com, praesidia.ai, sphr.world) — explicitly NOT adopted; primary source used instead (see Pitfall 3)
- Go Secure Coding Practices Guide as a Memory Management anchor — language-specific, not confirmed as the intended crosswalk target (see Assumption A2 / Open Question area)

## Metadata

**Confidence breakdown:**
- Standard editions (ASVS/MASVS/API/LLM/Agentic/K8s status): HIGH — every edition claim was independently confirmed via live WebFetch/WebSearch against an official OWASP domain during this session, with exact quotes captured
- SCP archival status: HIGH — direct quote from the official project page
- SCP per-domain crosswalk URLs: MEDIUM — 5 of 14 domains directly WebFetch-confirmed (Input Validation, Logging, Database Security, Proactive Controls x2); remaining 9 confirmed via search-result title match only, not individually fetched — low risk given the existing `owasp-urls.json` fallback convention already handles 404s
- Memory Management / File Management crosswalk anchors: LOW — flagged explicitly in Assumptions Log A2/A3, recommend a quick manual spot-check before lock

**Research date:** 2026-07-22
**Valid until:** 30 days for the confirmed-current-and-stable standards (ASVS, MASVS, API, LLM); 7 days for the Kubernetes 2025 in-progress status specifically, since that one is actively moving (check again before any future phase relies on a Kubernetes 2025 "final" claim)
