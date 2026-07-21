# Phase 3: Remaining Standards Verification & Refresh - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-21
**Phase:** 3-remaining-standards-verification-refresh
**Areas discussed:** SCP re-derivation depth, Citation-hardening format, Agentic & Kubernetes specifics

---

## SCP re-derivation depth

| Option | Description | Selected |
|--------|-------------|----------|
| Light re-anchor | Keep 14-domain checklist structure/items; re-cite to living Developer Guide / Cheat Sheets / Proactive Controls; note QRG archived | ✓ |
| Restructure to Proactive Controls | Re-map checklist onto Proactive Controls 2024 (C1–C10) spine with a crosswalk | |
| Full content rebuild | Re-author checklist from Developer Guide + Cheat Sheets from scratch | |

**User's choice:** Light re-anchor
**Notes:** Honors the "refresh, not teardown" compatibility constraint and satisfies CONT-05 at lowest risk.

### Follow-up — citation granularity

| Option | Description | Selected |
|--------|-------------|----------|
| Per-domain crosswalk | Each of 14 domains mapped to a living-source anchor (Cheat Sheet + Proactive Control) with URL + retrieval date; crosswalk table | ✓ |
| Single top-level statement | One blanket note at the top; no per-domain mapping | |

**User's choice:** Per-domain crosswalk
**Notes:** Chosen for auditability (accuracy / QUAL-01 spirit).

---

## Citation-hardening format

| Option | Description | Selected |
|--------|-------------|----------|
| Mirror Phase 2 convention | Per-file edition-verification note + owasp-urls.json entry (edition / retrieval_date / confidence: verified) for all 5 standards | ✓ |
| owasp-urls.json only | Centralize all metadata in owasp-urls.json; leave reference-file prose unchanged | |
| You decide | Per-standard hybrid — prose note only where a file lacks an edition statement | |

**User's choice:** Mirror Phase 2 convention
**Notes:** Self-documents each file when loaded; feeds the Phase 5 coverage matrix (QUAL-02).

---

## Agentic & Kubernetes specifics

### Agentic Apps 2026 sourcing + gate

| Option | Description | Selected |
|--------|-------------|----------|
| Primary source + Final-gate | Pull ASI01–ASI10 verbatim from the official primary source; halt-and-flag if RC/draft/unverifiable (Phase 2 D-04) | ✓ |
| Primary source + footnote-and-proceed | Cite draft/RC with an "as of {date}" caveat and proceed; no halt | |

**User's choice:** Primary source + Final-gate
**Notes:** STATE.md flagged the ASI names were only paraphrased in prior research — must come from the primary source.

### Kubernetes 2025-draft footnote depth

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal one-liner | 2022 primary + one sentence noting a 2025 edition is in progress and not final | ✓ |
| Short "what's changing" note | 2–3 line footnote on the 2025 draft's direction/status | |

**User's choice:** Minimal one-liner
**Notes:** Keeps the reference clean; avoids implying draft categories are authoritative.

## Claude's Discretion

- Exact wording/placement of each per-file edition-verification note and the SCP crosswalk table.
- Whether LLM 2025 and Agentic 2026 keep sharing `llm-agentic.md` or are split (a Phase 4 file-structure concern).
- Per-domain source selection for the SCP crosswalk (which Cheat Sheet / Proactive Control anchors each domain) — a research task.

## Deferred Ideas

- QUAL-02 coverage matrix artifact — Phase 5 (this phase produces the metadata that feeds it).
- Kubernetes Top 10 2025 adoption once final — v2 (EXP-02).
- Splitting `llm-agentic.md` into separate files — Phase 4 file-structure concern.

## Not discussed (carried forward as default)

- **Version-drift policy (D-06):** Not selected for discussion; defaulted to Phase 2's halt-if-RC gate extended phase-wide — halt-and-flag if any expected standard label proves wrong during live verification.
