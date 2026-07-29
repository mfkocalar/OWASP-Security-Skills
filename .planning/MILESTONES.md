# Milestones

## v1.0 OWASP Security Skills Modernization (Shipped: 2026-07-29)

**Phases completed:** 5 phases, 20 plans, 42 tasks

**Key accomplishments:**

- Authored `.claude-plugin/plugin.json` (owasp-security-skills / 0.1.0) and `.claude-plugin/marketplace.json` (self-hosted github-source catalog), both verified against the live-fetched official Claude Code plugin schema and passing `claude plugin validate . --strict`.
- Authored docs/SKILL-STRUCTURE.md locking the SKILL.md + references/ + scripts/ + assets/examples/ layout, and verified/recorded PKG-03's structural compliance (no symlinks, both skills at plugin root, per-skill canonical examples).
- install.sh and README.md repointed to per-skill canonical paths, then root skill.json and duplicate examples/ deleted with a byte-identical safety check gating the removal — main stays installable at every commit.
- Rewrote `top10.md` and the Top 10 block of `owasp-urls.json` from the 2021 edition to the OWASP Top 10 2025 (Final) edition, resolving every category by topic against the official OWASP mapping — not by numeric substitution.
- Swept every remaining Top 10 category ID, name, edition label, and citation URL in the loaded skill path (SKILL.md mirror, vulnerable-patterns.md, quick_scan.py, README.md) to the 2025 (Final) taxonomy established by plan 02-01, closing the CONT-02 gate with a clean zero-stale-reference grep.
- Added five verified edition-verification notes (ASVS 5.0.0, MASVS 2.1.0, API Security Top 10 2023, LLM Top 10 2025, Agentic Apps Top 10 2026) across four owasp-security-audit reference files, upgrading Agentic 2026 provenance to Final-confirmed against the primary OWASP announcement
- Task 1 — Kubernetes footnote tightening
- Re-anchored the secure-coding-practices skill's provenance from the archived OWASP SCP Quick Reference Guide to a 14-row living-source crosswalk (Cheat Sheet Series / Proactive Controls 2024 / Developer Guide), without touching the existing 100+-item checklist.
- Reframed asvs.md's edition-verification note and reporting exemplar so the file no longer contradicts itself: it now honestly discloses ASVS 4.0.3 chapter/requirement numbering alongside verified ASVS 5.0.0 provenance, with the 5.0.0 V-series re-mapping named and explicitly deferred.
- Stdlib-only Python lint script (scripts/lint_skill_md.py) proving both SKILL.md files already satisfy FMT-01/FMT-02/FMT-05, giving 04-02/04-03 a re-runnable gate for their description edits
- Split the 555-line combined llm-agentic.md into single-standard references/llm.md (LLM Top 10 2025) and references/agentic.md (Agentic Apps Top 10 2026 + AG## mapping table), repointed the audit SKILL.md's two reference sites, and fixed the description's ASVS 5.0 overclaim to match asvs.md's 4.0.3-numbering disclosure
- Reworded the secure-coding-practices skill's description and its two human-facing docs so the archived OWASP Secure Coding Practices Quick Reference Guide is framed only as historical origin, with the 14-domain checklist attributed to OWASP's living sources (Developer Guide, Cheat Sheet Series, Proactive Controls).
- All nine paired vulnerable/secure example files carry topic-correct OWASP 2025 category IDs and point at surviving reference files instead of the soon-to-be-deleted legacy comprehensive guide.
- Deleted the three FMT-04 legacy files (owasp-css.instructions.md, the 900-line comprehensive guide, and its in-skill duplicate) and minimally patched install.sh's sentinel/required_files in the same commit so main stays installable.
- Bumped plugin.json to the single-canonical-source version 1.0.0, added the missing MIT LICENSE, extended discoverability metadata on both manifests, and shipped a stdlib-only `check_version_drift.py` that catches version-string drift while ignoring OWASP edition numbers.
- Self-labeling placeholder convention (D-10/QUAL-03) applied to every plausible-looking API-key and password literal across both skills' shipped example files, preserving the vulnerable/secure teaching intent.
- CONTRIBUTING.md gained a Maintenance & versioning section (plugin.json-canonical version rule, release checklist, OWASP-edition update story), a Release & discoverability subsection with the manual gh repo edit --add-topic command list, and the documented example-secret placeholder convention; DEPLOYMENT.md and TESTING.md were deleted after confirming all accurate content was salvaged.
- End-to-end `claude plugin validate` -> local-source marketplace add -> install -> discovery smoke test proved both skills load, with a byte-exact revert of the temporary marketplace.json source override enforced by an EXIT trap.
- Re-synced docs/SKILL-STRUCTURE.md's two "verbatim" SKILL.md quote blocks to the live 2025 Top 10 / 4.0.3-numbered-ASVS / 14-domain-SCP description text, closing the sole confirmed Phase-5 verification gap (QUAL-01).

---
