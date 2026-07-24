---
phase: 04
slug: skill-md-conversion-legacy-retirement
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-24
---

# Phase 04 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

Register authored at plan time (all 5 PLANs carried a `<threat_model>` block). ASVS L1, block-on `high`. Verified at L1 grep-depth via the short-circuit rule (threats_open: 0 AND register_authored_at_plan_time: true AND asvs_level == 1) — no separate auditor pass required. This phase is a documentation/format restructuring with no new network endpoints, auth paths, or runtime dependencies; the trust surface is the *loaded skill path* and the *installer*.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| repo content → skill loader / marketplace validator | SKILL.md frontmatter is parsed at install/activation; a malformed field silently disables the skill | frontmatter fields (name, description) |
| SKILL.md routing table → references/*.md | The skill body is a pointer; a pointer to a deleted file loads nothing on the deep-lookup path | file-path references |
| public description → user request matcher | The description is the sole activation signal; an inaccurate claim misrepresents coverage of a public OWASP reference | activation text / coverage claims |
| example / header content → reader-learner | Paired examples are teaching material; a wrong OWASP mapping teaches a wrong standard | OWASP category IDs, cross-references |
| install.sh sentinel → repo layout → end user | The installer gates every install on a sentinel file; deleting it (or leaving stale required_files) breaks install for everyone | installer control flow |
| dev environment → lint tool | The lint script runs against local files; a false PASS lets broken frontmatter slip through | lint verdicts |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-04-01 | Tampering | lint script gives a false PASS (regex misses an angle bracket) | medium | mitigate | Verified check bodies from RESEARCH.md run against known-good baseline; both SKILL.md pass 24/24 (`lint_skill_md.py skills/` exit 0) | closed |
| T-04-02 | Denial of Service | lint script imports PyYAML and crashes in a clean env | medium | mitigate | Stdlib-only enforced — `grep -c "import yaml" scripts/lint_skill_md.py` == 0 | closed |
| T-04-SC | Tampering (supply chain) | package installs (npm/pip/cargo) | n/a | accept | No package installs in this phase; lint tool adds zero runtime deps (see Accepted Risks) | closed |
| T-04-03 | Information Disclosure | SKILL.md still points at deleted `llm-agentic.md` | high | mitigate | Split + repoint in one plan; `grep llm-agentic` on loaded path == 0; both `llm.md`/`agentic.md` referenced | closed |
| T-04-04 | Tampering | LLM/ASI item dropped or duplicated during the verbatim split | high | mitigate | Verifier confirmed `llm.md` = 10/10 LLM headings, `agentic.md` = 10/10 ASI headings; no cross-leak | closed |
| T-04-05 | Spoofing | description overclaims ASVS 5.0 vs the 4.0.3-numbered body | medium | mitigate | Reworded to "ASVS (4.0.3-numbered verification requirements; 5.0.0 is the current edition)"; re-linted | closed |
| T-04-06 | Tampering | description edit introduces a literal angle bracket → FMT-05 fail / skill won't load | high | mitigate | `lint_skill_md.py` gate (no-angle-brackets check) passes on the audit skill | closed |
| T-04-07 | Spoofing | docs/description still cite the archived QRG as current | medium | mitigate | Every surviving QRG mention framed "archived historical origin"; living-source terms present | closed |
| T-04-08 | Tampering | SCP description reword adds an angle bracket or overruns 1024 chars → FMT-05 fail | high | mitigate | `lint_skill_md.py skills/secure-coding-practices/` exit 0 (description 695 chars) | closed |
| T-04-09 | Denial of Service | reword drops the SCP-compliance trigger → skill stops activating | medium | mitigate | Activation triggers ("SCP compliance", "secure coding") confirmed present in SKILL.md | closed |
| T-04-10 | Tampering | example relabeled to the WRONG 2025 category via literal-number substitution | high | mitigate | Relabeled by TOPIC against top10.md/llm.md/agentic.md; verifier confirmed all IDs match 2025/2026 canon | closed |
| T-04-11 | Information Disclosure | example header still targets the legacy comprehensive guide after 04-05 delete | high | mitigate | 04-04 repointed headers before the delete; `grep owasp-comprehensive` on loaded path == 0 | closed |
| T-04-12 | Tampering | prompt-injection.txt's four AG codes blanket-replaced to one ASI code | high | mitigate | Per-code map from agentic.md; four distinct LLM items present, `grep AG##` == 0; manual mapping check | closed |
| T-04-13 | Information Disclosure | a surviving loaded-path file references a deleted legacy file | high | mitigate | Cross-reference sweep before delete; `grep` of skills/ + install.sh for all 4 deleted files == 0 | closed |
| T-04-14 | Repudiation / integrity | salvage-check misses unique still-current content in the 900-line file | high | mitigate | Explicit Task 1 salvage gate (section-by-section skim vs references/ tree) recorded in 04-05 SUMMARY; no unique content found | closed |
| T-04-15 | Denial of Service | install.sh sentinel/required_files still name a deleted file → main uninstallable | high | mitigate | Sentinel repointed to `.claude-plugin/plugin.json` + required_files trimmed in the same commit as the delete; `bash -n` OK; two real install runs succeeded | closed |
| T-04-16 | Repudiation | reviewer flags root-doc broken refs as an oversight | low | accept | Deferred-and-known gap explicitly recorded (Phase 5 scope; see Accepted Risks) | closed |

*Status: open · closed · open — below `high` threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above workflow.security_block_on (`high`) count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-04-01 | T-04-SC | No package installs occur in this phase; the lint tool is stdlib-only and adds zero runtime dependencies. No supply-chain surface to mitigate. | Phase plan (04-01) | 2026-07-24 |
| AR-04-02 | T-04-16 | Non-loaded-path docs (`README.md`, `DEPLOYMENT.md`, `TESTING.md`, `CONTRIBUTING.md`, `.claude/CLAUDE.md`, `docs/SKILL-STRUCTURE.md`) still name deleted files. Out of scope for Phase 4's loaded-path goal; explicitly deferred to Phase 5 doc-polish. Low severity — cosmetic doc staleness, not a loaded-path or installer defect. | Phase plan (04-05) | 2026-07-24 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-24 | 16 | 16 | 0 | gsd-secure-phase (L1 short-circuit, grep-depth) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-24
