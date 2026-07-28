---
phase: 05
slug: packaging-validation-credibility-polish
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
block_on: high
created: 2026-07-28
---

# Phase 05 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Verified by gsd-security-auditor (State B — built from the plan-authored threat registers; `register_authored_at_plan_time: true`, mitigations verified against the implemented code). 12/12 threats closed; no threat at or above the `high` block threshold.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| repo manifests → Claude Code CLI installer | `plugin.json` / `marketplace.json` are configuration Claude Code parses to install the plugin | plugin identity, version, source |
| repo content → public consumers / scanners | LICENSE, README, and example files are read by humans and automated credential scanners after publication | license identity, coverage claims, example code |
| README / docs claims → OWASP official sources | every edition/ID claim must trace to an owasp-urls.json-recorded official URL + retrieval date | OWASP edition/category identifiers |
| test-time marketplace.json edit → committed/shipped manifest | the temporary local-source override used by the install-validation gate must never reach a commit | plugin source resolution |
| CONTRIBUTING topic list → live public GitHub repo | the `gh repo edit --add-topic` command list mutates an outward-facing public surface — kept user-controlled | repo discoverability metadata |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-05-01 | Information Disclosure | example secret literals (`skills/*/assets/examples/`) | low | mitigate | D-10 self-labeling placeholders only (`sk-EXAMPLE-not-a-real-key`, `sk-your-api-key-here`, `PLACEHOLDER_PASSWORD`); no real-looking/high-entropy secret; convention documented in CONTRIBUTING.md | closed |
| T-05-02 | Repudiation / trust erosion | README badges | low | mitigate | D-08 static honest-only shields (license-MIT, version-1.0.0, Claude Code plugin, OWASP-aligned); no CI/coverage/build badge present | closed |
| T-05-03 | Tampering | marketplace.json test-time source override | medium | mitigate | Byte-exact backup + `trap … EXIT` revert in `checkpoint1_install_validate.sh`; `git diff --quiet .claude-plugin/marketplace.json` clean; committed source still `github: mfkocalar/OWASP-Security-Skills` | closed |
| T-05-04 | Tampering | version strings across manifest/README/docs | low | mitigate | `plugin.json` 1.0.0 single canonical source; `check_version_drift.py` (narrow badge/label regex) exits 0 and never flags OWASP edition numbers | closed |
| T-05-05 | Information Disclosure | LICENSE legal identity | low | mitigate | MIT holder "Security Education Community" / year 2026 sourced only from `plugin.json` declared fields; zero new claims | closed |
| T-05-06 | Spoofing (misrepresentation) | README coverage matrix accuracy | medium | mitigate | Editions/IDs + retrieval dates match `owasp-urls.json` verbatim; "What this is NOT" discloses guidance-not-scanner and the uncovered example categories (A03/A04/A06/A08/A10) | closed |
| T-05-07a | Elevation of Privilege / unintended action | `gh repo edit --add-topic` on live public repo | medium | mitigate | D-11 command list documented as a MANUAL maintainer step; grep confirms no auto-execution of `gh`/`--add-topic` in any script | closed |
| T-05-07b | Repudiation / trust erosion | `docs/SKILL-STRUCTURE.md` worked-example excerpts | low | mitigate | Excerpts re-synced verbatim to the live SKILL.md descriptions (QUAL-01 gap closure); in-doc "sole authoritative source" pointer added | closed |
| T-05-08 | Repudiation / staleness | retired legacy docs (DEPLOYMENT.md / TESTING.md) | low | mitigate | D-09 salvage-then-delete; both files absent on disk (removed in `b3634e5`); no surviving cross-reference in README/CONTRIBUTING/docs | closed |
| T-05-09 | Spoofing / silent wrong-content install | local `marketplace add` vs plugin source confusion | medium | mitigate | Gate forces a relative on-disk source for the true local-content install; `claude plugin details` Skills count read as authoritative — transcript records "Skills (2) owasp-security-audit, secure-coding-practices" | closed |
| T-05-10 | Availability | unconfirmed "0 skills" regression at CLI v2.1.201 | low | mitigate | Real sequence run + actual `plugin details`/`list --json` output recorded (regression disproven); documented symlink workaround as fallback | closed |
| T-05-SC | Tampering (supply chain) | npm/pip/cargo installs | low | accept | No package-manager installs anywhere in phase tooling; scripts confirmed stdlib-only; `claude plugin install` installs this repo's own local content only — no external supply-chain surface | closed (accepted) |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above `high` count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-05-01 | T-05-SC | No npm/pip/cargo installs in phase tooling; all scripts are stdlib-only Python/Bash, and `claude plugin install` installs this repo's own local content only — no external supply-chain surface is introduced | Phase 5 threat model (all plans) + gsd-security-auditor | 2026-07-28 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-28 | 12 | 12 | 0 | gsd-security-auditor (ASVS L1, block_on: high) |

---

## Informational (out of threat scope — not gaps, not blocking)

- `__pycache__/` directories exist under both `assets/examples/` folders (Python bytecode). Canonical example counts unaffected; consider a `.gitignore` sweep at ship.
- `.claude/CLAUDE.md` (auto-generated project memory, not part of the distributed plugin surface) still references the Phase-4-deleted `owasp-comprehensive-security-skills.md` / `owasp-css.instructions.md`. No dead reference survives in any shipped file (README/CONTRIBUTING/docs/SKILL.md).

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-28
