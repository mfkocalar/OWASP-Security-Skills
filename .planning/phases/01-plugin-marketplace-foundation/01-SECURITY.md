---
phase: 01
slug: plugin-marketplace-foundation
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-20
---

# Phase 01 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

Verified from the PLAN.md threat registers (authored at plan time) at ASVS L1 grep-depth.
`security_block_on: high` — no threat in this phase is high severity, and every open
mitigation was confirmed present in the implementation, so the short-circuit path applied
(no separate auditor pass required). One additional installer path-traversal (T-01-08),
surfaced by the phase code review, was fixed and is recorded here for completeness.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| public GitHub repo → Claude Code plugin loader | Untrusted static manifest JSON crosses here; validated by `claude plugin validate` (JSON schema + type checks) | `plugin.json` / `marketplace.json` |
| marketplace catalog → end-user install | The github `source` object determines which repo/code a user actually installs from | `marketplace.json` source object |
| convention doc → downstream phase authors | Inaccurate structure guidance would misroute later-phase content; grounded in verified on-disk layout to prevent drift | `docs/SKILL-STRUCTURE.md` |
| repo working tree → installer/reader (`install.sh`, `README`) | File removals must not leave the installer or README pointing at absent files; patch-then-delete ordering enforces consistency | source paths / links |
| user input → installer filesystem writes | Custom install path is user-supplied before `mkdir -p`/`ln -s` | filesystem path |
| planning state → future phases | Known doc staleness must be durably tracked so a later phase does not ship stale docs unknowingly | `.planning/STATE.md` |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-01-01 | Spoofing | `marketplace.json` name / source resolution | medium | mitigate | Non-reserved marketplace `name` (`owasp-security-skills`); exact `owner/repo` locked in a github source object (`mfkocalar/OWASP-Security-Skills`) — confirmed to match `git remote` | closed |
| T-01-02 | Elevation of Privilege | `plugin.json` component declarations | low | mitigate | Declares no `hooks`, `mcpServers`, or `commands` — skills-only via default scan; minimal executable surface (keys: `$schema, name, displayName, version, description, author, homepage, repository, license, keywords`) | closed |
| T-01-03 | Repudiation / Tampering (trust signal) | `plugin.json` version / repository / homepage | low | mitigate | Honest `0.1.0` pre-1.0 version + real `repository`/`homepage` URLs pointing at the verified origin, no placeholders | closed |
| T-01-04 | Tampering (of guidance) / Repudiation | `docs/SKILL-STRUCTURE.md` | low | mitigate | Every assertion grounded in the verified on-disk layout; compliance checks recorded and re-verified line-by-line against `find`/`ls` output | closed |
| T-01-05 | Denial of Service (broken install path) | `install.sh` / `README` after removals | medium | mitigate | Referencing files patched first to per-skill canonical paths, retired files deleted second; `install.sh` happy path exits 0 and all README links resolve | closed |
| T-01-06 | Tampering / data loss | root `examples/` deletion | medium | mitigate | `diff -rq` byte-identical safety check before delete; 9 canonical per-skill copies confirmed to remain afterward | closed |
| T-01-07 | Repudiation (silent scope gap) | `DEPLOYMENT.md` / `TESTING.md` staleness | low | mitigate | Gap recorded explicitly in `.planning/STATE.md` Blockers/Concerns (lines 77, 88) for Phase 5 doc-polish — no silent omission | closed |
| T-01-08 | Elevation of Privilege / Path Traversal | `install.sh` custom install path option | medium | mitigate | Guard rejects any custom path containing `..` before `mkdir -p`/`ln -s` (code review WR-02, commit `64c3782`); traversal repro now exits 1 | closed |
| T-01-SC | Tampering | package installs (npm / pip / cargo) | low | accept | No package-manager installs occur in this phase — it authors static JSON/markdown and patches shell; the Package Legitimacy Gate does not apply | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above `workflow.security_block_on` count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| SC-01 | T-01-SC | Phase authors static JSON/markdown and patches shell only; no npm/pip/cargo install occurs, so supply-chain package legitimacy checks are not applicable to this phase | mkh | 2026-07-20 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-20 | 9 | 9 | 0 | gsd-secure-phase (ASVS L1 grep-depth, short-circuit; T-01-08 added from code review) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-20
