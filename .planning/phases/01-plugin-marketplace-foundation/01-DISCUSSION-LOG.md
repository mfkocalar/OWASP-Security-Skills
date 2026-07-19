# Phase 1: Plugin/Marketplace Foundation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-19
**Phase:** 1-plugin-marketplace-foundation
**Areas discussed:** Examples de-duplication, Marketplace source type, Plugin identity & version, Convention doc + legacy

---

## Examples De-duplication

| Option | Description | Selected |
|--------|-------------|----------|
| Per-skill canonical, delete root | Each skill owns its examples in its own assets/examples/; delete root examples/ entirely | ✓ |
| Root canonical, skills reference | Keep root examples/ as source, skills point to it — rejected by PKG-03 (cross-dir dependency) | |
| Keep root as showcase + de-dupe | Root examples/ stays as browsable gallery, skill copies canonical; accept intentional duplication | |

**User's choice:** Per-skill canonical, delete root
**Notes:** The 9 Top-10 example files already exist in owasp-security-audit/assets/examples/; secure-coding-practices keeps its own 2 files. No symlinks currently exist in skills/.

### Follow-up: fallout from deleting root examples/

| Option | Description | Selected |
|--------|-------------|----------|
| Patch refs in Phase 1 | Update install.sh example check + repoint README links as part of the delete; main stays consistent | ✓ |
| Delete now, fix in Phase 5 | Accept temporarily broken install.sh + README, fold fix into Phase 5 | |
| Defer the whole delete | Keep root examples/ through Phase 1, delete + fix in Phase 4/5 | |

**User's choice:** Patch refs in Phase 1
**Notes:** install.sh references root examples/ at lines ~100–105 and ~146; README links at lines ~102–109. Full README rewrite is still Phase 5 — Phase 1 only keeps links valid.

---

## Marketplace Source Type

| Option | Description | Selected |
|--------|-------------|----------|
| GitHub source | source points at the GitHub repo; public-install ready | ✓ |
| Local path source | source is a local path (".") — good for dev testing, not public install | |
| Both / dual-source | Local-path + GitHub variants — more to maintain, can confuse validation | |

**User's choice:** GitHub source
**Notes:** origin remote confirmed as https://github.com/mfkocalar/OWASP-Security-Skills.git → source `mfkocalar/OWASP-Security-Skills`.

---

## Plugin Identity & Version

| Option | Description | Selected |
|--------|-------------|----------|
| Reset to 0.1.0 | Fresh public artifact; pre-1.0 while content refresh lands; reaches 1.0.0 at milestone ship | ✓ |
| Continue 1.1.0 | Preserve old skill.json lineage — overclaims stability | |
| Start at 1.0.0 | Declare 1.0 now — least honest, credibility work not done until Phase 5 | |

**User's choice:** Reset to 0.1.0

| Option | Description | Selected |
|--------|-------------|----------|
| owasp-security-skills | Matches repo, describes the collection, kebab-case | ✓ |
| owasp-security-audit | Reuses one skill's name — undersells the bundled second skill | |
| owasp-skills | Shorter, loses the "security" discoverability signal | |

**User's choice:** owasp-security-skills
**Notes:** plugin.json restricted to closed official schema fields only — no custom fields ported from old skill.json.

---

## Convention Doc + Legacy

| Option | Description | Selected |
|--------|-------------|----------|
| docs/SKILL-STRUCTURE.md | Dedicated docs/ file, single canonical reference for downstream phases | ✓ |
| In CONTRIBUTING.md | Fold into CONTRIBUTING — mixes contribution guide with structure spec | |
| Repo-root CONVENTIONS.md | Top-level file — clutters root, collides with .planning/codebase/CONVENTIONS.md | |

**User's choice:** docs/SKILL-STRUCTURE.md

| Option | Description | Selected |
|--------|-------------|----------|
| Retire old skill.json only | Delete root skill.json now (superseded by plugin.json); leave other legacy for Phase 4/5 | ✓ |
| Leave all legacy untouched | Touch nothing legacy — risks two-manifest validation ambiguity | |
| Retire all legacy now | Delete skill.json + owasp-css + comprehensive md + install.sh — overreaches, Phase 4 needs final content first | |

**User's choice:** Retire old skill.json only
**Notes:** owasp-css.instructions.md, owasp-comprehensive-security-skills.md, and install.sh stay for Phase 4/5; install.sh still gets the example-check patch from the examples decision.

---

## Claude's Discretion

- Exact plugin.json / marketplace.json field names, ordering, and required-vs-optional structure — to be resolved against the official Claude Code plugin spec during research/planning.
- Precise structure and wording of docs/SKILL-STRUCTURE.md.

## Deferred Ideas

None — discussion stayed within phase scope.
