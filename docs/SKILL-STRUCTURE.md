# Skill Directory Structure

**Status:** Locked convention (D-07 / SC4)
**Scope:** This document fixes the directory/file *layout* every skill in this repo must follow. It does not cover naming style (filenames, variables, functions) — see `.planning/codebase/CONVENTIONS.md` for that.

This is the single canonical structure reference. Phases 2–4 of this milestone, and any future contributor adding or restructuring a skill, file content into this layout rather than renegotiating it.

## The Convention

Every skill directory under `skills/<skill-name>/` follows this layout:

```
skills/<skill-name>/
├── SKILL.md              # required — frontmatter (name + description) + skill body
├── references/            # required — standard-specific lookup docs
│   ├── *.md
│   └── *.json             # data files (e.g. owasp-urls.json) belong here too
├── scripts/                # optional — only present if the skill ships executable tooling
│   └── *.py / *.sh / ...
└── assets/
    └── examples/           # required — the skill's OWN canonical example files
```

### 1. `SKILL.md` (required, at skill directory root)

Every skill has exactly one `SKILL.md` at the root of its directory. Its frontmatter is two fields only:

- **`name`** — kebab-case, and **MUST exactly match the parent directory name**. This is not a display label; it is the skill's identity key.
- **`description`** — the long, trigger-rich activation text. This paragraph is the Agent Skills activation mechanism: it replaces the old `skill.json` keyword-trigger arrays entirely. There is no separate keywords/triggers field — activation detection is driven by this description matching the user's request.

*The two blocks below are verbatim excerpts of the live SKILL.md frontmatter.
`skills/owasp-security-audit/SKILL.md` and `skills/secure-coding-practices/SKILL.md`
are the sole authoritative source for these skill descriptions — if either
`description:` line changes, these excerpts must be updated in lockstep.*

Real example (`skills/owasp-security-audit/SKILL.md`, first 3 lines):

```yaml
---
name: owasp-security-audit
description: Perform OWASP-aligned security audits of source code, API handlers, mobile apps, Kubernetes manifests, LLM/agent code, and deployment configuration. Covers the OWASP Top 10 (2025), ASVS 5.0.0 (V1-V17 chapter numbering), MASVS, API Security Top 10 (2023), Kubernetes Top 10 (2022), and the OWASP LLM Top 10 (2025) plus Agentic Applications Top 10 (2026). Use this skill whenever the user asks for a security review, vulnerability audit, threat assessment, compliance check, or hardening guidance — including indirect phrasings like "is this login flow secure?", "review this endpoint", "audit my pod spec", "what could go wrong with this prompt?", or when the user pastes auth, crypto, SQL, RBAC, or LLM-tool-calling code without explicitly asking for security review.
---
```

Second confirming example (`skills/secure-coding-practices/SKILL.md`, first 3 lines) shows the same two-field shape:

```yaml
---
name: secure-coding-practices
description: Audit code against a 14-domain secure coding checklist derived from OWASP's living sources — the Developer Guide, Cheat Sheet Series, and Proactive Controls — with the original OWASP Secure Coding Practices Quick Reference Guide noted only as the archived historical origin. Covers 14 critical domains including input validation, output encoding, authentication, session management, access control, cryptographic practices, error handling & logging, data protection, communication security, system configuration, database security, file management, memory management, and general coding practices. Triggers on requests like "review this code for secure practices", "audit for SCP compliance", "check if this follows secure coding", or when examining code with data handling, authentication, database queries, file operations, or system configuration without explicit security context.
---
```

Below the frontmatter, `SKILL.md` contains the skill's narrative body (workflow steps, "when this skill applies" guidance, etc.).

### 2. `references/` (required)

Holds standard-specific lookup docs the skill's workflow loads while auditing: markdown files organized by standard/domain, plus any JSON data files (e.g. `owasp-urls.json`). These are read-only lookup indices — never generated or modified during a review.

### 3. `scripts/` (optional)

Present only when a skill ships executable tooling. Today, only `owasp-security-audit` has one: `scripts/quick_scan.py`, a regex-based lead scanner. `secure-coding-practices` has no `scripts/` directory, and that is correct — this subdirectory is not mandatory.

### 4. `assets/examples/` (required — self-contained, no cross-references)

Each skill owns its **own** canonical example files under `assets/examples/`. Two hard rules apply (D-05 / PKG-03):

- **No symlinks.** Every file under `assets/examples/` is a plain file, not a symlink to a file elsewhere in the repo (or elsewhere on disk).
- **No cross-skill or cross-directory references.** A skill never points into another skill's `assets/examples/`, and no skill points back at a shared root-level `examples/` directory. Each skill's `assets/examples/` is the sole canonical source of truth for its own examples — this is what enables a clean, self-contained copy when the skill is installed.

## Naming

Directory and file naming (kebab-case, security-focused descriptive names) is governed by `.planning/codebase/CONVENTIONS.md` — this document does not duplicate those rules. It is scoped strictly to directory/file *layout*.

## Placement Rule: skills/ Lives at Plugin Root

`skills/` (and, if/when added, `commands/`, `agents/`, `hooks/`) live at the **plugin root** — i.e. `skills/<skill-name>/`, siblings of `.claude-plugin/`, `README.md`, etc. They are never nested inside `.claude-plugin/`.

Only two files belong inside `.claude-plugin/`:

- `.claude-plugin/plugin.json` — plugin identity manifest
- `.claude-plugin/marketplace.json` — marketplace catalog listing

`.claude-plugin/` is a manifest-only directory. It does not contain skill content.

## Worked Example: Both Skills' Real Directory Trees

These are the verified, on-disk trees of both skills in this repo — the literal worked example for the convention above.

```
skills/owasp-security-audit/
├── SKILL.md                        # frontmatter: name + description (activation trigger)
├── references/
│   ├── top10.md
│   ├── asvs.md
│   ├── masvs.md
│   ├── api-top10.md
│   ├── kubernetes-top10.md
│   ├── llm.md
│   ├── agentic.md
│   ├── vulnerable-patterns.md
│   └── owasp-urls.json
├── scripts/
│   └── quick_scan.py
└── assets/
    └── examples/                   # 9 canonical files (sole source of truth)
        ├── api-auth-bypass.js
        ├── broken-access-control.py
        ├── cryptographic-failures.js
        ├── injection.js
        ├── k8s-rbac.yaml
        ├── logging-monitoring-failures.py
        ├── prompt-injection.txt
        ├── security-misconfiguration.py
        └── xss.html

skills/secure-coding-practices/
├── SKILL.md
├── secure-coding-practices.md
├── README.md
├── references/
│   ├── scp-checklist.md
│   ├── secure-patterns.md
│   └── owasp-urls.json
└── assets/
    └── examples/                   # 2 canonical files (sole source of truth)
        ├── vulnerable-examples.js
        └── vulnerable-examples.py
```

Note that `secure-coding-practices` has no `scripts/` directory — confirming that subdirectory is optional, not required, per rule 3 above.

## Verified Compliance (PKG-03)

The structural invariants below were checked against the live repository and are recorded here so a future phase can re-run the exact same checks without re-deriving them.

**Check 1 — No symlinks anywhere in the skills tree:**

```bash
find skills -type l
```

Expected/actual result: empty output (no lines). Confirmed — zero symlinks exist under `skills/`. All example files are plain-file copies.

**Check 2 — Both skill directories sit at plugin root, not inside `.claude-plugin/`:**

```bash
find skills -maxdepth 1 -type d
```

Expected/actual result: `skills`, `skills/owasp-security-audit`, `skills/secure-coding-practices`. Confirmed — both directories are direct children of `skills/`, itself a plugin-root sibling of `.claude-plugin/`. Neither skill directory is nested inside `.claude-plugin/`.

**Check 3 — Each skill owns its own `assets/examples/` with the expected file counts:**

```bash
ls skills/owasp-security-audit/assets/examples | wc -l
ls skills/secure-coding-practices/assets/examples | wc -l
```

Expected/actual result: `9` and `2` respectively. Confirmed — `owasp-security-audit/assets/examples/` contains its 9 canonical files (api-auth-bypass.js, broken-access-control.py, cryptographic-failures.js, injection.js, k8s-rbac.yaml, logging-monitoring-failures.py, prompt-injection.txt, security-misconfiguration.py, xss.html); `secure-coding-practices/assets/examples/` contains its 2 canonical files (vulnerable-examples.js, vulnerable-examples.py). No file appears in both directories — each skill's example set is fully self-contained.

**Conclusion:** PKG-03's structural invariants — skills at plugin root, no symlinks, per-skill canonical examples — are satisfied by the current repository state as of this check.
