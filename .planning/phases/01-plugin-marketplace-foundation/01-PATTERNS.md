# Phase 1: Plugin/Marketplace Foundation - Pattern Map

**Mapped:** 2026-07-19
**Files analyzed:** 6 (2 create + 1 create-doc + 2 modify + 2 delete groups)
**Analogs found:** 4 / 6 (2 have no direct codebase analog — schema is external/official)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `.claude-plugin/plugin.json` | config | request-response (loaded by Claude Code plugin loader) | root `skill.json` (retiring) | anti-pattern-reference only — do NOT copy structure, only reuse verified identity values |
| `.claude-plugin/marketplace.json` | config | request-response (loaded by Claude Code marketplace resolver) | none in repo | no analog — official schema from RESEARCH.md only |
| `docs/SKILL-STRUCTURE.md` | config/doc | transform (documents existing convention) | `skills/owasp-security-audit/` + `skills/secure-coding-practices/` directory layout, `.planning/codebase/CONVENTIONS.md` | exact — convention already exists on disk, this file formalizes it |
| `install.sh` (MODIFY) | utility/config | file-I/O (verification script) | itself (patch in place) | exact — same file, patch 3 locations |
| `README.md` (MODIFY) | config/doc | transform (doc links) | itself (patch in place) | exact — same file, patch 11 spots |
| `skill.json` (DELETE), `examples/` (DELETE) | config/asset | n/a (removal) | n/a | n/a |

## Pattern Assignments

### `.claude-plugin/plugin.json` (config, request-response)

**Analog:** root `skill.json` — for identity-field values ONLY (name lineage, author, license, repository), NOT for structure. `skill.json` is being deleted this phase (D-08) precisely because its custom schema (`standards`, `activation`, `functionality`, `models`, `performance`, `metadata`, `examples_by_category`, `deployment`, `changelog`, `roadmap`) is not part of the official plugin schema — none of that should be ported (D-03).

**What to reuse from `skill.json`** (lines 1-13, current file):
```json
{
  "name": "Comprehensive OWASP Security Skill",
  "version": "1.1.0",
  "description": "Security reference covering six OWASP standards ...",
  "author": "Security Education Community",
  "license": "MIT",
  "repository": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "keywords": [ "security", "owasp", "top-10", "asvs", "masvs", "api-security",
    "kubernetes", "llm-security", "secure-coding-practices", "secure-development",
    "vulnerability-assessment", "code-review" ]
}
```
Reusable values: `author` string → becomes `author: {"name": "Security Education Community"}` (object shape required by official schema, not a bare string); `license: "MIT"`; `repository` URL (also usable for `homepage`); a trimmed `keywords` subset. Do NOT reuse: `version` (D-02 resets to `0.1.0`, breaking the 1.1.0 lineage on purpose), `name` (schema requires kebab-case plugin name `owasp-security-skills`, not the old Title Case display string — that becomes `displayName` instead), and none of the standards/activation/functionality/models/performance/metadata/examples_by_category/deployment/changelog/roadmap blocks.

**No structural analog exists in-repo** — RESEARCH.md's "Code Examples" section has the confirmed, `[CITED]` complete schema-correct example to use verbatim as the target shape:
```json
{
  "$schema": "https://json.schemastore.org/claude-code-plugin-manifest.json",
  "name": "owasp-security-skills",
  "displayName": "OWASP Security Skills",
  "version": "0.1.0",
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "author": { "name": "Security Education Community" },
  "homepage": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "repository": "https://github.com/mfkocalar/OWASP-Security-Skills",
  "license": "MIT",
  "keywords": ["security", "owasp", "top-10", "asvs", "masvs", "secure-coding"]
}
```

---

### `.claude-plugin/marketplace.json` (config, request-response)

**Analog:** none in repo (first marketplace file this project has ever had).

**Source pattern:** RESEARCH.md's confirmed `[CITED: code.claude.com/docs/en/plugin-marketplaces]` schema — self-hosted single-plugin marketplace pointing back at its own GitHub repo:
```json
{
  "$schema": "https://json.schemastore.org/claude-code-marketplace.json",
  "name": "owasp-security-skills",
  "owner": { "name": "Security Education Community" },
  "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code.",
  "plugins": [
    {
      "name": "owasp-security-skills",
      "source": { "source": "github", "repo": "mfkocalar/OWASP-Security-Skills" },
      "description": "OWASP-aligned security audit and secure-coding-practices skills for Claude Code."
    }
  ]
}
```
Confirmed GitHub remote (from RESEARCH.md `git config` check): `mfkocalar/OWASP-Security-Skills`. Do NOT set `version` in the marketplace entry (plugin.json's version silently wins per resolution order — RESEARCH.md "Version resolution order"). Confirm `owasp-security-skills` (or chosen name) is not in the reserved-names list before finalizing.

---

### `docs/SKILL-STRUCTURE.md` (config/doc, transform)

**Analog:** the two existing skill directories already embody the convention this doc must describe. Use their on-disk layout as the literal example to document (verified via `find`, current state):

```
skills/owasp-security-audit/
├── SKILL.md                        # frontmatter: name + description (activation trigger)
├── owasp-security-audit.md         # supplementary narrative doc
├── references/
│   ├── top10.md
│   ├── asvs.md
│   ├── masvs.md
│   ├── api-top10.md
│   ├── kubernetes-top10.md
│   ├── llm-agentic.md
│   ├── vulnerable-patterns.md
│   └── owasp-urls.json
├── scripts/
│   └── quick_scan.py
└── assets/
    └── examples/                   # 9 canonical files (post D-05, sole source of truth)

skills/secure-coding-practices/
├── SKILL.md
├── secure-coding-practices.md
├── README.md
├── references/
│   ├── scp-checklist.md
│   ├── secure-patterns.md
│   └── owasp-urls.json
└── assets/
    └── examples/                   # 2 canonical files
```

**SKILL.md frontmatter pattern to cite** (`skills/owasp-security-audit/SKILL.md` lines 1-3):
```yaml
---
name: owasp-security-audit
description: Perform OWASP-aligned security audits of source code, API handlers, mobile apps, Kubernetes manifests, LLM/agent code, and deployment configuration. Covers the OWASP Top 10 (2021), ASVS 5.0, MASVS, API Security Top 10 (2023), Kubernetes Top 10 (2022), and the OWASP LLM Top 10 (2025) plus Agentic Applications Top 10 (2026). Use this skill whenever the user asks for a security review...
---
```
Second confirming example, `skills/secure-coding-practices/SKILL.md` lines 1-3, shows the same two-field frontmatter shape (`name` kebab-case matching directory name; `description` is a long, trigger-rich paragraph — this is the Agent Skills activation mechanism, confirmed in RESEARCH.md as replacing `skill.json`'s old keyword-trigger arrays).

**Convention document should assert (per D-07/SC4):**
1. `SKILL.md` is required at the skill directory root, frontmatter `name` (kebab-case, matches directory name) + `description` (activation trigger text).
2. `references/` holds standard-specific lookup docs (markdown + any JSON data files like `owasp-urls.json`).
3. `scripts/` is optional, only present when a skill ships executable tooling (only `owasp-security-audit` currently has one: `quick_scan.py`).
4. `assets/examples/` holds the skill's own canonical example files — no cross-skill or cross-directory references, no symlinks (D-05, PKG-03).
5. Cross-reference `.planning/codebase/CONVENTIONS.md` for naming (kebab-case filenames) rather than duplicating it — this doc is scoped to directory/file layout, not naming style.

**Existing near-analog for doc structure/tone:** `.planning/codebase/CONVENTIONS.md` (referenced in CONTEXT.md/RESEARCH.md as the sibling doc to avoid colliding with) — read it if present to match heading style and avoid duplicating naming-convention content.

---

### `install.sh` (utility/config, file-I/O) — MODIFY in place

**Analog:** itself. Three exact patch locations, confirmed by direct read this session:

**Patch 1 — `required_files` array** (current lines 83-88):
```bash
local required_files=(
    "owasp-comprehensive-security-skills.md"
    "owasp-css.instructions.md"
    "README.md"
    "skill.json"
)
```
Action: remove the `"skill.json"` line entirely (D-08 deletes that file; leaving the entry causes every future `install.sh` run — including the "test only" option 4 — to report `skill.json (missing)` and exit 1).

**Patch 2 — examples count check** (current lines ~99-105):
```bash
    # Check examples directory
    local example_count=$(find "${install_dir}/examples" -type f | wc -l)
    if [ "$example_count" -ge 9 ]; then
        echo -e "  ${GREEN}✓${NC} examples/ ($example_count files)"
    else
        echo -e "  ${RED}✗${NC} examples/ (expected 9, found $example_count)"
        all_present=false
    fi
```
Action: repoint at a still-existing canonical examples location (e.g. `${install_dir}/skills/owasp-security-audit/assets/examples`, expect 9) or remove the check entirely if `install_dir` no longer guarantees that subpath exists after copy — planner's discretion, but the check must not reference the now-deleted root `examples/`.

**Patch 3 — cosmetic echo** (current line ~146, inside the `case $choice in 1)` block):
```bash
                echo "  3. Paste any example from examples/ folder"
```
Action: update wording to point at the new canonical per-skill examples path (or generic phrasing) since root `examples/` no longer exists.

---

### `README.md` (config/doc, transform) — MODIFY in place

**Analog:** itself. Exact current line numbers, confirmed by direct read this session:

**Structure diagram** (line 89):
```
examples/                                9 vulnerable/secure code samples
```
Action: update/remove this row — root `examples/` is deleted (D-05); reflect that examples now live under each skill's `assets/examples/`.

**Intro sentence** (line 97):
```
The [`examples/`](examples/) directory contains **9 code samples**, each pairing a
vulnerable pattern with a secure implementation and an explanation.
```
Action: repoint the `examples/` link and rewrite the sentence to describe the two per-skill example sets (9 in `owasp-security-audit`, 2 in `secure-coding-practices`).

**9 example links** (lines 102-110), each currently `examples/<file>` → repoint to `skills/owasp-security-audit/assets/examples/<file>` (same filenames, verified byte-identical per RESEARCH.md diff):
```
[broken-access-control.py](examples/broken-access-control.py)
[cryptographic-failures.js](examples/cryptographic-failures.js)
[injection.js](examples/injection.js)
[security-misconfiguration.py](examples/security-misconfiguration.py)
[xss.html](examples/xss.html)
[logging-monitoring-failures.py](examples/logging-monitoring-failures.py)
[api-auth-bypass.js](examples/api-auth-bypass.js)
[k8s-rbac.yaml](examples/k8s-rbac.yaml)
[prompt-injection.txt](examples/prompt-injection.txt)
```
Action: change each `examples/<file>` prefix to `skills/owasp-security-audit/assets/examples/<file>`. 11 total spots in README.md reference `examples/` (line 89, line 97, lines 102-110).

---

## Shared Patterns

### Official schema fidelity (plugin.json / marketplace.json)
**Source:** RESEARCH.md `[CITED]` sections — no in-repo analog; must follow the officially fetched schema verbatim, not adapted from `skill.json`'s custom shape.
**Apply to:** `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`.
Key rule: only `name` is hard-required in `plugin.json`; `name`/`owner`/`plugins` are hard-required in `marketplace.json`. Do not gate "done" on porting extra fields from the old `skill.json`.

### Directory placement rule
**Source:** RESEARCH.md architecture/anti-patterns section.
**Apply to:** `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `skills/` layout.
Rule: `skills/`, `commands/`, `agents/`, `hooks/` must stay at plugin root, never nested inside `.claude-plugin/`. Both skill directories already comply (verified via `find`).

### Kebab-case naming
**Source:** `.planning/codebase/CONVENTIONS.md` (already-established repo convention).
**Apply to:** `plugin.json` `name`, `marketplace.json` `name`/`plugins[].name`, `docs/SKILL-STRUCTURE.md` filename itself.

### No-symlink, per-skill-canonical assets
**Source:** verified via `find skills -type l` (empty result, confirmed no symlinks exist).
**Apply to:** example file handling for D-05 — plain-file copies only, `skills/owasp-security-audit/assets/examples/` (9 files) and `skills/secure-coding-practices/assets/examples/` (2 files) are each self-contained.

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `.claude-plugin/marketplace.json` | config | request-response | First marketplace file in this repo's history — no local precedent; use RESEARCH.md's `[CITED]` official schema example directly |
| `.claude-plugin/plugin.json` (structural shape) | config | request-response | `skill.json` is a structural anti-pattern reference, not a shape to copy — only specific field *values* (author, license, repository) transfer; the containing object shape must follow the official schema from RESEARCH.md |

## Metadata

**Analog search scope:** repo root (`skill.json`, `install.sh`, `README.md`), `skills/owasp-security-audit/`, `skills/secure-coding-practices/`, `.planning/codebase/`
**Files scanned:** `skill.json`, `install.sh`, `README.md`, both `SKILL.md` files, both skill directory trees (via `find`)
**Pattern extraction date:** 2026-07-19
