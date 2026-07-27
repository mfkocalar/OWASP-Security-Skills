---
phase: 05-packaging-validation-credibility-polish
plan: 01
subsystem: infra
tags: [claude-code-plugin, packaging, licensing, discoverability, stdlib-python]

# Dependency graph
requires:
  - phase: 01-plugin-marketplace-foundation
    provides: ".claude-plugin/plugin.json and marketplace.json already valid; version 0.1.0 reset to break legacy 1.1.0 lineage; marketplace carries no version key"
  - phase: 04-skill-md-conversion-legacy-retirement
    provides: "scripts/lint_skill_md.py's LintResult/soft-append/--format {json,text}/exit-code pattern as the reuse analog"
provides:
  - "LICENSE file at repo root (MIT, holder Security Education Community, year 2026)"
  - "plugin.json at version 1.0.0 as the single canonical version source"
  - "Extended discoverability metadata on plugin.json (keywords) and marketplace.json (category, keywords, tags)"
  - "scripts/check_version_drift.py — reusable stdlib-only drift-check enforcing no conflicting version string"
affects: [05-02, 05-03, 05-04, 05-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "DriftResult dataclass + soft-append-never-raise + --format {json,text} + sys.exit(main()) — same family as lint_skill_md.py's LintResult"
    - "Narrow version-token matching (badge/label regex) instead of blanket \\d+\\.\\d+\\.\\d+ grep, to avoid false-flagging OWASP edition numbers"

key-files:
  created:
    - LICENSE
    - scripts/check_version_drift.py
  modified:
    - .claude-plugin/plugin.json
    - .claude-plugin/marketplace.json

key-decisions:
  - "plugin.json version bumped 0.1.0 -> 1.0.0 as the single canonical version source (D-03/D-04/PKG-05); marketplace.json intentionally carries no version key"
  - "plugin.json keywords extended with kubernetes, llm, agentic, api-security (existing entries unchanged) to reflect actual standards coverage; no category/tags added to plugin.json (not in its closed schema)"
  - "marketplace.json plugins[0] gains category=security, an extended keywords array, and tags=[security-audit, code-review, compliance]; source stays github, unchanged"
  - "check_version_drift.py scans README.md by default for plugin-version-shaped tokens only (shields.io badge version-x.y.z, or an explicit Version: label line) — deliberately not a blanket X.Y.Z grep, so MASVS 2.1.0/ASVS 5.0.0 are never false-flagged"

patterns-established:
  - "Version-drift enforcement: plugin.json is canonical; any future version string added to README/docs must match it or the CI-equivalent script fails"

requirements-completed: [ADPT-01, PKG-05, ADPT-04]

coverage:
  - id: D1
    description: "MIT LICENSE at repo root matching plugin.json's declared license and author"
    requirement: "ADPT-01"
    verification:
      - kind: unit
        ref: "test -f LICENSE && grep -q 'MIT' LICENSE && grep -q 'Security Education Community' LICENSE && grep -q '2026' LICENSE"
        status: pass
    human_judgment: false
  - id: D2
    description: "plugin.json bumped to 1.0.0 as single canonical version source; no illegal category/tags fields added"
    requirement: "PKG-05"
    verification:
      - kind: unit
        ref: "python3 -c \"import json; p=json.load(open('.claude-plugin/plugin.json')); assert p['version']=='1.0.0'\""
        status: pass
      - kind: integration
        ref: "claude plugin validate ."
        status: pass
    human_judgment: false
  - id: D3
    description: "marketplace.json plugins[0] carries category/keywords/tags discoverability metadata; source and version-key absence unchanged"
    requirement: "ADPT-04"
    verification:
      - kind: unit
        ref: "python3 -c \"import json; m=json.load(open('.claude-plugin/marketplace.json')); assert m['plugins'][0]['category']=='security'; assert 'keywords' in m['plugins'][0]; assert 'tags' in m['plugins'][0]; assert m['plugins'][0]['source']['source']=='github'; assert 'version' not in m['plugins'][0]\""
        status: pass
    human_judgment: false
  - id: D4
    description: "scripts/check_version_drift.py: stdlib-only, exits 0 on the 1.0.0 repo, detects planted drift, ignores OWASP edition numbers"
    requirement: "PKG-05"
    verification:
      - kind: unit
        ref: "python3 scripts/check_version_drift.py (exit 0)"
        status: pass
      - kind: unit
        ref: "python3 -c \"import ast; ast.parse(open('scripts/check_version_drift.py').read())\" (stdlib-only import check)"
        status: pass
      - kind: manual_procedural
        ref: "planted version-9.9.9 badge token in README.md -> script exits 1; reverted, diff clean, MASVS v2.1.0 not flagged"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-27
status: complete
---

# Phase 05 Plan 01: Version, License & Discoverability Foundation Summary

**Bumped plugin.json to the single-canonical-source version 1.0.0, added the missing MIT LICENSE, extended discoverability metadata on both manifests, and shipped a stdlib-only `check_version_drift.py` that catches version-string drift while ignoring OWASP edition numbers.**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-27T13:12:20Z
- **Completed:** 2026-07-27T13:27:35Z
- **Tasks:** 3
- **Files modified:** 4 (1 new LICENSE, 1 new script, 2 manifest edits)

## Accomplishments
- Repo now has a real MIT LICENSE at root matching plugin.json's declared license and author, closing the "no LICENSE" credibility gap (ADPT-01).
- `plugin.json` is now the honest, single canonical version source at `1.0.0` — the first credible public-release version, deliberately not a continuation of the pre-modernization 1.1.0 lineage (PKG-05).
- Both manifests carry aligned, schema-correct discoverability metadata: `plugin.json` keywords extended (kubernetes, llm, agentic, api-security); `marketplace.json`'s single plugin entry gained `category: security`, an extended `keywords` array, and `tags` — with `source` and version-key-absence left untouched (ADPT-04).
- `scripts/check_version_drift.py` gives this repo forward-looking drift protection: any future version string added to README/docs that disagrees with `plugin.json.version` will fail the check, while OWASP edition numbers (MASVS 2.1.0, ASVS 5.0.0) are structurally exempt from false-positiving.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add MIT LICENSE at repo root** - `df0b360` (feat)
2. **Task 2: Bump version to 1.0.0 and set discoverability metadata** - `cda9c86` (feat)
3. **Task 3: Create scripts/check_version_drift.py** - `ebc8a61` (feat)

**Plan metadata:** pending (docs: complete plan — see final commit below)

_Note: Task 3 carries `tdd="true"` in the plan frontmatter, but this repo has no pytest/jest test framework (matching `lint_skill_md.py`'s own precedent of zero separate test files). The script's own soft-check output IS the test surface; RED/GREEN was exercised manually (see Deviations) rather than via a committed test file, since none was named in the plan's `files_modified` list._

## Files Created/Modified
- `LICENSE` - Standard MIT license text, holder "Security Education Community", year 2026
- `.claude-plugin/plugin.json` - version 0.1.0 -> 1.0.0; keywords extended with kubernetes, llm, agentic, api-security
- `.claude-plugin/marketplace.json` - plugins[0] gained category, keywords, tags; source/no-version-key unchanged
- `scripts/check_version_drift.py` - New stdlib-only drift-check tool (DriftResult dataclass, plugin-json/marketplace-json/scan-target checks, `--format {json,text}`, exit-code contract)

## Decisions Made
- Extended `plugin.json` keywords with `kubernetes`, `llm`, `agentic`, `api-security` (Claude's discretion per CONTEXT.md) — these are the standards the plugin actually covers that weren't yet represented.
- Mirrored the same extended keyword list onto `marketplace.json`'s plugin entry rather than a divergent list, to keep the two manifests' discoverability metadata consistent.
- Chose `tags: [security-audit, code-review, compliance]` for the marketplace entry, matching the illustrative schema example verified in 05-RESEARCH.md.
- Implemented `check_version_drift.py` as a new standalone file (not an extension of `lint_skill_md.py`) to keep that script's FMT-0x scope clean, per RESEARCH.md's "Alternatives Considered" — while reusing its dataclass/soft-append/CLI-contract shape verbatim in spirit.
- Scoped the version-token matcher to two narrow patterns (shields.io `badge/version-x.y.z` token and an explicit `Version:` label line) rather than a blanket `\d+\.\d+\.\d+` regex, specifically to avoid false-flagging OWASP edition numbers (MASVS 2.1.0, ASVS 5.0.0) as version drift — verified empirically against the current README.

## Deviations from Plan

None - plan executed exactly as written. Task 3's TDD framing was honored in spirit (write behavior, verify it fails-safe on drift, verify it doesn't false-positive) via manual command-line verification rather than a committed pytest-style test file, consistent with this repo having no test framework and `lint_skill_md.py` (the designated analog) having no separate test file either.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `plugin.json` version 1.0.0 and `check_version_drift.py` are now available for 05-02 (README refresh) to reference — the README's future version badge/text should be validated against this same script.
- Discoverability metadata (keywords/category/tags) is in place for 05-02/05-05's discoverability documentation work; the `gh repo edit --add-topic` command list (D-11, user-controlled) is still owed by a later plan in this phase.
- No blockers for 05-02 through 05-05.

---
*Phase: 05-packaging-validation-credibility-polish*
*Completed: 2026-07-27*
