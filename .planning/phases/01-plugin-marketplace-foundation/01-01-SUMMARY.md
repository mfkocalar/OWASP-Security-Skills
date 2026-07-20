---
phase: 01-plugin-marketplace-foundation
plan: 01
subsystem: infra
tags: [claude-code-plugin, marketplace, packaging, json-schema]

# Dependency graph
requires: []
provides:
  - ".claude-plugin/plugin.json — official closed-schema plugin identity manifest (owasp-security-skills / 0.1.0)"
  - ".claude-plugin/marketplace.json — self-hosted single-plugin catalog with github source"
affects: [01-02, 01-03, phase-2-and-later-packaging-work]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Self-hosted single-plugin marketplace: one repo doubles as both the plugin (plugin.json) and the marketplace catalog (marketplace.json), catalog entry sources itself via a github object"
    - "plugin.json contains ONLY official closed-schema fields — no custom fields ported from legacy skill.json"

key-files:
  created:
    - .claude-plugin/plugin.json
    - .claude-plugin/marketplace.json
  modified: []

key-decisions:
  - "plugin.json version reset to 0.1.0 (D-02), intentionally breaking the old skill.json 1.1.0 lineage"
  - "plugin.json declares no component-path fields (skills/commands/agents/hooks/mcpServers) — both skills auto-discovered from default skills/ root, minimizing declared attack surface (T-01-02)"
  - "marketplace.json plugins[0] has no version key — plugin.json's 0.1.0 is authoritative per Claude Code's version-resolution order"
  - "marketplace name owasp-security-skills confirmed not on Anthropic's reserved-names list"

patterns-established:
  - "Official schema fidelity: manifests match the live-fetched Anthropic plugin/marketplace schema verbatim (01-RESEARCH.md), not adapted from the old skill.json shape"

requirements-completed: [PKG-01, PKG-02]

coverage:
  - id: D1
    description: ".claude-plugin/plugin.json exists with only official-schema fields, encodes owasp-security-skills / 0.1.0 identity, and passes claude plugin validate --strict"
    requirement: "PKG-01"
    verification:
      - kind: unit
        ref: "python3 json.tool + allowlist assertion (name/version/author shape check)"
        status: pass
      - kind: integration
        ref: "claude plugin validate . --strict"
        status: pass
    human_judgment: false
  - id: D2
    description: ".claude-plugin/marketplace.json exists, lists exactly one plugin via a github source object resolving to mfkocalar/OWASP-Security-Skills, and passes claude plugin validate --strict"
    requirement: "PKG-02"
    verification:
      - kind: unit
        ref: "python3 json.tool + allowlist/reserved-name/source-shape assertion"
        status: pass
      - kind: integration
        ref: "claude plugin validate . --strict"
        status: pass
    human_judgment: false

duration: 5min
completed: 2026-07-20
status: complete
---

# Phase 01 Plan 01: Plugin Identity + Marketplace Manifests Summary

**Authored `.claude-plugin/plugin.json` (owasp-security-skills / 0.1.0) and `.claude-plugin/marketplace.json` (self-hosted github-source catalog), both verified against the live-fetched official Claude Code plugin schema and passing `claude plugin validate . --strict`.**

## Performance

- **Duration:** 5 min
- **Started:** 2026-07-20T10:47:00Z
- **Completed:** 2026-07-20T10:52:00Z
- **Tasks:** 2
- **Files modified:** 2 (both new)

## Accomplishments
- `.claude-plugin/plugin.json` created with only official closed-schema fields (`$schema`, `name`, `displayName`, `version`, `description`, `author`, `homepage`, `repository`, `license`, `keywords`) — no legacy `skill.json` custom fields ported
- `.claude-plugin/marketplace.json` created listing exactly one plugin entry via a `github` source object pointing at `mfkocalar/OWASP-Security-Skills`
- `claude plugin validate . --strict` (CLI v2.1.201) confirmed available in this environment and exits 0 for both manifests — no manual-review fallback was needed

## Task Commits

Each task was committed atomically:

1. **Task 1: Create .claude-plugin/plugin.json (plugin identity manifest)** - `8d8ba80` (feat)
2. **Task 2: Create .claude-plugin/marketplace.json (catalog listing the plugin)** - `a6e8789` (feat)

**Plan metadata:** (pending — final docs commit, this SUMMARY + STATE/ROADMAP/REQUIREMENTS update)

## Files Created/Modified
- `.claude-plugin/plugin.json` - Plugin identity manifest: name=owasp-security-skills, version=0.1.0, displayName, description, author object, homepage/repository URLs, license, keywords. No component-path fields (skills auto-discovered from default `skills/`).
- `.claude-plugin/marketplace.json` - Marketplace catalog: name=owasp-security-skills, owner object, single plugin entry with a github source object (`repo: mfkocalar/OWASP-Security-Skills`), no version on the entry.

## Decisions Made
- Followed 01-RESEARCH.md's `[CITED]` schema examples verbatim rather than adapting the old `skill.json` structure — only identity *values* (author name, license, repository URL) were reused, not its shape (per D-03/01-PATTERNS.md).
- Confirmed `claude` CLI (v2.1.201) is available in this execution environment, so the machine-checkable `claude plugin validate . --strict` path was used directly rather than falling back to manual field-table review.

## Deviations from Plan

None - plan executed exactly as written. Both tasks' `<action>` and `<verify>` steps were followed as specified; no auto-fixes, no architectural questions, no auth gates encountered.

## Issues Encountered

None. One observational note (not a deviation): running `claude plugin validate . --strict` after both files existed printed only the marketplace manifest validation line in its output (not a duplicate line for plugin.json), but still exited 0 — consistent with the CLI validating the directory context that includes both manifests rather than emitting one line per file. Both manifests were independently confirmed valid via the JSON/allowlist assertions in each task's verify step before this combined run.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- PKG-01 and PKG-02 both satisfied; `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` exist at repo root and validate cleanly.
- Plan 01-02 and 01-03 (same phase, per ROADMAP wave structure) can now proceed — no blockers introduced by this plan.
- Legacy `skill.json` retirement (D-08) and root `examples/` deletion (D-05) are tracked in later plans of this phase, not this one; this plan only added the two new manifests and did not touch/delete any existing file.

---
*Phase: 01-plugin-marketplace-foundation*
*Completed: 2026-07-20*
