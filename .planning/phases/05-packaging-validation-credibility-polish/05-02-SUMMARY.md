---
phase: 05-packaging-validation-credibility-polish
plan: 02
subsystem: docs
tags: [security-examples, secret-scanning, credential-hygiene]

# Dependency graph
requires:
  - phase: 04-skill-md-conversion-legacy-retirement
    provides: relabeled/re-validated example files at their current 2025/2026 category IDs and canonical assets/examples/ paths
provides:
  - Self-labeling placeholder convention (D-10) applied to every plausible-looking secret literal across both skills' example files
affects: [05-packaging-validation-credibility-polish (README/CONTRIBUTING convention documentation), future example-authoring phases]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Self-labeling fake secrets: sk-EXAMPLE-not-a-real-key / sk-your-api-key-here for API keys, PLACEHOLDER_PASSWORD for passwords — structurally recognizable as the anti-pattern but unmistakably fake to humans and secret scanners"

key-files:
  created: []
  modified:
    - skills/owasp-security-audit/assets/examples/k8s-rbac.yaml
    - skills/owasp-security-audit/assets/examples/cryptographic-failures.js
    - skills/owasp-security-audit/assets/examples/prompt-injection.txt
    - skills/secure-coding-practices/assets/examples/vulnerable-examples.py
    - skills/secure-coding-practices/assets/examples/vulnerable-examples.js

key-decisions:
  - "Extended scope to password-like literals (not just sk-... API keys) per plan's explicit Pitfall #5 in-scope instruction, including admin123 in vulnerable-examples.js adminCredentials object"
  - "Left JWT_SECRET = \"super-secret-key-do-not-share\" in vulnerable-examples.js untouched — already self-labeling/obviously-fake and outside the plan's offender table, so no edit was needed"

patterns-established:
  - "Self-labeling placeholder convention (D-10): sk-EXAMPLE-not-a-real-key / sk-your-api-key-here for keys, PLACEHOLDER_PASSWORD for passwords"

requirements-completed: [QUAL-03]

coverage:
  - id: D1
    description: "All plausible-looking API-key and password literals in the 5 shipped example files normalized to self-labeling placeholders, with the vulnerable/secure teaching comments preserved"
    requirement: "QUAL-03"
    verification:
      - kind: other
        ref: "grep -rnE 'sk-[A-Za-z0-9]{10,}[^-]|password\\s*[:=]\\s*[\"'][A-Za-z][A-Za-z0-9]{6,}[\"']' skills/*/assets/examples -> NO_REAL_LOOKING_SECRETS_REPO_WIDE"
        status: pass
      - kind: other
        ref: "node --check skills/owasp-security-audit/assets/examples/cryptographic-failures.js"
        status: pass
      - kind: other
        ref: "node --check skills/secure-coding-practices/assets/examples/vulnerable-examples.js"
        status: pass
      - kind: other
        ref: "python3 -m py_compile skills/secure-coding-practices/assets/examples/vulnerable-examples.py"
        status: pass
    human_judgment: false

# Metrics
duration: 6min
completed: 2026-07-27
status: complete
---

# Phase 5 Plan 2: Example Secret Normalization Summary

**Self-labeling placeholder convention (D-10/QUAL-03) applied to every plausible-looking API-key and password literal across both skills' shipped example files, preserving the vulnerable/secure teaching intent.**

## Performance

- **Duration:** 6 min
- **Started:** 2026-07-27T13:26:00Z
- **Completed:** 2026-07-27T13:32:00Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- All `sk-...`-shaped fake-but-realistic API key literals across both skills replaced with `sk-EXAMPLE-not-a-real-key` (matching the pre-existing good exemplar `API_KEY=sk-your-api-key-here` in `cryptographic-failures.js`)
- All plausible password literals (`MySecurePassword123!`, `MySecurePassword123`, `MyDatabasePassword123`, `admin123`) replaced with `PLACEHOLDER_PASSWORD`, including the SCP-skill `admin123` default-credentials example (Pitfall #5 scope extension)
- Every edited line kept its original teaching comment (`# DANGEROUS: Plaintext in YAML`, `// Hardcoded!`, `# EXPOSED!`, `# In source code!`, `// CRITICAL: ...`, `// Default password!`) so the hardcoded-secret anti-pattern still reads clearly
- Repo-wide verification grep now returns zero non-placeholder matches across `skills/*/assets/examples`

## Task Commits

Each task was committed atomically:

1. **Task 1: Normalize secrets in owasp-security-audit example files (D-10 / QUAL-03)** - `4ace73e` (fix)
2. **Task 2: Normalize secrets in secure-coding-practices example files (D-10 / QUAL-03 + Pitfall #5)** - `f2cf4a7` (fix)

**Plan metadata:** pending (docs: complete plan)

## Files Created/Modified
- `skills/owasp-security-audit/assets/examples/k8s-rbac.yaml` - `database_password` → `PLACEHOLDER_PASSWORD`, `api_key` → `sk-EXAMPLE-not-a-real-key`
- `skills/owasp-security-audit/assets/examples/cryptographic-failures.js` - hardcoded `api_key` literal → `sk-EXAMPLE-not-a-real-key`
- `skills/owasp-security-audit/assets/examples/prompt-injection.txt` - illustrative leaked-API-key comment string → `sk-EXAMPLE-not-a-real-key`
- `skills/secure-coding-practices/assets/examples/vulnerable-examples.py` - `API_KEY` → `sk-EXAMPLE-not-a-real-key`, `DB_PASSWORD` → `PLACEHOLDER_PASSWORD`
- `skills/secure-coding-practices/assets/examples/vulnerable-examples.js` - `API_KEY` → `sk-EXAMPLE-not-a-real-key`, `DB_PASSWORD` → `PLACEHOLDER_PASSWORD`, `adminCredentials.password` (`admin123`) → `PLACEHOLDER_PASSWORD`

## Decisions Made
- Extended normalization to password-like literals in addition to API-key literals, per the plan's explicit Pitfall #5 in-scope instruction — includes `admin123` in the SCP-skill's `adminCredentials` default-credentials example.
- Left `JWT_SECRET = "super-secret-key-do-not-share"` (vulnerable-examples.js line 86) unmodified: it is already self-labeling/obviously-fake and was not listed in 05-PATTERNS.md's offender table or the plan's task scope, so touching it would be scope creep beyond D-10's enumerated offenders.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- All 5 example files verified to still parse (`node --check` x2, `python3 -m py_compile` x1) and still teach the hardcoded-secret anti-pattern via preserved comments.
- Repo-wide secret-literal grep confirms zero real-looking secrets remain in `skills/*/assets/examples`, closing the QUAL-03 gap ahead of the phase's README/CONTRIBUTING convention-documentation work (D-10 documentation, still owned by other plans in this phase).
- No blockers for remaining Phase 5 plans (01 already complete; 03/04/05 pending).

---
*Phase: 05-packaging-validation-credibility-polish*
*Completed: 2026-07-27*

## Self-Check: PASSED

All 5 modified example files found on disk; both task commits (`4ace73e`, `f2cf4a7`) found in git log.
