---
status: testing
phase: 03-remaining-standards-verification-refresh
source: [03-VERIFICATION.md]
started: "2026-07-22T14:30:00Z"
updated: "2026-07-22T14:30:00Z"
---

## Current Test

number: 1
name: Living-Source Crosswalk weak-anchor spot-check (SCP, CONT-05)
expected: |
  The two LOW-confidence anchors in the secure-coding-practices Living-Source
  Crosswalk are adequate (or a better anchor is identified). Both are already
  honestly labeled ASSUMED / cited-weak in scp-checklist.md and owasp-urls.json —
  this check confirms the labels are correct, it is not an accuracy regression.
    - File Management row → OWASP File Upload Cheat Sheet: confirm it genuinely
      covers the File Management domain's checklist controls.
    - Memory Management row → OWASP Developer Guide index: confirm this is the
      best available anchor, or identify a more specific one.
awaiting: user response

## Tests

### 1. Living-Source Crosswalk weak-anchor spot-check (SCP, CONT-05)
expected: |
  Open the two anchors and judge topical coverage:
    - File Management → OWASP File Upload Cheat Sheet covers the domain's controls.
    - Memory Management → OWASP Developer Guide index is the best available anchor
      (or note a better one).
  Both are pre-labeled ASSUMED / cited-weak; confirm the labels are honest and
  must not be silently upgraded to "verified" without this check.
result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
