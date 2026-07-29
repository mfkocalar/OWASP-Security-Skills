# Retrospective

Living retrospective across milestones. Newest milestone first.

## Milestone: v1.0 — OWASP Security Skills Modernization

**Shipped:** 2026-07-29 (PR #4, merged to `main`)
**Phases:** 5 | **Plans:** 20 (+ 1 gap-closure) | **Tasks:** ~42

### What Was Built

A mature two-skill repo turned into a credible, publicly distributable Claude Code plugin: `.claude-plugin/` manifests (plugin.json 1.0.0 + marketplace.json); OWASP Top 10 rewritten 2021 → 2025 (Final) by topic mapping; all remaining standards citation-hardened (ASVS 5.0.0/4.0.3-numbered, MASVS 2.1.0, API 2023, LLM 2025, Agentic 2026, K8s 2022) with sourced URLs + retrieval dates; `secure-coding-practices` re-anchored to living OWASP sources; both skills converted to spec-compliant `SKILL.md` with legacy routing/manifest files retired; root MIT LICENSE; honest README coverage matrix + "What this is NOT"; stdlib `check_version_drift.py` + `lint_skill_md.py`; example secrets normalized to self-labeling placeholders; end-to-end install validated.

### What Worked

- **Wave-based phase execution with per-phase verification** caught real gaps at the right boundary (e.g., the QUAL-01 `docs/SKILL-STRUCTURE.md` citation drift) instead of at ship time.
- **Topic-first Top 10 remapping** (not numeric substitution) avoided mislabeling categories that swapped numbers across the 2021→2025 edition change.
- **Independent verifier + security + Nyquist gates** each ran against the real codebase, not SUMMARY claims — the code review and verifier independently converged on the same WR-01/QUAL-01 finding.
- **Clean single-commit release branch** (content-only, `.planning`/`.claude` excluded) produced a professional public PR.

### What Was Inefficient

- **Sequential-executor premature completion**: with worktrees auto-degraded (HEAD diverged from unpushed origin), executors marked the phase complete in STATE.md/ROADMAP.md *before* verification each time — required manual reconciliation on the gaps-found pass.
- **State verbs partially no-op on this repo's prose STATE.md** (`state.planned-phase` did nothing) — needed hand-reconciliation.
- **The 74-commit filtered cherry-pick replay for the PR branch was fragile** — hit a conflict and stranded the branch; a `git read-tree` single-commit rebuild proved far more robust.
- **Credential friction at ship**: a fine-grained PAT lacking Contents/PR write blocked push + PR create until permissions were granted.

### Patterns Established

- Public release = clean content-only branch via `read-tree main` from `origin/main`, `.planning/`+`.claude/` gitignored.
- Every OWASP edition/ID claim traces to `owasp-urls.json` with a retrieval date.
- Deliberately-vulnerable teaching code and self-labeling placeholder secrets are intentional — never "fixed" by reviewers/auditors.

### Key Lessons

- On sequential-degrade runs here, always reconcile STATE.md/ROADMAP tracking against the *verifier's* verdict, not the executor's self-mark.
- Prefer a single `read-tree` rebuild over N-commit cherry-pick replays when producing a filtered branch.
- Confirm outward/irreversible steps (public push, force-update, credential changes) before acting.

### Cost Observations

- Model mix: orchestration on Opus; executors/verifier on Sonnet; plan-checker on Haiku; planner on Opus.
- Notable: per-phase verification gates prevented an incorrect "complete" from shipping.

## Cross-Milestone Trends

_(First milestone — trends accumulate from v1.1 onward.)_
