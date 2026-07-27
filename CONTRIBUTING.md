# Contributing to OWASP-Security-Skills

Thanks for considering a contribution! This project is a community-driven
resource that packages OWASP-aligned security guidance as a Claude Code
plugin — two skills (`owasp-security-audit` and `secure-coding-practices`)
covering web apps, APIs, mobile, containers, and AI/LLM systems.

## Getting started

1. Fork the repository and clone your fork.
2. Create a new branch for your change: `git checkout -b fix-description`.
3. Add or improve skill content, examples, or documentation.
4. Run `git diff` to verify your changes.
5. Submit a Pull Request explaining the purpose of your update.

## Guidelines

- Keep skill reference files focused on one vulnerability category or standard.
- Use clear language and provide concrete code snippets where appropriate.
- Avoid copying large blocks directly from other projects; make content original and tailored.
- New examples belong in the relevant skill's `assets/examples/` directory
  (e.g. `skills/owasp-security-audit/assets/examples/` or
  `skills/secure-coding-practices/assets/examples/`) — there is no root-level
  `examples/` directory anymore.
- Ensure adequate examples exist for each standard: OWASP Top 10, ASVS, MASVS,
  API Security, Kubernetes, LLM, and Agentic Applications. LLM and Agentic
  Applications are two separate standards, each with its own reference file
  (`references/llm.md`, `references/agentic.md`) — do not conflate them.
- Keep documentation consistent: if adding new content, follow existing formatting patterns.
- The authoritative sources are each skill's `SKILL.md` (routing + workflow)
  and its `references/owasp-urls.json` (verified edition, source URL, and
  retrieval date per standard) — there is no single unified reference doc.
- Test activation triggers to ensure your new content is discoverable.

### Example-secret placeholder convention

Example code must never contain a value that looks like a real, valid
secret. Use obviously-fake, self-labeling placeholders that are structurally
recognizable as the pattern being taught but unmistakably fake to both a
human reader and automated secret scanners (GitHub push protection,
GitGuardian):

- API keys: `sk-EXAMPLE-not-a-real-key` or `sk-your-api-key-here`
- Passwords: `PLACEHOLDER_PASSWORD`

This is the single documented home for the convention — if you add or edit
an example containing a credential-shaped literal, use one of the forms
above (or an equally self-labeling variant) rather than inventing a
plausible-looking value.

## Maintenance & versioning

**`plugin.json`'s `version` field is the single canonical version source.**
No other file may declare a competing version number for this plugin.
`marketplace.json` intentionally carries no top-level or per-plugin
`version` key — Claude Code always resolves the plugin's version from
`.claude-plugin/plugin.json`. `scripts/check_version_drift.py` enforces this:
it reads `plugin.json` as canonical, asserts `marketplace.json` has no
disagreeing version key, and scans README.md for any badge or `Version:`
label that doesn't match. Run it before every release:

```bash
python3 scripts/check_version_drift.py --format text
```

OWASP edition numbers (e.g. MASVS `2.1.0`, ASVS `5.0.0`) are never flagged
as drift — the check only matches plugin-version-shaped tokens (a
shields.io `version-X.Y.Z` badge segment or an explicit `Version:` label),
never a blanket `X.Y.Z` grep.

### Cutting a release

1. Bump `"version"` in `.claude-plugin/plugin.json` (semantic versioning).
2. Update the version badge in `README.md` if present.
3. Run `python3 scripts/check_version_drift.py --format text` and
   `python3 scripts/lint_skill_md.py skills --format text` — both must pass.
4. Run `claude plugin validate .` — must exit 0.
5. Commit, tag, and push. GitHub Releases document what changed for that
   version.

### Keeping OWASP content current

Each skill's `references/owasp-urls.json` records the verified edition,
official source URL, and retrieval date for every standard it cites. When an
OWASP standard publishes a new edition:

1. Verify the new edition against the official OWASP source — never rely on
   training-data recall for version numbers, category IDs, or control IDs.
2. Update the relevant `references/*.md` file's edition note and the
   corresponding entry in `owasp-urls.json` (new edition, source URL, new
   retrieval date).
3. Re-check every prose surface that mirrors that edition (README coverage
   matrix, `SKILL.md` descriptions) for consistency.
4. Re-run `python3 scripts/lint_skill_md.py skills --format text` to confirm
   both `SKILL.md` files still pass.

## Release & discoverability

`plugin.json` `keywords` and the `marketplace.json` plugin entry's
`category`/`keywords`/`tags` drive in-repo discoverability inside Claude
Code. GitHub repository topics are a separate, outward-facing surface on the
live public repo and are **not** set automatically by this project's
tooling — they must be applied manually by a maintainer with push access,
using the `gh` CLI:

```bash
gh repo edit --add-topic security \
  --add-topic owasp \
  --add-topic claude-code \
  --add-topic claude-code-plugin \
  --add-topic security-audit \
  --add-topic secure-coding \
  --add-topic top-10 \
  --add-topic asvs \
  --add-topic masvs \
  --add-topic kubernetes \
  --add-topic llm \
  --add-topic agentic \
  --add-topic api-security \
  --add-topic compliance \
  mfkocalar/OWASP-Security-Skills
```

These topic values mirror the `keywords`/`category`/`tags` already declared
in `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`. **A
maintainer must review and run this command manually** — it is a
documented deliverable, not something this project's workflow executes on
your behalf.

All contributions are subject to review; maintainers may ask for
revisions or clarifications.
