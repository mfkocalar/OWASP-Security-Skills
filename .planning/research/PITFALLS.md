# Pitfalls Research

**Domain:** OWASP reference-content refresh + Agent Skills reformat + Claude Code marketplace packaging + public-adoption polish
**Researched:** 2026-07-19
**Confidence:** MEDIUM (cross-checked web sources on Anthropic/Claude Code specs and OWASP edition histories; no single-source HIGH-confidence citation available for a private research corpus, but all claims below were corroborated across 2+ independent sources)

## Critical Pitfalls

### Pitfall 1: Mixing edition numbering when only some standards are refreshed

**What goes wrong:**
OWASP Top 10:2025 (final, Jan 2026) renumbered categories relative to 2021: Security Misconfiguration moved from A05 to A02, SSRF was *folded into* Broken Access Control (A01:2025) rather than kept standalone, and two new categories appeared — A03 Software Supply Chain Failures and A10 Mishandling of Exceptional Conditions. ASVS 5.0 similarly renumbered chapters (Architecture & Design moved V1→V15; V10 Malicious Code no longer exists as a standalone chapter). If the repo updates the *labels* ("Top 10 2025") but leaves old category IDs (A04 Insecure Design, A06 Vulnerable Components, A08 Software/Data Integrity, A10 SSRF — the exact four gaps already flagged in CONCERNS.md) untouched in examples, cross-references, and `owasp-urls.json`, the collection ends up internally inconsistent: title says 2025, body still argues 2021 taxonomy.

**Why it happens:**
Teams update the version string in one place (skill.json / README) as a quick "looks refreshed" win without re-deriving every downstream mapping (example files, reference `.md` category tables, `owasp-urls.json` anchors, quick_scan.py regex categories). Because the old and new numbering both use "A0N" syntax, a stale reference *looks* plausible even when it points at the wrong risk.

**How to avoid:**
Treat each OWASP standard as an atomic unit: for every edition bump, regenerate the full ID→name→description mapping table from the *official* OWASP source first, diff it against the existing repo mapping, and only then touch prose. Use OWASP's own migration/mapping artifacts where they exist (e.g., ASVS ships an official 4.0.3→5.0 JSON mapping) instead of hand-translating.

**Warning signs:**
- Any file where the standard's declared version in a heading disagrees with the version implied by the category IDs used in body text
- `grep -r "A0[0-9]"` across the repo returns IDs that don't appear in the *newest* official list
- Example files reference a category name that was renamed/merged/split in the new edition

**Phase to address:** version-refresh

---

### Pitfall 2: Citing a Release Candidate as final (or vice versa) because "latest" is ambiguous mid-cycle

**What goes wrong:**
OWASP editions ship as RCs before finalization — OWASP Top 10:2025 had an RC1 (Nov 6, 2025) that was "almost final" but still open for community feedback before the true final release (Jan 2026). A refresh done during that window risks baking in RC-only wording, numbering, or category names that shifted slightly before final publication. The reverse failure also happens: treating a still-draft/RC standard as authoritative and citing it with unqualified "final" language, which is itself a credibility risk for a public security reference.

**Why it happens:**
Search results and blog recaps rarely distinguish RC from final in their titles, and OWASP's own project pages sometimes host both under similar URLs during the transition period. An agent (or human) doing a quick pass over search results can easily grab the RC snapshot.

**How to avoid:**
For every standard being refreshed, verify against the canonical OWASP page/repo (owasp.org/Top10/, github.com/OWASP/ASVS releases, mas.owasp.org) and record the exact publication status (Final / RC / Draft) and date next to the version number in the source-of-truth table. If a standard is still RC at time of refresh, either explicitly label it "RC" in the repo or defer that standard's refresh to the next cycle — never silently present RC content as final.

**Warning signs:**
- Version claims sourced only from third-party blog summaries, not the OWASP project's own repo/site
- No recorded "as of" date next to a version claim
- A standard whose edition year matches the current year (higher chance of being mid-cycle)

**Phase to address:** version-refresh

---

### Pitfall 3: Bloated SKILL.md that eats context and defeats progressive disclosure

**What goes wrong:**
The existing `owasp-comprehensive-security-skills.md` is ~900 lines covering 6 standards and 60+ patterns in one monolithic file (flagged in CONCERNS.md). A naive "conversion" to Agent Skills format just renames this file to `SKILL.md` and keeps everything inline, or reproduces every OWASP category's full detail directly in the skill body instead of `references/`. Since Claude loads the *entire* SKILL.md body into context the moment the skill activates (tier 2 of the 3-tier progressive-disclosure model — name+description, then full body, then reference files), an oversized SKILL.md consumes context budget on every activation even when only one standard (e.g., just K8s Top 10) is relevant to the user's request.

**Why it happens:**
It's the path of least resistance during a refresh: existing content already exists as one file, and restructuring into per-standard reference files with a thin SKILL.md router is more work than a straight copy.

**How to avoid:**
Keep SKILL.md to a short router: what the skill does, when to use it, and a table of contents pointing to `references/top10.md`, `references/asvs.md`, etc. (the repo already has this structure under `skills/owasp-security-audit/references/` — the fix is disciplining what stays in SKILL.md vs. what moves to references, not inventing new structure). Keep reference files one level deep — a reference file should not itself point to another reference file, or agents get lost in a documentation tree.

**Warning signs:**
- SKILL.md line count grows during the refresh instead of shrinking
- SKILL.md contains full category tables/checklists rather than pointers to `references/*.md`
- Any `references/*.md` file that itself links out to a third-level reference file

**Phase to address:** reformat

---

### Pitfall 4: Weak or overlapping `description` fields break auto-activation across 17 skills

**What goes wrong:**
The Agent Skills spec caps `description` at 1024 characters and requires it to state both *what* the skill does and *when* to use it — description quality directly drives auto-activation, since only name+description are loaded at discovery time. This repo has ~17 skills (2 OWASP-specific + 15 cyber-domain skills like `08-network-security`, `06-threat-hunting`, `13-crypto-analysis`) whose scope overlaps heavily (e.g., a "review this API auth code" prompt plausibly matches `owasp-security-audit`, `09-web-security`, and `secure-coding-practices` simultaneously). The current `skill.json`'s 66+ keyword list (flagged in CONCERNS.md as "activation trigger brittleness") is exactly the anti-pattern the Agent Skills description field is meant to replace — porting it verbatim as a giant keyword dump into `description` wastes the character budget on redundant synonyms instead of clear differentiation between skills.

**Why it happens:**
Teams write descriptions that describe the skill "elegantly" (what it covers) rather than competitively (when *specifically* to reach for this skill over a sibling skill). With many skills in one collection, this produces either over-triggering (multiple skills fire, confusing output) or never-triggering (none of the descriptions is specific enough to win activation).

**How to avoid:**
Write each skill's description as a boundary statement relative to its siblings, not just a topic summary — e.g., `owasp-security-audit` should explicitly claim "structured, standards-cited audits against Top 10/ASVS/MASVS/API/K8s/Agentic" while `secure-coding-practices` claims "checklist-driven review against the 14-domain SCP guide," so the two don't compete for the same generic "review my code for security" prompt. Test activation with the exact ambiguous prompts already documented in `TESTING.md` sections 3.1–3.6 and confirm the *intended* skill wins, not just *a* skill.

**Warning signs:**
- Two or more skill descriptions both plausibly match the same sample prompt from TESTING.md
- A description under 100 characters (likely too generic to differentiate)
- Descriptions written as prose about the domain rather than trigger conditions

**Phase to address:** reformat

---

### Pitfall 5: Losing the old instructions file's routing behavior in the conversion

**What goes wrong:**
`owasp-css.instructions.md` (Copilot-style) and the current `skill.json` currently do double duty: they don't just describe content, they *route* — deciding which of the 6+ standards' worth of guidance to surface for a given request. Converting to native Agent Skills format per-skill (one `SKILL.md` per skill) risks losing this cross-skill routing logic entirely, because the official format has no equivalent "if request mentions Kubernetes, prefer references/kubernetes-top10.md over references/top10.md" concept inside a single skill — that logic has to be re-expressed as SKILL.md's own internal guidance to the model about which reference file to open.

**Why it happens:**
The retirement of `owasp-css.instructions.md` (an explicit Active requirement in PROJECT.md) is treated as "delete the file" rather than "extract the routing logic and re-host it inside the new SKILL.md bodies," so routing intelligence is silently dropped rather than migrated.

**How to avoid:**
Before deleting `owasp-css.instructions.md` and the old `skill.json` activation-trigger block, extract every routing decision they encode (which standard/example is chosen for which kind of request) into an explicit "when the request is about X, read references/Y.md" section inside the new SKILL.md. Verify with the same activation-trigger prompts in TESTING.md before removing the legacy files.

**Warning signs:**
- Legacy files deleted in the same change that adds new SKILL.md files, with no diff showing routing logic was preserved
- New SKILL.md has no explicit "which reference file for which request" guidance
- TESTING.md activation prompts (3.1–3.6) produce different (wrong-standard) results after the conversion than before

**Phase to address:** reformat

---

### Pitfall 6: Frontmatter violates spec constraints in ways that silently fail to load

**What goes wrong:**
The Agent Skills frontmatter has hard constraints that are easy to violate invisibly: `name` must be lowercase letters/numbers/hyphens only, ≤64 characters, cannot start/end with a hyphen, and — critically — **must match the parent folder name exactly or the skill will not load**. Frontmatter must start at byte 0 with `---`. Angle brackets (`<`/`>`) anywhere in frontmatter are a documented anti-pattern because they can inject unintended instructions into the system prompt — a real risk here since some existing example content shows raw HTML/JS with angle brackets that could get copy-pasted into a description or metadata field during conversion.

**Why it happens:**
Folder names and `name:` fields drift when a skill is renamed once ("owasp-security-audit" repo folder vs. some other display name used in prose), and nobody re-validates after the rename. Byte-0 frontmatter requirements break silently if an editor inserts a BOM or leading blank line/comment.

**How to avoid:**
Add a pre-ship validation pass (even a simple script) that: (1) parses every SKILL.md frontmatter, (2) asserts `name` == parent folder name, (3) asserts `name` matches the allowed character set and length, (4) asserts frontmatter starts at byte 0, (5) greps frontmatter block for `<`/`>` and fails the build if found.

**Warning signs:**
- Any skill folder whose directory name and `name:` frontmatter value differ even in case or hyphenation
- A SKILL.md with a leading blank line, BOM, or comment before `---`
- Description or metadata fields containing raw code snippets with angle brackets

**Phase to address:** reformat

---

### Pitfall 7: Symlink-based install pattern breaks under native plugin/marketplace packaging

**What goes wrong:**
The repo's current distribution mechanism is exactly a symlink installer (`install.sh`), which CONCERNS.md already flags as a single point of failure with no cross-platform testing (macOS/Linux/Windows Git Bash). Moving to Claude Code's plugin/marketplace mechanism doesn't remove this risk — it changes its shape: documented regressions include symlinked skill directories **not being copied into the plugin cache** in some Claude Code versions, local marketplace paths registering with "0 skills" unless a symlink is pre-created manually, a Windows path bug that collapses `Users\<name>\.claude` into `<name>.claude` causing an `EPERM` rename failure during install, and a "Path escapes plugin directory" error when a skill references files outside its own plugin directory (which matters here because `references/owasp-urls.json` and shared assets currently get reused across the `owasp-security-audit` and `secure-coding-practices` skill folders).

**Why it happens:**
Marketplace packaging is assumed to be a pure metadata change (add `plugin.json`/`marketplace.json`) on top of the existing file layout, without re-examining whether any file is referenced *across* skill/plugin directory boundaries or relies on symlinks that the installer, not the plugin runtime, used to resolve.

**How to avoid:**
Before packaging, ensure every skill directory is self-contained (no skill references a file living in a sibling skill's directory or above the plugin root — duplicate shared reference data like `owasp-urls.json` per-skill if needed, or hoist it to a location the plugin format explicitly supports). Test the actual `/plugin marketplace add <path>` + install flow on macOS and at least one Linux/Windows CI runner, not just the legacy `install.sh`, before calling packaging "done."

**Warning signs:**
- Any `references/` or `assets/` path reachable only via `../` from a skill directory
- Install succeeds locally on macOS but plugin cache directory is empty of skill files
- No CI step actually runs `/plugin marketplace add` (or equivalent) against a fresh environment

**Phase to address:** packaging

---

### Pitfall 8: Plugin/marketplace manifest violates the "closed schema" and breaks CI validation

**What goes wrong:**
`plugin.json` at `.claude-plugin/plugin.json` has an intentionally minimal, closed schema — only a small fixed set of fields (name, version, description, author, etc.) is permitted, and validation rejects any manifest with extra properties. Teams porting existing rich metadata from the current `skill.json` (which has custom fields like `standards`, `activation.triggers`, `models.recommended` — none of which are in the official plugin schema) risk copy-pasting those extra fields straight into `plugin.json`, which fails marketplace validation outright rather than degrading gracefully.

**Why it happens:**
The existing `skill.json` is rich and useful internally, so the instinct during packaging is to preserve all of it in the new manifest rather than splitting "official marketplace metadata" (small, closed schema) from "internal documentation" (can live in README/DEPLOYMENT.md, not the manifest).

**How to avoid:**
Treat `plugin.json`/`marketplace.json` as strictly the official schema and nothing else — move everything else (standards list, activation triggers, model recommendations) into README/DEPLOYMENT.md prose or per-skill SKILL.md content instead. Validate `plugin.json` and `marketplace.json` against the published schemas (`json.schemastore.org/claude-code-marketplace.json`) as part of the same file-integrity checks TESTING.md already runs for `skill.json`.

**Warning signs:**
- `plugin.json` contains any field not in the official 8-field schema
- No automated JSON-schema validation step for the new manifest (the existing `python3 -m json.tool skill.json` check only proves valid JSON, not schema conformance)

**Phase to address:** packaging

---

### Pitfall 9: Version/changelog drift between plugin manifest, skill.json remnants, and README claims

**What goes wrong:**
This repo already has one instance of exactly this problem: `skill.json` example line counts don't match actual file sizes (flagged in CONCERNS.md — off by ~200 lines across 5 files), and model recommendations reference outdated Claude models. Adding a *second* version surface (`plugin.json` semver) without retiring or reconciling the first (`skill.json` 1.1.0) creates two sources of truth that will drift independently — e.g., `plugin.json` says 2.0.0 while a stray `skill.json` still says 1.1.0, or README's "current version" callout isn't bumped when either manifest changes.

**Why it happens:**
Nothing enforces that a version bump touches all surfaces simultaneously; there's no single script or CI check for it today (TESTING.md's checks are file-integrity/syntax only, not cross-file consistency).

**How to avoid:**
Pick exactly one canonical version source (`plugin.json` once packaging lands) and either delete `skill.json` or make it derive from/mirror the plugin manifest programmatically. Add a CI/pre-commit check that fails if README version references, `plugin.json` version, and (if retained) `skill.json` version disagree.

**Warning signs:**
- Two files in the repo independently declaring a "version" for the same conceptual release
- A CHANGELOG entry that doesn't match the version bump in the manifest committed alongside it
- Line-count/metadata mismatches recurring after the fix in CONCERNS.md (i.e., the fix wasn't made structural, just applied once)

**Phase to address:** packaging

---

### Pitfall 10: Overclaiming coverage undermines the exact credibility the refresh is meant to build

**What goes wrong:**
CONCERNS.md documents that 4 of 10 OWASP Top 10 (2021) items already lack worked examples (A04, A06, A08, A10), and PROJECT.md explicitly puts "no new example languages" and "no new domain skills" out of scope for this milestone — meaning the *format and version labels* will be modernized before the *coverage gaps* are closed. If README/marketing copy claims "complete OWASP Top 10 coverage" or "covers ASVS L1/L2/L3" without an explicit, honest caveat, a public security reference sets up its own credibility failure the first time a security-literate reviewer checks the examples directory and finds gaps (and, per the 2025 renumbering, the *specific* gaps will have shifted category letters again).

**Why it happens:**
Public-facing README copy is optimized for adoption ("comprehensive," "complete," "covers everything") at exactly the moment a milestone is deliberately choosing not to close known coverage gaps — the polish phase and the honesty obligation pull in opposite directions unless explicitly reconciled.

**How to avoid:**
State coverage precisely and verifiably: which standards, which editions, which categories have worked examples vs. reference-only guidance, and say so in the README (a coverage matrix, not a superlative). This is cheap to do and converts a credibility risk into a trust signal ("here's exactly what's covered, and here's the gap list") for a security-literate audience that will check anyway.

**Warning signs:**
- README/marketing language uses "complete," "full," or "comprehensive" without a coverage table backing it up
- No visible link from README to a gap/roadmap list
- Example directory coverage doesn't match category claims after the 2025/5.0/2.1/2026 renumbering is applied

**Phase to address:** polish

---

### Pitfall 11: Insecure or misleading example code undermines a security-education repo specifically

**What goes wrong:**
This repo's core value proposition is *paired vulnerable/secure examples* — so any example that is itself subtly wrong (a "secure" example that still has a flaw, or hardcoded-looking secrets used for illustration) is a much sharper credibility failure here than in a generic codebase, because the entire premise is "trust these patterns." CONCERNS.md already flags hardcoded-looking values in examples (e.g., `api_key = "sk-abc123xyz789"`) and notes examples aren't syntax-validated in CI beyond `py_compile`/`node --check` (which proves parseability, not security correctness).

**Why it happens:**
Syntax validation is mistaken for correctness validation; nobody re-reviews "secure" examples against the *new* edition's requirements when a standard is refreshed (e.g., an example marked "secure per ASVS 4.0 V2.1.1" may not satisfy the renumbered/rewritten ASVS 5.0 requirement it now claims to demonstrate).

**How to avoid:**
Add explicit review of every "SECURE:" example against the *newly cited* edition's actual requirement text (not just carrying forward the old citation), and standardize placeholder formatting (`${PLACEHOLDER}` or similar, already suggested in CONCERNS.md) across all examples so nothing looks like a real credential even out of context.

**Warning signs:**
- A "secure" example's inline comment still cites the old edition's control ID after the standard section header was bumped to the new edition
- Any credential-shaped string in example code not using a placeholder convention
- No documented re-review step between "bump version label" and "ship" for example files tied to that standard

**Phase to address:** version-refresh (re-validate examples against new edition text) and polish (placeholder convention, disclaimers)

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|-----------------|------------------|
| Keep `skill.json` alongside new `plugin.json` "just in case" | Avoids breaking anything referencing the old file during transition | Two version/metadata sources drift (Pitfall 9) | Only as a time-boxed transition artifact with a tracked removal date, never as permanent state |
| Copy the 900-line monolithic reference file into SKILL.md as-is to "convert fast" | Skill loads and works immediately | Every activation burns context budget; violates progressive disclosure (Pitfall 3) | Never for the shipped milestone — acceptable only as a scratch intermediate step before splitting into references/ |
| Update version numbers in README/skill.json without re-deriving category ID mappings | Repo "looks" updated quickly | Internal inconsistency between declared edition and actual category IDs used (Pitfall 1) | Never — this is exactly the credibility risk the milestone exists to close |
| Port the old 66-keyword activation-trigger list directly into the new `description` field | Fast, reuses existing "known good" keywords | Wastes the 1024-char budget on redundant synonyms instead of differentiating from sibling skills (Pitfall 4) | Never; keywords should inform description writing, not be pasted in verbatim |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|-----------------|-------------------|
| Claude Code plugin cache / `/plugin marketplace add` | Assuming symlinked skill dirs get copied into cache like the old installer did | Verify actual install produces populated cache dirs on a fresh machine/CI runner; avoid cross-directory symlinks inside a plugin |
| Claude Code slash-command autocomplete | Assuming a skill installed via marketplace automatically shows in autocomplete like a manually-symlinked one | Test autocomplete discovery explicitly post-install, not just skill activation |
| OWASP official sources (owasp.org, github.com/OWASP/*, mas.owasp.org, genai.owasp.org) | Citing secondary blog recaps as if they were the standard itself | Always resolve to the canonical OWASP repo/site and record edition status (RC vs Final) and date |
| JSON Schema validation for `plugin.json`/`marketplace.json` | Treating "valid JSON" (current `python3 -m json.tool` check) as equivalent to "valid against the plugin schema" | Add explicit schema validation against the published Claude Code marketplace schema, not just JSON syntax |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|-----------------|
| Monolithic SKILL.md body loaded on every activation | Every security-review interaction consumes tokens for all 6 standards even when only 1 is relevant | Split by standard into `references/`, keep SKILL.md as router | Noticeable once a session mixes multiple skill activations (e.g., OWASP audit + a cyber-domain skill) in the same context window |
| Reference-file chains (reference → reference → reference) | Agent "gets lost," fails to find the actually-relevant detail, or reads unnecessary files | Enforce one-level-deep references | Breaks down as soon as a skill author adds a "see also" link inside a references/*.md file |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Angle brackets or raw HTML in frontmatter fields (name/description/metadata) | Can be interpreted as injected instructions in the system prompt per the Agent Skills spec's own safety note | Lint frontmatter for `<`/`>` before shipping; keep code snippets out of frontmatter, only in the body |
| "Secure" example silently out of date with the newly-cited edition | Users copy a pattern that satisfies the *old* standard's requirement, not the *new* one it's now labeled against | Re-validate every secure example's claim against the new edition's actual requirement text during version-refresh, not just relabel the header |
| Hardcoded-looking secrets in illustrative examples | Copy-paste risk if a user lifts example code without reading context | Standardize a placeholder convention (`${PLACEHOLDER}`) across all examples, enforced by a grep-based pre-commit/CI check |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|--------------|-------------------|
| Coverage overclaimed in README relative to actual example depth | User trusts a gap exists where none does, discovers the gap mid-use, credibility drops | Publish an explicit coverage matrix (standard × category × has-example y/n) |
| Legacy `owasp-css.instructions.md` routing silently dropped during conversion | Skill picks the wrong reference file / wrong standard for a request that used to route correctly | Explicitly re-test the exact activation prompts in TESTING.md 3.1-3.6 before and after the conversion, diff results |
| Install instructions still describe the old symlink `install.sh` flow after marketplace packaging ships | New users follow stale instructions and get a broken/duplicate install | Replace (not append to) install docs the moment the marketplace path is the primary distribution channel; keep symlink method only as an explicitly-labeled "manual/advanced" fallback |

## "Looks Done But Isn't" Checklist

- [ ] **Version refresh:** Every `A0N`/category ID used in prose and examples matches the *newest* edition's actual numbering — verify with a full grep-and-cross-check against the official mapping, not just the top-level version string.
- [ ] **Agent Skills conversion:** Every skill's `name:` frontmatter exactly matches its folder name, frontmatter starts at byte 0, and no `<`/`>` appears anywhere in frontmatter.
- [ ] **Skill routing:** The routing logic previously encoded in `owasp-css.instructions.md`/`skill.json` activation triggers has an explicit equivalent inside the new SKILL.md bodies — verify by re-running TESTING.md's activation prompts and confirming the *same* (correct) skill/reference wins.
- [ ] **Packaging:** A full end-to-end `/plugin marketplace add` + install has been run on a clean environment (not just validated as JSON) and the installed skill actually appears in both activation and autocomplete.
- [ ] **Coverage claims:** README's coverage language matches an explicit, current coverage matrix — not a superlative claim assumed true from the old version.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|-----------------|------------------|
| Mixed edition numbering (Pitfall 1) | MEDIUM | Regenerate the ID mapping table from the official OWASP mapping artifact, then do a single pass grep-and-replace across all files referencing old IDs; re-run cross-reference validation |
| Bloated SKILL.md (Pitfall 3) | LOW-MEDIUM | Mechanically move detail sections into `references/*.md`, leave a table-of-contents + routing note in SKILL.md, verify nothing was lost via diff |
| Broken plugin/marketplace install (Pitfall 7/8) | MEDIUM | Roll back to the symlink installer as a documented fallback while the manifest/cache issue is root-caused against the specific Claude Code version affected |
| Overclaimed coverage (Pitfall 10) | LOW | Replace superlative language with a coverage matrix; this is a docs-only fix once the underlying gap is accurately known |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|-------------------|----------------|
| Mixed edition numbering across standards (1) | version-refresh | Cross-check every category ID against the official OWASP mapping/edition source; fail if any mismatch |
| RC cited as final or vice versa (2) | version-refresh | Record edition status + date per standard from the canonical OWASP source; flag any standard without a recorded status |
| Bloated SKILL.md (3) | reformat | Line-count / token-budget check on every SKILL.md; content audit that detail lives in references/ |
| Weak/overlapping descriptions (4) | reformat | Re-run TESTING.md activation prompts against the new descriptions; confirm intended skill wins, not just any skill |
| Lost routing logic from legacy instructions file (5) | reformat | Diff routing outcomes before/after conversion using the same test prompts |
| Frontmatter spec violations (6) | reformat | Automated frontmatter linter: name==folder, charset/length, byte-0 start, no angle brackets |
| Symlink/cache packaging failures (7) | packaging | Fresh-environment install test (not just local dev machine) across macOS/Linux/Windows |
| Manifest schema violations (8) | packaging | JSON-schema validation of plugin.json/marketplace.json against the published schema, not just JSON syntax |
| Version/changelog drift across manifests (9) | packaging | Single canonical version source + CI check that all version-declaring files agree |
| Overclaimed coverage (10) | polish | README coverage matrix cross-checked against actual example inventory |
| Insecure/misleading examples (11) | version-refresh (content) + polish (placeholders) | Re-review every "secure" example's citation against new edition text; grep for credential-shaped strings |

## Sources

- [Agent Skills Specification](https://agentskills.io/specification)
- [Equipping agents for the real world with Agent Skills — Anthropic](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Skill authoring best practices — Claude Platform Docs](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)
- [Create and distribute a plugin marketplace — Claude Code Docs](https://code.claude.com/docs/en/plugin-marketplaces)
- [Plugins reference — Claude Code Docs](https://code.claude.com/docs/en/plugins-reference)
- [anthropics/claude-code Issue #54967 — marketplace add local path 0 skills](https://github.com/anthropics/claude-code/issues/54967)
- [anthropics/claude-code Issue #52435 — Windows EPERM path collapse](https://github.com/anthropics/claude-code/issues/52435)
- [anthropics/claude-code Issue #53948 — symlinked skills not copied to cache regression](https://github.com/anthropics/claude-code/issues/53948)
- [anthropics/claude-code Issue #18949 — marketplace skills missing from autocomplete](https://github.com/anthropics/claude-code/issues/18949)
- [OWASP Top 10:2025 official project page](https://owasp.org/Top10/2025/)
- [OWASP Top 10 2025 vs 2021: What Has Changed? — Equixly](https://equixly.com/blog/2025/12/01/owasp-top-10-2025-vs-2021/)
- [What Changed in OWASP Top 10 2025? — Qualys](https://blog.qualys.com/qualys-insights/2026/06/15/what-changed-in-owasp-top-10-2025-and-recommendations-for-each-category)
- [What's New in ASVS 5.0 — SoftwareMill](https://softwaremill.com/whats-new-in-asvs-5-0/)
- [Differences Between ASVS 5.0 and 4.0 — DeepWiki](https://deepwiki.com/owasp-ja/asvs-ja/12-differences-between-asvs-5.0-and-4.0)
- [OWASP MASVS 2026: Version 2.1.0, 8 Categories, Changes — Vervali](https://www.vervali.com/blog/owasp-masvs-in-2026-current-version-the-8-categories-and-what-changed/)
- [OWASP/mastg Releases](https://github.com/OWASP/mastg/releases)
- [OWASP Top 10 for Agentic Applications for 2026 — OWASP GenAI Security Project](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Top 10 for LLM Applications (2025) — Giskard](https://www.giskard.ai/knowledge/owasp-top-10-for-llm-2025-understanding-the-risks-of-large-language-models)
- [OWASP Kubernetes Top Ten project page](https://owasp.org/www-project-kubernetes-top-ten/)
- Existing codebase analysis: `.planning/codebase/CONCERNS.md`, `.planning/codebase/TESTING.md`, `.planning/PROJECT.md`

---
*Pitfalls research for: OWASP Security Skills modernization milestone*
*Researched: 2026-07-19*
