# OWASP Security Skills

![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.1.0-blue)
![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8)
![OWASP](https://img.shields.io/badge/OWASP-aligned-orange)

OWASP Security Skills is a Claude Code plugin that adds two security skills.
`owasp-security-audit` reviews code and configuration against seven OWASP
standards: Top 10, ASVS, MASVS, API Security, Kubernetes, LLM, and Agentic
Applications (the last two are counted as separate standards).
`secure-coding-practices` is a 14-domain secure coding checklist derived from
OWASP's living sources. When you ask about code reviews, authentication,
cryptography, Kubernetes manifests, or LLM and agent code, the skills answer
with analysis tied to the relevant standard and cite their sources.

Once the plugin is installed, Claude Code picks the OWASP guidance that fits
your question without being asked. Each skill's activation triggers and
workflow are in
[`skills/owasp-security-audit/SKILL.md`](skills/owasp-security-audit/SKILL.md)
and [`skills/secure-coding-practices/SKILL.md`](skills/secure-coding-practices/SKILL.md),
and the standard-specific lookup docs are in each skill's `references/`
directory.

## What's new in 1.1

Version 1.1, the OWASP Edition Refresh, updates the reference files to the
newest published OWASP editions and adds a script that checks they stay
consistent.

- The LLM Top 10 moves to the 2026 edition. `llm.md` covers `LLM01:2026` to
  `LLM10:2026` in the new rank order. Excessive Agency rises to LLM03, and the
  previous edition's System Prompt Leakage is renamed and re-scoped as LLM08,
  Hidden Context Exposure. Every LLM code the skill cites, including scanner
  tags, examples, and the Agentic crosswalk, now uses its 2026 code. An
  appendix maps each item to its predecessor in the previous edition.
- ASVS follows the 5.0.0 chapter numbering, V1 to V17 (for example V6
  Authentication, V8 Authorization, and V11 Cryptography). Requirement IDs use
  OWASP's versioned form, `v5.0.0-X.Y.Z`, and each one was checked against
  OWASP's official 5.0.0 mapping file at a pinned commit.
- `masvs.md` stays on MASVS 2.1.0 and adds a section on its companion, MASWE
  v1.0.0. MASWE defines 78 weaknesses across the 8 MASVS groups and links each
  control to MASTG tests. It is a separate project with its own versioning, so
  it does not count as a new MASVS edition.
- Kubernetes coverage stays on the 2022 edition. A footnote records that the
  2025 Kubernetes Top 10 is still a draft with no formal release, and a
  labeled appendix (repo-inferred and spot-checked) translates between the 2022
  and 2025 numbering. The RBAC example's category labels now match the
  scanner's.
- `scripts/check_edition_consistency.py` is new. It confirms that each
  SKILL.md description is mirrored in `docs/SKILL-STRUCTURE.md`, that no
  superseded edition label or ID appears outside the allow-listed history
  sections, and that each Coverage row below matches its reference file's
  edition and retrieval date. Run it with `--format text`.

## What it does

The skills identify risks in code, configuration, and design across web, API,
mobile, container, and AI/LLM work. For each finding they cite the OWASP
standard that applies, recommend a fix with code or configuration examples,
and point out the bypasses and edge cases attackers commonly use.

## Coverage

Editions and source URLs come from the
[`owasp-urls.json`](skills/owasp-security-audit/references/owasp-urls.json)
citation files.

| Standard | Edition covered | Scope and caveats |
|----------|------------------|-----------------|
| **OWASP Top 10** | 2025 (Final), [source](https://owasp.org/Top10/2025/), retrieved 2026-07-21 | Web application risks: access control (including SSRF), misconfiguration, supply chain, cryptographic failures, injection, insecure design, authentication failures, integrity failures, logging and alerting, and exceptional conditions |
| **OWASP ASVS** | 5.0.0 current edition, [source](https://owasp.org/www-project-application-security-verification-standard/), retrieved 2026-10-04 | Requirement summaries use the official 5.0.0 V1-V17 chapter numbering and cite IDs as `v5.0.0-X.Y.Z`. Each ID was checked against OWASP's official 5.0.0 mapping file at a pinned commit. Confirm IDs against the edition you audit against |
| **OWASP MASVS** | 2.1.0, [source](https://mas.owasp.org/MASVS/), retrieved 2026-07-22 | Mobile app security controls for iOS and Android. The companion OWASP MASWE v1.0.0 weakness catalogue ([source](https://mas.owasp.org/MASWE/), retrieved 2026-11-09) is tracked separately from the MASVS edition |
| **OWASP API Security Top 10** | 2023, [source](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), retrieved 2026-07-22 | API-specific risks such as BOLA, broken authentication, resource consumption, and SSRF |
| **OWASP Kubernetes Top 10** | 2022 (stable), [source](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/), retrieved 2026-07-22 | Container and cluster risks: RBAC, secrets, workload configuration, and network policy. This is not the 2025 draft, which was at the feedback stage with no formal release when retrieved |
| **OWASP LLM Top 10** | 2026, [source](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), retrieved 2026-10-04 | Prompt injection, sensitive information disclosure, supply chain, output handling, unbounded consumption, and other LLM risks |
| **OWASP Agentic Applications Top 10** | 2026, [source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), retrieved 2026-07-22 | Agent goal hijack, tool misuse, identity and privilege abuse, memory and context poisoning, and other agent-specific risks. Tracked as its own standard, separate from the LLM Top 10 |
| **Secure Coding Practices** (`secure-coding-practices` skill) | Living-source derivation with no single dated edition, [Cheat Sheet Series](https://cheatsheetseries.owasp.org/), retrieved 2026-07-22 | A 14-domain checklist derived from OWASP's living sources: the Developer Guide, the Cheat Sheet Series, and the Proactive Controls. The original [SCP Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/) is archived. It is kept as the project's historical origin and is not cited as a current edition |

### Limitations

- The skills are guidance and reference material, not a runtime scanner. They
  do not execute code, run tests, or make network requests. They review the
  code you paste or point them at by reading it and matching known patterns.
- The example files do not yet cover every 2025 Top 10 category. No example
  demonstrates A03 Software Supply Chain Failures, A06 Insecure Design, A08
  Software or Data Integrity Failures, or A10 Mishandling of Exceptional
  Conditions. Examples for these categories are planned.

## Installation

### Option 1: Claude Code plugin marketplace (recommended)

```bash
claude plugin marketplace add mfkocalar/OWASP-Security-Skills
claude plugin install owasp-security-skills@owasp-security-skills
```

Then confirm that both skills were discovered:

```bash
claude plugin details owasp-security-skills@owasp-security-skills
```

This is the supported install path for Claude Code.

### Option 2: `install.sh` (symlink-based, for assistants without plugin support)

If your assistant does not support plugins, or you prefer a manual
symlink-based install for Claude Code, clone the repo and run the installer:

```bash
git clone https://github.com/mfkocalar/OWASP-Security-Skills.git
cd OWASP-Security-Skills
./install.sh
```

The installer detects your OS, symlinks the skills into the right directory,
and verifies the files. To create the links yourself:

```bash
# Claude (macOS)
ln -s "$PWD" ~/.claude/skills/owasp-security
# Claude (Linux)
ln -s "$PWD" ~/.local/share/claude/skills/owasp-security
# GitHub Copilot
ln -s "$PWD" ~/.copilot/skills/owasp-security
```

Restart or reload the assistant afterward.

## Usage

Describe what you're working on and paste the code. The skill chooses the
matching standard.

```
Review this REST API endpoint for OWASP API security issues.

[paste code here]
```

Other example prompts:

| Domain | Example prompt |
|--------|----------------|
| Web / API | `Review this code for SQL injection` · `Audit this endpoint for BOLA` |
| Mobile | `Is this iOS Keychain implementation secure?` |
| Kubernetes | `Harden this RBAC configuration` |
| AI / LLM | `How do I prevent prompt injection in my chatbot?` |
| Compliance | `What ASVS L2 requirements apply to authentication here?` |
| Secure coding | `Review this code against OWASP secure coding practices` |

## Repository structure

```
.claude-plugin/
  plugin.json                          Plugin identity manifest (canonical version source)
  marketplace.json                     Marketplace catalog listing
skills/
  owasp-security-audit/                Structured audit skill
    SKILL.md                           Frontmatter (name + description) + workflow
    references/                        Standard-specific lookup docs + owasp-urls.json
    scripts/quick_scan.py              Regex-based lead scanner
    assets/examples/                   9 vulnerable/secure code samples
  secure-coding-practices/             Secure Coding Practices skill
    SKILL.md
    references/                        Checklist, patterns, owasp-urls.json
    assets/examples/                   2 vulnerable/secure code samples
docs/
  SKILL-STRUCTURE.md                   Canonical skill-directory convention
scripts/
  check_edition_consistency.py         OWASP edition and stale-ID drift check
  check_version_drift.py               Version single-source-of-truth check
  lint_skill_md.py                      SKILL.md frontmatter linter
LICENSE
README.md
CONTRIBUTING.md
install.sh                             Alternative symlink-based installer
```

## Examples

Each skill keeps its examples in its own `assets/examples/` directory. There
are 9 samples in
[`skills/owasp-security-audit/assets/examples/`](skills/owasp-security-audit/assets/examples/)
covering the OWASP Top 10 and related standards, and 2 in
[`skills/secure-coding-practices/assets/examples/`](skills/secure-coding-practices/assets/examples/)
for secure coding practices. Each file pairs a vulnerable pattern with a
secure implementation and explains the difference.

| File | Focus |
|------|-------|
| [broken-access-control.py](skills/owasp-security-audit/assets/examples/broken-access-control.py) | Missing authorization / IDOR (A01) |
| [security-misconfiguration.py](skills/owasp-security-audit/assets/examples/security-misconfiguration.py) | Debug mode, default creds, missing headers (A02) |
| [cryptographic-failures.js](skills/owasp-security-audit/assets/examples/cryptographic-failures.js) | Weak hashing, plaintext storage, missing TLS (A04) |
| [injection.js](skills/owasp-security-audit/assets/examples/injection.js) | SQL injection via string concatenation (A05) |
| [xss.html](skills/owasp-security-audit/assets/examples/xss.html) | Reflected XSS via `innerHTML` (A05: Injection) |
| [logging-monitoring-failures.py](skills/owasp-security-audit/assets/examples/logging-monitoring-failures.py) | Missing logs, secrets in logs, no alerting (A09) |
| [api-auth-bypass.js](skills/owasp-security-audit/assets/examples/api-auth-bypass.js) | JWT and CORS flaws (API Security Top 10) |
| [k8s-rbac.yaml](skills/owasp-security-audit/assets/examples/k8s-rbac.yaml) | Overly permissive RBAC, unencrypted secrets (Kubernetes Top 10) |
| [prompt-injection.txt](skills/owasp-security-audit/assets/examples/prompt-injection.txt) | Direct/indirect LLM prompt injection and tool misuse (LLM Top 10 / Agentic Applications) |

To try a skill, paste a sample into a prompt:

```
Review this code for security vulnerabilities according to the OWASP Top 10.

[paste example code here]
```

## Documentation

- [`skills/owasp-security-audit/SKILL.md`](skills/owasp-security-audit/SKILL.md) and its [`references/`](skills/owasp-security-audit/references/) directory describe each vulnerability, with detection clues, mitigations, and checklists for the audit skill's standards.
- [`skills/secure-coding-practices/SKILL.md`](skills/secure-coding-practices/SKILL.md) and its [`references/`](skills/secure-coding-practices/references/) directory hold the 14-domain secure coding checklist and the crosswalk to its living sources.
- [`docs/SKILL-STRUCTURE.md`](docs/SKILL-STRUCTURE.md) defines the skill-directory convention both skills follow.
- [CONTRIBUTING.md](CONTRIBUTING.md) explains how to contribute.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Released under the [MIT License](LICENSE).
