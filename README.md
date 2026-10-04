# OWASP Security Skills

![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8)
![OWASP](https://img.shields.io/badge/OWASP-aligned-orange)

A Claude Code plugin with two OWASP-aligned security skills:
**`owasp-security-audit`**, covering seven OWASP standards (Top 10, ASVS,
MASVS, API Security, Kubernetes, LLM, and Agentic Applications — LLM and
Agentic Applications are counted separately), and **`secure-coding-practices`**,
a 14-domain secure coding checklist re-derived from OWASP's living sources.
Together they ground security-related prompts — code reviews, auth and crypto
implementation, Kubernetes manifests, LLM/agent code — in standard-aligned
analysis with citations.

Install the plugin into Claude Code and any security question automatically
draws on the OWASP guidance most relevant to your context. See
[`skills/owasp-security-audit/SKILL.md`](skills/owasp-security-audit/SKILL.md)
and [`skills/secure-coding-practices/SKILL.md`](skills/secure-coding-practices/SKILL.md)
for the full activation triggers and workflow each skill follows, and each
skill's `references/` directory for the underlying standard-specific lookup docs.

## What it does

- **Identifies risks** in code, configuration, or design across web, API, mobile,
  container, and AI/LLM contexts.
- **Cites the relevant OWASP standard** for the situation at hand.
- **Recommends concrete fixes** with code and configuration examples.
- **Flags bypasses and edge cases** attackers commonly exploit.

## Coverage

Every edition and source URL below is sourced from the hardened
[`owasp-urls.json`](skills/owasp-security-audit/references/owasp-urls.json)
citation files (Phases 2–3 of this project) — not re-derived here.

| Standard | Edition covered | Scope / caveat |
|----------|------------------|-----------------|
| **OWASP Top 10** | 2025 (Final) — [source](https://owasp.org/Top10/2025/), retrieved 2026-07-21 | Web application risks: access control (incl. SSRF), misconfiguration, supply chain, cryptographic failures, injection, insecure design, auth failures, integrity failures, logging/alerting, exceptional conditions |
| **OWASP ASVS** | 5.0.0 current edition — [source](https://owasp.org/www-project-application-security-verification-standard/), retrieved 2026-10-04 | Requirement summaries use the official 5.0.0 V1-V17 chapter numbering and cite IDs as `v5.0.0-X.Y.Z`, each checked against OWASP's official 5.0.0 mapping file at a pinned commit; confirm IDs against the edition you audit against |
| **OWASP MASVS** | 2.1.0 — [source](https://mas.owasp.org/MASVS/), retrieved 2026-07-22 | Mobile app security controls (iOS / Android) |
| **OWASP API Security Top 10** | 2023 — [source](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), retrieved 2026-07-22 | API-specific risks — BOLA, broken auth, resource consumption, SSRF, and more |
| **OWASP Kubernetes Top 10** | 2022 (stable) — [source](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/), retrieved 2026-07-22 | **Not** the 2025 draft (feedback-stage only as of retrieval, no formal release). Container/cluster risks — RBAC, secrets, workload config, network policy |
| **OWASP LLM Top 10** | 2025 — [source](https://genai.owasp.org/llm-top-10/), retrieved 2026-07-22 | Prompt injection, sensitive information disclosure, supply chain, output handling, unbounded consumption, and more |
| **OWASP Agentic Applications Top 10** | 2026 — [source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), retrieved 2026-07-22 | Agent goal hijack, tool misuse, identity/privilege abuse, memory/context poisoning, and other agent-specific risks — tracked as its own standard, distinct from the LLM Top 10 row above |
| **Secure Coding Practices** (`secure-coding-practices` skill) | Living-source derivation, no single dated edition — [Cheat Sheet Series](https://cheatsheetseries.owasp.org/), retrieved 2026-07-22 | 14-domain checklist re-derived from OWASP's living sources (Developer Guide, Cheat Sheet Series, Proactive Controls). The original [SCP Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/) is **archived** and kept only as historical origin, not cited as a current edition |

### What this is NOT

- **This is guidance and reference material, not a runtime scanner.** It does
  not execute code, run tests, or make network requests — it audits code you
  paste or point it at, via inspection and pattern matching.
- **The example files do not yet cover every 2025 Top 10 category.** As of
  this release, no example demonstrates **A03 Software Supply Chain
  Failures**, **A04 Insecure Design**, **A06 Vulnerable & Outdated
  Components**, **A08 Software or Data Integrity Failures**, or **A10
  Mishandling of Exceptional Conditions**. This table discloses that gap —
  it does not fill it. Authoring examples for these categories is tracked as
  future work.

## Installation

### Option 1: Claude Code plugin marketplace (recommended)

```bash
claude plugin marketplace add mfkocalar/OWASP-Security-Skills
claude plugin install owasp-security-skills@owasp-security-skills
```

Then confirm both skills were discovered:

```bash
claude plugin details owasp-security-skills@owasp-security-skills
```

This is the primary, supported install path for Claude Code.

### Option 2: `install.sh` (alternative — symlink-based, non-plugin assistants)

For assistants without plugin/marketplace support (or for a manual,
symlink-based Claude Code install), clone the repo and run the installer:

```bash
git clone https://github.com/mfkocalar/OWASP-Security-Skills.git
cd OWASP-Security-Skills
./install.sh
```

The installer detects your OS, symlinks the skills into the right directory,
and verifies the files. To link manually instead:

```bash
# Claude (macOS)
ln -s "$PWD" ~/.claude/skills/owasp-security
# Claude (Linux)
ln -s "$PWD" ~/.local/share/claude/skills/owasp-security
# GitHub Copilot
ln -s "$PWD" ~/.copilot/skills/owasp-security
```

Reload or restart the assistant afterward.

## Usage

Just describe what you're working on and paste the code. The skill selects the
matching standard automatically.

```
Review this REST API endpoint for OWASP API security issues.

[paste code here]
```

More examples:

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
  check_version_drift.py               Version single-source-of-truth check
  lint_skill_md.py                      SKILL.md frontmatter linter
LICENSE
README.md
CONTRIBUTING.md
install.sh                             Alternative symlink-based installer
```

## Examples

Examples live per-skill under each skill's `assets/examples/` directory: **9 samples**
in [`skills/owasp-security-audit/assets/examples/`](skills/owasp-security-audit/assets/examples/)
covering the OWASP Top 10 and related standards, plus **2 samples** in
[`skills/secure-coding-practices/assets/examples/`](skills/secure-coding-practices/assets/examples/)
for secure coding practices. Each pairs a vulnerable pattern with a secure implementation
and an explanation.

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

Paste any sample into a prompt to see the skill in action:

```
Review this code for security vulnerabilities according to the OWASP Top 10.

[paste example code here]
```

## Documentation

- [`skills/owasp-security-audit/SKILL.md`](skills/owasp-security-audit/SKILL.md) and its [`references/`](skills/owasp-security-audit/references/) — vulnerability descriptions, detection clues, mitigations, and checklists for the audit skill's standards.
- [`skills/secure-coding-practices/SKILL.md`](skills/secure-coding-practices/SKILL.md) and its [`references/`](skills/secure-coding-practices/references/) — the 14-domain secure coding checklist and living-source crosswalk.
- [`docs/SKILL-STRUCTURE.md`](docs/SKILL-STRUCTURE.md) — the canonical skill-directory convention followed by both skills.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Released under the [MIT License](LICENSE).
