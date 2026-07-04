# OWASP Security Skills

A security reference skill for AI coding assistants (Claude, GitHub Copilot, and
similar tools). It brings **six OWASP standards** and the **OWASP Secure Coding
Practices** guide into one place, so security-related prompts — code reviews, auth
and crypto implementation, Kubernetes manifests, LLM/agent code — get grounded,
standard-aligned analysis.

Install it into your assistant's skill directory and any security question
automatically draws on the OWASP guidance most relevant to your context.

## What it does

- **Identifies risks** in code, configuration, or design across web, API, mobile,
  container, and AI/LLM contexts.
- **Cites the relevant OWASP standard** for the situation at hand.
- **Recommends concrete fixes** with code and configuration examples.
- **Flags bypasses and edge cases** attackers commonly exploit.

## Coverage

The unified reference ([`owasp-comprehensive-security-skills.md`](owasp-comprehensive-security-skills.md))
covers six OWASP standards:

| Standard | Scope |
|----------|-------|
| **OWASP Top 10 (2025)** | Web application risks — access control, crypto, injection, misconfiguration, SSRF, and more |
| **OWASP ASVS 5.0** | Application security verification requirements (L1 / L2 / L3) |
| **OWASP MASVS v2.1.0** | Mobile app security controls (iOS / Android) |
| **OWASP API Security Top 10 (2023)** | API-specific risks — BOLA, broken auth, resource consumption, and more |
| **OWASP Kubernetes Top 10** | Container and cluster risks — RBAC, secrets, workload config, network policy |
| **OWASP Agentic Applications 2026** *(preview)* | AI/LLM risks — prompt injection, tool access, output handling |

A companion skill covers the **OWASP Secure Coding Practices Quick Reference
Guide** — 14 domains of general secure-development guidance (see
[`skills/secure-coding-practices/`](skills/secure-coding-practices/)).

## Installation

```bash
git clone https://github.com/mfkocalar/OWASP-Security-Skills.git
cd OWASP-Security-Skills
./install.sh
```

The installer detects your OS, symlinks the skill into the right directory, and
verifies the files. To link manually instead:

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
owasp-comprehensive-security-skills.md   Unified reference for the six OWASP standards
owasp-css.instructions.md                Activation triggers and model guidance
skill.json                               Skill manifest and metadata
install.sh                               Interactive installer
examples/                                9 vulnerable/secure code samples
skills/
  owasp-security-audit/                  Structured audit skill (references, scripts, assets)
  secure-coding-practices/               Secure Coding Practices skill (checklist, patterns)
```

## Examples

The [`examples/`](examples/) directory contains **9 code samples**, each pairing a
vulnerable pattern with a secure implementation and an explanation.

| File | Focus |
|------|-------|
| [broken-access-control.py](examples/broken-access-control.py) | Missing authorization / IDOR (A01) |
| [cryptographic-failures.js](examples/cryptographic-failures.js) | Weak hashing, plaintext storage, missing TLS (A02) |
| [injection.js](examples/injection.js) | SQL injection via string concatenation (A03) |
| [security-misconfiguration.py](examples/security-misconfiguration.py) | Debug mode, default creds, missing headers (A05) |
| [xss.html](examples/xss.html) | Reflected XSS via `innerHTML` (A07) |
| [logging-monitoring-failures.py](examples/logging-monitoring-failures.py) | Missing logs, secrets in logs, no alerting (A09) |
| [api-auth-bypass.js](examples/api-auth-bypass.js) | JWT and CORS flaws (API Security Top 10) |
| [k8s-rbac.yaml](examples/k8s-rbac.yaml) | Overly permissive RBAC, unencrypted secrets (Kubernetes Top 10) |
| [prompt-injection.txt](examples/prompt-injection.txt) | Direct/indirect LLM prompt injection (Agentic Applications 2026) |

Paste any sample into a prompt to see the skill in action:

```
Review this code for security vulnerabilities according to the OWASP Top 10.

[paste example code here]
```

## Documentation

- [`owasp-comprehensive-security-skills.md`](owasp-comprehensive-security-skills.md) — the main reference: vulnerability descriptions, detection clues, mitigations, and checklists across all six standards.
- [DEPLOYMENT.md](DEPLOYMENT.md) — installation and deployment options.
- [TESTING.md](TESTING.md) — how to verify the skill is installed and working.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Released under the MIT License.
