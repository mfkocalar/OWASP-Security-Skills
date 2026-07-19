# Technology Stack

**Analysis Date:** 2026-07-19

## Project Type

This is a **security reference skill** for AI coding assistants (Claude, GitHub Copilot, etc.) — not a traditional application. The project delivers documentation, activation triggers, and instructional guidance for security review across OWASP standards.

## Delivery Format

**Primary Medium:**
- Markdown documentation (`.md` files)
  - `owasp-comprehensive-security-skills.md` — Main reference (~2,500 lines)
  - `owasp-css.instructions.md` — Model activation and behavior guidance
  - README.md, DEPLOYMENT.md, CONTRIBUTING.md — User-facing docs

**Manifest Format:**
- `skill.json` — Skill metadata, activation triggers, file references (1.1.0)

**Deployment:**
- Symlink-based installation to assistant skill directories
- Shell script installer (`install.sh`) — Bash (portable to macOS, Linux)

## Languages & Runtime

**No core runtime dependencies.** The skill is pure documentation consumed by LLM assistants.

**Example Code Coverage** (reference/educational only):
- **Python** 3.x — Flask, crypto, logging examples
- **JavaScript/Node.js** — Express, bcrypt, crypto, jsonwebtoken examples
- **YAML** — Kubernetes manifests
- **HTML/CSS/JavaScript** — Web security examples
- **Bash** — Installation script, shell commands

## Assistant Models (Supported)

**Recommended:**
- Claude Haiku 4.5 (200k context window)
- Claude Sonnet 4.1 (200k context window)
- Claude Opus 3+ (200k context window)

**Minimum Requirements:**
- 8k token context window
- Response time <3 seconds typical
- Activation detection <500ms

**Alternative Assistants:**
- GitHub Copilot (with `.copilot/skills/` deployment)
- Other LLM-based assistants (custom deployment)

## Core Files & Structure

**Reference Documents:**
- `owasp-comprehensive-security-skills.md` — 6 OWASP standards + 1 secure coding guide
- `skills/owasp-security-audit/SKILL.md` — Audit skill documentation
- `skills/secure-coding-practices/SKILL.md` — Secure coding practices skill
- `skills/secure-coding-practices/references/` — Checklists, patterns, URLs

**Example Files** (11 files, ~2,500 lines):
- `examples/broken-access-control.py`
- `examples/cryptographic-failures.js`
- `examples/injection.js`
- `examples/security-misconfiguration.py`
- `examples/xss.html`
- `examples/logging-monitoring-failures.py`
- `examples/api-auth-bypass.js`
- `examples/k8s-rbac.yaml`
- `examples/prompt-injection.txt`

**Configuration:**
- `.gitignore` — Standard exclusions + skill directory patterns
- `skill.json` — Manifest with standards coverage, activation triggers, metadata

## External Dependencies

**None required for core skill functionality.**

The skill is self-contained documentation that activates within the assistant runtime. It references common libraries and frameworks in *example code patterns*, but does not require installing or running them.

### Frameworks Referenced in Examples

**Web/API:**
- Flask (Python web framework)
- Express.js (Node.js web framework)
- Node.js crypto (built-in module)
- bcrypt (password hashing library)
- jsonwebtoken (JWT validation library)
- CORS middleware

**Infrastructure:**
- Docker (containerization examples)
- Kubernetes (orchestration examples)
- Nginx (reverse proxy examples)
- Apache (web server examples)
- PostgreSQL (database examples)

**Monitoring & Logging:**
- ELK Stack (Elasticsearch, Logstash, Kibana) — referenced in examples
- Prometheus (metrics) — referenced in examples
- Structured logging patterns (JSON, correlation IDs)

**Authentication:**
- JWT (JSON Web Tokens)
- Session management patterns
- OAuth / OpenID Connect (conceptual, not implemented)

## Build & Deployment

**Build Process:**
- None required. The skill is delivered as-is.

**Installation:**
- Symlink-based via `./install.sh` (Bash)
- Targets:
  - Claude Desktop: `~/.claude/skills/owasp-security` (macOS)
  - Claude Desktop: `~/.local/share/claude/skills/owasp-security` (Linux)
  - GitHub Copilot: `~/.copilot/skills/owasp-security`
  - Custom paths supported

**Verification:**
- `install.sh` includes checks for required files
- Counts example files (expects 9+)
- Tests activation by asking about security vulnerabilities

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Skill load time | <500ms |
| Average response | <3s |
| Memory footprint | ~100KB |
| Core reference file | ~2,500 lines |
| Example code | ~2,500 lines across 11 files |
| Activation triggers | 7 contexts (web, API, mobile, K8s, LLM, compliance, SCP) |

## Environment Configuration

**Installation Options:**
- Interactive installer detects OS and offers Claude, Copilot, or custom target
- No environment variables required for skill itself
- Example code patterns show best practices for managing `.env` files and secrets

**Development:**
- No build configuration
- No package manager (npm, pip, etc.)
- Version tracked in `skill.json` → "version": "1.1.0"

## Version Management

**Current Version:** 1.1.0 (as of 2026-03-14)

**Changelog:**
- 1.1.0: Added Secure Coding Practices skill, organized packaged skills with references/assets
- 1.0.0: Initial release with 6 OWASP standards integrated

**Active Maintenance:**
- Status: Production
- Updates: Regularly maintained with new vulnerability data and patterns
- Distribution: Git-based (pull from main branch)

## Standards & References Included

**OWASP Standards Covered:**
1. OWASP Top 10 (2021) — 10 web app vulnerabilities
2. OWASP ASVS 5.0 — Verification requirements (L1/L2/L3)
3. OWASP MASVS v2.1.0 — Mobile security controls
4. OWASP API Security Top 10 (2023) — API-specific risks
5. OWASP Kubernetes Top 10 (2022) — Container security
6. OWASP Agentic Applications (2026) — LLM/AI security
7. OWASP Secure Coding Practices — 14 development domains

---

*Stack analysis: 2026-07-19*
