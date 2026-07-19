<!-- GSD:project-start source:PROJECT.md -->

## Project

**OWASP Security Skills**

A pair of OWASP-focused security skills for Claude Code (and compatible AI coding assistants) that bring OWASP standards and secure-coding practices into automated code, infrastructure, and configuration review. This milestone modernizes the repo: OWASP content is refreshed to its newest published editions, both skills are restructured into Anthropic's official Agent Skills format, and the whole repo is polished for public distribution via the Claude Code plugin marketplace.

<!-- SCOPE NOTE (corrected 2026-07-19): This repository's skills/ directory contains only two skills — owasp-security-audit and secure-coding-practices. The 15 cyber-domain skills (recon, malware, red-team, etc.) are globally-installed skills living outside this repo (~/.claude/skills) and are NOT in scope for this milestone. -->

**Core Value:** A security engineer or developer can install the collection into Claude Code and get accurate, current, OWASP-grounded security review — with the reference content matching the *latest* published OWASP editions and the packaging matching the *official* skill spec so it installs cleanly and is worth sharing.

### Constraints

- **Accuracy**: Every OWASP version number, category, and control ID must be verified against official OWASP sources — Why: a public security reference loses all credibility if editions or IDs are wrong.
- **Format**: Must conform to Anthropic's official Agent Skills spec (`SKILL.md` + frontmatter + progressive disclosure) — Why: enables clean Claude Code install and marketplace distribution.
- **Tech stack**: Markdown-first, optional Python for tooling; no heavy runtime dependencies — Why: keeps the skill lightweight, portable, and easy to install.
- **Distribution**: Must be installable via Claude Code plugin/marketplace mechanisms — Why: this is the definition of "done" for reach and adoption.
- **Compatibility**: Preserve the value of existing content (examples, checklists, scanner) through the restructure — Why: this is a refresh, not a teardown.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->

## Technology Stack

## Project Type

## Delivery Format

- Markdown documentation (`.md` files)
- `skill.json` — Skill metadata, activation triggers, file references (1.1.0)
- Symlink-based installation to assistant skill directories
- Shell script installer (`install.sh`) — Bash (portable to macOS, Linux)

## Languages & Runtime

- **Python** 3.x — Flask, crypto, logging examples
- **JavaScript/Node.js** — Express, bcrypt, crypto, jsonwebtoken examples
- **YAML** — Kubernetes manifests
- **HTML/CSS/JavaScript** — Web security examples
- **Bash** — Installation script, shell commands

## Assistant Models (Supported)

- Claude Haiku 4.5 (200k context window)
- Claude Sonnet 4.1 (200k context window)
- Claude Opus 3+ (200k context window)
- 8k token context window
- Response time <3 seconds typical
- Activation detection <500ms
- GitHub Copilot (with `.copilot/skills/` deployment)
- Other LLM-based assistants (custom deployment)

## Core Files & Structure

- `owasp-comprehensive-security-skills.md` — 6 OWASP standards + 1 secure coding guide
- `skills/owasp-security-audit/SKILL.md` — Audit skill documentation
- `skills/secure-coding-practices/SKILL.md` — Secure coding practices skill
- `skills/secure-coding-practices/references/` — Checklists, patterns, URLs
- `examples/broken-access-control.py`
- `examples/cryptographic-failures.js`
- `examples/injection.js`
- `examples/security-misconfiguration.py`
- `examples/xss.html`
- `examples/logging-monitoring-failures.py`
- `examples/api-auth-bypass.js`
- `examples/k8s-rbac.yaml`
- `examples/prompt-injection.txt`
- `.gitignore` — Standard exclusions + skill directory patterns
- `skill.json` — Manifest with standards coverage, activation triggers, metadata

## External Dependencies

### Frameworks Referenced in Examples

- Flask (Python web framework)
- Express.js (Node.js web framework)
- Node.js crypto (built-in module)
- bcrypt (password hashing library)
- jsonwebtoken (JWT validation library)
- CORS middleware
- Docker (containerization examples)
- Kubernetes (orchestration examples)
- Nginx (reverse proxy examples)
- Apache (web server examples)
- PostgreSQL (database examples)
- ELK Stack (Elasticsearch, Logstash, Kibana) — referenced in examples
- Prometheus (metrics) — referenced in examples
- Structured logging patterns (JSON, correlation IDs)
- JWT (JSON Web Tokens)
- Session management patterns
- OAuth / OpenID Connect (conceptual, not implemented)

## Build & Deployment

- None required. The skill is delivered as-is.
- Symlink-based via `./install.sh` (Bash)
- Targets:
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

- Interactive installer detects OS and offers Claude, Copilot, or custom target
- No environment variables required for skill itself
- Example code patterns show best practices for managing `.env` files and secrets
- No build configuration
- No package manager (npm, pip, etc.)
- Version tracked in `skill.json` → "version": "1.1.0"

## Version Management

- 1.1.0: Added Secure Coding Practices skill, organized packaged skills with references/assets
- 1.0.0: Initial release with 6 OWASP standards integrated
- Status: Production
- Updates: Regularly maintained with new vulnerability data and patterns
- Distribution: Git-based (pull from main branch)

## Standards & References Included

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

## Naming Patterns

- kebab-case for filenames: `broken-access-control.py`, `cryptographic-failures.js`, `api-auth-bypass.js`
- Security-focused descriptive names: filenames describe the vulnerability or pattern
- Examples in `examples/` and mirrored in `skills/*/assets/examples/`
- **Python:** snake_case throughout: `vulnerable_store_password()`, `secure_hash_password()`, `verify_auth()`, `login_attempt()`
- **JavaScript:** camelCase: `verifyAuth()`, `requireAdmin()`, `secure_encrypt_data()`, but some prefixed as `vulnerable_` or `secure_` for clarity
- **Python:** snake_case: `user_id`, `api_key`, `connection_string`, `auth_tag`
- **JavaScript:** camelCase: `userId`, `apiKey`, `authTag`, `jwtSecret`
- Environment variables: UPPERCASE: `API_KEY`, `JWT_SECRET`, `DATABASE_ENCRYPTION_KEY`, `CANONICAL_HOST`
- CamelCase: `VulnerableAuthService`, `SecureLogger`, `VulnerableDistributedLogs`, `SecureAuthService`
- Prefixed with security context: `Vulnerable*` or `Secure*` to make intent explicit
- One class per file or grouped by related functionality
- UPPERCASE_SNAKE_CASE for module-level constants: `MAX_FILE_BYTES`, `DEFAULT_INCLUDES`, `SKIP_DIRS`
- Literal strings often UPPERCASE for event types: `LOGIN_ATTEMPT`, `UNAUTHORIZED_ACCESS`, `CONFIG_CHANGE`

## Code Style

- No automated formatter configured (no .eslintrc, .prettierrc, or similar)
- Manual consistency required across team contributions
- 4 spaces indentation in Python (PEP 8 default)
- 2 spaces indentation in JavaScript (Express.js convention)
- Line length: Not explicitly constrained; examples range 80-120 characters
- No eslint or pylint configuration files present
- Code follows implicit conventions observed in examples, not enforced tooling
- Syntax validation via `python3 -m py_compile` and `node --check` at review time

## Import Organization

- Not used in this repository (no alias config observed)
- Relative requires in JavaScript: `require('express')`, `require('cors')`

## Error Handling

- Try/except blocks for operations that may fail
- `except OSError:` for file operations (seen in `quick_scan.py`)
- `except Exception as e:` for broad exception catching in decorator/middleware
- Type-safe error logging: `details['error'] = type(e).__name__`
- Exceptions logged before re-raising: catch → log → raise
- HTTP-style status codes returned in Flask/JSON responses: 401, 403, 404, 500
- Try/catch blocks around JWT verification and async operations
- Early returns for error cases: `if (error) return res.status(500).json({ error: "..." })`
- Validation before processing: check input exists/is valid, return 400 before executing logic
- Error objects standardized: `{ error: "message" }` or `{ status: "error", message: "..." }`
- No explicit stack traces logged; error messages are user-friendly

## Logging

- Structured JSON logging for security events: timestamp, event_type, user_id, severity, details
- JSON formatter produces pure `{}` JSON (no prefix) for Logstash compatibility
- Security logs go to dedicated file: `/var/log/security.log`
- **Never log secrets:** password, API keys, connection strings, tokens
- Sensitive data masked with `***` if key name indicates secret (e.g., `config_key == 'password'`)
- Event types are descriptive: `LOGIN_ATTEMPT`, `UNAUTHORIZED_ACCESS`, `CONFIG_CHANGE`, `USER_LOGIN`
- Severity levels: `INFO`, `WARNING`, `CRITICAL`
- `console.log("message")` for debug output
- `console.error()` for errors (implicitly in Node.js production, would use proper logger)
- No secrets logged; messages describe action, not data

## Comments

- Every function has a docstring/header comment explaining security implications
- Vulnerable sections marked: `# VULNERABLE:` (Python) or `// VULNERABLE:` (JavaScript)
- Secure sections marked: `# SECURE:` (Python) or `// SECURE:` (JavaScript)
- Inline comments explain the "why" for security decisions
- Comments above code blocks show input/output transformations and risks
- Python uses triple-quoted docstrings for functions and classes
- Docstrings include purpose, security context, and potential issues
- Example from `broken-access-control.py`:
- JavaScript uses block comments `// Comment` and explicit documentation inline
- No JSDoc tags (@param, @returns) observed; focus is on narrative description

## Function Design

- Functions are typically 5-30 lines for simple operations
- Complex operations (e.g., logging middleware) may reach 40+ lines
- Decorators in Python keep cross-cutting concerns separate from business logic
- Functions accept only required parameters
- Defaults avoided unless sensible (e.g., optional severity='INFO')
- Express route handlers follow pattern: `(req, res) => { ... }`
- Decorator factories follow closure pattern: `def decorator(func): def wrapper(*args, **kwargs): ...`
- Functions return dictionaries/JSON objects with predictable shape: `{ status: "success", data: ... }`
- HTTP handlers return responses: `res.json(data)`, `res.status(code).json(error)`
- Decorators return wrapped functions (middleware pattern)
- Boolean returns for simple checks: `success = self.validate_credentials(...)`

## Module Design

- **Python:** Classes and functions are module-level; no explicit exports (entire module is library)
- **JavaScript:** Explicit `module.exports = { func1, func2, ... }` at end of file
- Examples are typically self-contained (can be run standalone with `node` or `python3 -m`)
- Not used in this codebase
- Each skill has its own example files; no re-export index
- Heavy use of Python decorators for authentication, authorization, and audit logging
- Express middleware functions for CORS, security headers, request validation
- Decorators return wrapped functions with same signature as original
- Middleware chains applied with `app.use()` or route-specific: `app.get('/path', middleware1, middleware2, handler)`

## Security-Specific Patterns

- Every code file contains side-by-side `VULNERABLE` and `SECURE` implementations
- Pattern markers: `===== VULNERABLE: [Description] =====` and `===== SECURE: [Description] =====`
- Vulnerable code shows the anti-pattern first, then secure code shows the fix
- Inline comments in vulnerable sections explain the risk; secure sections explain the defense
- Never expose internal system details to users
- Generic error messages: `{ error: "Internal server error" }` instead of stack traces
- Log detailed errors internally; return sanitized errors to clients
- HTTP status codes guide the client: 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Error
- Secrets loaded from environment variables only: `process.env.API_KEY`, `os.getenv('DATABASE_ENCRYPTION_KEY')`
- No hardcoded keys/passwords (examples show anti-pattern for education)
- Configuration validation: throw if required env var missing

<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

## System Overview

```text

```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| **Activation & Routing** | Detects security-related prompts via keyword matching, confidence scoring, and context analysis; routes to appropriate standard/skill based on code type | `owasp-css.instructions.md`, `skill.json` |
| **Main Guidance** | Consolidated reference covering all 6 OWASP standards + secure coding practices; provides detection signals, checklists, and code examples | `owasp-comprehensive-security-skills.md` |
| **Vulnerability Assessment** | Structured workflow for auditing code against OWASP standards (Top 10, ASVS, MASVS, API Security, Kubernetes, Agentic Apps); includes pattern references and scanning scripts | `skills/owasp-security-audit/` |
| **Best Practices Audit** | Structured workflow for evaluating code against the OWASP Secure Coding Practices Quick Reference Guide (14 domains, 100+ checklist items) | `skills/secure-coding-practices/` |
| **Reference Documentation** | Standard-specific guidance: detection clues, mitigation strategies, compliance requirements organized by domain/category | `skills/*/references/` |
| **Pattern Examples** | Paired vulnerable/secure code samples across Python, JavaScript, YAML, HTML, showing how to fix common issues | `examples/`, `skills/*/assets/examples/` |
| **Scanning & Tooling** | Quick-scan script to find hardcoded credentials, debug flags, weak crypto, dangerous patterns via regex; generates leads for manual analysis | `skills/owasp-security-audit/scripts/quick_scan.py` |

## Pattern Overview

- **Context-Aware Activation** — Skill auto-activates on security-related prompts across 7 contexts (web, API, mobile, K8s, AI/LLM, compliance, secure coding)
- **Standard-Specific Routing** — Routes to appropriate OWASP standard or SCP based on code type (web → Top 10, REST → API Security, pod manifests → Kubernetes, etc.)
- **Reference-Based Assessment** — Audits ground findings in standard definitions, checklists, and pattern libraries rather than generic rules
- **Dual Workflows** — Vulnerability assessment (what could go wrong) + best practices audit (does it follow guidelines) operate in parallel
- **Evidence-Grounded Reporting** — Every finding cites specific file paths, line numbers, and code snippets; connects to standard sections

## Layers

- Purpose: Detect when skill should activate; route to appropriate standard/workflow based on prompt and code context
- Location: `owasp-css.instructions.md`, `skill.json`
- Contains: Trigger keyword sets (e.g., "SQL", "pod", "prompt injection"), context mappings (web → Top 10), confidence thresholds
- Depends on: Nothing (entry point)
- Used by: AI assistant (Claude, Copilot) to decide when to invoke skill
- Purpose: Provide comprehensive, standard-specific guidance organized as lookup indices and checklists
- Location: `skills/owasp-security-audit/references/`, `skills/secure-coding-practices/references/`, `owasp-comprehensive-security-skills.md`
- Contains: OWASP standard definitions, detection clues, mitigation strategies, compliance requirements, vulnerability patterns
- Depends on: Nothing (reference data, no runtime dependencies)
- Used by: Auditor workflows to ground findings and cross-reference against standards
- Purpose: Execute structured audit workflow against OWASP standards
- Location: `skills/owasp-security-audit/SKILL.md`, referenced via router
- Contains: Audit steps (scope, scan, read code like attacker would, cross-reference), workflow guidance, script invocation rules
- Depends on: Reference layer (loads appropriate standard refs), scanning layer (executes quick_scan.py)
- Used by: Security review requests (code audit, vulnerability assessment, compliance check)
- Purpose: Execute structured audit workflow against OWASP Secure Coding Practices checklist
- Location: `skills/secure-coding-practices/SKILL.md`, referenced via router
- Contains: Audit steps (scope, load checklist, read code like defender would, cross-reference, report), 14-domain checklist, pattern library
- Depends on: Reference layer (loads SCP checklist and patterns)
- Used by: Best practices review requests ("review for secure coding", "SCP compliance", "does this follow guidelines?")
- Purpose: Provide paired vulnerable/secure code examples by language, framework, vulnerability type
- Location: `examples/`, `skills/*/assets/examples/`
- Contains: Real code snippets in Python, JavaScript, YAML, HTML, shell demonstrating both insecure and hardened implementations
- Depends on: Nothing (reference examples)
- Used by: Both auditor workflows as concrete fix templates and learning aids
- Purpose: Automatically detect obvious anti-patterns (hardcoded credentials, debug mode, weak crypto, dangerous calls) via regex scanning
- Location: `skills/owasp-security-audit/scripts/quick_scan.py`
- Contains: Python script with pattern sets for common issues, regex rules, output formatting
- Depends on: File system (reads source files)
- Used by: Vulnerability auditor to generate initial lead list before manual code review

## Data Flow

### Primary Request Path (Vulnerability Assessment)

### Secondary Request Path (Best Practices Assessment)

### Error Paths & Missing Control Detection

- **Absence-of-Control Finding** — No auth middleware, no rate limiting, no encryption, no logging, no input validation. These often aren't found by pattern matching; they come from understanding the threat model and reading what should be there but isn't.
- **Ambiguous Code** — If findings depend on context not visible in the snippet (e.g., "is this endpoint rate-limited by API gateway?"), the auditor asks a clarifying question before finalizing the report.
- No persistent state — Each review is stateless (no stored audit history, no prior findings carry forward)
- Context only lives in the prompt/request (user provides code, standard selection is deterministic from code type)
- Reference files are immutable lookup indices (never written to during a review)

## Key Abstractions

- Purpose: Encapsulates the multi-step process of evaluating code against a standard
- Examples: `skills/owasp-security-audit/SKILL.md` (vulnerability workflow), `skills/secure-coding-practices/SKILL.md` (best practices workflow)
- Pattern: 5-step procedure — scope, load reference, read code (from attacker/defender perspective), cross-reference, report
- Purpose: Provides a lookup index for a specific OWASP standard or domain
- Examples: `skills/owasp-security-audit/references/top10.md` (web app risks), `references/scp-checklist.md` (best practices domains)
- Pattern: Organized by category (A01-A10 for Top 10), with detection clues, checklists, and mitigation examples
- Purpose: Pairs vulnerable code with secure implementation to show how to fix a category of issue
- Examples: `examples/broken-access-control.py` (OWASP Top 10 A01), `examples/api-auth-bypass.js` (API Security)
- Pattern: Vulnerable snippet → explanation → secure snippet → testing guidance
- Purpose: Regex-based pattern matcher for obviously problematic code (hardcoded secrets, debug flags, dangerous calls)
- Examples: `r"debug\s*=\s*True"` (Flask debug mode), `r"sk-[A-Za-z0-9]{20,}"` (OpenAI-style API key)
- Pattern: Regex → confidence level → severity mapping

## Entry Points

- Location: `owasp-css.instructions.md`
- Triggers: Security-related prompts (code review, audit, compliance, vulnerability assessment, "is this secure?")
- Responsibilities: Identifies that skill should activate, provides guidance on when to use vulnerability vs. best-practices workflow
- Location: `skills/owasp-security-audit/SKILL.md`
- Triggers: When auditor chooses vulnerability-focused assessment (e.g., "Review for OWASP vulnerabilities", "Audit this endpoint for security issues")
- Responsibilities: Loads appropriate standard reference, optionally runs quick_scan.py, guides manual code review, produces vulnerability report
- Location: `skills/secure-coding-practices/SKILL.md`
- Triggers: When auditor chooses best-practices-focused assessment (e.g., "Review for secure coding practices", "SCP compliance audit")
- Responsibilities: Loads SCP checklist, guides code review from defender perspective, cross-references findings to domains, produces compliance report
- Location: `skills/owasp-security-audit/scripts/quick_scan.py`
- Triggers: Automatically run by vulnerability auditor workflow when auditing files/directories
- Responsibilities: Scans source code for hardcoded credentials, debug flags, weak crypto, SQL injection patterns, XSS sinks, dangerous subprocess calls, returns pattern matches with line numbers

## Architectural Constraints

- **No code execution** — This is a reference skill; it does not run code, execute tests, or make HTTP requests. All assessment is via code inspection and pattern matching.
- **Language-agnostic core** — The OWASP standards and SCP checklist apply across languages (Python, JavaScript, Go, Rust, Java, etc.). Language-specific examples and patterns are in the reference files, but the core workflow is universal.
- **No persistent audit history** — Each review starts fresh; there's no database of prior findings, vulnerability tracking, or trend analysis.
- **Single-threaded, request-response** — No background jobs, webhooks, or asynchronous processing. The auditor responds to a single user request with a single structured report.
- **Reference immutability** — OWASP standard definitions and SCP checklists are read-only; they're updated manually when new standards are released, never dynamically generated or modified by the auditor.
- **Context-limited** — The auditor can only see code pasted in the prompt or files accessed via the file system. No integration with CI/CD pipelines, version control, or live running systems.
- **No global mutable state** — Each skill instance is independent; there's no shared memory between concurrent audits or cross-request state.

## Anti-Patterns

### Anti-Pattern: Vulnerability Checklist as Sole Assessment

### Anti-Pattern: Pattern Matching Without Threat Context

### Anti-Pattern: Confusing Absence of Control with Explicit Vulnerability

## Error Handling

- **Ambiguous code** — If a finding depends on context not visible in the snippet, ask one clarifying question. If unclear after asking, note the assumption in the report (e.g., "Assuming this endpoint is internet-facing; if internal-only, risk is lower").
- **Missing information** — If threat model is unclear (is this library code, backend service, or embedded system?), ask. If compliance context is unknown (L1, L2, L3?), offer to assess at all levels.
- **Findings with caveats** — Some patterns look suspicious but have legitimate use cases (e.g., `exec()` with user input is dangerous, but `subprocess.run()` with a list of args is safe; dynamic `eval()` is dangerous, but `ast.literal_eval()` is safe for JSON-like input). In reports, always explain why the pattern is dangerous AND when it's acceptable.

## Cross-Cutting Concerns

<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
