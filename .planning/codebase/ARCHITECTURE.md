<!-- refreshed: 2026-07-19 -->
# Architecture

**Analysis Date:** 2026-07-19

## System Overview

This codebase is a **security reference skill** — a modular knowledge system for AI coding assistants (Claude, GitHub Copilot) that brings OWASP standards and secure coding practices into automated security reviews of code, infrastructure, and configuration.

```text
┌─────────────────────────────────────────────────────────────────────┐
│                     Activation & Routing Layer                      │
│            `owasp-css.instructions.md` + `skill.json`               │
│  (Detects security review requests, auto-activates skill)           │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Guidance & Reference Layer                        │
│              (Primary standards and best practices)                   │
├──────────────────────┬──────────────────┬──────────────────────────┤
│   Vulnerability     │   Secure Coding  │     Example Patterns      │
│    Assessment       │    Practices     │  (Vulnerable + Secure)    │
│                     │                  │                           │
│ • Top 10 2021       │ • 14 domains     │ • Python patterns         │
│ • ASVS 5.0          │ • Input validation│ • JavaScript patterns    │
│ • MASVS 2.1.0       │ • Auth/crypto    │ • Infrastructure (YAML)  │
│ • API Security      │ • Data protection│ • Web (HTML/CSS)         │
│ • Kubernetes        │ • Logging        │ • Mobile (iOS/Android)   │
│ • Agentic Apps      │ • 100+ checklist │ • Configuration files    │
└──────────────────────┴──────────────────┴──────────────────────────┘
        ▲                      ▲                      ▲
        │                      │                      │
        │ references/          │ scp-checklist.md     │ assets/
        │ top10.md             │ secure-patterns.md   │ examples/
        │ api-top10.md         │ (code samples)       │
        │ kubernetes.md        │                      │
        │ masvs.md             │                      │
        │ asvs.md              │                      │
        │ llm-agentic.md       │                      │
        │ vulnerable-patterns. │                      │
        │ md                   │                      │
        │                      │                      │
└──────────────────────┬──────────────────┬──────────────────────────┘
                       │                  │
    ┌──────────────────┴──────────────────┴──────────┐
    │                                                │
    ▼                                                ▼
┌────────────────────────────────┐     ┌────────────────────────────────┐
│    owasp-security-audit/       │     │  secure-coding-practices/      │
│    (Vulnerability Auditing)    │     │  (Best Practices Auditing)     │
│  `skills/owasp-security-audit/`│     │`skills/secure-coding-practic/ │
│                                │     │                                │
│ ├─ SKILL.md (workflow)         │     │ ├─ SKILL.md (workflow)         │
│ ├─ references/                 │     │ ├─ references/                 │
│ ├─ scripts/quick_scan.py       │     │ ├─ assets/examples/            │
│ └─ assets/examples/            │     │ └─ secure-coding-practices.md  │
└────────────────────────────────┘     └────────────────────────────────┘
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

**Overall:** **Modular Knowledge System with Dual-Track Assessment**

**Key Characteristics:**
- **Context-Aware Activation** — Skill auto-activates on security-related prompts across 7 contexts (web, API, mobile, K8s, AI/LLM, compliance, secure coding)
- **Standard-Specific Routing** — Routes to appropriate OWASP standard or SCP based on code type (web → Top 10, REST → API Security, pod manifests → Kubernetes, etc.)
- **Reference-Based Assessment** — Audits ground findings in standard definitions, checklists, and pattern libraries rather than generic rules
- **Dual Workflows** — Vulnerability assessment (what could go wrong) + best practices audit (does it follow guidelines) operate in parallel
- **Evidence-Grounded Reporting** — Every finding cites specific file paths, line numbers, and code snippets; connects to standard sections

## Layers

**Activation & Routing Layer:**
- Purpose: Detect when skill should activate; route to appropriate standard/workflow based on prompt and code context
- Location: `owasp-css.instructions.md`, `skill.json`
- Contains: Trigger keyword sets (e.g., "SQL", "pod", "prompt injection"), context mappings (web → Top 10), confidence thresholds
- Depends on: Nothing (entry point)
- Used by: AI assistant (Claude, Copilot) to decide when to invoke skill

**Reference Layer:**
- Purpose: Provide comprehensive, standard-specific guidance organized as lookup indices and checklists
- Location: `skills/owasp-security-audit/references/`, `skills/secure-coding-practices/references/`, `owasp-comprehensive-security-skills.md`
- Contains: OWASP standard definitions, detection clues, mitigation strategies, compliance requirements, vulnerability patterns
- Depends on: Nothing (reference data, no runtime dependencies)
- Used by: Auditor workflows to ground findings and cross-reference against standards

**Vulnerability Auditor Layer:**
- Purpose: Execute structured audit workflow against OWASP standards
- Location: `skills/owasp-security-audit/SKILL.md`, referenced via router
- Contains: Audit steps (scope, scan, read code like attacker would, cross-reference), workflow guidance, script invocation rules
- Depends on: Reference layer (loads appropriate standard refs), scanning layer (executes quick_scan.py)
- Used by: Security review requests (code audit, vulnerability assessment, compliance check)

**Best Practices Auditor Layer:**
- Purpose: Execute structured audit workflow against OWASP Secure Coding Practices checklist
- Location: `skills/secure-coding-practices/SKILL.md`, referenced via router
- Contains: Audit steps (scope, load checklist, read code like defender would, cross-reference, report), 14-domain checklist, pattern library
- Depends on: Reference layer (loads SCP checklist and patterns)
- Used by: Best practices review requests ("review for secure coding", "SCP compliance", "does this follow guidelines?")

**Pattern Library Layer:**
- Purpose: Provide paired vulnerable/secure code examples by language, framework, vulnerability type
- Location: `examples/`, `skills/*/assets/examples/`
- Contains: Real code snippets in Python, JavaScript, YAML, HTML, shell demonstrating both insecure and hardened implementations
- Depends on: Nothing (reference examples)
- Used by: Both auditor workflows as concrete fix templates and learning aids

**Scanning & Tooling Layer:**
- Purpose: Automatically detect obvious anti-patterns (hardcoded credentials, debug mode, weak crypto, dangerous calls) via regex scanning
- Location: `skills/owasp-security-audit/scripts/quick_scan.py`
- Contains: Python script with pattern sets for common issues, regex rules, output formatting
- Depends on: File system (reads source files)
- Used by: Vulnerability auditor to generate initial lead list before manual code review

## Data Flow

### Primary Request Path (Vulnerability Assessment)

1. **User Request** — Pastes code or describes what they're auditing (e.g., "Review this Flask endpoint for OWASP vulnerabilities")
2. **Activation** (`owasp-css.instructions.md`, `skill.json`) — Detects security keywords, calculates confidence, auto-activates if >0.7
3. **Context Detection** — Identifies code type (web, API, mobile, K8s, AI, general) from syntax/keywords
4. **Router Decision** — Maps context to primary OWASP standard (e.g., REST API → API Security Top 10)
5. **Load References** (`skills/owasp-security-audit/references/`) — Fetches standard-specific reference (top10.md, api-top10.md, etc.)
6. **Quick Scan** (optional, for files/dirs) — Runs `scripts/quick_scan.py` to find obvious patterns, generates initial leads list
7. **Manual Code Review** — Reads code like attacker would: Who accesses? What input? What sinks? What's missing?
8. **Cross-Reference** — For each finding, looks up in reference docs to confirm category, severity, checklist items
9. **Load Pattern Examples** — Fetches vulnerable/secure pairs from `examples/` or `assets/examples/` to show fix
10. **Structured Report** — Outputs findings grouped by OWASP category, ranked by severity, with file:line, code snippet, mitigation steps

### Secondary Request Path (Best Practices Assessment)

1. **User Request** — Asks to review code against "secure coding practices", "SCP compliance", or general best practices
2. **Activation** (`owasp-css.instructions.md`, `skill.json`) — Detects SCP keywords
3. **Router Decision** — Routes to `secure-coding-practices/SKILL.md` workflow
4. **Scope Review** — Clarifies: snippet, file, or directory? Language/framework? Threat context?
5. **Load Checklist** (`references/scp-checklist.md`) — Fetches 14-domain checklist with 100+ items
6. **Code Review as Defender** — Traces data flow: untrusted input → processing → output; identifies where controls are missing
7. **Cross-Reference** — Maps findings to specific SCP domains and checklist items
8. **Load Secure Patterns** (`references/secure-patterns.md`) — Fetches language-specific secure patterns for fixes
9. **Structured Report** — Outputs findings grouped by SCP domain (Input Validation, Auth, Crypto, Logging, etc.), ranked by severity, with remediation code

### Error Paths & Missing Control Detection

- **Absence-of-Control Finding** — No auth middleware, no rate limiting, no encryption, no logging, no input validation. These often aren't found by pattern matching; they come from understanding the threat model and reading what should be there but isn't.
- **Ambiguous Code** — If findings depend on context not visible in the snippet (e.g., "is this endpoint rate-limited by API gateway?"), the auditor asks a clarifying question before finalizing the report.

**State Management:**
- No persistent state — Each review is stateless (no stored audit history, no prior findings carry forward)
- Context only lives in the prompt/request (user provides code, standard selection is deterministic from code type)
- Reference files are immutable lookup indices (never written to during a review)

## Key Abstractions

**Auditor Workflow:**
- Purpose: Encapsulates the multi-step process of evaluating code against a standard
- Examples: `skills/owasp-security-audit/SKILL.md` (vulnerability workflow), `skills/secure-coding-practices/SKILL.md` (best practices workflow)
- Pattern: 5-step procedure — scope, load reference, read code (from attacker/defender perspective), cross-reference, report

**Standard Reference:**
- Purpose: Provides a lookup index for a specific OWASP standard or domain
- Examples: `skills/owasp-security-audit/references/top10.md` (web app risks), `references/scp-checklist.md` (best practices domains)
- Pattern: Organized by category (A01-A10 for Top 10), with detection clues, checklists, and mitigation examples

**Pattern Library:**
- Purpose: Pairs vulnerable code with secure implementation to show how to fix a category of issue
- Examples: `examples/broken-access-control.py` (OWASP Top 10 A01), `examples/api-auth-bypass.js` (API Security)
- Pattern: Vulnerable snippet → explanation → secure snippet → testing guidance

**Scanning Rule:**
- Purpose: Regex-based pattern matcher for obviously problematic code (hardcoded secrets, debug flags, dangerous calls)
- Examples: `r"debug\s*=\s*True"` (Flask debug mode), `r"sk-[A-Za-z0-9]{20,}"` (OpenAI-style API key)
- Pattern: Regex → confidence level → severity mapping

## Entry Points

**Main Skill Activation:**
- Location: `owasp-css.instructions.md`
- Triggers: Security-related prompts (code review, audit, compliance, vulnerability assessment, "is this secure?")
- Responsibilities: Identifies that skill should activate, provides guidance on when to use vulnerability vs. best-practices workflow

**Vulnerability Assessment Workflow:**
- Location: `skills/owasp-security-audit/SKILL.md`
- Triggers: When auditor chooses vulnerability-focused assessment (e.g., "Review for OWASP vulnerabilities", "Audit this endpoint for security issues")
- Responsibilities: Loads appropriate standard reference, optionally runs quick_scan.py, guides manual code review, produces vulnerability report

**Best Practices Assessment Workflow:**
- Location: `skills/secure-coding-practices/SKILL.md`
- Triggers: When auditor chooses best-practices-focused assessment (e.g., "Review for secure coding practices", "SCP compliance audit")
- Responsibilities: Loads SCP checklist, guides code review from defender perspective, cross-references findings to domains, produces compliance report

**Quick Scanner:**
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

**What happens:** Auditor runs through a generic OWASP checklist item-by-item regardless of code type, context, or threat model.
**Why it's wrong:** A checklist answer "not applicable" for 80% of items wastes time and misses context-specific risks. SQL injection checklist items aren't relevant in a Kubernetes RBAC review. Rate limiting is critical for public APIs but irrelevant for internal microservices.
**Do this instead:** Use the routing layer (`skill.json`, `owasp-css.instructions.md`) to select the right standard for the code type. For vulnerability assessment, detect context first (web → Top 10, REST → API Security, pod manifest → Kubernetes) before opening references. For best practices, ask clarifying questions about threat model (internet-facing vs. internal) to rank which SCP domains are critical.

### Anti-Pattern: Pattern Matching Without Threat Context

**What happens:** Auditor flags a finding (e.g., "hardcoded API key") without understanding whether that API key would actually be exposed (e.g., if it's in a .env file that's not committed to git, risk is lower; if it's in app code deployed to production, risk is high).
**Why it's wrong:** False positives reduce trust; real impact depends on data flow and deployment model.
**Do this instead:** When running `quick_scan.py`, treat hits as **leads, not verdicts**. In manual review, always understand: Who can access this code? Is this in source, git, Docker image, or just local dev? What privilege would an attacker gain by using this key? Then cross-reference the threat model against the finding severity.

### Anti-Pattern: Confusing Absence of Control with Explicit Vulnerability

**What happens:** Auditor flags "no rate limiting on login endpoint" and "no security headers set" but doesn't distinguish between: a) the code attempts rate limiting and it's broken (explicit vulnerability) vs. b) rate limiting isn't in the code at all (absence of control, may be by design at gateway level).
**Why it's wrong:** The fix strategy is completely different. Broken rate limiting is a code-level bug. Missing rate limiting might be correct if an API gateway enforces it upstream.
**Do this instead:** Ask clarifying questions ("Is rate limiting enforced at API gateway level?") before flagging. In the report, distinguish: "Absence of control" (might be delegated elsewhere) vs. "Explicit misconfiguration" (broken implementation).

## Error Handling

**Strategy:** **Evidence-Based Assessment with Uncertainty Disclosure**

**Patterns:**
- **Ambiguous code** — If a finding depends on context not visible in the snippet, ask one clarifying question. If unclear after asking, note the assumption in the report (e.g., "Assuming this endpoint is internet-facing; if internal-only, risk is lower").
- **Missing information** — If threat model is unclear (is this library code, backend service, or embedded system?), ask. If compliance context is unknown (L1, L2, L3?), offer to assess at all levels.
- **Findings with caveats** — Some patterns look suspicious but have legitimate use cases (e.g., `exec()` with user input is dangerous, but `subprocess.run()` with a list of args is safe; dynamic `eval()` is dangerous, but `ast.literal_eval()` is safe for JSON-like input). In reports, always explain why the pattern is dangerous AND when it's acceptable.

## Cross-Cutting Concerns

**Logging:** Reference logs only — there's no live logging in this skill. Documentation and SKILL.md files explain what to audit for in application logs (authentication events, access denials, security events, no sensitive data in logs).

**Validation:** The reference files embed validation rules (input validation checklist in SCP, parameterized query requirement in Top 10 SQL injection section, JWT signature validation in API Security). The auditor applies these to code; there's no centralized validation engine.

**Authentication:** Again, reference-only. The skill teaches what secure authentication looks like (bcrypt/Argon2 for password hashing, MFA for sensitive ops, cryptographically secure session IDs, rate limiting on login) but doesn't implement it. Auditors use these principles to review code.

**Authorization:** The core vulnerability pattern in Top 10 A01 (Broken Access Control). Every standard includes authorization checks in its reference. The auditor looks for: Is authorization verified server-side for every sensitive operation? Is there a default-deny policy? Are resource ownership checks in place?

---

*Architecture analysis: 2026-07-19*
