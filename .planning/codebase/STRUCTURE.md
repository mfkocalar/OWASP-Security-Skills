# Codebase Structure

**Analysis Date:** 2026-07-19

## Directory Layout

```
OWASP-Security-Skills/
├── .planning/                          # Planning documents (codebase analysis)
│   └── codebase/
│
├── skills/                             # Modular skill implementations
│   ├── owasp-security-audit/          # Vulnerability assessment skill
│   │   ├── SKILL.md                   # Skill definition and workflow
│   │   ├── owasp-security-audit.md    # Metadata (frontmatter + guide)
│   │   ├── references/                # OWASP standard references
│   │   │   ├── top10.md               # OWASP Top 10 (2021)
│   │   │   ├── api-top10.md           # API Security Top 10 (2023)
│   │   │   ├── asvs.md                # ASVS 5.0 requirements
│   │   │   ├── masvs.md               # MASVS v2.1.0 (mobile)
│   │   │   ├── kubernetes-top10.md    # Kubernetes Top 10 (2022)
│   │   │   ├── llm-agentic.md         # Agentic Applications 2026
│   │   │   ├── vulnerable-patterns.md # Paired vulnerable/secure snippets
│   │   │   └── owasp-urls.json        # URLs and references
│   │   ├── scripts/
│   │   │   └── quick_scan.py          # Regex-based pattern scanner
│   │   └── assets/
│   │       └── examples/              # Example code from root, symlinked or copied
│   │           ├── broken-access-control.py
│   │           ├── cryptographic-failures.js
│   │           ├── injection.js
│   │           ├── security-misconfiguration.py
│   │           ├── xss.html
│   │           ├── logging-monitoring-failures.py
│   │           ├── api-auth-bypass.js
│   │           ├── k8s-rbac.yaml
│   │           └── prompt-injection.txt
│   │
│   └── secure-coding-practices/       # Best practices audit skill
│       ├── SKILL.md                   # Skill definition and workflow
│       ├── secure-coding-practices.md # User guide (14 domains)
│       ├── README.md                  # Overview
│       ├── references/
│       │   ├── scp-checklist.md       # 100+ checklist items (14 domains)
│       │   ├── secure-patterns.md     # Secure code patterns by language
│       │   └── owasp-urls.json        # Reference URLs
│       └── assets/
│           └── examples/
│               ├── vulnerable-examples.py
│               └── vulnerable-examples.js
│
├── examples/                           # Root-level example files (canonical source)
│   ├── broken-access-control.py       # A01: Broken Access Control
│   ├── cryptographic-failures.js      # A02: Cryptographic Failures
│   ├── injection.js                   # A03: Injection (SQL)
│   ├── security-misconfiguration.py   # A05: Security Misconfiguration
│   ├── xss.html                       # A07: Injection (XSS)
│   ├── logging-monitoring-failures.py # A09: Logging & Monitoring Failures
│   ├── api-auth-bypass.js             # API Security: Auth Bypass
│   ├── k8s-rbac.yaml                  # Kubernetes Top 10: RBAC
│   └── prompt-injection.txt           # Agentic Apps: Prompt Injection
│
├── owasp-comprehensive-security-skills.md    # Main reference guide (6 standards)
├── owasp-css.instructions.md                  # Activation triggers and routing
├── skill.json                                 # Skill manifest (metadata, version, models)
│
├── install.sh                          # Interactive installer (symlinks/copies to ~/.claude/skills/)
│
├── README.md                           # Project overview
├── CONTRIBUTING.md                     # Contribution guidelines
├── DEPLOYMENT.md                       # Deployment and installation guide
├── TESTING.md                          # Testing procedures and verification
│
├── .gitignore                          # Git ignore rules
└── .git/                               # Git repository
```

## Directory Purposes

**Root Level:**
- Purpose: Project metadata, main entry point, and example files
- Contains: README, installation script, skill manifest, contribution guidelines
- Key files: `skill.json` (metadata), `install.sh` (setup), `owasp-css.instructions.md` (activation logic)

**`skills/`:**
- Purpose: Container for modular skill implementations
- Contains: Two independent skills (vulnerability audit, best practices audit), each with its own workflow, references, and examples
- Why separate: Skills can be deployed independently; each has its own SKILL.md defining activation and workflow

**`skills/owasp-security-audit/`:**
- Purpose: Vulnerability assessment skill for OWASP standards
- Contains: Workflow definition, references for 6 standards, pattern scanner, example files
- Key files: `SKILL.md` (workflow), `references/top10.md` (entry point), `scripts/quick_scan.py` (scanner)
- Usage: Route here when user asks to audit code for vulnerabilities, security risks, OWASP compliance

**`skills/owasp-security-audit/references/`:**
- Purpose: Lookup indices for each OWASP standard
- Contains: One reference file per standard (top10, api-top10, asvs, masvs, kubernetes, llm-agentic, vulnerable-patterns)
- Pattern: Each file is organized by category (A01-A10, L1-L3, etc.) with detection clues, checklists, mitigations
- Usage: Auditor loads the appropriate reference based on detected code type

**`skills/owasp-security-audit/scripts/`:**
- Purpose: Automated pattern detection via regex scanning
- Contains: Python script that scans source files for hardcoded credentials, debug flags, dangerous calls
- Key files: `quick_scan.py`
- Usage: Run before manual code review to generate initial leads list

**`skills/secure-coding-practices/`:**
- Purpose: Best practices audit skill for OWASP Secure Coding Practices
- Contains: Workflow definition, 14-domain checklist, secure patterns library, example files
- Key files: `SKILL.md` (workflow), `references/scp-checklist.md` (14 domains), `references/secure-patterns.md` (language-specific fixes)
- Usage: Route here when user asks to review code for best practices, SCP compliance, secure development

**`skills/secure-coding-practices/references/`:**
- Purpose: Lookup index and pattern library for secure coding practices
- Contains: Checklist (100+ items across 14 domains), secure code patterns (Python, JavaScript, SQL), reference URLs
- Key files: `scp-checklist.md` (organized by domain), `secure-patterns.md` (vulnerable vs. secure patterns)
- Usage: Auditor loads checklist to scope review; loads patterns to show fixes

**`examples/`:**
- Purpose: Real-world code samples demonstrating vulnerable and secure implementations
- Contains: 9 files covering OWASP Top 10 categories, API security, Kubernetes, and AI/LLM risks
- Pattern: Each file pairs vulnerable code with secure implementation, explains the vulnerability, shows testing approach
- Key files: `broken-access-control.py`, `injection.js`, `k8s-rbac.yaml`, `prompt-injection.txt`
- Usage: Referenced by both audit workflows as concrete fix templates; used in onboarding/demos

## Key File Locations

**Entry Points:**
- `skill.json`: Master manifest defining skill metadata, activation triggers, available standards, available functions
- `owasp-css.instructions.md`: Activation logic and routing rules (when to use vulnerability vs. best-practices workflow)
- `README.md`: Project overview, usage examples, installation instructions

**Core References:**
- `owasp-comprehensive-security-skills.md`: Consolidated reference for all 6 OWASP standards (900 lines); overview with examples
- `skills/owasp-security-audit/references/top10.md`: Deep reference for OWASP Top 10 (entry point for web app audits)
- `skills/owasp-security-audit/references/api-top10.md`: Deep reference for API Security Top 10
- `skills/secure-coding-practices/references/scp-checklist.md`: 14-domain best practices checklist (100+ items)

**Workflows:**
- `skills/owasp-security-audit/SKILL.md`: 5-step vulnerability assessment workflow (scope → scan → read → cross-reference → report)
- `skills/secure-coding-practices/SKILL.md`: 5-step best practices audit workflow (scope → load checklist → read as defender → cross-reference → report)

**Examples & Patterns:**
- `examples/`: Root-level canonical example files (9 files demonstrating Top 10, API, K8s, AI risks)
- `skills/owasp-security-audit/assets/examples/`: Symlinks or copies of root examples (available within skill)
- `skills/secure-coding-practices/assets/examples/`: Vulnerable code examples for SCP domains (Python, JavaScript)
- `skills/secure-coding-practices/references/secure-patterns.md`: Secure code patterns by category and language

**Automation:**
- `skills/owasp-security-audit/scripts/quick_scan.py`: Regex-based pattern scanner (credentials, debug mode, weak crypto, SQL injection sinks)

**Documentation:**
- `DEPLOYMENT.md`: Installation methods, verification steps, troubleshooting
- `TESTING.md`: How to verify skill is installed and working (activation tests, example code walkthrough)
- `CONTRIBUTING.md`: Guidelines for submitting new examples, references, or improvements

## Naming Conventions

**Files:**
- Skill files: UPPERCASE.md (e.g., `SKILL.md`, `README.md`)
- Guides: Lowercase with hyphens (e.g., `secure-coding-practices.md`, `owasp-css.instructions.md`)
- References: Category name (e.g., `top10.md`, `api-top10.md`, `asvs.md`)
- Scripts: Lowercase with underscores (e.g., `quick_scan.py`)
- Examples: Kebab-case vulnerability name (e.g., `broken-access-control.py`, `api-auth-bypass.js`)

**Directories:**
- Skill directories: Lowercase with hyphens (e.g., `owasp-security-audit`, `secure-coding-practices`)
- Standard organizational dirs: Lowercase (e.g., `references`, `scripts`, `assets`, `examples`)

**JSON Files:**
- `skill.json`: Manifest (metadata, standards, activation triggers, file locations, functionality)
- `owasp-urls.json`: Reference URLs (links to OWASP pages, standards documents, tools)

## Where to Add New Code

**New OWASP Standard Reference:**
- Add file to: `skills/owasp-security-audit/references/[standard-name].md`
- Format: Markdown organized by category (A01-A10, L1-L3, K01-K10, etc.), with detection clues, checklists, mitigations
- Update: `skill.json` to register new standard in the `standards` array
- Update: `owasp-css.instructions.md` to add activation triggers for new standard

**New Example Code Sample:**
- Add file to: `examples/[vulnerability-name].[language]` (canonical source)
- Format: Vulnerable code → comment explaining the issue → secure code → testing approach
- Symlink/copy to: `skills/owasp-security-audit/assets/examples/` and/or `skills/secure-coding-practices/assets/examples/`
- Update: `skill.json` `examples_by_category` section to register new file, language, vulnerabilities demonstrated

**New Secure Coding Pattern:**
- Add to: `skills/secure-coding-practices/references/secure-patterns.md`
- Organize by: Domain (Input Validation, Auth, Crypto, etc.), then by language (Python, JavaScript, SQL, etc.)
- Format: Problem statement → vulnerable code → explanation → secure code → test case

**New SCP Checklist Item:**
- Add to: `skills/secure-coding-practices/references/scp-checklist.md`
- Organize by: One of 14 domains (Input Validation, Output Encoding, Auth, Session, Access Control, Crypto, Error Handling, Logging, Data Protection, Comms Security, System Config, Database Security, File Management, Memory Management)
- Format: ☐ Item description (with detection clues, why it matters, how to fix)

**New Scanning Rule:**
- Add to: `skills/owasp-security-audit/scripts/quick_scan.py`
- Format: Regex pattern → severity level (Critical, High, Medium, Low) → message → category (e.g., "credentials", "debug mode", "injection", "crypto")
- Test: Run against all example files to ensure no false positives

**New Activation Trigger:**
- Add to: `owasp-css.instructions.md` (human-readable) and `skill.json` `activation.triggers` array
- Format: Context (web_application, api_security, etc.) → keywords (list of terms) → example prompts (sample user queries that should trigger)

## Special Directories

**`.planning/codebase/`:**
- Purpose: Generated codebase analysis documents (ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, STACK.md, INTEGRATIONS.md, CONCERNS.md)
- Generated: Yes (via `/gsd-map-codebase` agent)
- Committed: Yes (part of project)
- Consumed by: `/gsd-plan-phase`, `/gsd-execute-phase` (phases load these docs when planning implementation)

**`.git/`:**
- Purpose: Git repository metadata and history
- Generated: Yes (version control)
- Committed: N/A (part of .gitignore)

**`skills/*/assets/examples/`:**
- Purpose: Local copies/symlinks of example code files for use within each skill
- Generated: Yes (either hardlinked/symlinked from root examples/ or custom examples)
- Committed: Yes (actual files, not symlinks if committed)
- Note: Keeping both root and skill-local copies ensures each skill is self-contained (can be deployed independently without requiring root/examples/)

## Incremental Changes: Adding a New Skill

If you were to add a new skill (e.g., a "Threat Modeling" skill):

1. **Create directory**: `skills/threat-modeling/`
2. **Add SKILL.md**: Define activation triggers (keywords like "threat model", "attack surface"), workflow (5 steps), entry points
3. **Add references**: `skills/threat-modeling/references/threat-modeling-guide.md` (framework, patterns, example threat models)
4. **Add examples**: `skills/threat-modeling/assets/examples/` (sample threat models for different app types)
5. **Update skill.json**: Add new skill to `files.skills` section, add standards to `standards` array, add activation triggers to `activation.triggers`
6. **Update owasp-css.instructions.md**: Add new skill to routing logic and example prompts
7. **Document in README**: Add threat-modeling to coverage section

The skill would be **independent** — it could be deployed without the other skills, has its own workflow and references, and is activated by separate keywords.

---

*Structure analysis: 2026-07-19*
