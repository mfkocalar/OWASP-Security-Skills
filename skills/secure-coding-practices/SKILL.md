---
name: secure-coding-practices
description: Audit code against the OWASP Secure Coding Practices Quick Reference Guide checklist. Covers 14 critical domains including input validation, output encoding, authentication, session management, access control, cryptographic practices, error handling & logging, data protection, communication security, system configuration, database security, file management, memory management, and general coding practices. Triggers on requests like "review this code for secure practices", "audit for SCP compliance", "check if this follows secure coding", or when examining code with data handling, authentication, database queries, file operations, or system configuration without explicit security context.
---

# OWASP Secure Coding Practices Audit

This skill turns Claude into a rigorous auditor that applies the OWASP Secure Coding Practices (SCP) Quick Reference Guide checklist to evaluate code quality and security posture, grounds every finding in observable evidence, and produces a structured, actionable compliance report.

## When this skill applies

Any request that asks Claude to evaluate code against secure coding practices, conduct compliance audits, or harden code: SCP reviews, secure coding audits, compliance checks, "does this follow best practices?" questions. Also trigger when the user pastes code involving data handling, input processing, authentication, database operations, file management, or cryptography without explicitly mentioning security. That's when the value is highest.

## How to use this skill

This skill provides two main workflows:

1. **Quick Audit** — for snippets and individual functions (5-50 lines)
2. **Comprehensive Audit** — for files, directories, or full codebases

Both reference the OWASP SCP checklist organized into 14 domains:
- Input validation
- Output encoding
- Authentication and password management
- Session management
- Access control
- Cryptographic practices
- Error handling and logging
- Data protection
- Communication security
- System configuration
- Database security
- File management
- Memory management
- General coding practices

## Audit workflow

Run these steps in order. Skipping ahead means you missed context.

### 1. Scope the review

Pin down three things before reading any code:

- **Target:** snippet, file, directory, or repo? A 30-line paste and an
  audit of `backend/` need different shapes. Ask if unclear.
- **Stack:** language, framework, runtime. A SCP finding in Django reads different from one in raw SQL or C.
- **Threat context:** internet-facing, internal-only, or library? High-trust vs. low-trust boundaries change which checklist items are critical.

Ask one targeted clarifying question if ambiguity would change the findings. Don't interrogate.

### 2. Load the reference checklist

Open `references/scp-checklist.md` and scan for the domains that apply to the code:

| If you see… | Focus on… |
| --- | --- |
| Form input, query strings, API bodies, file uploads | Input validation |
| HTML templates, JSON responses, SQL queries | Output encoding |
| Login flows, password storage, MFA, account lockout | Authentication and password management |
| Cookies, session tokens, logout logic | Session management |
| Role checks, permission enforcement, resource ownership | Access control |
| Keys, encryption, random number generation | Cryptographic practices |
| Error messages, logs, stack traces | Error handling and logging |
| Caching, sensitive data in memory, client-side storage | Data protection |
| TLS, HTTPS, external APIs, redirects | Communication security |
| Server patches, unnecessary services, HTTP methods | System configuration |
| SQL queries, prepared statements, connection strings | Database security |
| File uploads, downloads, path traversal, temp files | File management |
| Buffer handling, memory allocation, NULL terminators | Memory management |
| Threading, race conditions, hardcoded values, code generation | General coding practices |

For a standard-by-standard compliance audit, read the reference end-to-end and walk through each relevant requirement. Otherwise, treat it as a lookup index.

### 3. Read the code the way a defender would

For each handler, function, or module:

- **What untrusted data enters here?** URL params, form fields, API bodies, uploads, environment variables, database rows, third-party API responses.
- **Where does that data go?** SQL queries, shell commands, filesystem paths, HTML output, JSON responses, deserialization, authorization decisions.
- **What's protecting it?** Input validation, output encoding, parameterized queries, access checks, rate limits, audit logs.
- **What's missing?** Often absence of controls is the finding: no input validation, no encoding, no rate limit, no audit log, no TLS, no prepared statements.

### 4. Cross-reference against the checklist

For each suspected gap, look it up in `references/scp-checklist.md` and note:

- **Which domain(s)** it violates
- **Which specific checklist items** are not met
- **Why it matters** (harm model: injection, data leak, unauthorized access, DoS, etc.)
- **How to fix it** (code example, test case, or reference to `assets/examples/`)

### 5. Produce a structured report

Group findings by domain, rank by severity (Critical, High, Medium, Low), and for each:

- **Checklist item(s)** violated
- **Evidence** (file, line, code snippet)
- **Risk** (attack scenario, compliance impact)
- **Remediation** (code change, control to add, test to write)

Omit passing domains unless the audit is a full compliance check; focus on what needs to change.

## Detection signals (Common patterns by domain)

### Input validation gaps
- No validation of URL params, form fields, or API bodies
- Validation on client only, not server
- Allow-list not used (using deny-list instead)
- Character set not specified
- UTF-8 canonicalization skipped
- Input length not checked
- Redirects followed without validation
- Range checks missing (e.g., age, page number)

### Output encoding gaps
- No encoding when inserting data into HTML, SQL, or URLs
- Encoding on client only
- Context-specific encoding not used (HTML vs. SQL vs. URL)
- Template auto-escape disabled
- User data inserted into unsafe constructs (innerHTML, eval, etc.)
- Character set not specified for responses

### Authentication gaps
- No authentication check, or check only on client
- Passwords stored in plaintext or weak hash
- Default credentials not changed
- No account lockout after failed attempts
- No MFA for sensitive accounts
- Session not regenerated after login
- Password reset link has no expiration
- No re-authentication for critical operations

### Session management gaps
- Custom session logic instead of framework default
- Session ID created client-side
- Session ID predictable or insufficient randomness
- Session ID exposed in URLs or logs
- No logout (sessions not terminated)
- No session timeout (inactivity)
- Cookies lack secure/httponly flags
- No CSRF token for state-changing requests
- Concurrent logins allowed

### Access control gaps
- Authorization checks only on client
- No centralized access control module
- Direct object reference (e.g., `/user/123` with no ownership check)
- No role/permission checks on protected endpoints
- Privilege escalation not prevented
- Resource access not limited by user ownership
- No rate limiting or per-user quotas
- Configuration/security settings accessible to unauthorized users

### Cryptographic gaps
- Hard-coded encryption keys or credentials
- Weak algorithms (MD5, SHA1, DES, etc.)
- Random number generation not cryptographically secure
- Keys stored in plain text or client-side
- No key rotation policy
- Crypto operations not on server-side only
- Modules not FIPS 140-2 compliant (if required)

### Error handling & logging gaps
- Error messages expose system details (stack traces, SQL, file paths)
- Sensitive data in logs (passwords, tokens, PII)
- No logging of security events (login, access denial, tampering)
- Logs not protected from unauthorized access
- No centralized logging
- Log analysis and alerting missing
- No audit trail for administrative changes

### Data protection gaps
- Sensitive data cached or in temporary files without encryption
- Passwords or API keys in client-side code or comments
- Sensitive data in GET request parameters (URLs)
- Autocomplete not disabled on sensitive forms
- Client-side caching not disabled on sensitive pages
- Sensitive data not deleted when no longer needed
- No access controls on cached/temporary files

### Communication security gaps
- No TLS for authenticated or sensitive data
- TLS certificate invalid or expired
- HTTP allowed when HTTPS required
- Fallback to HTTP allowed
- Sensitive headers exposed in referer
- Character encoding not specified for connections
- External API calls not encrypted

### System configuration gaps
- Outdated or unpatched server/framework versions
- Unnecessary services or ports open
- Directory listing enabled
- Test code or debug mode in production
- Unnecessary files or functionality deployed
- Error pages reveal system details
- robots.txt exposes private directories
- Unnecessary HTTP methods not disabled
- OS/server version leaked in response headers

### Database security gaps
- Dynamic SQL queries (no prepared statements or parameterization)
- Database user has admin privileges instead of least-privilege
- Hard-coded connection strings or credentials
- Default database passwords not changed
- Connection not closed promptly
- No input validation before queries
- No output encoding for query results
- Stored procedures not used for data abstraction

### File management gaps
- User-supplied file paths used directly (path traversal)
- File upload not authenticated
- File type validation based on extension only (not magic bytes)
- Uploaded files in web-accessible directory
- Upload directory execution privileges not disabled
- Dynamic includes from user input
- File downloads bypass access controls
- Absolute file paths sent to client

### Memory management gaps
- Buffer overflow risks (fixed buffers, no bounds checking)
- Not checking buffer size before operations
- NULL terminators not handled correctly
- Loop bounds not verified
- Resources not explicitly freed (memory leak)
- Sensitive data not overwritten before deallocation
- Known vulnerable functions used (strcpy, gets, etc.)
- Stack canaries or NX not enabled (if applicable)

### General coding practices gaps
- Dynamic code execution from user input (eval, exec, etc.)
- Race conditions in shared resource access
- No synchronization/locking for concurrent access
- Uninitialized variables used
- Privileges raised permanently instead of dropped early
- Third-party code/libraries not reviewed
- No integrity verification (checksums, signatures)
- Update mechanism not encrypted

## Reference resources

- **OWASP SCP Checklist:** `references/scp-checklist.md`
- **Vulnerable code examples:** `assets/examples/` (organized by language and domain)
- **Remediation patterns:** `references/secure-patterns.md`

## When NOT to use this skill

- If the user explicitly asks for OWASP Top 10 (use owasp-security-audit skill)
- If the focus is on API-specific security (use owasp-security-audit + API Top 10)
- If auditing Kubernetes manifests (use owasp-security-audit + Kubernetes Top 10)
- If auditing LLM/agent code (use owasp-security-audit + LLM Top 10)
- General code review not focused on security

If in doubt, use this skill for any "is this code written securely?" question.
