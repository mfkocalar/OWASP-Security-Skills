# Secure Coding Practices Skill Guide

**Skill Name:** `secure-coding-practices`

**Purpose:** Conduct OWASP-aligned secure coding practices audits on source code, highlighting violations of the 14 critical domains in the OWASP Secure Coding Practices Quick Reference Guide.

**Reference:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist.html

---

## Quick Start

### When to invoke this skill

Use this skill when:
- Code needs review against secure coding best practices
- Conducting a security audit or compliance check
- Evaluating code for common vulnerabilities and misconfigurations
- Examining code with data handling, authentication, database queries, or file operations
- Asking "is this code written securely?" or "does this follow best practices?"

Example trigger phrases:
- "Review this code for secure coding practices"
- "Audit this for SCP compliance"
- "Does this follow OWASP secure coding guidelines?"
- "Check if this input validation is secure"

### When NOT to invoke this skill

- If auditing against OWASP Top 10 → use `owasp-security-audit` skill
- If auditing REST/GraphQL APIs → use `owasp-security-audit` + API Top 10
- If auditing Kubernetes manifests → use `owasp-security-audit` + Kubernetes Top 10
- If auditing LLM/agent code → use `owasp-security-audit` + LLM Top 10

---

## The 14 Domains

### 1. **Input Validation**
- Validate all untrusted input on the server-side
- Use allow-lists, not deny-lists
- Check data type, range, length, and format
- Canonicalize input before validation
- **Common gap:** Client-side validation only; no server-side checks

### 2. **Output Encoding**
- Encode output contextually based on target (HTML, SQL, URL, etc.)
- Perform encoding on the server-side
- Use framework auto-escape where available
- **Common gap:** User data inserted directly into templates or queries

### 3. **Authentication & Password Management**
- Use centralized, tested authentication services
- Hash passwords with strong algorithms (bcrypt, Argon2)
- Enforce password complexity and length
- Implement account lockout after failed attempts
- Use MFA for sensitive accounts
- **Common gap:** Plaintext passwords; no lockout; generic error messages too specific

### 4. **Session Management**
- Use framework session management, not custom logic
- Generate session IDs server-side with sufficient randomness
- Set secure, HttpOnly, SameSite cookie flags
- Implement session timeout and inactivity logout
- Regenerate session ID after login
- **Common gap:** Predictable session IDs; exposed in URLs/logs; no timeout

### 5. **Access Control**
- Use centralized authorization checks
- Verify resource ownership (prevent direct object reference)
- Enforce authorization on every request
- Deny by default; only grant necessary permissions
- Implement rate limiting and per-user quotas
- **Common gap:** Authorization checks only on client; no ownership verification

### 6. **Cryptographic Practices**
- Use approved algorithms (AES-256, not MD5/SHA1)
- Generate random numbers cryptographically
- Protect encryption keys; never hard-code them
- Implement key rotation policies
- Use authenticated encryption (AES-GCM)
- **Common gap:** Hard-coded keys; weak algorithms; random number generation not cryptographic

### 7. **Error Handling & Logging**
- Use generic error messages; don't expose system details
- Log security events (auth, access denial, tampering)
- Restrict log access to authorized users
- Don't store sensitive data in logs
- Implement centralized logging with analysis capability
- **Common gap:** Stack traces in error messages; PII in logs; no audit trail

### 8. **Data Protection**
- Encrypt sensitive data at rest
- Disable autocomplete on sensitive forms
- Disable client-side caching on sensitive pages
- Use POST (not GET) for sensitive parameters
- Remove unnecessary comments and documentation
- **Common gap:** Sensitive data in GET parameters; no caching headers; client-side storage of secrets

### 9. **Communication Security**
- Use TLS/HTTPS for all sensitive data
- Verify TLS certificates
- Use TLS 1.2 or higher
- Don't fall back to HTTP
- Set security headers (HSTS, CSP, etc.)
- **Common gap:** Mixed HTTP/HTTPS; certificate validation skipped; sensitive data in URL

### 10. **System Configuration**
- Keep servers and frameworks patched and updated
- Disable unnecessary services and HTTP methods
- Remove test code and debug info from production
- Hide server version and framework info
- Turn off directory listing
- **Common gap:** Outdated versions; debug mode on; unnecessary services enabled

### 11. **Database Security**
- Use parameterized queries (prepared statements)
- Store connection strings in secure config, encrypted
- Use database user with least-privilege access
- Remove or change default database passwords
- Use different credentials for different trust levels
- **Common gap:** Dynamic SQL queries; hard-coded credentials; admin privileges for app user

### 12. **File Management**
- Validate file type by magic bytes, not extension
- Store uploads outside web root
- Disable execution in upload directory
- Prevent path traversal attacks
- Scan uploads for malware
- **Common gap:** File type validation by extension; uploads in web root; no path validation

### 13. **Memory Management**
- Truncate input strings before passing to functions
- Check buffer bounds before operations
- Explicitly free resources; don't rely on garbage collection
- Overwrite sensitive data before deallocation
- Avoid known vulnerable functions (strcpy, gets, etc.)
- **Common gap:** Buffer overflow risks; resources not freed; sensitive data in memory

### 14. **General Coding Practices**
- Don't execute dynamic code from user input (eval, exec)
- Use locking/synchronization for concurrent access
- Review third-party code and libraries
- Explicitly initialize variables
- Raise and drop privileges carefully
- **Common gap:** Dynamic code execution; race conditions; uninitialized variables

---

## Audit Report Structure

When reporting findings from this skill, organize them as follows:

```
DOMAIN: [Domain name]
────────────────────────────────────────────────

Finding 1: [Specific checklist item violated]
Evidence:  [File, line number, code snippet]
Risk:      [Attack scenario or compliance impact]
Fix:       [Remediation steps or code example]
Severity:  [Critical | High | Medium | Low]

Finding 2: [Next finding]
...
```

### Severity levels

- **Critical:** Direct path to data breach, unauthorized access, or code execution
- **High:** Significant control gap affecting authentication, authorization, or data protection
- **Medium:** Important control missing; would amplify impact of other vulnerabilities
- **Low:** Best practice gap; unlikely to be exploited in isolation

---

## Reference Files

### In this skill directory

- **`SKILL.md`** — Full skill definition and audit workflow
- **`references/scp-checklist.md`** — Complete checklist for all 14 domains (use for compliance audits)
- **`references/secure-patterns.md`** — Secure code examples by domain and language (Python, JavaScript, SQL, etc.)
- **`assets/examples/`** — Vulnerable code samples organized by domain
- **`scripts/`** — Helper scripts (quick scan, pattern matching, etc.)

### External references

- **OWASP Secure Coding Practices Quick Reference Guide:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **OWASP Top 10 (for comparison):** https://owasp.org/www-project-top-ten/
- **CWE Top 25:** https://cwe.mitre.org/top25/

---

## Example audit flow

### User request
> "Review this Python authentication code for secure coding practices"

### Skill invocation
1. Load `SKILL.md` (this document outlines when to use)
2. Examine the code
3. Reference `references/scp-checklist.md` → section "3. Authentication and Password Management"
4. Cross-check findings against checklist items
5. For remediation examples, reference `references/secure-patterns.md` → section "3. Authentication & Password Management"
6. Generate report grouping findings by domain

### Example finding
```
DOMAIN: Authentication and Password Management
────────────────────────────────────────────────

Finding: Passwords not hashed with strong algorithm
Evidence: app/auth.py, line 42:
          hashed_pw = hashlib.sha1(password).hexdigest()

Risk: SHA1 is cryptographically broken. Attackers can crack passwords using 
      rainbow tables or GPU brute force.

Fix: Use bcrypt or Argon2 instead:
     import bcrypt
     hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

Severity: CRITICAL
```

---

## Tips for effective use

1. **Know your context:** Is the code internet-facing? Internal-only? A library? This affects which checklist items are most critical.

2. **Be systematic:** Walk through the 14 domains in order; don't jump around. This ensures you don't miss anything.

3. **Ground findings in evidence:** Always cite the specific file, line, and code snippet.

4. **Provide actionable remediation:** Point to secure patterns in `secure-patterns.md` or explain the fix directly.

5. **Rank by severity:** Focus on critical issues first; those with direct exploitability or compliance impact.

6. **Use the checklist:** For full compliance audits, systematically walk through every item in `scp-checklist.md`.

---

## FAQ

**Q: Should I use this skill or the `owasp-security-audit` skill?**

A: Use this skill when evaluating code against general secure coding best practices (the 14 domains). Use `owasp-security-audit` when evaluating code against:
   - OWASP Top 10 (web vulnerabilities like injection, XSS, broken auth)
   - API Security Top 10 (REST/GraphQL specific)
   - Kubernetes Top 10 (container security)
   - LLM Top 10 (LLM/agent security)

This skill is broader and domain-agnostic; the audit skill is narrower and vulnerability-focused.

**Q: Can I use this for compliance audits?**

A: Yes! Use the full `references/scp-checklist.md` as a compliance baseline. Walk through every item and document whether your code meets each requirement.

**Q: What if I find vulnerabilities that aren't in the 14 domains?**

A: This skill is specifically for Secure Coding Practices. If you find other vulnerabilities (e.g., OWASP Top 10 issues), reference them separately or use the `owasp-security-audit` skill for a broader review.

**Q: Are these patterns applicable to all languages?**

A: The principles are universal. `secure-patterns.md` provides examples in Python, JavaScript, and SQL. Adapt the core concepts to your language.

---

## When to iterate

- If the user clarifies the threat model or context, reassess which checklist items are critical
- If new findings emerge, check them against the full checklist to ensure systematic coverage
- If asking for remediation examples, reference `secure-patterns.md` first; then provide additional examples if needed
