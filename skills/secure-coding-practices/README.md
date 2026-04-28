# Secure Coding Practices Skill

Audit code against the **OWASP Secure Coding Practices Quick Reference Guide** checklist.

## Overview

This skill evaluates code for compliance with the **14 critical domains** of secure coding practices:

1. **Input Validation** — Server-side validation, allow-lists, data type/range/length checks
2. **Output Encoding** — Context-specific encoding (HTML, SQL, URL, etc.)
3. **Authentication & Password Management** — Strong hashing, account lockout, MFA
4. **Session Management** — Secure session IDs, timeout, cookie flags
5. **Access Control** — Authorization checks, ownership verification, rate limiting
6. **Cryptographic Practices** — Strong algorithms, key management, approved modules
7. **Error Handling & Logging** — Generic errors, secure logging, no sensitive data in logs
8. **Data Protection** — Encryption at rest, autocomplete disabled, cache headers
9. **Communication Security** — TLS/HTTPS, certificate validation, security headers
10. **System Configuration** — Patching, unnecessary services disabled, version info hidden
11. **Database Security** — Parameterized queries, least privilege, secure credentials
12. **File Management** — Upload validation, path traversal prevention, execution disabled
13. **Memory Management** — Buffer bounds, resource cleanup, sensitive data overwrite
14. **General Coding Practices** — No dynamic execution, thread safety, code review

## Structure

```
secure-coding-practices/
├── SKILL.md                          # Full skill definition and workflow
├── secure-coding-practices.md        # User guide and quick reference
├── references/
│   ├── scp-checklist.md             # Complete 14-domain checklist
│   ├── secure-patterns.md           # Secure code examples by domain
│   └── owasp-urls.json              # Links to OWASP standards and CWEs
├── assets/
│   └── examples/
│       ├── vulnerable-examples.py   # Vulnerable Python code samples
│       └── vulnerable-examples.js   # Vulnerable JavaScript code samples
└── scripts/                          # Helper scripts (future)
```

## Quick Start

### Invoking the skill

The skill is automatically loaded when you:

- Ask to "review this code for secure coding practices"
- Request an "SCP compliance audit"
- Ask "is this code written securely?" or similar
- Paste code involving input validation, authentication, database queries, file handling, or cryptography

### How to use

1. **Provide code** — Paste the code you want audited
2. **Set scope** — Clarify: is this a snippet, file, or directory?
3. **Skill loads** — References the SCP checklist and patterns
4. **Audit runs** — Cross-references code against the 14 domains
5. **Report generated** — Findings grouped by domain, with severity and remediation

### Example audit report

```
DOMAIN: Input Validation
────────────────────────

Finding: Missing data range validation
Evidence: app/user.py, line 42
Code: age = int(request.args.get('age'))
Risk: Negative or excessive age values accepted, causing logic errors
Fix: if not (0 <= age <= 150): raise ValueError("Invalid age")
Severity: MEDIUM

────────────────────────

DOMAIN: Database Security
────────────────────────

Finding: SQL Injection via dynamic query
Evidence: db/queries.py, line 18
Code: query = f"SELECT * FROM users WHERE id = {user_id}"
Risk: Attacker can inject SQL code and extract/modify data
Fix: Use parameterized query: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
Severity: CRITICAL
```

## Reference Files

### `SKILL.md`
Full skill definition with:
- When to invoke this skill
- Audit workflow (5 steps)
- Detection signals for each domain
- Complete reference list

Use this to understand the skill's scope and limitations.

### `secure-coding-practices.md`
User-friendly guide with:
- Quick overview of the 14 domains
- Common gaps for each domain
- Severity levels
- Audit report structure
- FAQ and tips

Start here if you're new to the skill.

### `references/scp-checklist.md`
Comprehensive checklist from OWASP with:
- 100+ checklist items across 14 domains
- All items formatted as checkboxes
- Core principles for each domain
- Usage in audit reports

Use this for **full compliance audits**. Reference specific items when reporting findings.

### `references/secure-patterns.md`
Secure code examples organized by domain with:
- Python, JavaScript, SQL, and general patterns
- Before/after code samples
- Explanations of why each pattern is secure
- Applicable frameworks (Django, Flask, Express, etc.)

Use this when **remediating findings** or need implementation guidance.

### `references/owasp-urls.json`
Links to:
- OWASP Secure Coding Practices official guide
- Related OWASP standards (Top 10, ASVS, MASVS, API Security, etc.)
- CWE references for each domain
- NIST and FIPS standards

Use this for **deep dives** into specific domains or standards.

### `assets/examples/`
Vulnerable code samples:
- `vulnerable-examples.py` — Python/Flask examples (XSS, SQL injection, missing auth checks, etc.)
- `vulnerable-examples.js` — JavaScript/Node.js examples (same patterns)

Use these as **teaching examples** or to understand what mistakes look like.

## Workflow

### For quick audits (snippets)
1. Load `SKILL.md` mentally (understand the 14 domains)
2. Read code
3. Reference `secure-patterns.md` for fixes
4. Report findings

### For full compliance audits
1. Load `SKILL.md` for scope/context
2. Use `scp-checklist.md` as master checklist
3. Walk through every item in relevant domains
4. Document which items pass, which fail
5. Reference `secure-patterns.md` for remediation

### For remediation/implementation
1. Find finding in checklist
2. Reference `secure-patterns.md` for code examples
3. Look at `assets/examples/` for what NOT to do
4. Implement fix using framework-specific guidance

## Domains at a glance

| Domain | Key Risk | Common Gap |
| --- | --- | --- |
| **Input Validation** | Injection attacks | No server-side validation |
| **Output Encoding** | XSS attacks | Direct HTML insertion |
| **Authentication** | Unauthorized access | Plaintext passwords |
| **Session Management** | Session hijacking | Predictable IDs |
| **Access Control** | Data breach | No ownership checks |
| **Cryptography** | Secret disclosure | Hard-coded keys |
| **Error/Logging** | Information disclosure | Stack traces in responses |
| **Data Protection** | Data leak | No caching headers |
| **Communication** | Man-in-the-middle | HTTP for sensitive data |
| **System Config** | Exploitation of known vulns | Unpatched servers |
| **Database** | SQL injection | Dynamic queries |
| **File Management** | Path traversal | No validation |
| **Memory** | Buffer overflow | No bounds checking |
| **General Practices** | Code execution | Dynamic eval() |

## Integration with other OWASP skills

This skill is **complementary** to `owasp-security-audit`:

| Skill | Focus | Use when |
| --- | --- | --- |
| **secure-coding-practices** | Secure coding best practices (14 domains) | "Review for secure practices" |
| **owasp-security-audit** | OWASP Top 10 + API/Mobile/K8s/LLM standards | "Is this vulnerable to OWASP Top 10?" |

Both can be used together:
- Use this skill first for **general code quality**
- Then use `owasp-security-audit` for **vulnerability-specific checks**

## Tips for effectiveness

1. **Know your context** — Internet-facing? Internal? Library? This affects priority.
2. **Be systematic** — Walk through domains in order; don't skip around.
3. **Ground findings** — Always cite file, line, and code snippet.
4. **Provide remediation** — Point to `secure-patterns.md` or explain the fix.
5. **Rank by severity** — CRITICAL first, then HIGH, MEDIUM, LOW.
6. **Use the checklist** — For compliance audits, document every item.

## FAQ

**Q: Is this the same as OWASP Top 10?**

A: No. Top 10 focuses on **common web vulnerabilities** (injection, XSS, broken auth, etc.). This skill focuses on **secure coding practices** across 14 domains that encompass much more (session management, error handling, cryptography, memory management, etc.).

**Q: Should I use this skill or owasp-security-audit?**

A: Use **this skill** for general "is this code written securely?" questions. Use **owasp-security-audit** for vulnerability-specific audits against standards like Top 10, API Security, ASVS, etc. Both can be used together.

**Q: Can I use this for compliance audits?**

A: Yes! Use `references/scp-checklist.md` as your compliance baseline and document each item as pass/fail.

**Q: What if I find vulnerabilities not in these 14 domains?**

A: This skill is specifically for SCP. Reference vulnerabilities separately or use `owasp-security-audit` for a broader review.

**Q: Are the secure patterns applicable to my language?**

A: The principles are universal. `secure-patterns.md` provides Python, JavaScript, and SQL examples. Adapt the patterns to your language.

## References

- **OWASP Secure Coding Practices Quick Reference Guide:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **CWE Top 25:** https://cwe.mitre.org/top25/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **NIST Cryptographic Standards:** https://csrc.nist.gov/

## Support

For issues, improvements, or feedback on this skill, see the main repository README or CONTRIBUTING guide.
