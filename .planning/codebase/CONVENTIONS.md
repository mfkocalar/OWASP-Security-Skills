# Coding Conventions

**Analysis Date:** 2026-07-19

## Naming Patterns

**Files:**
- kebab-case for filenames: `broken-access-control.py`, `cryptographic-failures.js`, `api-auth-bypass.js`
- Security-focused descriptive names: filenames describe the vulnerability or pattern
- Examples in `examples/` and mirrored in `skills/*/assets/examples/`

**Functions:**
- **Python:** snake_case throughout: `vulnerable_store_password()`, `secure_hash_password()`, `verify_auth()`, `login_attempt()`
- **JavaScript:** camelCase: `verifyAuth()`, `requireAdmin()`, `secure_encrypt_data()`, but some prefixed as `vulnerable_` or `secure_` for clarity

**Variables:**
- **Python:** snake_case: `user_id`, `api_key`, `connection_string`, `auth_tag`
- **JavaScript:** camelCase: `userId`, `apiKey`, `authTag`, `jwtSecret`
- Environment variables: UPPERCASE: `API_KEY`, `JWT_SECRET`, `DATABASE_ENCRYPTION_KEY`, `CANONICAL_HOST`

**Classes:**
- CamelCase: `VulnerableAuthService`, `SecureLogger`, `VulnerableDistributedLogs`, `SecureAuthService`
- Prefixed with security context: `Vulnerable*` or `Secure*` to make intent explicit
- One class per file or grouped by related functionality

**Constants:**
- UPPERCASE_SNAKE_CASE for module-level constants: `MAX_FILE_BYTES`, `DEFAULT_INCLUDES`, `SKIP_DIRS`
- Literal strings often UPPERCASE for event types: `LOGIN_ATTEMPT`, `UNAUTHORIZED_ACCESS`, `CONFIG_CHANGE`

## Code Style

**Formatting:**
- No automated formatter configured (no .eslintrc, .prettierrc, or similar)
- Manual consistency required across team contributions
- 4 spaces indentation in Python (PEP 8 default)
- 2 spaces indentation in JavaScript (Express.js convention)
- Line length: Not explicitly constrained; examples range 80-120 characters

**Linting:**
- No eslint or pylint configuration files present
- Code follows implicit conventions observed in examples, not enforced tooling
- Syntax validation via `python3 -m py_compile` and `node --check` at review time

## Import Organization

**Python:**
1. Standard library imports: `import os`, `import sys`, `from datetime import datetime`
2. Third-party framework imports: `from flask import Flask, request, jsonify`, `from functools import wraps`
3. Custom/local imports (rarely used; examples are typically standalone)

Pattern observed in `quick_scan.py`:
```python
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
```

**JavaScript:**
1. Built-in/standard modules: `const crypto = require('crypto');`
2. Third-party libraries: `const express = require('express');`
3. Module exports at end of file: `module.exports = { func1, func2 };`

Arrow functions preferred: `(req, res) => { ... }` and `(f) => { ... }`

**Path Aliases:**
- Not used in this repository (no alias config observed)
- Relative requires in JavaScript: `require('express')`, `require('cors')`

## Error Handling

**Python Patterns:**
- Try/except blocks for operations that may fail
- `except OSError:` for file operations (seen in `quick_scan.py`)
- `except Exception as e:` for broad exception catching in decorator/middleware
- Type-safe error logging: `details['error'] = type(e).__name__`
- Exceptions logged before re-raising: catch → log → raise
- HTTP-style status codes returned in Flask/JSON responses: 401, 403, 404, 500

**JavaScript Patterns:**
- Try/catch blocks around JWT verification and async operations
- Early returns for error cases: `if (error) return res.status(500).json({ error: "..." })`
- Validation before processing: check input exists/is valid, return 400 before executing logic
- Error objects standardized: `{ error: "message" }` or `{ status: "error", message: "..." }`
- No explicit stack traces logged; error messages are user-friendly

## Logging

**Framework:** Console (Node.js), logging module (Python), or custom structured loggers

**Python Security Logging Pattern** (seen in `logging-monitoring-failures.py`):
```python
def log_security_event(self, event_type, user_id, details, severity='INFO'):
    event = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'details': details,
        'severity': severity
    }
    self.logger.log(getattr(logging, severity), json.dumps(event))
```

**Patterns:**
- Structured JSON logging for security events: timestamp, event_type, user_id, severity, details
- JSON formatter produces pure `{}` JSON (no prefix) for Logstash compatibility
- Security logs go to dedicated file: `/var/log/security.log`
- **Never log secrets:** password, API keys, connection strings, tokens
- Sensitive data masked with `***` if key name indicates secret (e.g., `config_key == 'password'`)
- Event types are descriptive: `LOGIN_ATTEMPT`, `UNAUTHORIZED_ACCESS`, `CONFIG_CHANGE`, `USER_LOGIN`
- Severity levels: `INFO`, `WARNING`, `CRITICAL`

**Console logging (development/examples):**
- `console.log("message")` for debug output
- `console.error()` for errors (implicitly in Node.js production, would use proper logger)
- No secrets logged; messages describe action, not data

## Comments

**When to Comment:**
- Every function has a docstring/header comment explaining security implications
- Vulnerable sections marked: `# VULNERABLE:` (Python) or `// VULNERABLE:` (JavaScript)
- Secure sections marked: `# SECURE:` (Python) or `// SECURE:` (JavaScript)
- Inline comments explain the "why" for security decisions
- Comments above code blocks show input/output transformations and risks

**JSDoc/TSDoc:**
- Python uses triple-quoted docstrings for functions and classes
- Docstrings include purpose, security context, and potential issues
- Example from `broken-access-control.py`:
```python
def vulnerable_get_user(user_id):
    """
    VULNERABLE (A01): No authentication AND no authorization check. Any caller -
    authenticated or not - can read any user's profile, including email and other
    sensitive data.
    """
```
- JavaScript uses block comments `// Comment` and explicit documentation inline
- No JSDoc tags (@param, @returns) observed; focus is on narrative description

## Function Design

**Size:** 
- Functions are typically 5-30 lines for simple operations
- Complex operations (e.g., logging middleware) may reach 40+ lines
- Decorators in Python keep cross-cutting concerns separate from business logic

**Parameters:**
- Functions accept only required parameters
- Defaults avoided unless sensible (e.g., optional severity='INFO')
- Express route handlers follow pattern: `(req, res) => { ... }`
- Decorator factories follow closure pattern: `def decorator(func): def wrapper(*args, **kwargs): ...`

**Return Values:**
- Functions return dictionaries/JSON objects with predictable shape: `{ status: "success", data: ... }`
- HTTP handlers return responses: `res.json(data)`, `res.status(code).json(error)`
- Decorators return wrapped functions (middleware pattern)
- Boolean returns for simple checks: `success = self.validate_credentials(...)`

## Module Design

**Exports:**
- **Python:** Classes and functions are module-level; no explicit exports (entire module is library)
- **JavaScript:** Explicit `module.exports = { func1, func2, ... }` at end of file
- Examples are typically self-contained (can be run standalone with `node` or `python3 -m`)

**Barrel Files:**
- Not used in this codebase
- Each skill has its own example files; no re-export index

**Decorators and Middleware:**
- Heavy use of Python decorators for authentication, authorization, and audit logging
- Express middleware functions for CORS, security headers, request validation
- Decorators return wrapped functions with same signature as original
- Middleware chains applied with `app.use()` or route-specific: `app.get('/path', middleware1, middleware2, handler)`

## Security-Specific Patterns

**Vulnerable vs. Secure Examples:**
- Every code file contains side-by-side `VULNERABLE` and `SECURE` implementations
- Pattern markers: `===== VULNERABLE: [Description] =====` and `===== SECURE: [Description] =====`
- Vulnerable code shows the anti-pattern first, then secure code shows the fix
- Inline comments in vulnerable sections explain the risk; secure sections explain the defense

**Error Handling Philosophy:**
- Never expose internal system details to users
- Generic error messages: `{ error: "Internal server error" }` instead of stack traces
- Log detailed errors internally; return sanitized errors to clients
- HTTP status codes guide the client: 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Error

**Configuration Management:**
- Secrets loaded from environment variables only: `process.env.API_KEY`, `os.getenv('DATABASE_ENCRYPTION_KEY')`
- No hardcoded keys/passwords (examples show anti-pattern for education)
- Configuration validation: throw if required env var missing

---

*Convention analysis: 2026-07-19*
