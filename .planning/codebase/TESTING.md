# Testing Patterns

**Analysis Date:** 2026-07-19

## Test Framework

**Runner:**
- No dedicated test framework (no Jest, pytest, unittest, or Vitest configured)
- Validation approach: syntax checking and file integrity verification
- This is an educational repository; examples are meant to be read and studied, not automatically tested

**Assertion Library:**
- None; verification is manual or via script-based checks
- Bash scripts validate file existence and cross-references
- Python/JavaScript syntax validators ensure code is parseable

**Run Commands:**
```bash
# Syntax validation for Python
python3 -m py_compile examples/broken-access-control.py

# Syntax validation for JavaScript
node --check examples/cryptographic-failures.js

# JSON validation
python3 -m json.tool skill.json > /dev/null && echo "✓ Valid JSON"

# File integrity test (from install.sh or manual)
./install.sh  # Option 4: test only
```

## Test File Organization

**Location:**
- Test/verification procedures documented in `TESTING.md` (root level)
- Examples live in `examples/` (top-level reference examples)
- Examples also mirrored in `skills/*/assets/examples/` for skill-specific use
- No separate `__tests__` or `test/` directory

**Naming:**
- Examples follow pattern: `[vulnerability]-[description].{py|js|yaml|html|txt}`
- Examples: `injection.js`, `broken-access-control.py`, `xss.html`, `k8s-rbac.yaml`, `prompt-injection.txt`
- No `*.test.*` or `*.spec.*` files
- Each file contains both vulnerable and secure patterns inline

**Structure:**
No traditional test suite structure. Examples are standalone files with internal comments marking sections:
```
[vulnerability]-[description].py/js
├── Comments explaining the OWASP reference
├── ===== VULNERABLE: [Pattern] ===== section
│   ├── Vulnerable implementation
│   └── Inline comments explaining the risk
└── ===== SECURE: [Pattern] ===== section
    ├── Secure implementation
    └── Inline comments explaining the defense
```

## Test Structure

**Suite Organization:**
Instead of test suites, examples are organized by vulnerability category:

```python
# Example: broken-access-control.py

# ===== VULNERABLE: No Authorization Check =====
@app.route("/vulnerable/user/<int:user_id>", methods=["GET"])
def vulnerable_get_user(user_id):
    """VULNERABLE: explanation"""
    # ... vulnerable code

# ===== SECURE: Server-Side Authorization Check =====
def require_auth(f):
    """Decorator to check if user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # ... secure implementation
    return decorated_function
```

**Patterns:**
- No setup/teardown phases (examples are stateless)
- No test fixtures or mock data factories
- Each vulnerable/secure pair is self-contained and can be understood independently

## Mocking

**Framework:** 
- None; mocking not used
- Examples show patterns but don't require test doubles
- Database interactions use placeholder functions: `db.query(...)` (assumed to exist)

**Patterns:**
- Examples reference external systems (databases, APIs, message queues) but don't mock them
- Focus is on pattern demonstration, not on isolating units

**What to Mock:**
- Not applicable; mocking is not part of this repository's testing strategy

**What NOT to Mock:**
- Security decisions (auth, validation) are shown in full, not stubbed
- Encryption algorithms are shown with real libraries (crypto, bcrypt) to demonstrate correct usage
- Error handling is shown realistically

## Fixtures and Factories

**Test Data:**
- Simulated databases are inline dictionaries for examples:
```python
# From broken-access-control.py
users_db = {
    1: {"name": "Alice", "email": "alice@example.com", "role": "user"},
    2: {"name": "Bob", "email": "bob@example.com", "role": "admin"},
}
orders_db = {
    1: {"user_id": 1, "product": "Laptop", "price": 999},
}
```
- No factory pattern; data is hardcoded as examples
- YAML fixtures for Kubernetes examples: `examples/k8s-rbac.yaml` contains sample manifests

**Location:**
- Inline in example files (no separate fixture directory)
- Kubernetes manifests in `examples/k8s-rbac.yaml`
- No database seeding scripts or factory libraries

## Coverage

**Requirements:** 
- No coverage targets enforced
- No `.coveragerc` or coverage configuration
- All OWASP Top 10, ASVS, MASVS, API Security, Kubernetes, and Agentic standards should have examples
- Coverage tracked manually via checklist in `TESTING.md` and `skill.json`

**View Coverage:**
```bash
# Manual coverage check: verify examples exist for each category
for category in "A01" "A02" "A03" "A04" "A05" "A06" "A07" "A08" "A09" "A10"; do
    grep -l "$category" examples/* && echo "✓ $category covered" || echo "✗ $category missing"
done

# Verify example files referenced in skill.json
grep -r "examples/" skill.json | wc -l
```

## Test Types

**Unit Tests:**
- Not applicable; examples are not isolated units
- Focus is on pattern demonstration with realistic workflows

**Integration Tests:**
- Not applicable; no automated test execution
- Manual testing via code review and syntax validation

**E2E Tests:**
- Not applicable; examples are not executable applications
- Examples show patterns that would be tested in downstream projects

## Common Patterns

**Async Testing:**
Not applicable. JavaScript examples using Express use synchronous request handlers:
```javascript
app.get('/api/endpoint', (req, res) => {
  // synchronous logic
  res.json(result);
});
```
If async were needed, pattern would be:
```javascript
app.get('/api/endpoint', async (req, res) => {
  try {
    const result = await dbQuery(...);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

**Error Testing:**
Examples show error handling patterns inline:
```python
def secure_refund_order(order_id):
    current_user_id = session.get("user_id")
    current_user = users_db.get(current_user_id)
    
    if current_user is None:
        return jsonify({"error": "User not found"}), 404
    if order_id not in orders_db:
        return jsonify({"error": "Order not found"}), 404
    # ... more validation and error paths
```

Each error path is documented with comments explaining the security check:
```python
# Authorization: User owns order OR is admin
if order["user_id"] != current_user_id and current_user["role"] != "admin":
    return jsonify({"error": "Forbidden - you do not own this order"}), 403
```

## Verification Procedures

**From TESTING.md:**

1. **File Integrity Tests**
   - Verify all core files present
   - Validate JSON syntax: `python3 -m json.tool skill.json > /dev/null`
   - Count example files: `ls examples/ | wc -l`

2. **Cross-Reference Validation**
   - Check anchor links in README match target files
   - Verify example files referenced in `skill.json`
   - Ensure all OWASP standards have adequate examples

3. **Code File Syntax Checking**
   - Python: `python3 -m py_compile examples/*.py`
   - JavaScript: `node --check examples/*.js`
   - YAML: `python3 -c "import yaml; yaml.safe_load(open('file.yaml'))"`
   - HTML: Manual DOCTYPE and structure inspection

4. **Installation Verification**
   - Run `./install.sh` option 4 (test only)
   - Verify skill is discoverable via activation triggers
   - Check cross-references between standards

## Testing Discipline

**What Is Tested:**
- Syntax validity of all code examples
- File structure and organization
- Cross-references between documentation and examples
- JSON manifest validity
- Activation trigger keywords map to content

**What Is NOT Tested:**
- Actual vulnerability behavior (examples are educational, not exploitable)
- Runtime behavior of example code (examples assume external services exist)
- Integration with external systems
- Performance or load characteristics

**Maintenance:**
- Examples updated when OWASP standards are revised
- Syntax validation run before release
- Cross-reference checks ensure documentation accuracy
- Manual code review for security accuracy (examples must correctly show vulnerabilities and defenses)

**Quality Gates:**
- All example files must pass `python3 -m py_compile` or `node --check`
- `skill.json` must be valid JSON
- No broken cross-references between skill.json and example files
- Every standard section must have at least one example

---

*Testing analysis: 2026-07-19*
