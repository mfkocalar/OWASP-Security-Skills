# OWASP Top 10 Security Skills

This comprehensive guide covers the OWASP Top 10 most critical security vulnerabilities found in web applications. Each section provides detection guidance, real-world examples, mitigation strategies, and prevention checklists to help developers secure their code.

## Table of Contents

1. [Injection](#1-injection)
2. [Broken Authentication and Session Management](#2-broken-authentication-and-session-management)
3. [Sensitive Data Exposure](#3-sensitive-data-exposure)
4. [XML External Entities (XXE)](#4-xml-external-entities-xxe)
5. [Broken Access Control](#5-broken-access-control)
6. [Security Misconfiguration](#6-security-misconfiguration)
7. [Cross-Site Scripting (XSS)](#7-cross-site-scripting-xss)
8. [Insecure Deserialization](#8-insecure-deserialization)
9. [Using Components with Known Vulnerabilities](#9-using-components-with-known-vulnerabilities)
10. [Insufficient Logging & Monitoring](#10-insufficient-logging--monitoring)

---

## 1. Injection

Injection flaws occur when untrusted data is sent to an interpreter as
part of a command or query. The attacker's hostile data can trick the
interpreter into executing unintended commands or accessing data without
proper authorization.

### Common patterns

- Concatenating user input directly into a SQL query string:
  ```js
  const sql = "SELECT * FROM users WHERE email='" + req.body.email + "'";
  db.query(sql, ...);
  ```
- Executing shell commands with unsanitized arguments:
  ```python
  os.system("tar -czf " + filename + " /var/data")
  ```
- Constructing XPath, LDAP, or NoSQL expressions using raw input.

### Detection clues

- Look for string construction operations that mix literals and
  variables from request parameters, cookies, headers, or files.
- Functions named `exec`, `query`, `run`, `shell`, etc., are red flags
  when passed user-controlled data.
- Absence of parameter binding, prepared statements, or escaping calls.

### Mitigation strategies

1. **Use parameterized queries / prepared statements** provided by the
   database driver.
2. **Whitelist input** – only allow expected characters or values, and
   reject the rest.
3. **Escape or encode data** only when an interpreter requires it, but
   prefer parameterization.
4. **Avoid invoking interpreters** unnecessarily. When running
   commands, use safe APIs (e.g., Python's `subprocess.run([...])` with a
   list argument).
5. **Employ ORM/ODM libraries** carefully; understand how they handle
   interpolation.

### Bypass and edge cases

- Numeric fields may be exploited with `0 OR 1=1` or `; DROP TABLE`
- Encodings (`%27`, Unicode homoglyphs) may bypass naive filters.
- In NoSQL (MongoDB) an attacker can send `{"$gt": ""}` to bypass
  equality checks.
- When using ORM query builders, injection can happen in the `raw`
  or `literal` clauses.

### Prevention Checklist

- [ ] Treat all input as data; never interpolate it directly into commands.
- [ ] Use bound parameters or parameterized queries for every database
      operation.
- [ ] Avoid string concatenation when building SQL, shell, XPath, or
      other interpreter statements.
- [ ] When invoking the operating system, prefer APIs that accept argument
      lists (`subprocess.run`, `spawn`, etc.).
- [ ] Whitelist allowed values and reject or canonicalize the rest.
- [ ] Review ORM/ODM raw or literal interfaces for potential injection
      risks.

### Example fix

**PHP (MySQLi)**

Bad:
```php
$query = "SELECT * FROM products WHERE id=" . $_GET['id'];
$result = mysqli_query($conn, $query);
```
Good:
```php
$stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

**Node.js (mysql library)**

Bad:
```js
const q = `SELECT * FROM users WHERE email='${req.body.email}'`;
db.query(q, callback);
```
Good:
```js
const q = 'SELECT * FROM users WHERE email = ?';
db.query(q, [req.body.email], callback);
```

**Python shell command**

Bad:
```python
os.system("tar -czf " + filename + " /var/data")
```
Good:
```python
subprocess.run(["tar", "-czf", filename, "/var/data"], check=True)
```

These examples demonstrate that the user-supplied data is always sent as
an argument rather than merged into the command string.

---

## 2. Broken Authentication and Session Management

When authentication mechanisms are implemented incorrectly, attackers
can compromise passwords, keys, or session tokens, or exploit other
implementation flaws to assume other users' identities.

### Red flags to spot

- Passwords stored in plaintext or with weak hashing (MD5, SHA1).
- Login logic that doesn't rate-limit or lock out after repeated
  failures.
- Missing multi-factor authentication for sensitive operations.
- Session IDs that don't expire or are predictable (e.g., incremental
  numbers in URLs).
- Password reset flows that rely on weak tokens or expose information
  about user existence.

### Best practices

1. **Hash passwords** with a strong algorithm (bcrypt, Argon2, PBKDF2).
2. **Implement account lockout/rate limiting** after several failed
   attempts.
3. **Use secure, HttpOnly cookies** for session tokens and rotate them
   after login.
4. **Invalidate sessions on logout** and after a reasonable timeout.
5. **Don't expose credentials** in URLs or logs; use POST bodies.
6. **Ensure MFA** is available for privileged accounts and critical
   actions.
7. **Protect password reset tokens** with sufficient entropy and
   expiration; send them via email only, not via SMS or GET parameters.

### Examples

**Insecure password storage (Node.js):**
```javascript
if (user.password === submittedPassword) { // No hashing!
  // Authenticate user
}
```

**Secure password storage (Node.js with bcrypt):**
```javascript
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);
if (await bcrypt.compare(submittedPassword, hash)) {
  // Authenticate user
}
```

**Insecure session handling (PHP):**
```php
$_SESSION['user_id'] = $user_id; // Session ID is predictable
```

**Secure session handling (PHP):**
```php
session_regenerate_id(true);
setcookie('PHPSESSID', '', [
  'expires' => time() + 3600,
  'path' => '/',
  'secure' => true,
  'httponly' => true,
  'samesite' => 'Strict',
]);
```

**Weak password reset token (Python):**
```python
import random
token = str(random.randint(100000, 999999))  // Guessable!
```

**Strong password reset token (Python):**
```python
import secrets
token = secrets.token_urlsafe(32)  // Cryptographically secure
```

### Prevention Checklist

- [ ] Passwords are hashed using bcrypt, Argon2, or PBKDF2 with adequate salt and iterations.
- [ ] Login endpoints have rate limiting or account lockout after failed attempts.
- [ ] Session tokens are generated using cryptographically secure randomness.
- [ ] Authentication cookies are marked `Secure`, `HttpOnly`, and `SameSite=Strict`.
- [ ] Sessions are invalidated on logout and after inactivity periods.
- [ ] Password reset tokens expire after a short time and are single-use.
- [ ] Multi-factor authentication is implemented for privileged accounts.

---

## 3. Sensitive Data Exposure

Applications and APIs that do not properly protect sensitive information
— such as financial records, health data, or personal details — allow
attackers to access or transmit it insecurely.

### Things to watch for

- Transmitting secrets (passwords, tokens, keys) in cleartext over HTTP.
- Logging sensitive values (credit card numbers, social security
  numbers).
- Storing unencrypted data at rest or using weak encryption (DES,
  ECB mode).
- Failure to enforce `Strict-Transport-Security`, `Content-Security-Policy`,
  or other headers that mitigate data leaks in transit.
- Predictable or public URLs serving private files (e.g., `GET
  /files/transaction_12345.pdf`).

### Defensive measures

1. **Always use HTTPS/TLS** and redirect HTTP requests to HTTPS.
2. **Encrypt data at rest** with modern algorithms and proper key
   management.
3. **Mask or omit sensitive fields** from logs and error messages.
4. **Use the principle of least privilege** for database access.
5. **Avoid storing secrets in code**; use environment variables or a
   secrets manager.
6. **Apply robust input validation** on uploads to prevent data
   exfiltration via metadata or hidden fields.

### Examples

**Insecure: storing API key in code (Python):**
```python
api_key = "sk-abc123xyz789"
response = requests.get("https://api.example.com", headers={"Authorization": api_key})
```

**Secure: storing API key in environment variable (Python):**
```python
import os
api_key = os.getenv("API_KEY")
if not api_key:
  raise ValueError("API_KEY not set")
response = requests.get("https://api.example.com", headers={"Authorization": api_key})
```

**Insecure: logging sensitive data (Java):**
```java
logger.info("User login: username=" + username + ", password=" + password);
```

**Secure: masking sensitive data in logs (Java):**
```java
logger.info("User login: username=" + username + ", password=****");
```

**Insecure: transmitting over HTTP:**
```html
<form action="http://example.com/login" method="POST">
  <input type="password" name="pwd">  <!-- Sent in cleartext! -->
</form>
```

**Secure: enforcing HTTPS and headers (Node.js):**
```javascript
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (req.protocol !== 'https') {
    return res.redirect(301, 'https://' + req.host + req.url);
  }
  next();
});
```

### Edge cases

- Data exposure through `Referer` headers when linking to third-party
  sites.
- Response bodies accidentally including sensitive tokens when
  pagination occurs (e.g., `pageToken` visible in JSON).
- In mobile apps, storing credentials in insecure storage (plist filed,
  SharedPreferences without encryption).

### Prevention Checklist

- [ ] HTTPS/TLS is enforced site-wide; HTTP traffic is redirected.
- [ ] Encryption keys are stored securely (secrets manager, HSM, not in code).
- [ ] Data at rest is encrypted with AES-256 or equivalent.
- [ ] Sensitive values never appear in logs, error messages, or source code.
- [ ] Security headers are configured: `Strict-Transport-Security`, `Content-Security-Policy`.
- [ ] Database access is restricted to least-privilege accounts.

---

## 4. XML External Entities (XXE)

XXE occurs when XML parsers process external entity references within user-
controlled XML documents. This can lead to sensitive file disclosure,
port scanning, server-side request forgery, or denial of service.

### Indicators

- Use of `xml.etree`, `javax.xml`, `lxml`, `libxml2`, or similar
  libraries parsing XML from untrusted sources.
- Configuration flags like `ENTITY`, `resolve_entities`, or `allow_dtd`
  being enabled.
- Code reading files based on `SYSTEM` or `PUBLIC` entity definitions.

### Preventive steps

1. **Disable DTD processing** or external entity resolution by default.
   Most libraries offer a safe mode (e.g., `XMLParser(resolve_entities=False)`
   in Python).
2. **Use a simple data format** like JSON when XML capabilities aren't
   needed.
3. **Validate and sanitize XML** against a strict schema before parsing.
4. **Run parsers in sandboxed environments** or with limited network
   access to mitigate SSRF consequences.

### Common pitfalls and bypasses

- XML bombs (`<!ENTITY a "&a;&a;">`) causing exponential expansion.
- Using insecure third-party libraries that re-enable XXE in later
  methods (e.g., `libxml2`'s `parseMemory` vs `parseFile`).
- Ignoring non-XML input types such as SOAP or RSS feeds.

### Examples

**Vulnerable Python (lxml):**
```python
from lxml import etree

def load(xml_string):
    # default parser resolves external entities
    parser = etree.XMLParser()
    return etree.fromstring(xml_string, parser)
```

**Safe Python:**
```python
from lxml import etree

def load(xml_string):
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False)
    return etree.fromstring(xml_string, parser)
```

**Java (insecure):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
```

**Java (hardened):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
```

### Prevention Checklist

- [ ] DTD processing and external entity resolution are disabled by
      default.
- [ ] Parser configurations are explicit and set to safe values.
- [ ] Incoming XML is validated against a strict schema before parsing.
- [ ] Any XML input sources (file uploads, SOAP messages, SAML
      assertions) are treated as untrusted.
- [ ] Dependencies are reviewed to ensure no library re-enables XXE in
      alternative APIs.
- [ ] Consider switching to simpler formats such as JSON when XML
      features aren't required.

---

## 5. Broken Access Control

Access control failures allow users to act outside of their intended
permissions, whether by bypassing UI checks or manipulating backend
references.

### Common indicators

- URLs or API endpoints that reference IDs directly (`/user/1234/orders`)
  without verifying the current user owns the resource.
- Client-side enforcement only (hiding buttons with JavaScript but not
  enforcing server-side checks).
- Role or permission logic duplicated in many places, increasing the
  chance of a missing check.

### Defensive advice

1. **Enforce authorization on the server** for every sensitive action.
   Use middleware, filters, or decorators to avoid omission.
2. **Implement horizontal and vertical checks**: confirm the acting user
   is allowed to access the target resource and perform the requested
   operation.
3. **Do not rely on obscurity**; numeric or GUID identifiers aren't
   sufficient.
4. **Tokenize or encrypt identifiers** when exposing them to users.
5. **Use established libraries/framework features** for access control
   (e.g., Django's `@login_required` + `user.has_perm`, Spring Security
   annotations, Express ACL middleware).

### Examples

**Insecure: no authorization check (Express.js):**
```javascript
app.get('/users/:id/orders', (req, res) => {
  const orders = db.query('SELECT * FROM orders WHERE user_id = ?', req.params.id);
  res.json(orders); // No check if req.user.id === req.params.id!
});
```

**Secure: authorization check (Express.js):**
```javascript
app.get('/users/:id/orders', (req, res) => {
  if (req.user.id !== parseInt(req.params.id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const orders = db.query('SELECT * FROM orders WHERE user_id = ?', req.params.id);
  res.json(orders);
});
```

**Insecure: client-side only enforcement (JavaScript):**
```javascript
if (user.role === 'admin') {
  document.getElementById('deleteBtn').style.display = 'block';
}
```

**Secure: server-side authorization (Django):**
```python
from django.contrib.auth.decorators import permission_required

@permission_required('app.delete_resource')
def delete_resource(request, resource_id):
  if request.user.id != resource.owner_id:
    return HttpResponseForbidden()
  resource.delete()
  return JsonResponse({'status': 'deleted'})
```

**Insecure: mass assignment (Python/Flask):**
```python
@app.route('/user/update', methods=['POST'])
def update_user():
  user = User.query.get(request.form.get('user_id'))
  user.update(request.form)  // Blindly assigns all fields!
  db.session.commit()
```

**Secure: whitelist allowed fields (Python/Flask):**
```python
@app.route('/user/update', methods=['POST'])
def update_user():
  user = User.query.get(request.user.id)  // Use authenticated user
  allowed_fields = {'name', 'email', 'phone'}
  for field in allowed_fields:
    if field in request.form:
      setattr(user, field, request.form[field])
  db.session.commit()
```

### Bypass techniques

- Parameter tampering: modify `?id=42` to `?id=43`.
- Changing HTTP verbs: using `PUT` instead of `POST` if only `POST` handlers validate permissions.
- Exploiting mass-assignment to overwrite `role` or `isAdmin` flags.

### Prevention Checklist

- [ ] Authorization is enforced on the server for every sensitive operation.
- [ ] User identity is verified before access checks.
- [ ] Resource ownership is confirmed before permitting the action.
- [ ] A centralized authorization mechanism is used consistently.
- [ ] Default-deny policy is applied; only explicitly allowed actions are permitted.
- [ ] All HTTP methods (GET, POST, PUT, DELETE, PATCH) are protected.
- [ ] Mass-assignment vulnerabilities are prevented by whitelisting fields.

---

## 6. Security Misconfiguration

Security misconfigurations arise when systems, frameworks, or
infrastructure components are left in insecure states.

### Symptoms to recognize

- Default credentials still in use (`admin:admin`, etc.).
- Debug endpoints (e.g., `/debug`, `/actuator`) exposed in production.
- Unnecessary services running or ports open (FTP, SSH from web
  servers).
- Insecure HTTP headers missing (`X-Frame-Options`, `X-XSS-Protection`,
  etc.).
- Overly verbose error messages revealing stack traces or SQL queries.

### Remediation guidance

1. **Harden configurations** before deployment: disable unused
   features, remove demo code, and rotate default passwords.
2. **Use environment-specific settings** (development vs production).
3. **Automate configuration management** with tools like Ansible,
   Terraform, or Docker to minimize manual mistakes.
4. **Apply security headers** and configure them correctly:
   - `Content-Security-Policy`
   - `Strict-Transport-Security`
   - `X-Content-Type-Options: nosniff`
5. **Validate API and admin routes** are not accessible to unauthenticated
   users.
6. **Keep platform and dependencies patched**; disable version
   disclosure (e.g., `Server` header showing `nginx/1.18`).

### Examples

**Insecure: debug mode enabled in production (Flask):**
```python
app = Flask(__name__)
app.debug = True  // Exposes stack traces, REPL access!
```

**Secure: debug mode disabled in production (Flask):**
```python
app = Flask(__name__)
app.debug = False  // or use environment variable
if not os.getenv('FLASK_ENV') == 'development':
  app.debug = False
```

**Insecure: overpermissive CORS (Node.js/Express):**
```javascript
app.use(cors({ origin: '*' }));  // Allows any origin
```

**Secure: restrictive CORS (Node.js/Express):**
```javascript
app.use(cors({ origin: 'https://myapp.com', credentials: true }));
```

**Insecure: default credentials in database:**
```bash
mysql -u root -p  // Password: root (never changed!)
```

**Secure: strong, unique credentials:**
```bash
mysql -u dbadmin -p$(openssl rand -base64 32)  // Random password
```

**Insecure: version disclosure (Apache):**
```
Server: Apache/2.4.29 (Ubuntu)
```

**Secure: hide version (Apache config):**
```apache
ServerTokens Prod
ServerSignature Off
```

### Edge cases

- Cloud metadata services accessible from application code (SSRF risk).
- Over-permissive CORS policies (`Access-Control-Allow-Origin: *`).
- Temporary debug flags left enabled (`app.debug = true`).

### Prevention Checklist

- [ ] All default credentials have been changed to strong, unique values.
- [ ] Debug mode and development endpoints are disabled in production.
- [ ] Security headers are configured: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
- [ ] CORS is explicitly configured with trusted origins only.
- [ ] Unnecessary services, ports, and features are disabled.
- [ ] Server version information is hidden.
- [ ] All software and dependencies are up to date and regularly patched.
- [ ] Access to cloud metadata endpoints is blocked.

---

## 7. Cross-Site Scripting (XSS)

XSS vulnerabilities occur when an application includes untrusted data in a
web page without proper validation or escaping, allowing attackers to
execute arbitrary JavaScript in victims' browsers.

### Types of XSS

- **Stored (persistent):** data saved on the server and displayed later
  (e.g., comments, profile fields).
- **Reflected:** malicious input echoed in an immediate response (e.g., in
  a search result).
- **DOM-based:** the vulnerability exists in client-side scripts that
  modify the DOM using unsanitized input.

### Detection hints

- Look for `innerHTML`, `document.write`, or template literals that
  interpolate user data.
- Server-side templates that don't escape output (e.g., `<%= user.name
  %>` in ERB without `h`).
- Absence of output encoding functions (e.g., `htmlspecialchars`,
  `escapeHtml`).

### Defensive patterns

1. **Escape output** based on context (HTML, attribute, JavaScript,
   URL).
2. **Use a safe templating engine** that auto-escapes by default.
3. **Validate input** and strip unwanted tags or attributes using a
   library like DOMPurify.
4. **Implement Content Security Policy (CSP)** with `script-src`
   restrictions and `nonce`/`hash` support to limit script execution.
5. **Avoid inserting user-provided HTML** unless absolutely necessary.

### Examples

**Insecure: reflected XSS (PHP):**
```php
<input value="<?= $_GET['q'] ?>">  <!-- If q=\" onclick=alert(1) -->
```

**Secure: escaped output (PHP):**
```php
<input value="<?= htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') ?>">
```

**Insecure: stored XSS (Express.js):**
```javascript
app.post('/comment', (req, res) => {
  db.query('INSERT INTO comments (text) VALUES (?)', req.body.text);
});
app.get('/comments', (req, res) => {
  const comments = db.query('SELECT text FROM comments');
  res.send(comments.map(c => `<p>${c.text}</p>`).join(''));  // Unescaped!
});
```

**Secure: escaped output (Express.js):**
```javascript
const escapeHtml = require('escape-html');
app.get('/comments', (req, res) => {
  const comments = db.query('SELECT text FROM comments');
  res.send(comments.map(c => `<p>${escapeHtml(c.text)}</p>`).join(''));
});
```

**Insecure: DOM-based XSS (JavaScript):**
```javascript
const userInput = document.getElementById('userInput').value;
document.getElementById('output').innerHTML = userInput;  // Raw HTML!
```

**Secure: DOM-based safe replacement (JavaScript):**
```javascript
const userInput = document.getElementById('userInput').value;
document.getElementById('output').textContent = userInput;  // Text only
```

**Insecure: React with dangerouslySetInnerHTML:**
```jsx
<div dangerouslySetInnerHTML={{ __html: userContent }} />
```

**Secure: React with proper escaping:**
```jsx
<div>{userContent}</div>  // React auto-escapes by default
```

### Bypass and edge cases

- Crafting payloads using event handlers (`onerror`, `onclick`) or URI
  schemes (`javascript:`).
- Polyglot strings that break out of attribute contexts (e.g.,
  `" onmouseover=alert(1) "`).
- Storing payloads in unexpected places like JSON fields that are later
  rendered.

### Prevention Checklist

- [ ] All user-supplied data is escaped based on context (HTML, attribute, JavaScript, URL).
- [ ] Templating engines auto-escape output by default.
- [ ] `innerHTML` and similar unsafe APIs are avoided with user data.
- [ ] Content Security Policy (CSP) is implemented with strict `script-src` directives.
- [ ] DOMPurify or equivalent is used if HTML input is necessary.
- [ ] Client-side data from `location.hash` and `localStorage` is sanitized before rendering.
- [ ] File uploads cannot contain executable scripts.

---

## 8. Insecure Deserialization

Applications that deserialize untrusted data without sufficient checks can
be made to execute arbitrary code, escalate privileges, or cause
application crashes.

### Red flags

- Use of `pickle`, `PHP unserialize()`, `Java`'s `ObjectInputStream`, or
  similar features on input received from users (cookies, POST bodies,
  WebSocket messages).
- Accepting uploaded files that are later deserialized by the server.
- Logging or storing serialized objects that are later reloaded without
  validation.

### Mitigations

1. **Avoid native serialization formats** when possible; use JSON or
   other simple formats and explicitly parse fields.
2. **Validate and sanitize** serialized content before deserializing.
3. **Restrict which classes can be instantiated** during deserialization
   (e.g., `allowed_classes` in PHP's `unserialize()`).
4. **Use integrity checks or signatures** on serialized payloads to detect
   tampering.
5. **Run deserialization logic in a sandbox or with limited permissions**.

### Examples

**Insecure: unsafe pickle deserialization (Python):**
```python
import pickle
users = pickle.loads(request.data)  // Untrusted data!
```

**Secure: JSON deserialization (Python):**
```python
import json
users = json.loads(request.data)  // Safe, only data structures
```

**Insecure: unsafe Java deserialization:**
```java
ObjectInputStream eis = new ObjectInputStream(request.getInputStream());
Object obj = eis.readObject();  // Gadget chain risk!
```

**Secure: whitelisted class deserialization (Java):**
```java
ObjectInputStream eis = new ObjectInputStream(request.getInputStream()) {
  protected Class<?> resolveClass(ObjectStreamClass osc)
    throws IOException, ClassNotFoundException {
    if (!osc.getName().startsWith("com.myapp.")) {
      throw new ClassNotFoundException(osc.getName());
    }
    return super.resolveClass(osc);
  }
};
Object obj = eis.readObject();
```

**Insecure: PHP unserialize with user input:**
```php
$data = unserialize($_COOKIE['user']);  // Dangerous!
```

**Secure: JSON for cookies (PHP):**
```php
$data = json_decode($_COOKIE['user'], true);
if (json_last_error() !== JSON_ERROR_NONE) {
  throw new Exception('Invalid data');
}
```

### Exploitation techniques

- Crafting a malicious payload that, when deserialized, invokes a
  gadget chain in application libraries leading to code execution.
- Modifying fields to escalate privileges, e.g., changing `isAdmin=false`
  to `true` in a serialized session object.

### Prevention Checklist

- [ ] Serialized data is never accepted from user input; JSON is used instead.
- [ ] Only trusted sources are deserialized if native serialization is unavoidable.
- [ ] A whitelist of allowed classes is defined and enforced during deserialization.
- [ ] Serialized payloads are signed (HMAC or RSA) to detect tampering.
- [ ] Deserialization runs with minimal privileges or in a sandboxed environment.
- [ ] Libraries and gadget chains are kept up to date and reviewed.

---

## 9. Using Components with Known Vulnerabilities

Applications often rely on open-source libraries or frameworks. When
those components contain security flaws and are not updated, attackers
can take advantage of them.

### Detection clues

- `package.json`, `requirements.txt`, `Gemfile`, etc. listing old
  versions.
- URLs or comments referring to known CVEs.
- The presence of unmaintained or deprecated modules.

### Recommendations

1. **Maintain a dependency inventory** and regularly scan it for
   vulnerabilities using tools like `npm audit`, `Dependabot`,
   `Snyk`, or `OWASP Dependency-Check`.
2. **Update dependencies promptly** when security fixes are released.
3. **Avoid including unnecessary libraries**; remove unused packages.
4. **Isolate critical functions** behind interfaces so updates affect
   fewer areas of the codebase.
5. **Use locked versions** (package lock files), but review and update
   them frequently.
6. **Monitor third-party components** for security advisories specific
   to your platform (e.g., PyPI, Maven Central, npm).

### Examples

**Check for vulnerable dependencies (Node.js):**
```bash
npm audit
```

**Check for vulnerable dependencies (Python):**
```bash
pip install safety
safety check
```

**Outdated package manifest (package.json):**
```json
{
  "dependencies": {
    "lodash": "3.10.0"  // Contains known CVEs!
  }
}
```

**Updated package manifest:**
```json
{
  "dependencies": {
    "lodash": "^4.17.21"  // Patched version
  }
}
```

**Vulnerable Docker image:**
```dockerfile
FROM ubuntu:16.04  // Outdated OS with many CVEs
RUN npm install
```

**Secure Docker image:**
```dockerfile
FROM ubuntu:22.04  // Current LTS
RUN npm install && npm audit fix
```

**CI automation for scanning (GitHub Actions):**
```yaml
name: Security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm audit --audit-level=moderate
      - run: pip install safety && safety check
```

### Special cases

- Transitive dependencies: a secure top-level package may depend on an
  outdated library.
- Frontend packages: unpatched JavaScript libs served to clients can lead
  to XSS or other issues.
- Container images and OS packages also count; run `trivy` or `clair`
  scans.

### Prevention Checklist

- [ ] All dependencies are listed in a lock file (package-lock.json, requirements.lock, etc.).
- [ ] Regular dependency audits are performed using platform-specific tools.
- [ ] Vulnerable dependencies are updated promptly when patches are released.
- [ ] Unused dependencies are removed to reduce the attack surface.
- [ ] Transitive dependencies are reviewed and monitored.
- [ ] CI/CD pipelines include automated dependency scanning.
- [ ] Container base images are frequently updated and scanned.
- [ ] Security advisories and mailing lists are monitored.

---

## 10. Insufficient Logging & Monitoring

Without proper logging and monitoring, attackers can operate inside an
application undetected and response teams cannot assess the scope of an
incident.

### Red flags

- Authentication and authorization failures aren't logged.
- Logs contain sensitive data (passwords, tokens) in cleartext.
- No centralized logging system; logs are scattered across servers.
- Lack of alerts for unusual activities (e.g., repeated 404s, failed
  logins, high-volume requests).

### Guidance

1. **Log security-relevant events**: logins, logouts, access denied,
   file access, configuration changes.
2. **Ensure logs have context** (user ID, timestamp, source IP) and are
   tamper-evident.
3. **Monitor and alert** on anomalies using SIEM tools or cloud native
   monitors (CloudWatch, Azure Monitor).
4. **Protect log storage** – restrict who can read or modify logs.
5. **Rotate and archive logs** securely; retain them for a period
   appropriate to your compliance needs.

### Examples

**Insecure: no logging of authentication events (Express.js):**
```javascript
app.post('/login', (req, res) => {
  if (authenticate(req.body.username, req.body.password)) {
    req.session.userId = user.id;  // No log!
  }
});
```

**Secure: logging authentication (Express.js):**
```javascript
const logger = require('winston');
app.post('/login', (req, res) => {
  try {
    if (authenticate(req.body.username, req.body.password)) {
      logger.info('Login successful', {
        username: req.body.username,
        ip: req.ip,
        timestamp: new Date(),
      });
      req.session.userId = user.id;
    } else {
      logger.warn('Login failed', { username: req.body.username, ip: req.ip });
    }
  } catch (error) {
    logger.error('Login error', { error: error.message });
  }
});
```

**Insecure: logging secrets (Python):**
```python
logger.info(f"Connecting with password: {password}")  // Don't do this!
```

**Secure: redacting secrets (Python):**
```python
logger.info(f"Connecting to DB")  // No sensitive data
```

**Insecure: insufficient monitoring:**
```bash
echo "Failed login" >> /var/log/auth.log  // Logs written, no alerts
```

**Secure: monitoring with alerts:**
```yaml
AlarmActions:
  - SNS topic for failed logins
MetricName: FailedLoginAttempts
Statistic: Sum
Threshold: 5  // Alert if 5 failed logins in 5 minutes
```

### Edge cases

- Logging too much data can expose sensitive information or create
  performance issues.
- Attackers may delete their own log entries if they gain file system
  access.
- Application logs may be bypassed if the attacker achieves remote code
  execution and disables logging.

### Prevention Checklist

- [ ] All security-relevant events are logged: logins, failed authentications, access denials.
- [ ] Logs include sufficient context: user ID, source IP, timestamp, action, result.
- [ ] Sensitive data never appears in logs.
- [ ] Logs are centralized and retained for a sufficient period.
- [ ] Log integrity is protected: write-once storage or cryptographic signatures.
- [ ] Automated alerts are triggered for suspicious patterns.
- [ ] Log access is restricted to authorized personnel.
- [ ] Log retention policies comply with compliance requirements.

---

*This comprehensive guide is part of the OWASP Top 10 security skill set, designed to help developers identify, understand, and fix the most critical security vulnerabilities found in web applications.*
