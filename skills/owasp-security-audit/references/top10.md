# OWASP Top 10 — Web Application Risks

This is the default reference for any code that speaks HTTP, renders HTML,
persists data, or handles user credentials. Its ten categories recur in
the API, Kubernetes, and LLM standards under different names; reading
through this list first will speed up every later reference.

**Source:** OWASP Top 10 project — **OWASP Top 10 2025 (Final)**,
<https://owasp.org/Top10/2025/>. Retrieved 2026-07-21. The OWASP Foundation's
own repository marks this edition **RELEASED** and the prior 2021 edition
**SUPERSEDED**; this file uses the 2025 category codes and ordering below.
The mapping table immediately following this note bridges every 2025
identifier back to its 2021 origin (or marks it net-new) so readers who
still know the list by its 2021 numbers can find their footing. Category
codes below use plain `A01`–`A10` form per repo convention (no `:2025`
suffix in headers); the edition itself is recorded here and in
`owasp-urls.json`.

## What changed: 2021 to 2025

Nine of the ten 2025 categories carried over from 2021 — only A10
(Mishandling of Exceptional Conditions) is net-new. Of those nine, five
moved rank (A02–A06) and four were renamed (A03, A07–A09) — this is not a
simple renumbering. Every section below is built from its **topic**, never
from a numeric find-and-replace against the 2021 file.

| 2025 ID | 2025 Name | 2021 origin | Change |
|---|---|---|---|
| A01 | Broken Access Control | A01:2021 Broken Access Control | Same rank (#1); SSRF (former A10:2021) rolled in |
| A02 | Security Misconfiguration | A05:2021 Security Misconfiguration | Moved #5 → #2 |
| A03 | Software Supply Chain Failures | A06:2021 Vulnerable and Outdated Components | New name/scope, expanded from #6 → #3 |
| A04 | Cryptographic Failures | A02:2021 Cryptographic Failures | Moved #2 → #4 |
| A05 | Injection | A03:2021 Injection | Moved #3 → #5 |
| A06 | Insecure Design | A04:2021 Insecure Design | Moved #4 → #6 |
| A07 | Authentication Failures | A07:2021 Identification and Authentication Failures | Same rank (#7); renamed (dropped "Identification and") |
| A08 | Software or Data Integrity Failures | A08:2021 Software and Data Integrity Failures | Same rank (#8); renamed ("and" → "or") |
| A09 | Security Logging & Alerting Failures | A09:2021 Security Logging and Monitoring Failures | Same rank (#9); renamed ("Monitoring" → "Alerting") |
| A10 | Mishandling of Exceptional Conditions | *(no 2021 equivalent)* | Net-new category |
| *(retired)* | — | A10:2021 Server-Side Request Forgery (SSRF) | Folded into A01, no longer standalone |

Only A01, A07, A08, and A09 keep the same numeric slot — and three of those
four were renamed. A02 through A06 each reference a *different* underlying
risk topic than their 2021 numeric counterpart; always resolve a category by
name, not by number.

## How to use this file

For each suspected category, read the matching section, apply the
**detection signals** to the code in front of you, then use the
**mitigation** column to phrase the fix. The **code example** shows the
vulnerable/secure pair in one language; look in
`../assets/examples/` for fuller paired examples or in
`vulnerable-patterns.md` for other languages.

---

## A01: Broken Access Control

The most common real-world finding. Covers missing authorization checks,
IDOR, privilege escalation, and relying on client-side enforcement. For
2025, Server-Side Request Forgery — formerly its own category, A10 in the
2021 edition — is now assessed under this category (CWE-918); see the SSRF
sub-section below.

**Detection signals**
- Handlers that read or mutate resources keyed by a URL parameter
  (`/users/:id`, `/orders/:id`) with no check that the authenticated user
  owns or may access that resource.
- Authorization checked only in the UI (hidden fields, disabled buttons)
  while the server endpoint is wide open.
- Role checks done with "blacklist" logic (`if not is_guest` → treat as
  admin) instead of explicit allowlists.
- Functions that update privileged state (billing, roles, feature flags)
  with no explicit role check.
- Direct database lookups by primary key without a `WHERE user_id = ?`
  ownership clause.

**Mitigations**
- Default-deny: every handler requires explicit allow. A missing
  `@require_auth` or `requireRole(...)` is a finding.
- Enforce ownership at the data layer: `WHERE id = ? AND user_id = ?`
  beats a post-query check because a successful query itself is now the
  authorization.
- Use opaque / unguessable IDs for resources whose enumeration matters
  (UUIDs, signed tokens) — but never as the *only* control.
- Log every denial; repeated 403s on sequential IDs are the classic IDOR
  signature.

**Code example**
```python
# VULNERABLE
@app.get("/orders/<int:order_id>")
def get_order(order_id):
    return jsonify(db.get_order(order_id))

# SECURE
@app.get("/orders/<int:order_id>")
@require_auth
def get_order(order_id):
    order = db.get_order(order_id)
    if order is None or (order.user_id != g.user.id and not g.user.is_admin):
        abort(403)
    return jsonify(order)
```

**Checklist**
- [ ] Every sensitive handler has explicit auth + authorization.
- [ ] Ownership is enforced at the query layer or immediately after.
- [ ] Admin-only functions check role, not presence of a token.
- [ ] Access denials are logged with user id and resource id.

### Sub-section: Server-Side Request Forgery (SSRF) — CWE-918

Formerly its own category, A10 in the 2021 edition, SSRF is now assessed
as part of Broken Access Control: the underlying failure is the same trust
boundary violation (the server acts on a resource location the caller
controls). Its technical detection signals and mitigations are unchanged —
only its home category moved.

**Detection signals**
- Handlers that accept URLs (`picture_url`, `webhook`, `import_from`,
  `callback`) and pass them to `fetch`, `requests`, `axios`, `http.get`,
  a headless browser, or an image processor.
- Parsing with string operations (`url.startswith("https://")`) rather
  than a real URL parser.
- Clients with `allow_redirects=True` / `followRedirect: true`.
- No network egress controls: the app can reach `169.254.169.254`,
  `10.0.0.0/8`, `127.0.0.1`, `::1`.

**Mitigations**
- Parse with a real library (`urllib.parse`, `new URL()`).
- Allowlist schemes, hosts, and ports. Resolve the hostname and reject
  private/loopback/link-local IPs *after* resolution (to defeat DNS
  rebinding).
- Disable redirects on user-supplied fetches; if you must follow,
  re-validate the target.
- Block egress to cloud metadata and internal ranges at the network
  layer, not just in app code. This is the single most effective SSRF
  defense.

**Code example**
```python
# VULNERABLE
import requests
def fetch_avatar(url):
    return requests.get(url).content

# SECURE
import ipaddress, socket
from urllib.parse import urlparse

ALLOW_SCHEMES = {"https"}
ALLOW_HOSTS = {"images.example.com", "cdn.partner.com"}

def fetch_avatar(url):
    u = urlparse(url)
    if u.scheme not in ALLOW_SCHEMES or u.hostname not in ALLOW_HOSTS:
        raise ValueError("disallowed URL")
    for fam, _, _, _, sa in socket.getaddrinfo(u.hostname, None):
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("internal address")
    return requests.get(url, allow_redirects=False, timeout=5).content
```

**Checklist**
- [ ] URLs parsed with a library, not regex/startswith.
- [ ] Scheme + host allowlist enforced.
- [ ] Resolved IP rejected if in private/loopback/link-local ranges.
- [ ] Redirects off by default.
- [ ] Egress firewall blocks metadata endpoints and internal ranges.

---

## A02: Security Misconfiguration

Formerly A05 in the 2021 edition (moving up from #5 to #2 — OWASP reports
that 100% of applications tested in the 2025 dataset had some form of
misconfiguration). Defaults that were safe in dev and got shipped to
production; substance is unchanged from the 2021 edition, only its rank
and number moved.

**Detection signals**
- `DEBUG = True`, `app.debug = True`, `NODE_ENV !== 'production'`.
- Stack traces or framework pages returned to clients on error.
- Default credentials (`admin` / `admin`) still present.
- Missing security headers: no `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options` / CSP `frame-ancestors`, `Referrer-Policy`.
- Overly permissive CORS: `Access-Control-Allow-Origin: *` combined
  with `Access-Control-Allow-Credentials: true`.
- Cloud buckets, message queues, admin consoles with public ACLs.
- `X-Powered-By`, `Server:`, framework version headers leaking stack.
- XML parsers configured to resolve external entities (CWE-611 XXE) —
  called out explicitly in the 2025 CWE mapping alongside CWE-16
  Configuration.

**Mitigations**
- Use `helmet` (Express), `SecureHeaders` middleware (Python), or the
  framework's production preset.
- Centralize error handling; return a generic error to clients and log
  the stack internally.
- Pin CORS origins to an allowlist; never pair `*` with credentials.
- Infrastructure-as-code linters (`trivy config`, `checkov`,
  `kube-linter`) on every PR.
- Disable external entity resolution in XML parsers (`resolve_entities=False`,
  `XMLConstants.FEATURE_SECURE_PROCESSING`) to close the CWE-611 XXE path.

**Code example**
```python
# VULNERABLE
app.debug = True
app.config["SECRET_KEY"] = "dev"

# SECURE
app.debug = False
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # fail fast if unset
app.after_request(lambda r: (r.headers.update({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}), r)[1])
```

**Checklist**
- [ ] Debug flags off; generic error page returned to clients.
- [ ] Defaults rotated; no `admin/admin`-style credentials.
- [ ] Security headers set on every response.
- [ ] CORS uses a specific origin allowlist.
- [ ] IaC scanner runs on every PR.
- [ ] XML parsers reject external entity resolution (XXE closed).

---

## A03: Software Supply Chain Failures

New category for 2025 — expands on what was A06:2021 (Vulnerable and
Outdated Components) to cover the full software supply chain, not just
known-vulnerable dependencies. The category originated from 2013's "A9 –
Using Components with Known Vulnerabilities" but now spans the entire
dependency, build, and distribution ecosystem: source, CI/CD pipeline,
build artifacts, and distribution channel are all in scope, not just a
package's declared version number.

**Detection signals**
- `package.json`, `requirements.txt`, `pom.xml`, `go.mod` with versions
  you can google and find CVEs on. Unpinned ranges (`^1.2.3`, `~1.2`)
  that have silently moved to a vulnerable release.
- No SCA / dependency scanning in CI. `npm audit`, `pip-audit`,
  `cargo audit`, GitHub Dependabot, Snyk, Trivy.
- CI/CD pipelines that pull build tools, actions, or base images by
  floating tag (`uses: actions/checkout@v4` unpinned to a SHA, `FROM
  node:latest`) rather than a pinned, verifiable reference.
- Build or publish steps that run with broad, long-lived credentials
  instead of short-lived, scoped tokens.
- No signed-artifact verification before deployment; packages installed
  straight from a registry with no provenance check.
- Abandoned packages (last publish > 2 years on a security-sensitive
  library), or a maintainer account takeover risk (compromised npm/PyPI
  publisher credentials).

**Mitigations**
- Generate and track a Software Bill of Materials (SBOM) for every build;
  diff SBOMs between releases to catch unexpected dependency changes.
- Harden CI/CD: pin actions/base images by SHA (not tag), use short-lived
  scoped credentials, require code review + branch protection before merge
  to a release branch.
- Require signed artifacts (Sigstore/cosign) and verify signatures before
  deployment; reject unsigned or unverifiable builds.
- Stage rollouts (canary, percentage-based) so a compromised dependency
  or build step is caught before it reaches 100% of production.
- SCA in CI: `npm audit`, `pip-audit`, `trivy`, Dependabot. Break the
  build on criticals; open issues on the rest. Pin by lockfile
  (`package-lock.json`, `poetry.lock`, `Pipfile.lock`).

**Example attack scenarios** (per OWASP's 2025 write-up): the SolarWinds
Orion build-system compromise (2019); the 2025 Bybit exploit, in which a
compromised piece of wallet-signing software led to a reported $1.5B theft;
and the 2025 `Shai-Hulud` self-propagating npm worm, which harvested and
republished credentials through compromised maintainer accounts across
transitive dependencies.

**Code example**
```bash
# VULNERABLE: unpinned CI action + unverified install
# .github/workflows/deploy.yml
- uses: actions/checkout@v4          # floating tag, not a pinned SHA
- run: npm install && npm run build  # no lockfile enforcement, no audit gate

# SECURE: pinned action, locked install, audit gate, signed artifact
# .github/workflows/deploy.yml
- uses: actions/checkout@8f4b7f84   # actions/checkout, pinned to commit SHA
- run: npm ci                        # fails if lockfile doesn't match package.json
- run: npm audit --audit-level=high  # blocks build on high/critical CVEs
- run: cosign sign --key cosign.key dist/app.tar.gz
```

**Checklist**
- [ ] SBOM generated per build and diffed across releases.
- [ ] CI/CD actions and base images pinned by SHA, not floating tag.
- [ ] Build credentials are short-lived and scoped, not long-lived secrets.
- [ ] Artifacts signed; signatures verified before deployment.
- [ ] Rollouts staged (canary/percentage) rather than all-at-once.
- [ ] SCA scanner runs in CI and blocks on critical findings.

---

## A04: Cryptographic Failures

Formerly A02 in the 2021 edition (moving down two positions to #4).
Sensitive data transmitted or stored without appropriate protection;
substance is unchanged, common CWEs include weak PRNG use (CWE-327,
CWE-331, CWE-1241, CWE-338) alongside the long-standing weak-hash and
plaintext-secret findings.

**Detection signals**
- Plaintext secrets in source (`api_key = "sk-..."`, `password =`).
- Weak hashes for passwords (`md5`, `sha1`, unsalted `sha256`). Only
  `bcrypt`, `scrypt`, `argon2`, or `pbkdf2` with an appropriate cost
  factor belong here.
- DIY crypto or ECB-mode AES (`AES.new(key, AES.MODE_ECB)`). Look for
  GCM or authenticated modes; ECB leaks patterns.
- `http://` URLs for anything authenticated, or `verify=False` on TLS
  clients.
- Keys derived from passwords with a single hash iteration.
- Secrets logged (`logger.info(f"token={token}")`).
- Weak or predictable pseudo-random number generation used for tokens,
  session IDs, or key material (`random.random()`, `Math.random()`,
  non-CSPRNG sources) — the 2025 CWE list calls this out explicitly.

**Mitigations**
- Passwords: `bcrypt` / `argon2id`. Never store reversible.
- Symmetric encryption: AES-256-GCM, with random IV per message.
- Secrets from env vars, vault, or KMS. Never in source.
- TLS 1.2+ everywhere, including service-to-service.
- Mask sensitive fields in logs; implement log filters that redact
  patterns like `Bearer [A-Za-z0-9._\-]+`.
- Use a cryptographically secure RNG (`secrets` module in Python,
  `crypto.randomBytes` in Node) for anything security-sensitive — never
  a general-purpose PRNG.

**Code example**
```javascript
// VULNERABLE
const bcrypt = require('bcrypt');
const hash = crypto.createHash('md5').update(password).digest('hex');

// SECURE
const hash = await bcrypt.hash(password, 12);
const ok = await bcrypt.compare(candidate, hash);
```

**Checklist**
- [ ] Password hashes use bcrypt/argon2 with cost ≥ 10/12.
- [ ] No secrets in source or CI config.
- [ ] TLS enforced everywhere; no `verify=False` in production.
- [ ] Encryption uses an authenticated mode (GCM/CCM/ChaCha20-Poly1305).
- [ ] Logs pass through a redactor that removes tokens/keys/PANs.
- [ ] Tokens/session IDs/key material use a CSPRNG, not a general PRNG.

---

## A05: Injection

Formerly A03 in the 2021 edition (falling two spots from #3 to #5). SQL,
NoSQL, command, LDAP, XPath, template, and header injection, plus
Cross-Site Scripting. This category has the greatest number of associated
CVEs of any Top 10 category: XSS alone accounts for 30,000+ CVEs (high
frequency, comparatively low individual impact) while SQL injection
accounts for 14,000+ CVEs (lower frequency, high impact). Whenever
untrusted input reaches a parser, treat it as a possible sink.

**Detection signals**
- String-built SQL: `f"SELECT ... WHERE id = {id}"` or `query + userInput`.
- `exec`, `eval`, `subprocess.Popen(..., shell=True)`, `os.system` with
  arguments built from input.
- `innerHTML = …`, `document.write(...)`, `$("<div>" + x + "</div>")`.
- Template engines rendered with user-controlled strings (`render_template_string(x)`
  where `x` comes from a request) — Jinja/EJS/Handlebars SSTI.
- MongoDB queries built from raw request JSON without sanitizing
  `$`-prefixed operators.

**Mitigations**
- Parameterized queries / prepared statements. Every language has them.
- For shell, pass argv arrays, never a shell string: `subprocess.run(["tar", ...])`.
- Render HTML through an encoder (`escape`, `htmlspecialchars`) or a
  framework that auto-escapes (React JSX, Jinja2 autoescape).
- Validate input with a positive allowlist where possible — "numeric, 1–8
  digits" is better than "no semicolons".

**Code example**
```python
# VULNERABLE
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")

# SECURE
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```

**Checklist**
- [ ] No SQL built from string concatenation or f-strings.
- [ ] No `shell=True` on subprocess with untrusted input.
- [ ] Template rendering is auto-escaped or inputs are explicitly
      escaped.
- [ ] Input validated with allowlists at the boundary.

---

## A06: Insecure Design

Formerly A04 in the 2021 edition (sliding two spots from #4 to #6). A flaw
in the design, not the implementation. Notable CWEs include CWE-256
Unprotected Storage of Credentials, CWE-269 Improper Privilege Management,
CWE-434 Unrestricted Upload, CWE-501 Trust Boundary Violation, and CWE-522
Insufficiently Protected Credentials. You can't linter-fix this — you have
to think about it.

**Detection signals**
- Password reset flows that reveal whether an email is registered.
- Rate limits that only protect against accidents, not attackers
  (per-IP limit on a flow attackers would distribute).
- Trust boundaries that aren't drawn at all — e.g., a SPA backend that
  trusts a cookie the SPA itself sets.
- Single-factor auth for sensitive financial or admin actions.
- "Security by obscurity": relying on unguessable URLs rather than auth.
- Upload handlers that accept any file type/size with no restriction.

**Mitigations**
- Threat-model new features before they ship. Ask: who can call this?
  What happens when they lie about who they are?
- Adopt known-good patterns (OWASP ASVS, OAuth 2.1) rather than invent.
- Design for misuse: for every "user does X" flow, consider the
  "attacker does X at scale" version.

**Checklist**
- [ ] Threat model exists for the feature and names the adversaries.
- [ ] Sensitive actions require step-up auth.
- [ ] Rate limits consider distributed abuse, not just per-IP.
- [ ] Error responses don't leak existence of accounts/resources.
- [ ] Upload handlers restrict file type/size and validate content.

---

## A07: Authentication Failures

Formerly "Identification and Authentication Failures" in the 2021 edition
— same rank (#7), name shortened for 2025 to more accurately reflect the
36 mapped CWEs. Weaknesses in proving who the user is.

**Detection signals**
- Custom auth code where a library would do. 90% of DIY auth has bugs.
- No rate limiting on login, password reset, or MFA verification.
- Weak password policies (no min length, no breached-password check).
- Predictable session IDs; tokens that don't expire or aren't
  invalidated on logout.
- Password reset that accepts short, non-expiring tokens, or reveals
  whether the email existed.
- JWT tokens with `alg: none`, unverified signatures, or secrets
  committed to git.

**Mitigations**
- Use well-reviewed auth: Passport, Devise, django.contrib.auth,
  NextAuth, Auth0/Okta/Ory/Supabase. Never roll your own token format.
- Rate-limit login + reset + MFA; lock accounts after repeated failures.
- Enforce password strength (length, breach check via HIBP API, not
  complexity rules).
- MFA: TOTP or WebAuthn, gated on sensitive actions.
- Session tokens: ≥128 bits of entropy, HttpOnly + Secure cookies,
  regenerate on login, invalidate on logout and password change.

**Code example**
```javascript
// VULNERABLE
const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64'));
const userId = payload.user_id;  // never verified!

// SECURE
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],   // explicit, defeats alg:none tricks
  issuer: 'api.example.com',
  audience: 'web',
});
```

**Checklist**
- [ ] Auth via a vetted library, not hand-rolled.
- [ ] Login, reset, and MFA endpoints rate-limited.
- [ ] Passwords hashed with bcrypt/argon2 and checked against breached
      lists.
- [ ] JWTs verified with an explicit algorithm allowlist.
- [ ] Sessions invalidated on logout and password change.

---

## A08: Software or Data Integrity Failures

Formerly "Software and Data Integrity Failures" in the 2021 edition — same
rank (#8), name changed from "and" to "or" for 2025 as a clarifying tweak.
Code, updates, and data consumed without integrity checks.

**Detection signals**
- `pickle.loads`, `yaml.load` (without `SafeLoader`), Java
  `ObjectInputStream`, PHP `unserialize` on untrusted input.
- Auto-updaters that fetch code from the network without signature
  verification.
- CI/CD pipelines that install from the public internet without lock
  files, pin, or SHA check.
- CDN / script tags loaded without Subresource Integrity (`integrity=`).
- Webhooks accepted without signature verification.

**Mitigations**
- Prefer JSON (or a schema-validated format) over native serialization.
- Sign artifacts; verify signatures before installation
  (Sigstore/cosign for containers, Sigstore for packages).
- Pin dependencies by hash where the ecosystem supports it
  (`pip install --require-hashes`, `npm ci` with lockfile).
- Verify webhook signatures using constant-time comparison.

**Checklist**
- [ ] No unsafe deserialization of user-supplied data.
- [ ] Artifacts signed; signatures verified in deployment.
- [ ] Dependencies pinned by version + hash.
- [ ] Webhook handlers verify signatures with a constant-time compare.

---

## A09: Security Logging & Alerting Failures

Formerly "Security Logging and Monitoring Failures" in the 2021 edition —
same rank (#9), renamed for 2025 to emphasize the *alerting* function, not
just the act of writing logs. This category is notoriously difficult to
test for (only 723 associated CVEs in the 2025 dataset, the lowest of any
category) because the absence of an alert is invisible until an incident
happens. Relevant CWEs: CWE-117 (output encoding to logs), CWE-532
(sensitive data in logs), CWE-778 (insufficient logging).

**Detection signals**
- No logs around auth success/failure, privilege changes, admin actions,
  data exports.
- Logs contain secrets (tokens, PANs, passwords).
- No centralized log aggregation; logs on the box that got owned.
- Alerts trigger only on infra (CPU/disk), not on security events.
- Logs exist and are retained, but nothing consumes or alerts on them —
  a SIEM ingestion pipeline with zero configured alert rules is still a
  finding under this category, even if logging itself is complete.

**Mitigations**
- Log auth events, access denials, role/permission changes, configuration
  changes, and significant data exports. Include user id, source IP,
  user agent, request id.
- Redact secrets in a log filter before they reach the sink.
- Ship logs off-box to a SIEM or log service; retain per policy.
- Alert on: impossible travel, brute-force patterns, sudden permission
  grant, mass export, account takeover indicators.
- Treat "logs exist" and "someone gets paged" as two separate controls —
  verify both, not just the first.

**Checklist**
- [ ] Security events logged with correlation ids and user context.
- [ ] Logs centralized and retained; the host can't silence them.
- [ ] Redaction filter prevents secrets from entering logs.
- [ ] Alerts defined for the top 5 abuse patterns for your app.
- [ ] At least one alert rule actually fires and pages someone (not just
      log collection with no downstream consumer).

---

## A10: Mishandling of Exceptional Conditions

New category for 2025 — no 2021 equivalent. Covers failure to prevent,
detect, or respond to abnormal conditions: improper error handling,
"failing open" instead of "failing closed," verbose error messages that
leak system internals, uncaught exceptions, null pointer dereferences, and
exception handling scattered inconsistently across a codebase instead of
centralized. Maps to 24 CWEs: CWE-209, 215, 234, 235, 248, 252, 274, 280,
369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755,
756.

**Detection signals**
- Bare `except:` / `catch (e) {}` blocks that swallow errors silently
  instead of failing closed.
- Error responses that include stack traces, SQL text, internal file
  paths, or framework version info.
- Resource-acquisition code (file handles, DB connections, locks) with no
  `finally`/`try-with-resources`/context-manager guarantee of release on
  the exception path — a classic resource-exhaustion DoS vector.
- Multi-step transactions (payment, inventory, multi-table writes) with
  no rollback on partial failure, leaving state inconsistent.
- Authorization or validation logic that defaults to "allow" when an
  upstream check throws or times out (fail-open instead of fail-closed).
- Duplicate or inconsistent exception-handling logic copy-pasted across
  handlers instead of centralized middleware.

**Mitigations**
- Centralize error handling in one place (middleware/decorator) so every
  handler gets consistent fail-closed behavior instead of ad hoc
  try/except blocks.
- Return generic error messages to clients; log full detail (including
  stack trace) only to the internal, redacted log sink.
- Wrap resource acquisition in guaranteed-release constructs
  (`with`/`try-with-resources`/`defer`) so exceptions can't leak file
  handles, connections, or locks.
- Design multi-step operations as transactions with explicit rollback on
  any step's failure — never leave partial state on an exception.
- Default to "deny"/"fail closed" when a dependency (auth check, feature
  flag service, rate limiter) is unreachable or throws, rather than
  silently allowing the request through.

**Example attack scenarios** (per OWASP's 2025 write-up): (1) a
resource-exhaustion denial-of-service caused by a file-upload handler
whose exception path never releases the temp-file handle or memory
buffer, letting an attacker exhaust resources with repeated failed
uploads; (2) a verbose database error message that leaks schema/table
names, which an attacker uses to refine a follow-on SQL injection attack;
(3) financial transaction state corruption from a multi-step payment flow
that isn't rolled back on partial failure, leaving the ledger
inconsistent after a mid-transaction error ("fail closed," not
attempt-to-resume).

**Code example**
```python
# VULNERABLE: swallows the exception, leaks resources, fails open
def process_upload(file):
    try:
        tmp = save_temp(file)
        validate(tmp)
        return store(tmp)
    except Exception:
        return {"status": "ok"}  # silently reports success; tmp file leaks

# SECURE: fails closed, releases resources, returns a generic error
def process_upload(file):
    with tempfile.NamedTemporaryFile() as tmp:
        try:
            save_temp(file, tmp)
            validate(tmp)
            return store(tmp)
        except ValidationError:
            logger.warning("upload validation failed", exc_info=True)
            raise HTTPException(400, "Invalid file")
        except Exception:
            logger.error("upload processing failed", exc_info=True)
            raise HTTPException(500, "Internal server error")
    # tempfile context manager guarantees cleanup on every exit path
```

**Checklist**
- [ ] Exception handling is centralized, not duplicated per-handler.
- [ ] Clients receive generic errors; full detail is logged internally
      only.
- [ ] Resource acquisition uses guaranteed-release constructs on every
      exception path.
- [ ] Multi-step operations roll back fully on partial failure.
- [ ] Dependent-service failures default to fail-closed, not fail-open.
