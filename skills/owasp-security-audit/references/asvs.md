# OWASP ASVS — Application Security Verification Standard

Load this reference when a user asks a compliance-shaped question:
"does this meet ASVS L2?", "which requirements apply to session
management?", "what's the bar for a regulated environment?" ASVS is
a **verification** standard — a list of testable requirements, not
a narrative standard like the Top 10.

**Source:** OWASP Application Security Verification Standard (ASVS) 5.0.0 —
<https://owasp.org/www-project-application-security-verification-standard/>.
Requirement text, chapter files and version mappings come from OWASP's own
repository, <https://github.com/OWASP/ASVS>, pinned to commit
`2b300716ebbef654788d0a14d6c878cecc70c2e9`. OWASP content is licensed
`CC BY-SA 4.0`; the entries below paraphrase it with attribution.

**Edition verification:** ASVS 5.0.0, released 2025-05-30, is the latest stable
edition: the project page names it as the current version, and the repository
has no release tag for any later edition. Chapter names, requirement IDs and
levels were read from the pinned CSV
`5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`
and the chapter files. Every ID cited below is a key of the official mapping
file `5.0/mappings/mapping_v5.0.0_to_v4.0.3.yml` at that commit (sha256
`d92aafd2410526f6e62666cbb12bb4ae170c54de5021fd48bf0f481af955207f`). OWASP
corrected that file after the release tag (the `v5.0.0-6.2.10` row), so the
commit is pinned rather than the tag. Retrieved 2026-10-04.

**How to cite:** OWASP's versioned identifier format is
`v<version>-<chapter>.<section>.<requirement>`, for example `v5.0.0-6.2.1`.
Every ID in this file uses that form, because the same bare number names
different requirements in different editions. The final section of this file
explains how to translate reports that cite older numbers.

## Verification levels

ASVS defines three cumulative levels: each level includes every requirement of
the levels below it. The official CSV holds 345 requirements: 70 at L1, 183 at
L2 and 92 at L3.

- **L1** — the first layer and the starting point, about a fifth of the
  standard. These are the basic, first-line defenses against common attacks
  that need no other flaw to succeed.
- **L2** — where most applications should aim. L1 plus L2 together make up
  about 70% of the standard.
- **L3** — the remaining defense-in-depth and harder-to-implement controls.

Each requirement carries exactly one level: the lowest level at which it
applies. Which level to target is the organization's decision, made from its
own risk and maturity, not a tier fixed by the kind of data an application
holds. Some requirements tighten inside their own text at a higher level while
staying filed at their CSV level, for example `v5.0.0-6.3.3` (a
hardware-based factor at L3), `v5.0.0-12.1.2` and `v5.0.0-16.3.2`.

When the user asks "does this meet Ln", the answer is "for each
applicable chapter, here's the L1/L2/L3 requirements and which are
met / partially met / missing". Don't treat "pass" or "fail" as a
single number.

## The 17 chapters at a glance

| Chapter | Name | Requirements | L1 / L2 / L3 | Start here when the code has |
|---|---|---|---|---|
| V1 | Encoding and Sanitization | 30 | 8 / 19 / 3 | HTML, URL, JavaScript, SQL, OS-command or LDAP sinks, templates, XML or object deserialization |
| V2 | Validation and Business Logic | 13 | 4 / 7 / 2 | input validation, multi-step workflows, business limits, bulk or automated calls |
| V3 | Web Frontend Security | 31 | 8 / 11 / 12 | browser-facing pages, cookies, CSP and security headers, cross-origin messaging, third-party scripts |
| V4 | API and Web Service | 16 | 2 / 8 / 6 | REST, GraphQL or SOAP endpoints, WebSocket handlers, raw HTTP message handling |
| V5 | File Handling | 13 | 4 / 5 / 4 | file uploads, downloads, stored user files, archive extraction |
| V6 | Authentication | 47 | 13 / 22 / 12 | login, registration, password reset, MFA, identity provider integration |
| V7 | Session Management | 19 | 6 / 12 / 1 | session cookies or tokens, logout, timeouts, re-authentication |
| V8 | Authorization | 13 | 4 / 3 / 6 | role checks, object IDs in requests, multi-tenant data, admin functions |
| V9 | Self-contained Tokens | 7 | 4 / 3 / 0 | JWTs or similar signed tokens being issued or verified |
| V10 | OAuth and OIDC | 36 | 5 / 24 / 7 | OAuth clients, resource servers, authorization servers, OIDC logins |
| V11 | Cryptography | 24 | 3 / 11 / 10 | encryption, hashing, random values, key handling, signatures |
| V12 | Secure Communication | 12 | 3 / 6 / 3 | TLS settings, outbound HTTPS calls, service-to-service traffic |
| V13 | Configuration | 21 | 1 / 12 / 8 | config files, secrets, backend credentials, debug or build artifacts left exposed |
| V14 | Data Protection | 13 | 2 / 7 / 4 | personal or sensitive data, caching, client-side storage, data classification |
| V15 | Secure Coding and Architecture | 21 | 3 / 10 / 8 | third-party dependencies, race conditions, defensive coding patterns |
| V16 | Security Logging and Error Handling | 17 | 0 / 16 / 1 | logging calls, audit trails, error handlers, stack traces |
| V17 | WebRTC | 12 | 0 / 7 / 5 | WebRTC media, TURN servers, signaling |

V16 and V17 have no L1 requirements, so an L1-only review never covers
logging, and V13 has exactly one (`v5.0.0-13.4.1`).

## Mapping to code review

ASVS isn't a replacement for the Top 10 — the Top 10 tells you what
classes of bugs exist; ASVS tells you what controls a verified app
must have in place. Use the Top 10 for offense ("what can go wrong
here?") and ASVS for defense ("what must be true for this to be
secure?").

When a user pastes an auth flow and asks for an ASVS check, walk
through the chapter's requirements and say which are satisfied, which
are violated, and which can't be determined from the snippet.

---

## V1: Encoding and Sanitization

Covers how untrusted data is encoded, escaped and sanitized before it reaches
an interpreter, plus memory-unsafe code and safe handling of serialized data.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x10-V1-Encoding-and-Sanitization.md>

Sections: 1.1 Encoding and Sanitization Architecture; 1.2 Injection Prevention; 1.3 Sanitization; 1.4 Memory, String, and Unmanaged Code; 1.5 Safe Deserialization

**L1**
- `v5.0.0-1.2.1` Output encoding for HTTP responses and HTML or XML documents
  fits the context (HTML elements, attributes and comments, CSS, HTTP header
  fields), so the message or document structure cannot be altered.
- `v5.0.0-1.2.2` URLs built dynamically encode untrusted data for its context
  (URL encoding or base64url for query or path parameters), and only safe URL
  protocols are allowed, blocking `javascript:` and `data:`.
- `v5.0.0-1.2.3` JavaScript content built dynamically, JSON included, uses
  output encoding or escaping so JavaScript and JSON injection cannot change
  its structure.
- `v5.0.0-1.2.4` Data selection and database queries (SQL, HQL, NoSQL, Cypher)
  use parameterized queries, ORMs or entity frameworks, or are otherwise
  protected from SQL and other database injection; the same applies to stored
  procedures.
- `v5.0.0-1.2.5` OS command injection is prevented: operating system calls use
  parameterized OS queries or contextual command-line output encoding.
- `v5.0.0-1.3.1` Untrusted HTML from WYSIWYG editors and similar sources is
  sanitized with a well-known, secure HTML sanitization library or framework
  feature.
- `v5.0.0-1.3.2` The application avoids `eval()` and other dynamic code
  execution features such as Spring Expression Language; where there is no
  alternative, any user input involved is sanitized first.
- `v5.0.0-1.5.1` XML parsers use a restrictive configuration with unsafe
  features such as external entity resolution disabled, preventing XXE.

**L2**
- `v5.0.0-1.1.1` Input is decoded into canonical form only once, only when
  encoded data of that form is expected, and before further processing, never
  after validation or sanitization.
- `v5.0.0-1.1.2` Output encoding and escaping happen as the final step before
  the target interpreter uses the data, or inside the interpreter itself.
- `v5.0.0-1.2.6` Protection against LDAP injection, or specific controls that
  prevent it, is in place.
- `v5.0.0-1.2.7` XPath injection is prevented using query parameterization or
  precompiled queries.
- `v5.0.0-1.2.8` LaTeX processors are configured securely (no `--shell-escape`
  flag) with an allowlist of commands, preventing LaTeX injection.
- `v5.0.0-1.2.9` Special characters in regular expressions are escaped
  (typically with a backslash) so they are not misread as metacharacters.
- `v5.0.0-1.3.3` Data headed into a potentially dangerous context is sanitized
  first to enforce safety measures, such as allowing only characters that are
  safe for that context and trimming overlong input.
- `v5.0.0-1.3.4` User-supplied SVG with scriptable content is validated or
  sanitized to allow only safe tags and attributes (drawing graphics) and no
  scripts or foreignObject.
- `v5.0.0-1.3.5` User-supplied scriptable or expression-template content such
  as Markdown, CSS or XSL stylesheets, BBCode and similar is sanitized or
  disabled.
- `v5.0.0-1.3.6` SSRF is prevented: untrusted data is checked against an
  allowlist of permitted protocols, domains, paths and ports, and dangerous
  characters are sanitized, before the data is used in a call to another
  service.
- `v5.0.0-1.3.7` Template injection is prevented by never building templates
  from untrusted input; where that is unavoidable, the untrusted parts included
  during template creation are sanitized or strictly validated.
- `v5.0.0-1.3.8` Untrusted input is sanitized before JNDI queries, and JNDI is
  configured securely against JNDI injection.
- `v5.0.0-1.3.9` Content is sanitized before it is sent to memcache, preventing
  injection.
- `v5.0.0-1.3.10` Format strings that could resolve in an unexpected or
  malicious way are sanitized before processing.
- `v5.0.0-1.3.11` User input is sanitized before it reaches mail systems,
  preventing SMTP and IMAP injection.
- `v5.0.0-1.4.1` Memory-safe string handling, safer memory copy and safe
  pointer arithmetic detect or prevent stack, buffer and heap overflows.
- `v5.0.0-1.4.2` Sign, range and input validation techniques prevent integer
  overflows.
- `v5.0.0-1.4.3` Dynamically allocated memory and resources are released, and
  references to freed memory are cleared or nulled, preventing dangling
  pointers and use-after-free.
- `v5.0.0-1.5.2` Deserializing untrusted data enforces safe input handling,
  such as an allowlist of object types or limits on client-defined types;
  mechanisms known to be insecure are never used with untrusted input.

**L3**
- `v5.0.0-1.2.10` CSV and formula injection is prevented: CSV exports follow
  the RFC 4180 escaping rules (sections 2.6 and 2.7), and in CSV or other
  spreadsheet formats (XLS, XLSX, ODF) the special characters `=`, `+`, `-`,
  `@`, tab and null get a leading single quote when they start a field.
- `v5.0.0-1.3.12` Regular expressions are free of constructs that cause
  exponential backtracking, and untrusted input is sanitized against ReDoS
  (runaway regex) attacks.
- `v5.0.0-1.5.3` Different parsers for the same data type (JSON, XML, URL)
  parse consistently and share one character-encoding mechanism, avoiding
  exploits such as JSON interoperability flaws or differing URI and file
  parsing in RFI or SSRF attacks.

---

## V2: Validation and Business Logic

Covers documented validation rules, input validation at a trusted layer,
business-logic integrity and protection against automated abuse.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x11-V2-Validation-and-Business-Logic.md>

Sections: 2.1 Validation and Business Logic Documentation; 2.2 Input Validation; 2.3 Business Logic Security; 2.4 Anti-automation

**L1**
- `v5.0.0-2.1.1` Documentation check: the documentation defines input
  validation rules for checking data items against an expected structure,
  whether a common format (credit card numbers, email addresses, telephone
  numbers) or an internal one.
- `v5.0.0-2.2.1` Input is validated against business or functional
  expectations, using positive validation against an allowlist of values,
  patterns and ranges, or by comparing it to an expected structure and logical
  limits. At L1 this can focus on input used for business or security
  decisions; from L2 up it covers all input.
- `v5.0.0-2.2.2` Input validation is enforced at a trusted service layer;
  client-side validation helps usability but is never relied upon as a security
  control.
- `v5.0.0-2.3.1` Business logic flows for a user are processed only in the
  expected step order, with no skipped steps.

**L2**
- `v5.0.0-2.1.2` Documentation check: the documentation defines the method for
  validating logical and contextual consistency across combined data items (for
  example, suburb and ZIP code matching).
- `v5.0.0-2.1.3` Documentation check: expectations for business logic limits
  and validations, per user and across the whole application, are documented.
- `v5.0.0-2.2.3` Combinations of related data items are checked as reasonable
  against predefined rules.
- `v5.0.0-2.3.2` Business logic limits are implemented as the documentation
  states, preventing exploitation of business logic flaws.
- `v5.0.0-2.3.3` Transactions at the business logic level make an operation
  either succeed entirely or roll back to the previous correct state.
- `v5.0.0-2.3.4` Locking at the business logic level prevents limited-quantity
  resources (theater seats, delivery slots) from being double-booked by
  manipulating the logic.
- `v5.0.0-2.4.1` Anti-automation controls protect application functions from
  excessive calls, which could cause data exfiltration, junk-data creation,
  quota exhaustion, rate-limit breaches, denial of service, or heavy use of
  costly resources.

**L3**
- `v5.0.0-2.3.5` High-value business flows (large monetary transfers, contract
  approvals, access to classified information, safety overrides in
  manufacturing) require approval by multiple users to stop unauthorized or
  accidental action.
- `v5.0.0-2.4.2` Business logic flows demand realistic human timing, so
  transactions cannot be submitted excessively quickly.

---

## V3: Web Frontend Security

Covers what the browser is told to do with a response: content interpretation,
cookie setup, security headers, origin separation and external resources.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x12-V3-Web-Frontend-Security.md>

Sections: 3.1 Web Frontend Security Documentation; 3.2 Unintended Content Interpretation; 3.3 Cookie Setup; 3.4 Browser Security Mechanism Headers; 3.5 Browser Origin Separation; 3.6 External Resource Integrity; 3.7 Other Browser Security Considerations

**L1**
- `v5.0.0-3.2.1` Controls stop browsers from rendering a response in the wrong
  context, for example when an API response or user-uploaded file is requested
  directly. Options include serving only when `Sec-Fetch-*` request headers show
  the right context, a CSP `sandbox` directive, or a `Content-Disposition:
  attachment` disposition.
- `v5.0.0-3.2.2` Content meant to appear as text is inserted with safe
  rendering functions such as `createTextNode` or `textContent`, so HTML or
  script inside it never executes.
- `v5.0.0-3.3.1` Every cookie sets the `Secure` attribute; a cookie that does
  not use the `__Host-` name prefix uses the `__Secure-` prefix instead.
- `v5.0.0-3.4.1` All responses carry a `Strict-Transport-Security` header with
  a max-age of at least one year; from L2 upward the policy also covers all
  subdomains.
- `v5.0.0-3.4.2` The CORS `Access-Control-Allow-Origin` value is either fixed by
  the application or, when taken from the `Origin` request header, checked
  against an allowlist of trusted origins. A wildcard value is acceptable only
  when the response holds nothing sensitive.
- `v5.0.0-3.5.1` An application that does not depend on CORS preflight to block
  cross-origin calls to sensitive functions confirms that such requests come
  from the application itself, using anti-forgery tokens or an extra header
  that is not CORS-safelisted (the CSRF defense).
- `v5.0.0-3.5.2` An application that does depend on CORS preflight to block
  cross-origin use of sensitive functions has no way to reach them with a
  request that skips the preflight; this can require checking `Origin` and
  `Content-Type` or demanding an extra non-safelisted header.
- `v5.0.0-3.5.3` Sensitive functions are reached with POST, PUT, PATCH or
  DELETE, never with the HTTP-safe methods GET, HEAD or OPTIONS; strict
  `Sec-Fetch-*` validation can stand in, to reject cross-origin calls,
  navigations and resource loads that are not expected.

**L2**
- `v5.0.0-3.3.2` Each cookie's `SameSite` value matches the cookie's purpose,
  limiting UI redress (clickjacking) and CSRF exposure.
- `v5.0.0-3.3.3` Cookies use the `__Host-` name prefix unless they are
  deliberately shared with other hosts.
- `v5.0.0-3.3.4` A cookie whose value scripts must not read, such as a session
  token, sets `HttpOnly`, and that value reaches the client only through the
  `Set-Cookie` header.
- `v5.0.0-3.4.3` Responses include a `Content-Security-Policy` header limiting
  what the browser loads and runs. The minimum is a global policy with
  `object-src 'none'` and `base-uri 'none'` plus either an allowlist or nonces
  or hashes. An L3 application needs a per-response policy using nonces or
  hashes.
- `v5.0.0-3.4.4` Every response sends `X-Content-Type-Options: nosniff`, so the
  browser trusts the declared `Content-Type` instead of guessing (a stylesheet
  request accepts only `text/css`); this also enables Cross-Origin Read
  Blocking.
- `v5.0.0-3.4.5` A referrer policy (the `Referrer-Policy` header or HTML element
  attributes) keeps sensitive URL path or query data, and for internal apps the
  hostname, from leaking to third parties through the `Referer` header.
- `v5.0.0-3.4.6` Every response uses the CSP `frame-ancestors` directive so
  embedding is off by default and allowed only where needed; `X-Frame-Options`
  is obsolete and not to be relied on.
- `v5.0.0-3.5.4` Separate applications live on different hostnames, gaining
  same-origin policy isolation and hostname-scoped cookie restrictions.
- `v5.0.0-3.5.5` A `postMessage` message is dropped when its origin is not
  trusted or its syntax is invalid.
- `v5.0.0-3.7.1` Only client-side technologies that are still supported and
  considered secure are used; NSAPI plugins, Flash, Shockwave, ActiveX,
  Silverlight, NACL and Java applets are examples that fail.
- `v5.0.0-3.7.2` An automatic redirect to a hostname or domain outside the
  application's control happens only when the destination is on an allowlist.

**L3**
- `v5.0.0-3.1.1` Documentation lists the security features browsers must
  support to use the application (HTTPS, HSTS, CSP and other HTTP security
  mechanisms) and defines what happens when one is missing, such as warning
  the user or blocking access (a documentation check).
- `v5.0.0-3.2.3` Client-side JavaScript avoids DOM clobbering through explicit
  variable declarations, strict type checks, no globals stored on the
  `document` object, and namespace isolation.
- `v5.0.0-3.3.5` A cookie's name and value together stay within 4096 bytes,
  because browsers silently drop larger cookies and the feature depending on
  them breaks.
- `v5.0.0-3.4.7` The CSP names a location where violations are reported.
- `v5.0.0-3.4.8` Responses that start rendering a document (such as `text/html`)
  carry `Cross-Origin-Opener-Policy` set to `same-origin` or, where required,
  `same-origin-allow-popups`, defeating tabnabbing and frame counting.
- `v5.0.0-3.5.6` JSONP is not enabled anywhere, avoiding cross-site script
  inclusion (XSSI).
- `v5.0.0-3.5.7` Script resources such as JavaScript files never contain data
  that needs authorization, again to prevent XSSI.
- `v5.0.0-3.5.8` Authenticated resources (images, video, scripts, documents)
  load or embed on a user's behalf only when intended, through strict
  `Sec-Fetch-*` validation or a restrictive `Cross-Origin-Resource-Policy`
  response header.
- `v5.0.0-3.6.1` Scripts, stylesheets and fonts served from an outside host
  (for example a CDN) must be static and versioned and be checked with
  Subresource Integrity; where that is impossible, each exception has a
  documented security decision.
- `v5.0.0-3.7.3` Before redirecting a user to a URL the application does not
  control, a notice appears with an option to cancel the navigation.
- `v5.0.0-3.7.4` The application's top-level domain is on the HSTS preload
  list, building TLS enforcement into major browsers instead of relying only on
  the header.
- `v5.0.0-3.7.5` When the browser lacks the expected security features, the
  application behaves as documented, by warning the user or blocking access.

---

## V4: API and Web Service

Covers generic web-service hardening, validation of HTTP message structure,
and the GraphQL and WebSocket protocols.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x13-V4-API-and-Web-Service.md>

Sections: 4.1 Generic Web Service Security; 4.2 HTTP Message Structure Validation; 4.3 GraphQL; 4.4 WebSocket

**L1**
- `v5.0.0-4.1.1` Every response that has a body sends a `Content-Type` header
  matching the real content, with a charset parameter (UTF-8, ISO-8859-1) where
  the media type calls for one, such as `text/*` and the XML types.
- `v5.0.0-4.4.1` All WebSocket connections run over TLS (WSS).

**L2**
- `v5.0.0-4.1.2` Only endpoints meant for manual browser access redirect HTTP to
  HTTPS automatically; other services and API endpoints do not redirect
  transparently, so a client mistakenly sending plain HTTP is noticed instead
  of silently leaking sensitive data.
- `v5.0.0-4.1.3` Headers the application relies on that an intermediary sets (a
  load balancer, proxy or backend-for-frontend), such as `X-Real-IP`,
  `X-Forwarded-*` or `X-User-ID`, cannot be overridden by the end user.
- `v5.0.0-4.2.1` Every component in the path (load balancers, firewalls,
  application servers) finds message boundaries with the right mechanism for
  the HTTP version, defeating request smuggling. In HTTP/1.x a
  `Transfer-Encoding` header means `Content-Length` is ignored; in HTTP/2 and
  HTTP/3 a `Content-Length` header must agree with the length of the DATA
  frames.
- `v5.0.0-4.3.1` GraphQL and similar data-layer expressions are protected from
  denial of service by expensive nested queries, using a query allowlist, depth
  limits, amount limits or query cost analysis.
- `v5.0.0-4.3.2` GraphQL introspection is switched off in production, unless the
  API is intended for use by other parties.
- `v5.0.0-4.4.2` The initial WebSocket HTTP handshake checks the `Origin` header
  against the origins the application allows.
- `v5.0.0-4.4.3` If normal session management cannot serve a WebSocket,
  dedicated tokens are used and they meet the session management
  requirements.
- `v5.0.0-4.4.4` When an existing HTTPS session moves to a WebSocket channel,
  the dedicated WebSocket token is first obtained or validated through the
  already authenticated HTTPS session.

**L3**
- `v5.0.0-4.1.4` Only HTTP methods the application or API explicitly supports
  work (OPTIONS during preflight included); unused methods are blocked.
- `v5.0.0-4.1.5` Highly sensitive requests or transactions, or ones crossing
  several systems, carry per-message digital signatures on top of transport
  protection.
- `v5.0.0-4.2.2` When the application generates HTTP messages, the
  `Content-Length` header never conflicts with the content length given by the
  protocol framing, preventing request smuggling.
- `v5.0.0-4.2.3` The application neither sends nor accepts HTTP/2 or HTTP/3
  messages carrying connection-specific headers such as `Transfer-Encoding`,
  avoiding response splitting and header injection.
- `v5.0.0-4.2.4` HTTP/2 and HTTP/3 requests are accepted only when header names
  and values contain no CR, LF or CRLF sequence, preventing header injection.
- `v5.0.0-4.2.5` When backend or frontend code builds outgoing requests, it
  validates or sanitizes so URIs (such as API calls) and headers (such as
  `Authorization` or `Cookie`) never grow too long for the receiver to accept,
  a denial of service like an oversized cookie that makes the server always
  answer with an error.

---

## V5: File Handling

Covers documented file-handling rules, accepting and checking uploads, where
files are stored and how they are served back.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x14-V5-File-Handling.md>

Sections: 5.1 File Handling Documentation; 5.2 File Upload and Content; 5.3 File Storage; 5.4 File Download

**L1**
- `v5.0.0-5.2.1` Uploads are limited to a size the application can process
  without degraded performance or a denial of service.
- `v5.0.0-5.2.2` Each accepted file, including one inside an archive such as a
  zip, has its extension compared with the expected extensions and its content
  checked to match the claimed type (magic bytes, image re-writing,
  specialized validation libraries). At L1 this may concentrate on files used
  for business or security decisions; from L2 it applies to every accepted
  file.
- `v5.0.0-5.3.1` Files created from untrusted input and kept in a public folder
  are never run as server-side code when requested directly over HTTP.
- `v5.0.0-5.3.2` File paths for file operations are built from internally
  generated or trusted data; if user-submitted filenames or metadata must be
  used, they get strict validation and sanitization, guarding against path
  traversal, LFI, RFI and SSRF.

**L2**
- `v5.0.0-5.1.1` Documentation (a documentation check) defines, for each upload
  feature, the permitted file types, expected extensions and maximum size
  including unpacked size, and says how files are made safe to download and
  process, including what happens when a malicious file is found.
- `v5.0.0-5.2.3` Compressed files (zip, gz, docx, odt) are checked before
  extraction against a maximum uncompressed size and a maximum file count.
- `v5.0.0-5.4.1` User-submitted filenames, even in a JSON, JSONP or URL
  parameter, are validated or ignored, and the response names the file in the
  `Content-Disposition` header.
- `v5.0.0-5.4.2` Filenames in served output (response headers, email
  attachments) are encoded or sanitized, for instance per RFC 6266, keeping the
  document structure intact and blocking injection.
- `v5.0.0-5.4.3` Files from untrusted sources go through antivirus scanning, so
  known malicious content is not served.

**L3**
- `v5.0.0-5.2.4` A per-user file size quota and file count limit are enforced so
  one user cannot exhaust storage.
- `v5.0.0-5.2.5` Uploaded archives containing symlinks are refused unless truly
  required, in which case an allowlist limits what they may point to.
- `v5.0.0-5.2.6` Uploaded images whose pixel dimensions exceed the allowed
  maximum are rejected, stopping pixel flood attacks.
- `v5.0.0-5.3.3` Server-side processing such as decompression disregards path
  information supplied by the user, preventing flaws like zip slip.

---

## V6: Authentication

Covers how users and services prove identity: password policy, general
authentication controls, credential lifecycle and recovery, multi-factor
mechanisms and delegation to an identity provider.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x15-V6-Authentication.md>

Sections: 6.1 Authentication Documentation; 6.2 Password Security; 6.3 General Authentication Security; 6.4 Authentication Factor Lifecycle and Recovery; 6.5 General Multi-factor authentication requirements; 6.6 Out-of-Band authentication mechanisms; 6.7 Cryptographic authentication mechanism; 6.8 Authentication with an Identity Provider

**L1**
- `v5.0.0-6.1.1` Documentation check: the documentation explains how rate
  limiting, anti-automation and adaptive responses defend against credential
  stuffing and password brute force, how they are configured, and how they
  avoid letting an attacker lock legitimate users out.
- `v5.0.0-6.2.1` Passwords chosen by users are at least 8 characters long; 15
  or more is the strongly advised minimum.
- `v5.0.0-6.2.2` Users are able to change their own password.
- `v5.0.0-6.2.3` Changing a password requires both the current password and the
  new one.
- `v5.0.0-6.2.4` At registration and on every password change, the new password
  is screened against a list of at least the 3000 most common passwords that
  also satisfy the application's own policy (for example its minimum length).
- `v5.0.0-6.2.5` Passwords made of any characters are accepted; there are no
  composition rules demanding upper case, lower case, digits or symbols.
- `v5.0.0-6.2.6` Password fields are masked with `type=password`; letting the
  user briefly reveal the whole value or the last typed character is
  acceptable.
- `v5.0.0-6.2.7` Pasting, browser password helpers and external password
  managers all work on password fields.
- `v5.0.0-6.2.8` The password is checked exactly as the user typed it, with no
  truncation or case conversion.
- `v5.0.0-6.3.1` The defenses against credential stuffing and password brute
  force are actually implemented as the security documentation describes.
- `v5.0.0-6.3.2` Default accounts such as root, admin or sa do not exist, or
  are disabled.
- `v5.0.0-6.4.1` System-generated initial passwords or activation codes come
  from a secure random source, follow the password policy, expire after a short
  time or on first use, and never become the user's long-term password.
- `v5.0.0-6.4.2` There are no password hints and no knowledge-based "secret
  questions".

**L2**
- `v5.0.0-6.1.2` Documentation check: a list of context-specific words
  (permutations of organization, product, system, project, department or role
  names and the like) is documented so they can be blocked in passwords.
- `v5.0.0-6.1.3` Documentation check: when the application has several
  authentication pathways, all of them are documented together with the
  controls and authentication strength that must be enforced the same way on
  each.
- `v5.0.0-6.2.9` Passwords of at least 64 characters are accepted.
- `v5.0.0-6.2.10` A password stays valid until it is found compromised or the
  user changes it; the application never forces periodic rotation.
- `v5.0.0-6.2.11` The documented list of context-specific words is actually
  applied to reject easily guessed passwords.
- `v5.0.0-6.2.12` New passwords at registration and on change are checked
  against a set of known breached passwords.
- `v5.0.0-6.3.3` Access needs multi-factor authentication or a combination of
  single-factor mechanisms. At L3 one factor must be a hardware-based
  mechanism that resists phishing and impersonation and requires a deliberate
  user action (such as pressing a button on a FIDO key or phone). Weakening any
  part of this needs a fully documented rationale and compensating controls.
- `v5.0.0-6.3.4` When several authentication pathways exist, none is
  undocumented, and controls and authentication strength are enforced
  consistently across them.
- `v5.0.0-6.4.3` Forgotten-password recovery is secure and does not bypass any
  multi-factor mechanism that is enabled.
- `v5.0.0-6.4.4` When a user loses a multi-factor authentication factor,
  identity proofing at the same level as at enrollment is carried out.
- `v5.0.0-6.5.1` Lookup secrets, out-of-band requests or codes, and TOTPs can
  be used successfully only once.
- `v5.0.0-6.5.2` Backend storage of lookup secrets with fewer than 112 bits of
  entropy (about 19 random alphanumeric characters, or 34 random digits) uses
  an approved password-storage hashing algorithm that mixes in a 32-bit random
  salt; a plain standard hash suffices from 112 bits upward.
- `v5.0.0-6.5.3` Lookup secrets, out-of-band codes and TOTP seeds are generated
  with a CSPRNG so they cannot be predicted.
- `v5.0.0-6.5.4` Lookup secrets and out-of-band codes carry at least 20 bits of
  entropy; roughly 4 random alphanumeric characters or 6 random digits is
  normally enough.
- `v5.0.0-6.5.5` Out-of-band requests, codes, tokens and TOTPs have a defined
  lifetime: at most 10 minutes for out-of-band, at most 30 seconds for TOTP.
- `v5.0.0-6.6.1` Phone-network OTP delivery (call or SMS) is offered only for a
  previously validated number, alongside stronger options such as TOTP, with
  users told about its risks. At L3, phone and SMS must not be offered at all.
- `v5.0.0-6.6.2` Out-of-band requests, codes or tokens are bound to the
  authentication request that produced them and cannot be used for an earlier
  or later one.
- `v5.0.0-6.6.3` Code-based out-of-band mechanisms are rate limited against
  brute force; codes with at least 64 bits of entropy are worth considering.
- `v5.0.0-6.8.1` With several identity providers, one provider cannot be used
  to impersonate a user of another (for example through an identical user
  identifier); the usual mitigation keys accounts on the IdP identifier plus
  the user's ID at that IdP.
- `v5.0.0-6.8.2` Digital signatures on authentication assertions such as JWTs
  or SAML assertions are always checked for presence and validity, and unsigned
  or badly signed assertions are rejected.
- `v5.0.0-6.8.3` SAML assertions are processed uniquely and used only once
  within their validity period, preventing replay.
- `v5.0.0-6.8.4` When the application expects a specific authentication
  strength, method or recency from a separate identity provider, it verifies
  that from the information the provider returns (for OIDC, claims such as
  `acr`, `amr` and `auth_time`). If the provider supplies none, a documented
  fallback assumes the weakest mechanism, single-factor username and password.

**L3**
- `v5.0.0-6.3.5` Users are told about suspicious authentication attempts,
  whether they succeeded or not: an unusual location or client, partial success
  with only one of several factors, a login after long inactivity, or a success
  after repeated failures.
- `v5.0.0-6.3.6` Email is not used as a single-factor or multi-factor
  authentication mechanism.
- `v5.0.0-6.3.7` Users are notified when their authentication details change,
  such as a credential reset or a change of username or email address.
- `v5.0.0-6.3.8` Valid users cannot be inferred from failed authentication
  challenges through error messages, HTTP status codes or response timing;
  registration and forgotten-password flows share this protection.
- `v5.0.0-6.4.5` Where an authentication mechanism expires, renewal
  instructions go out early enough to finish before the old one lapses, with
  automated reminders if needed.
- `v5.0.0-6.4.6` Administrators can start a password reset for a user but
  cannot choose or set the password, so they never learn it.
- `v5.0.0-6.5.6` Any authentication factor, physical devices included, can be
  revoked after theft or other loss.
- `v5.0.0-6.5.7` Biometric authentication is used only as a secondary factor,
  together with something the user has or knows.
- `v5.0.0-6.5.8` TOTPs are validated against a time source from a trusted
  service, never one supplied by the client or otherwise untrusted.
- `v5.0.0-6.6.4` Where push notifications are used for multi-factor
  authentication, rate limiting prevents push bombing; number matching can also
  help.
- `v5.0.0-6.7.1` Certificates used to verify cryptographic authentication
  assertions are stored so that they are protected from modification.
- `v5.0.0-6.7.2` The challenge nonce is at least 64 bits long and statistically
  unique, or at minimum unique for as long as the cryptographic device lives.

---

## V7: Session Management

Covers how sessions are created, bounded in time, terminated and defended
against abuse, including re-authentication in federated setups. Cookie
attributes live in V3 under Cookie Setup.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x16-V7-Session-Management.md>

Sections: 7.1 Session Management Documentation; 7.2 Fundamental Session Management Security; 7.3 Session Timeout; 7.4 Session Termination; 7.5 Defenses Against Session Abuse; 7.6 Federated Re-authentication

**L1**
- `v5.0.0-7.2.1` All session token verification is performed by a trusted
  backend service.
- `v5.0.0-7.2.2` Sessions use dynamically generated tokens, either
  self-contained or reference tokens, and not static API secrets or keys.
- `v5.0.0-7.2.3` Reference tokens that represent user sessions are unique,
  produced by a CSPRNG and carry at least 128 bits of entropy.
- `v5.0.0-7.2.4` A new session token is issued on every authentication,
  re-authentication included, and the current token is terminated.
- `v5.0.0-7.4.1` Once logout or expiry triggers termination, the session can no
  longer be used. Stateful sessions and reference tokens are invalidated in the
  backend; self-contained tokens need a mechanism such as a revocation list,
  rejecting tokens issued before a per-user timestamp, or rotating a per-user
  signing key.
- `v5.0.0-7.4.2` All of a user's active sessions end when the account is
  disabled or deleted (for example when an employee leaves).

**L2**
- `v5.0.0-7.1.1` Documentation check: the inactivity timeout and the absolute
  maximum session lifetime are documented, fit with the other controls, and
  carry a justification for any departure from NIST SP 800-63B
  re-authentication requirements.
- `v5.0.0-7.1.2` Documentation check: the documentation states how many
  concurrent sessions one account may hold and what happens when that maximum
  is reached.
- `v5.0.0-7.1.3` Documentation check: every system that creates and manages
  sessions in a federated identity ecosystem (such as SSO) is documented, along
  with the controls that coordinate session lifetimes, termination and other
  conditions requiring re-authentication.
- `v5.0.0-7.3.1` An inactivity timeout forces re-authentication, set according
  to risk analysis and documented security decisions.
- `v5.0.0-7.3.2` An absolute maximum session lifetime forces re-authentication,
  set according to risk analysis and documented security decisions.
- `v5.0.0-7.4.3` After any change or removal of an authentication factor (a
  password change through reset or recovery, or an MFA settings update), the
  user is offered the option to terminate all other active sessions.
- `v5.0.0-7.4.4` Every page that requires authentication gives easy, visible
  access to logout.
- `v5.0.0-7.4.5` Administrators can terminate the active sessions of one user
  or of all users.
- `v5.0.0-7.5.1` Full re-authentication is required before changes to sensitive
  account attributes that can influence authentication, such as the email
  address, phone number, MFA setup, or other data used for account recovery.
- `v5.0.0-7.5.2` Users can view all of their active sessions and, after
  authenticating again with at least one factor, terminate any or all of them.
- `v5.0.0-7.6.1` Session lifetime and termination between relying parties and
  identity providers behave as documented, forcing re-authentication when
  needed, for example when the maximum time between IdP authentication events
  is reached.
- `v5.0.0-7.6.2` Creating a session requires the user's consent or an explicit
  action, so no new application session appears without user interaction.

**L3**
- `v5.0.0-7.5.3` Highly sensitive transactions or operations require further
  authentication with at least one factor, or a secondary verification, before
  they run.

---

## V8: Authorization

Covers documented authorization rules and their enforcement at function, data
and field level, plus tenant isolation and administrative interfaces.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x17-V8-Authorization.md>

Sections: 8.1 Authorization Documentation; 8.2 General Authorization Design; 8.3 Operation Level Authorization; 8.4 Other Authorization Considerations

**L1**
- `v5.0.0-8.1.1` Documentation check: authorization documentation sets out the
  rules that restrict access to functions and to specific data, based on the
  consumer's permissions and the resource's attributes.
- `v5.0.0-8.2.1` Function-level access is limited to consumers holding explicit
  permissions.
- `v5.0.0-8.2.2` Data-specific access is limited to consumers with explicit
  permissions on the specific data items, mitigating IDOR and BOLA.
- `v5.0.0-8.3.1` Authorization rules are enforced in a trusted service layer,
  not in controls an untrusted consumer can manipulate, such as client-side
  JavaScript.

**L2**
- `v5.0.0-8.1.2` Documentation check: the authorization documentation defines
  field-level restrictions for both reading and writing, based on consumer
  permissions and resource attributes; these rules may depend on other
  attributes of the data object, such as its state or status.
- `v5.0.0-8.2.3` Field-level access is limited to consumers with explicit
  permissions on the specific fields, mitigating BOPLA.
- `v5.0.0-8.4.1` Multi-tenant applications use cross-tenant controls so one
  consumer's operations can never affect tenants they have no permission to
  interact with.

**L3**
- `v5.0.0-8.1.3` Documentation check: the environmental and contextual
  attributes used for security decisions, including authentication decisions
  (time of day, user location, IP address, device and similar), are documented.
- `v5.0.0-8.1.4` Documentation check: authentication and authorization
  documentation explains how environmental and contextual factors feed
  decisions on top of function-level, data-specific and field-level rules,
  including the attributes evaluated, risk thresholds and the actions taken
  (allow, challenge, deny, step-up authentication).
- `v5.0.0-8.2.4` Adaptive controls based on a consumer's environmental and
  contextual attributes (time of day, location, IP address, device) apply to
  authentication and authorization decisions as documented, both when a new
  session starts and during an existing session.
- `v5.0.0-8.3.2` Changes to values that authorization decisions depend on take
  effect immediately. Where that is impossible, for example for data inside
  self-contained tokens, mitigating controls alert when a consumer acts after
  losing authorization and revert the change; this alternative does not stop
  information leakage.
- `v5.0.0-8.3.3` Access to an object is decided by the originating subject's
  permissions, not by those of an intermediary or service acting on its behalf.
  For example, a downstream service should rely on the consumer's own token,
  not a machine-to-machine token issued to the first service.
- `v5.0.0-8.4.2` Administrative interfaces are protected by multiple layers,
  including continuous identity verification, device security posture
  assessment and contextual risk analysis, so network location or trusted
  endpoints are never the sole authorization factor.

---

## V9: Self-contained Tokens

Covers whether a self-contained token (such as a JWT) comes from a trusted
source with its integrity checked, and what its content must satisfy.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x18-V9-Self-contained-Tokens.md>

Sections: 9.1 Token source and integrity; 9.2 Token content

**L1**
- `v5.0.0-9.1.1` A self-contained token is validated through its signature or
  MAC to detect tampering before any of its contents is trusted.
- `v5.0.0-9.1.2` Only allowlisted algorithms may create or verify tokens in a
  given context. The list names the permitted algorithms (ideally only
  symmetric or only asymmetric) and excludes the `None` algorithm; supporting
  both kinds needs extra controls against key confusion.
- `v5.0.0-9.1.3` Key material for validating tokens comes from trusted,
  pre-configured sources for the issuer, so attackers cannot choose their own
  keys. For JWTs and other JWS structures the `jku`, `x5u` and `jwk` headers
  are validated against an allowlist of trusted sources.
- `v5.0.0-9.2.1` When token data carries a validity period, the token is
  accepted only inside it; for JWTs this means checking the `nbf` and `exp`
  claims.

**L2**
- `v5.0.0-9.2.2` The receiving service checks that the token is of the right
  type and meant for the purpose at hand: only access tokens drive
  authorization decisions, and only ID Tokens prove user authentication.
- `v5.0.0-9.2.3` A service accepts only tokens meant for it (audience); for
  JWTs, the `aud` claim is checked against an allowlist held by the service.
- `v5.0.0-9.2.4` An issuer that signs tokens for several audiences with one
  private key includes an audience restriction that uniquely identifies each
  intended audience, so a token cannot be replayed elsewhere. If audience
  identifiers are provisioned dynamically, the issuer validates them to stop
  audience impersonation.

---

## V10: OAuth and OIDC

Covers every role in OAuth and OpenID Connect deployments: client, resource
server, authorization server, OIDC client, OpenID Provider and consent.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x19-V10-OAuth-and-OIDC.md>

Sections: 10.1 Generic OAuth and OIDC Security; 10.2 OAuth Client; 10.3 OAuth Resource Server; 10.4 OAuth Authorization Server; 10.5 OIDC Client; 10.6 OpenID Provider; 10.7 Consent Management

The chapter has 36 requirements (5 L1 / 24 L2 / 7 L3). Its five L1
requirements, `v5.0.0-10.4.1` to `v5.0.0-10.4.5`, all apply to the OAuth
authorization server. Open the Source chapter when code implements an OAuth
client, resource server, authorization server, OIDC client or OpenID Provider.

---

## V11: Cryptography

Covers keeping an inventory of cryptography, choosing and implementing
algorithms safely, generating random values and protecting data in use.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x20-V11-Cryptography.md>

Sections: 11.1 Cryptographic Inventory and Documentation; 11.2 Secure Cryptography Implementation; 11.3 Encryption Algorithms; 11.4 Hashing and Hash-based Functions; 11.5 Random Values; 11.6 Public Key Cryptography; 11.7 In-Use Data Cryptography

**L1**
- `v5.0.0-11.3.1` Insecure block modes such as ECB and weak padding schemes such
  as PKCS#1 v1.5 are not used.
- `v5.0.0-11.3.2` Only approved ciphers and modes are used, with AES-GCM as the
  stated example.
- `v5.0.0-11.4.1` Only approved hash functions serve general cryptographic needs
  (digital signatures, HMAC, KDFs, random bit generation); disallowed ones, MD5
  for instance, are not used for any cryptographic purpose.

**L2**
- `v5.0.0-11.1.1` A documented policy covers cryptographic key management and a
  key lifecycle that follows a standard such as NIST SP 800-57, including
  avoiding over-sharing of keys (a shared secret held by no more than two
  parties, a private key by one) (a documentation check).
- `v5.0.0-11.1.2` A cryptographic inventory is made, kept current and reviewed
  regularly. It lists all keys, algorithms and certificates the application
  uses, records where keys may and may not be used, and which kinds of data
  they may protect (a documentation check).
- `v5.0.0-11.2.1` Cryptographic operations use industry-validated
  implementations, whether libraries or hardware-accelerated ones.
- `v5.0.0-11.2.2` The design allows crypto agility: random number generators,
  authenticated encryption, MACs, hashes, key lengths, rounds, ciphers and modes
  stay replaceable through configuration or upgrade whenever needed, so a
  cryptographic break can be answered. Replacing keys and passwords and re-encrypting data must
  also be possible, easing a later move to post-quantum cryptography.
- `v5.0.0-11.2.3` Every cryptographic primitive offers at least 128 bits of
  security given its algorithm, key size and configuration (a 256-bit elliptic
  curve key is roughly 128 bits; RSA needs 3072 bits for the same).
- `v5.0.0-11.3.3` Encrypted data is protected against unauthorized change, by
  preference with an approved authenticated encryption method or an approved
  cipher paired with an approved MAC.
- `v5.0.0-11.4.2` Passwords are stored with an approved, computationally
  intensive key derivation (password hashing) function, its parameters set from
  current guidance and balancing security against performance so brute force
  stays hard enough.
- `v5.0.0-11.4.3` Hash functions used in signatures, data authentication or
  integrity are collision resistant with suitable bit lengths: output of at
  least 256 bits when collision resistance matters, at least 128 bits when only
  second pre-image resistance matters.
- `v5.0.0-11.4.4` Deriving secret keys from passwords uses approved key
  derivation functions with key stretching, parameters balancing security and
  performance so brute force cannot compromise the derived key.
- `v5.0.0-11.5.1` Every random number or string meant to be unguessable comes
  from a CSPRNG and carries at least 128 bits of entropy; UUIDs do not satisfy
  this.
- `v5.0.0-11.6.1` Only approved algorithms and modes are used for key
  generation and seeding and for signature creation and verification, and key
  generation must not yield keys open to known attacks (RSA keys weak to Fermat
  factorization, for example).

**L3**
- `v5.0.0-11.1.3` Cryptographic discovery mechanisms locate every use of
  cryptography in the system: encryption, hashing and signing.
- `v5.0.0-11.1.4` A cryptographic inventory is maintained together with a
  documented plan for migrating to new standards such as post-quantum
  cryptography (a documentation check).
- `v5.0.0-11.2.4` All cryptographic operations run in constant time, with no
  short-circuiting in comparisons, calculations or returns that could leak
  information.
- `v5.0.0-11.2.5` Cryptographic modules fail securely, handling errors so they
  open no weakness such as a padding oracle.
- `v5.0.0-11.3.4` A nonce, IV or other single-use number is never reused for
  more than one pairing of encryption key and data element, and is generated by
  a method suited to the algorithm.
- `v5.0.0-11.3.5` Any pairing of an encryption algorithm with a MAC operates as
  encrypt-then-MAC.
- `v5.0.0-11.5.2` The random number generator is designed to stay secure even
  under heavy demand.
- `v5.0.0-11.6.2` Key exchange (such as Diffie-Hellman) uses approved
  algorithms with secure parameters, preventing attacks on key establishment
  that enable adversary-in-the-middle or cryptographic breaks.
- `v5.0.0-11.7.1` Full memory encryption protects sensitive data while it is in
  use, keeping out unauthorized users and processes.
- `v5.0.0-11.7.2` Data minimization limits what is exposed during processing,
  and data is encrypted right after use or as soon as feasible.

---

## V12: Secure Communication

Covers TLS configuration, HTTPS toward external-facing services and the
security of traffic between internal services.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x21-V12-Secure-Communication.md>

Sections: 12.1 General TLS Security Guidance; 12.2 HTTPS Communication with External Facing Services; 12.3 General Service to Service Communication Security

**L1**
- `v5.0.0-12.1.1` Only the latest recommended TLS versions (TLS 1.2 and 1.3 are
  the examples) are enabled, and the newest is the preferred one.
- `v5.0.0-12.2.1` TLS covers all connectivity between a client and an external
  facing HTTP-based service, without falling back to insecure or unencrypted
  communication.
- `v5.0.0-12.2.2` External facing services use publicly trusted TLS
  certificates.

**L2**
- `v5.0.0-12.1.2` Only recommended cipher suites are enabled, the strongest
  preferred. At L3, only suites that provide forward secrecy may be supported.
- `v5.0.0-12.1.3` mTLS client certificates are confirmed trusted before the
  identity in the certificate is used for authentication or authorization.
- `v5.0.0-12.3.1` An encrypted protocol such as TLS protects every inbound and
  outbound connection of the application, including those to monitoring and
  management tools, remote access and SSH, middleware, databases, mainframes,
  partner systems and external APIs, with no fallback to insecure protocols.
- `v5.0.0-12.3.2` TLS clients validate the certificate a server presents before
  communicating with it.
- `v5.0.0-12.3.3` TLS or another suitable transport encryption protects all
  connections between internal HTTP-based services, with no fallback to
  insecure or unencrypted traffic.
- `v5.0.0-12.3.4` Internal service TLS connections rely on trusted
  certificates; where internally generated or self-signed ones are used, the
  consuming service trusts only the specific internal CAs and specific
  self-signed certificates.

**L3**
- `v5.0.0-12.1.4` Certificate revocation, such as OCSP stapling, is enabled and
  configured properly.
- `v5.0.0-12.1.5` Encrypted Client Hello (ECH) is enabled in the TLS settings so
  metadata such as the server name indication is not exposed in the handshake.
- `v5.0.0-12.3.5` Services talking to each other inside a system authenticate
  strongly so each endpoint is verified, using methods such as TLS client
  authentication built on public-key infrastructure and resistant to replay.
  For microservices, a service mesh can ease certificate management.

---

## V13: Configuration

Covers documented configuration, secure backend communication settings, secret
management and avoiding unintended information leakage.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x22-V13-Configuration.md>

Sections: 13.1 Configuration Documentation; 13.2 Backend Communication Configuration; 13.3 Secret Management; 13.4 Unintended Information Leakage

**L1**
- `v5.0.0-13.4.1` The application is deployed without source control metadata
  such as `.git` or `.svn` folders, or those folders cannot be reached from
  outside nor by the application itself.

**L2**
- `v5.0.0-13.1.1` Every communication the application needs is documented,
  covering the external services it depends on and any case where an end user
  can supply an external location the application then connects to (a
  documentation check).
- `v5.0.0-13.2.1` Backend components that cannot use the standard user session
  mechanism (APIs, middleware, data layers) authenticate each other with
  individual service accounts, short-term tokens or certificates, not
  unchanging credentials such as passwords, API keys or shared privileged
  accounts.
- `v5.0.0-13.2.2` Backend components talk to each other (local and OS services,
  APIs, middleware, data layers) through accounts granted only the privileges
  they need.
- `v5.0.0-13.2.3` A credential a consumer must use to authenticate to a service
  is never a default one such as root/root or admin/admin.
- `v5.0.0-13.2.4` An allowlist defines the external resources or systems the
  application may contact (outbound requests, data loads, file access); it can
  sit in the application layer, web server, firewall, or a mix.
- `v5.0.0-13.2.5` The web or application server itself is configured with an
  allowlist of the systems and resources it may send requests to or load data
  and files from.
- `v5.0.0-13.3.1` A secrets management solution such as a key vault creates,
  stores, controls access to and destroys backend secrets (passwords, key
  material, database and third-party integrations, seeds for time-based tokens,
  other internal secrets, API keys); none sit in source code or build
  artifacts. At L3 the solution must be hardware-backed, such as an HSM.
- `v5.0.0-13.3.2` Access to secret assets follows least privilege.
- `v5.0.0-13.4.2` Debug modes are off in every component in production.
- `v5.0.0-13.4.3` Web servers do not show directory listings unless that is
  explicitly intended.
- `v5.0.0-13.4.4` The HTTP TRACE method is unsupported in production.
- `v5.0.0-13.4.5` API documentation (for internal APIs, say) and monitoring
  endpoints stay unexposed unless exposure is deliberate.

**L3**
- `v5.0.0-13.1.2` For each service used, documentation sets the maximum number
  of concurrent connections (such as pool limits) and what the application does
  once that limit is hit, including fallback and recovery, to prevent denial of
  service (a documentation check).
- `v5.0.0-13.1.3` Documentation sets resource-management strategies for each
  external system or service (databases, file handles, threads, HTTP
  connections): release procedures, timeouts, failure handling, and where retry
  logic lives with its limits, delays and back-off. Synchronous HTTP
  request-response calls should use short timeouts and either no retries or
  strictly limited ones, to avoid cascading delay and resource exhaustion (a
  documentation check).
- `v5.0.0-13.1.4` Documentation names the secrets critical to the application's
  security and a rotation schedule based on the organization's threat model and
  business needs (a documentation check).
- `v5.0.0-13.2.6` Connections to separate services follow each connection's
  documented configuration: maximum parallel connections, what happens at that
  maximum, timeouts and retry strategy.
- `v5.0.0-13.3.3` All cryptographic operations run inside an isolated security
  module, such as a vault or HSM, so key material is never exposed outside it.
- `v5.0.0-13.3.4` Secrets are configured to expire and are rotated according to
  the application's documentation.
- `v5.0.0-13.4.6` Detailed version information about backend components is not
  exposed.
- `v5.0.0-13.4.7` The web tier serves only files with specific allowed
  extensions, so information, configuration and source code do not leak by
  accident.

---

## V14: Data Protection

Covers classifying data, protecting it on the server and limiting what the
client stores or caches.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x23-V14-Data-Protection.md>

Sections: 14.1 Data Protection Documentation; 14.2 General Data Protection; 14.3 Client-side Data Protection

**L1**
- `v5.0.0-14.2.1` Sensitive data reaches the server only in the HTTP message
  body or headers; URLs and query strings never carry things like an API key or
  session token.
- `v5.0.0-14.3.1` Once the client or session ends, data obtained while
  authenticated is wiped from client storage such as the browser DOM. The `Clear-Site-Data` response
  header can help, but the client side must also clean up on its own when the
  server connection is unavailable at that moment.

**L2**
- `v5.0.0-14.1.1` All sensitive data the application creates or processes is
  identified and sorted into protection levels, counting data that is merely
  encoded and so easily decoded (Base64 strings, the plaintext payload of a
  JWT), with levels that account for applicable privacy regulations and
  standards (a documentation check).
- `v5.0.0-14.1.2` Each protection level has documented protection requirements,
  at least covering encryption, integrity verification, retention, how the data
  is logged, access controls on sensitive log data, database-level encryption,
  privacy and privacy-enhancing technologies, and other confidentiality needs (a
  documentation check).
- `v5.0.0-14.2.2` Sensitive data is kept out of server-side caches such as load
  balancers and application caches, or is securely purged after use.
- `v5.0.0-14.2.3` Defined sensitive data is not sent to untrusted parties such
  as user trackers, avoiding collection outside the application's control.
- `v5.0.0-14.2.4` The controls documented for each protection level (encryption,
  integrity checks, retention, logging, log access, privacy technologies) are
  actually implemented as defined.
- `v5.0.0-14.3.2` Sufficient anti-caching response headers (for example
  `Cache-Control: no-store`) keep sensitive data out of browser caches.
- `v5.0.0-14.3.3` Browser storage (`localStorage`, `sessionStorage`, IndexedDB,
  cookies) holds no sensitive data apart from session tokens.

**L3**
- `v5.0.0-14.2.5` Caches store only responses of the expected content type for
  the resource and nothing sensitive or dynamic; a request for a non-existent
  file gets a 404 or 302 rather than some other valid file, preventing Web
  Cache Deception.
- `v5.0.0-14.2.6` Only the minimum sensitive data the function needs is
  returned (for example part of a card number, not all of it); when the full
  value is needed it is masked in the UI unless the user deliberately views it.
- `v5.0.0-14.2.7` Sensitive information carries a retention classification, so
  stale or unneeded data is removed automatically, on a fixed schedule or when
  circumstances call for it.
- `v5.0.0-14.2.8` Sensitive information is stripped from the metadata of
  user-submitted files unless the user consented to storing it.

---

## V15: Secure Coding and Architecture

Covers documented secure-coding and architecture decisions, dependency and
component hygiene, defensive coding and safe concurrency.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md>

Sections: 15.1 Secure Coding and Architecture Documentation; 15.2 Security Architecture and Dependencies; 15.3 Defensive Coding; 15.4 Safe Concurrency

**L1**
- `v5.0.0-15.1.1` Documentation sets risk-based remediation time frames for
  vulnerable third-party component versions and for updating libraries
  generally, limiting the risk those components carry (a documentation check).
- `v5.0.0-15.2.1` The application contains only components that have not
  overrun the documented update and remediation time frames.
- `v5.0.0-15.3.1` Only the required subset of fields in a data object is
  returned, rather than the whole object, because some fields must not reach
  users.

**L2**
- `v5.0.0-15.1.2` An inventory catalog such as an SBOM lists every third-party
  library in use, and components are verified to come from pre-defined, trusted
  and continually maintained repositories (a documentation check).
- `v5.0.0-15.1.3` Documentation identifies time-consuming or resource-demanding
  functionality and how to avoid losing availability by overuse or building a
  response slower than the consumer's timeout; defenses can include asynchronous
  processing, queues and per-user and per-application limits on parallel
  processes (a documentation check).
- `v5.0.0-15.2.2` The application carries defenses against availability loss
  from time-consuming or resource-demanding functionality, following the
  documented security decisions and strategies.
- `v5.0.0-15.2.3` Production includes only the functionality the application
  needs, with no extraneous test code, sample snippets or development
  functionality exposed.
- `v5.0.0-15.3.2` Backend calls to external URLs do not follow redirects unless
  that is intended.
- `v5.0.0-15.3.3` Mass assignment is countered by limiting the fields each
  controller and action accepts, so no field can be set or updated unless it was
  meant to be part of that action.
- `v5.0.0-15.3.4` Proxies and middleware pass the user's original IP address on
  through trusted fields the end user cannot manipulate, and the application and
  web server use that value for logging and decisions such as rate limiting,
  remembering that even the original address can be unreliable (dynamic IPs,
  VPNs, corporate firewalls).
- `v5.0.0-15.3.5` Variables are explicitly checked for the right type and
  compared with strict equality, avoiding type juggling or type confusion from
  assumptions about a variable's type.
- `v5.0.0-15.3.6` JavaScript code is written so prototype pollution cannot
  occur; preferring `Set()` or `Map()` over plain object literals is one way.
- `v5.0.0-15.3.7` Defenses exist against HTTP parameter pollution, especially
  when the framework does not distinguish where a parameter came from (query
  string, body, cookies, headers).

**L3**
- `v5.0.0-15.1.4` Documentation flags third-party libraries considered "risky
  components" (a documentation check).
- `v5.0.0-15.1.5` Documentation flags the parts of the application that use
  "dangerous functionality" (a documentation check).
- `v5.0.0-15.2.4` Third-party components and all their transitive dependencies
  come from the expected repository, internal or external, with no dependency
  confusion risk.
- `v5.0.0-15.2.5` Extra protection surrounds parts documented as "dangerous
  functionality" or built on "risky components", such as sandboxing,
  encapsulation, containerization or network isolation, to slow an attacker who
  compromises one part from pivoting to others.
- `v5.0.0-15.4.1` Multi-threaded code touches shared objects (caches, files,
  in-memory objects) safely, with thread-safe types and synchronization such as
  locks or semaphores, avoiding race conditions and data corruption.
- `v5.0.0-15.4.2` A check on a resource's state (existence, permissions) and the
  action depending on it happen as one atomic operation, preventing TOCTOU
  races, such as testing that a file exists before opening it or verifying
  access before granting it.
- `v5.0.0-15.4.3` Locks are used consistently so threads do not get stuck
  waiting on each other or retrying forever, and locking logic stays inside the
  code that manages the resource, where outside classes cannot alter it.
- `v5.0.0-15.4.4` Resource allocation policies prevent thread starvation through
  fair access, for example thread pools that let lower-priority threads proceed
  in reasonable time.

---

## V16: Security Logging and Error Handling

Covers documented logging rules, what gets logged and which security events
matter, protecting the logs, and handling errors without leaking details.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md>

Sections: 16.1 Security Logging Documentation; 16.2 General Logging; 16.3 Security Events; 16.4 Log Protection; 16.5 Error Handling

**L2**
- `v5.0.0-16.1.1` An inventory documents the logging at each layer of the
  technology stack: which events are logged, the formats, where logs are
  stored, how they are used, how access is controlled and how long they are
  kept (a documentation check).
- `v5.0.0-16.2.1` Each log entry has the metadata (when, where, who, what)
  needed to reconstruct the timeline of an event in detail.
- `v5.0.0-16.2.2` Time sources of all logging components are synchronized, and
  timestamps in security event metadata use UTC or carry an explicit time zone
  offset; UTC is recommended for consistency across distributed systems and
  daylight saving changes.
- `v5.0.0-16.2.3` The application writes or broadcasts logs only to the files
  and services listed in the log inventory.
- `v5.0.0-16.2.4` The log processor in use can read and correlate the logs,
  preferably through a common logging format.
- `v5.0.0-16.2.5` Logging of sensitive data follows the data's protection level:
  some data (credentials, payment details) may not be logged at all, while
  other data such as session tokens may be logged only hashed or masked, fully
  or partly.
- `v5.0.0-16.3.1` Every authentication operation is logged, successful or not,
  with extra metadata such as the authentication type or factors used.
- `v5.0.0-16.3.2` Failed authorization attempts are logged. At L3 this extends
  to every authorization decision, including access to sensitive data, without
  writing the sensitive data itself to the log.
- `v5.0.0-16.3.3` The security events defined in the documentation are logged,
  together with attempts to bypass security controls such as input validation,
  business logic and anti-automation.
- `v5.0.0-16.3.4` Unexpected errors and security control failures, such as
  backend TLS failures, are logged.
- `v5.0.0-16.4.1` All logging components encode data appropriately to prevent
  log injection.
- `v5.0.0-16.4.2` Logs are shielded from unauthorized access and cannot be
  modified.
- `v5.0.0-16.4.3` Logs travel securely to a logically separate system for
  analysis, detection, alerting and escalation, so a breach of the application
  does not compromise them.
- `v5.0.0-16.5.1` When an unexpected or security-sensitive error occurs, the
  consumer receives a generic message, exposing no internal data such as stack
  traces, queries, secret keys or tokens.
- `v5.0.0-16.5.2` The application keeps operating securely when access to an
  external resource fails, using patterns such as circuit breakers or graceful
  degradation.
- `v5.0.0-16.5.3` The application fails gracefully and securely, exceptions
  included, and never fails open, for instance by processing a transaction
  despite errors in validation logic.

**L3**
- `v5.0.0-16.5.4` A "last resort" error handler catches all unhandled
  exceptions, so error details bound for the logs are not lost and an error
  cannot take down the whole process and cause a loss of availability.

---

## V17: WebRTC

Covers the three places WebRTC deployments need attention: TURN servers, media
handling and signaling.

Source: <https://github.com/OWASP/ASVS/blob/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/en/0x26-V17-WebRTC.md>

Sections: 17.1 TURN Server; 17.2 Media; 17.3 Signaling

The chapter has 12 requirements, none at L1 (7 L2 / 5 L3). Open the Source
chapter for code that runs TURN servers, handles media or implements signaling.

---

## Using this chapter-by-chapter

When reviewing against ASVS:

1. Identify which chapters apply by what the code does. A login flow touches V6
   (Authentication) and V7 (Session Management), plus V3 (Web Frontend
   Security) for cookie attributes and V16 (Security Logging and Error
   Handling) for security events. A data-export endpoint touches V8
   (Authorization), V14 (Data Protection) and V16, plus V4 (API and Web
   Service) when it is served as an API. The last column of the chapter table
   covers the rest.
2. Within each chapter, check documented requirements separately from implementation
   requirements; they are not always in the first section. Documentation that
   is not visible in the snippet is "cannot be determined", not "missing".
3. Walk the L1 requirements first, then L2 and L3 up to the level the user or
   organization targets. Remember that V16 has no L1 requirements.
4. In the report, cite the chapter, the level, the versioned ID, the verdict
   and the evidence: "V7 L3 — `v5.0.0-7.5.3` (further authentication before
   highly sensitive operations) — not met; `/admin/users/delete` completes on
   the session cookie alone."

The official ASVS CSV at the pinned commit is the canonical list for a
compliance deliverable. This reference paraphrases it and is not a substitute
for the official requirement text. Never state that an application is
ASVS-compliant on the strength of this file alone.

---

## Translating 4.0.3 IDs

A report or ticket that cites older ASVS IDs cannot be read against this file
by number, because 5.0.0 renumbered every chapter and requirement. The same
bare number points at unrelated requirements: `v4.0.3-2.1.1` required
user-set passwords of at least 12 characters, while `v5.0.0-2.1.1` requires
documented input-validation rules.

Translate through OWASP's official mapping files at the pinned commit:

- old to new:
  <https://raw.githubusercontent.com/OWASP/ASVS/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/mappings/mapping_v4.0.3_to_v5.0.0.yml>
- new to old:
  <https://raw.githubusercontent.com/OWASP/ASVS/2b300716ebbef654788d0a14d6c878cecc70c2e9/5.0/mappings/mapping_v5.0.0_to_v4.0.3.yml>

Entries are tagged with keywords such as MOVED, SPLIT, MERGED, ADDED and
DELETED (a deletion carries a reason). Worked example: `v4.0.3-3.2.1` was
MOVED and became `v5.0.0-7.2.4` (a new session token on authentication). A
DELETED entry has no 5.0.0 equivalent; never substitute the nearest-looking
requirement.

Structural notes:

- The previous edition's architecture and threat-modeling chapter was removed,
  and its surviving requirements were spread across several chapters.
- Its malicious-code chapter has no 5.0.0 counterpart. Its one surviving
  requirement, `v4.0.3-10.3.2`, is now `v5.0.0-15.2.4`.
- V3, V9, V10, V15 and V17 are new chapters. V10 and V17 hold wholly new
  content; V3 and V9 gather material that used to sit in other chapters (the
  token material was part of session management); V15 groups general practices
  that fitted no existing chapter.
- Old chapters are referred to by name only here, because every V-number in
  this file means a 5.0.0 chapter.
