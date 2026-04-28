# Secure Coding Patterns & Remediation Examples

> **Reference:** OWASP Secure Coding Practices Quick Reference Guide

This file contains secure patterns organized by domain. Use these as templates when remediating findings.

## 1. Input Validation

### ✓ SECURE: Python input validation with allow-list
```python
import re

def validate_username(username):
    """
    Validate username using allow-list pattern.
    Only alphanumeric, underscore, hyphen; 3-20 chars.
    """
    if not isinstance(username, str):
        return False
    
    # Allow-list: strict pattern matching
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        return False
    
    return True

# Use centralized validation
if not validate_username(user_input):
    raise ValueError("Invalid username")
```

### ✓ SECURE: Django input validation
```python
from django import forms

class UserForm(forms.Form):
    username = forms.CharField(
        max_length=20,
        min_length=3,
        regex=r'^[a-zA-Z0-9_-]+$'
    )
    age = forms.IntegerField(min_value=0, max_value=150)
    email = forms.EmailField()

# Automatic validation
form = UserForm(request.POST)
if form.is_valid():
    # Access validated data
    username = form.cleaned_data['username']
```

### ✓ SECURE: JavaScript server-side validation (Node.js)
```javascript
const validator = require('validator');

app.post('/register', (req, res) => {
    // Server-side validation only
    const email = req.body.email;
    
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email' });
    }
    
    if (email.length > 254) {
        return res.status(400).json({ error: 'Email too long' });
    }
    
    // Process validated data
});
```

---

## 2. Output Encoding

### ✓ SECURE: HTML output encoding (Python)
```python
from html import escape

# Unsafe: vulnerable to XSS
# response = f"<h1>Hello {username}</h1>"

# Secure: HTML encode user data
username_safe = escape(username)
response = f"<h1>Hello {username_safe}</h1>"
```

### ✓ SECURE: Django template auto-escape (enabled by default)
```django
{# Auto-escape is ON by default in Django #}
{# User data is HTML-encoded automatically #}
<h1>Hello {{ username }}</h1>

{# If you must render raw HTML, mark it safe: #}
{# but only for data you control #}
<div>{{ description | safe }}</div>
```

### ✓ SECURE: SQL output encoding (parameterized queries)
```python
import sqlite3

# Unsafe: string concatenation
# query = f"SELECT * FROM users WHERE username = '{username}'"

# Secure: parameterized query
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

### ✓ SECURE: URL encoding
```python
from urllib.parse import quote

# Unsafe
# redirect_url = f"https://example.com?next={next_url}"

# Secure: URL encode the parameter
encoded_next = quote(next_url, safe='')
redirect_url = f"https://example.com?next={encoded_next}"
```

---

## 3. Authentication & Password Management

### ✓ SECURE: Bcrypt password hashing (Python)
```python
import bcrypt

# Hash password on registration
password = request.form['password']
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Verify password on login
if bcrypt.checkpw(provided_password.encode(), stored_hash):
    # Authentication successful
    pass
else:
    # Authentication failed
    pass
```

### ✓ SECURE: Argon2 password hashing (Python)
```python
from argon2 import PasswordHasher

ph = PasswordHasher()

# Hash password
hashed = ph.hash(password)

# Verify password
try:
    ph.verify(hashed, provided_password)
    # Authentication successful
except VerifyMismatchError:
    # Authentication failed
    pass
```

### ✓ SECURE: Generic error message (no info disclosure)
```python
# Unsafe
# if user_not_found:
#     return "User not found"
# if password_wrong:
#     return "Password incorrect"

# Secure: same message regardless
login_failed = user_not_found or password_incorrect
if login_failed:
    return "Invalid username or password"
```

### ✓ SECURE: Account lockout after failed attempts
```python
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes

def check_account_lockout(user_id):
    attempts = get_failed_attempts(user_id)
    if attempts >= MAX_FAILED_ATTEMPTS:
        lockout_time = get_lockout_time(user_id)
        if time.time() - lockout_time < LOCKOUT_DURATION:
            raise AccountLockedError()
        else:
            reset_failed_attempts(user_id)

def record_failed_attempt(user_id):
    attempts = get_failed_attempts(user_id)
    set_failed_attempts(user_id, attempts + 1)
    if attempts + 1 >= MAX_FAILED_ATTEMPTS:
        set_lockout_time(user_id, time.time())
```

### ✓ SECURE: MFA for sensitive accounts
```python
import pyotp

# Setup MFA (TOTP)
secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)

# Verify MFA code
def verify_mfa(user_id, code):
    secret = get_user_mfa_secret(user_id)
    totp = pyotp.TOTP(secret)
    
    # Allow for time skew (±1 time step)
    if totp.verify(code, valid_window=1):
        return True
    return False
```

---

## 4. Session Management

### ✓ SECURE: Server-side session (Flask)
```python
from flask import session
import secrets

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if authenticate_user(username, password):
        # Invalidate old session
        session.clear()
        
        # Create new secure session
        session['user_id'] = user_id
        session['login_time'] = time.time()
        
        # Mark as HttpOnly, Secure, SameSite
        response = redirect('/dashboard')
        return response
```

### ✓ SECURE: Session timeout (Flask with Redis)
```python
from flask_session import Session
import redis

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')
app.config['PERMANENT_SESSION_LIFETIME'] = 900  # 15 minutes
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

Session(app)
```

### ✓ SECURE: CSRF token for state-changing requests
```django
{# In template #}
<form method="POST">
    {% csrf_token %}
    <input type="text" name="action">
    <button>Submit</button>
</form>

{# Django validates token automatically #}
```

### ✓ SECURE: Session fixation prevention
```python
@app.route('/login', methods=['POST'])
def login():
    if authenticate_user(username, password):
        # Invalidate old session ID (if exists)
        old_session_id = session.get('_id')
        if old_session_id:
            invalidate_session(old_session_id)
        
        # Create entirely new session
        session.clear()
        session['user_id'] = user_id
        session['_created_at'] = time.time()
        
        return redirect('/dashboard')
```

---

## 5. Access Control

### ✓ SECURE: Centralized authorization decorator (Flask)
```python
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/dashboard')
@require_auth
def dashboard():
    user_id = session['user_id']
    return render_template('dashboard.html', user_id=user_id)
```

### ✓ SECURE: Ownership verification (prevent direct object reference)
```python
@app.route('/profile/<int:user_id>')
@require_auth
def view_profile(user_id):
    # Get current user from session
    current_user_id = session['user_id']
    
    # Verify ownership
    if current_user_id != user_id:
        return "Unauthorized", 403
    
    user = get_user(user_id)
    return render_template('profile.html', user=user)
```

### ✓ SECURE: Role-based access control
```python
def require_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return redirect('/login')
            
            user_role = get_user_role(user_id)
            if user_role != required_role:
                return "Forbidden", 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin')
@require_role('admin')
def admin_panel():
    return render_template('admin.html')
```

### ✓ SECURE: Rate limiting (prevent brute force)
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic
    pass
```

---

## 6. Cryptographic Practices

### ✓ SECURE: Random token generation (Python)
```python
import secrets

# Generate cryptographically secure random token
token = secrets.token_urlsafe(32)  # 32 bytes → 43 base64 chars

# Use for password reset links, CSRF tokens, etc.
session_token = secrets.token_hex(16)
```

### ✓ SECURE: Encryption with AES-256-GCM (Python)
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_sensitive_data(plaintext, key):
    """Encrypt with AES-256-GCM"""
    nonce = os.urandom(12)  # 96-bit nonce
    cipher = AESGCM(key)
    
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    
    # Return nonce + ciphertext (nonce doesn't need to be secret)
    return nonce + ciphertext

def decrypt_sensitive_data(encrypted_data, key):
    """Decrypt with AES-256-GCM"""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode()
```

### ✓ SECURE: Key derivation from password
```python
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

def derive_key(password, salt=None):
    """Derive encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return salt, key
```

---

## 7. Error Handling & Logging

### ✓ SECURE: Generic error messages
```python
@app.errorhandler(Exception)
def handle_error(error):
    # Log detailed error server-side
    logger.error(f"Unexpected error: {error}", exc_info=True)
    
    # Return generic message to client
    return {
        'error': 'An unexpected error occurred',
        'code': 'ERROR_INTERNAL'
    }, 500
```

### ✓ SECURE: Audit logging
```python
import logging

audit_logger = logging.getLogger('audit')

def log_authentication_attempt(user_id, success, ip_address):
    """Log authentication attempts for security monitoring"""
    audit_logger.info(f"auth_attempt user_id={user_id} success={success} ip={ip_address}")

def log_access_denial(user_id, resource, ip_address):
    """Log unauthorized access attempts"""
    audit_logger.warning(f"access_denied user_id={user_id} resource={resource} ip={ip_address}")

def log_privilege_escalation_attempt(user_id, target_role, ip_address):
    """Log privilege escalation attempts"""
    audit_logger.critical(f"privesc_attempt user_id={user_id} target_role={target_role} ip={ip_address}")
```

### ✓ SECURE: Structured logging (no sensitive data)
```python
import json
import logging

def log_event(event_type, user_id, action, result):
    """Structured logging without sensitive data"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'action': action,
        'result': result
        # Never log: passwords, tokens, keys, PII
    }
    
    logger.info(json.dumps(log_entry))
```

---

## 8. Data Protection

### ✓ SECURE: Disable autocomplete on sensitive fields
```html
<!-- Password fields -->
<input type="password" name="password" autocomplete="off">

<!-- Credit card -->
<input type="text" name="card_number" autocomplete="off">

<!-- SSN -->
<input type="text" name="ssn" autocomplete="off">
```

### ✓ SECURE: Cache-Control headers for sensitive pages
```python
@app.route('/account')
@require_auth
def account_page():
    response = make_response(render_template('account.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
```

### ✓ SECURE: Sensitive data in POST, not GET
```python
# Unsafe: GET with sensitive data
# GET /transfer?amount=1000&recipient=123

# Secure: POST with sensitive data
@app.route('/transfer', methods=['POST'])
@require_auth
def transfer():
    amount = request.form['amount']
    recipient = request.form['recipient']
    # Process transfer
```

### ✓ SECURE: Clear sensitive data from memory
```python
import gc

def process_sensitive_data(password):
    """Clear sensitive data after use"""
    try:
        # Use password
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    finally:
        # Explicitly overwrite and delete
        password = "x" * len(password)
        del password
        gc.collect()
```

---

## 9. Communication Security

### ✓ SECURE: TLS/HTTPS enforcement (Flask)
```python
@app.before_request
def enforce_https():
    """Redirect HTTP to HTTPS"""
    if not request.is_secure and not app.debug:
        return redirect(request.url.replace('http://', 'https://'))

# Also set in production server config
# Strict-Transport-Security header
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

### ✓ SECURE: TLS certificate validation (requests)
```python
import requests

# Secure: verify certificates
response = requests.get('https://api.example.com/data', verify=True)

# Certificate pinning (for sensitive APIs)
requests.packages.urllib3.util.ssl_.create_urllib3_context(
    ssl_version=ssl.PROTOCOL_TLSv1_2,
    cert_reqs=ssl.CERT_REQUIRED
)
```

### ✓ SECURE: Security headers
```python
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## 10. System Configuration

### ✓ SECURE: Disable unnecessary HTTP methods
```python
# Flask: restrict to POST and GET
@app.route('/data', methods=['GET', 'POST'])
def data_endpoint():
    if request.method == 'POST':
        # Handle POST
        pass
    else:
        # Handle GET
        pass
```

### ✓ SECURE: Remove sensitive headers
```python
@app.after_request
def remove_headers(response):
    """Remove server version and framework info"""
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response
```

### ✓ SECURE: robots.txt configuration
```
# robots.txt: prevent indexing of sensitive directories
User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /private/

# Don't expose directory structure
```

---

## 11. Database Security

### ✓ SECURE: Parameterized queries (prevent SQL injection)
```python
# Unsafe
# query = f"SELECT * FROM users WHERE username = '{username}'"

# Secure: parameterized query
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# ORM (Django)
User.objects.filter(username=username)
```

### ✓ SECURE: Connection strings in config
```python
# Unsafe
# DATABASE_URL = "postgres://user:password@localhost/db"  # in code

# Secure: in environment file or secure config
import os
DATABASE_URL = os.getenv('DATABASE_URL')

# Or use config management
from decouple import config
DATABASE_URL = config('DATABASE_URL')
```

### ✓ SECURE: Least privilege database user
```sql
-- Create minimal privilege user for app
CREATE USER app_user WITH PASSWORD 'strong_password';

-- Grant only necessary permissions
GRANT SELECT, INSERT, UPDATE ON users TO app_user;
GRANT SELECT, INSERT ON logs TO app_user;

-- Deny other operations
REVOKE DROP ON users FROM app_user;
REVOKE DELETE ON users FROM app_user;
```

---

## 12. File Management

### ✓ SECURE: File upload validation
```python
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg'}
UPLOAD_FOLDER = '/secure/uploads/outside/web/root'

def validate_file_upload(file):
    """Validate uploaded file"""
    # Check file extension
    if not allowed_file(file.filename):
        raise ValueError("File type not allowed")
    
    # Check file size
    if len(file.read()) > 5 * 1024 * 1024:  # 5MB
        raise ValueError("File too large")
    
    file.seek(0)
    
    # Check file magic bytes (not extension)
    file_bytes = file.read(4)
    if not is_valid_file_magic(file_bytes):
        raise ValueError("Invalid file type")
    
    file.seek(0)
    
    # Sanitize filename
    filename = secure_filename(file.filename)
    
    # Save to secure location
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    return filepath

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

### ✓ SECURE: Prevent path traversal
```python
import os

def serve_file(filename):
    """Safely serve user-requested file"""
    # Get absolute path
    base_dir = '/var/www/files'
    requested_path = os.path.normpath(os.path.join(base_dir, filename))
    
    # Ensure it's within base directory (prevent ../ traversal)
    if not requested_path.startswith(base_dir):
        return "Forbidden", 403
    
    if not os.path.exists(requested_path):
        return "Not found", 404
    
    return send_file(requested_path)
```

### ✓ SECURE: File execution prevention
```bash
# Linux: remove execute permissions from upload directory
chmod 755 /var/www/uploads
chmod 644 /var/www/uploads/*

# Disable PHP execution in upload directory (.htaccess)
<FilesMatch "\.php$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
```

---

## 13. Memory Management

### ✓ SECURE: String input truncation
```python
def process_username(username, max_length=20):
    """Truncate input before processing"""
    if len(username) > max_length:
        username = username[:max_length]
    
    return username
```

### ✓ SECURE: Explicit resource cleanup
```python
import contextlib

@contextlib.contextmanager
def get_database_connection():
    """Context manager for safe resource cleanup"""
    connection = db.connect()
    try:
        yield connection
    finally:
        connection.close()

# Usage
with get_database_connection() as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    # Automatically closed after block
```

---

## 14. General Coding Practices

### ✓ SECURE: Avoid dynamic code execution
```python
# Unsafe: eval with user input
# result = eval(user_provided_expression)

# Secure: use safe evaluation or predefined functions
import ast

def safe_math_eval(expression):
    """Safely evaluate mathematical expressions"""
    # Only allow safe AST nodes
    try:
        tree = ast.parse(expression, mode='eval')
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Expression, ast.BinOp, ast.Num, ast.operator)):
                raise ValueError("Invalid expression")
        return eval(compile(tree, '<string>', 'eval'))
    except Exception as e:
        raise ValueError(f"Expression error: {e}")
```

### ✓ SECURE: Thread-safe shared resource access
```python
import threading

class UserCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.RLock()
    
    def get(self, user_id):
        with self.lock:
            return self.cache.get(user_id)
    
    def set(self, user_id, user_data):
        with self.lock:
            self.cache[user_id] = user_data
```

### ✓ SECURE: Checksum integrity verification
```python
import hashlib

def verify_file_integrity(filepath, expected_sha256):
    """Verify file hasn't been tampered with"""
    sha256_hash = hashlib.sha256()
    
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest() == expected_sha256
```

---

## Applying these patterns

1. **Identify the domain** of your finding (e.g., "Input Validation")
2. **Find the matching section** above
3. **Copy the secure pattern** that applies to your language/framework
4. **Adapt to your code** while maintaining the security principles
5. **Test thoroughly** to ensure the fix works and doesn't break functionality
6. **Document** the change and rationale

Remember: Security patterns are not one-size-fits-all. Always validate the pattern against your specific threat model and requirements.
