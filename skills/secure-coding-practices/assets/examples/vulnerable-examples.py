"""
VULNERABLE: Input Validation - Missing server-side validation
Domain: Input Validation
Issue: Client-side validation only, no server-side checks
Risk: Attacker can bypass client-side checks and send malicious data
"""

from flask import Flask, request
import re

app = Flask(__name__)

# VULNERABLE: Only JavaScript validation on client
@app.route('/register', methods=['POST'])
def register_vulnerable():
    """
    Vulnerable pattern: trusting client-side validation
    """
    username = request.form.get('username')
    age = request.form.get('age')
    email = request.form.get('email')
    
    # Assuming client-side validation happened... WRONG!
    # An attacker can send any value they want
    
    # No server-side validation - directly process
    user = create_user(username, age, email)
    return f"User {username} created!"


# VULNERABLE: Allow-list not used, only deny-list
@app.route('/upload', methods=['POST'])
def upload_vulnerable():
    """
    Vulnerable pattern: using deny-list instead of allow-list
    """
    file = request.files['file']
    
    # Deny-list approach (weak)
    blocked_extensions = ['.exe', '.bat', '.cmd', '.com']
    
    if not any(file.filename.endswith(ext) for ext in blocked_extensions):
        # Allow any file not in blocked list
        file.save(f'uploads/{file.filename}')
        return "File uploaded!"
    
    return "File type blocked"


# VULNERABLE: No data range validation
@app.route('/transfer', methods=['POST'])
def transfer_vulnerable():
    """
    Vulnerable: No validation of data range
    """
    amount = request.form.get('amount')
    recipient = request.form.get('recipient')
    
    # No range check - attacker can transfer negative amounts, huge amounts
    process_transfer(amount, recipient)
    return "Transfer processed"


# ============================================
# VULNERABLE: Output Encoding - XSS via template
# ============================================

from flask import render_template_string

@app.route('/greet/<name>')
def greet_vulnerable(name):
    """
    Vulnerable: User input inserted directly into HTML (XSS)
    """
    # Django/Jinja2 auto-escape disabled or not used
    template = f"<h1>Hello {name}!</h1>"
    return template
    
    # Payload: /greet/<img%20src=x%20onerror=alert('XSS')>
    # Result: <h1>Hello <img src=x onerror=alert('XSS')>!</h1>


# ============================================
# VULNERABLE: Authentication - Plaintext passwords
# ============================================

@app.route('/register_auth', methods=['POST'])
def register_auth_vulnerable():
    """
    Vulnerable: Storing passwords in plaintext
    """
    username = request.form['username']
    password = request.form['password']
    
    # CRITICAL: Storing plaintext password!
    store_user_in_db(username, password)
    
    return "User registered"

# Database storage (simulated)
users_db = {}
def store_user_in_db(username, password):
    # Vulnerable: plaintext
    users_db[username] = password


# VULNERABLE: Weak password hashing
@app.route('/register_weak_hash', methods=['POST'])
def register_weak_hash():
    """
    Vulnerable: Using weak hash function (MD5/SHA1)
    """
    import hashlib
    
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: MD5 is broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    users_db[username] = hashed
    return "User registered"


# VULNERABLE: Informative error messages
@app.route('/login_bad_error', methods=['POST'])
def login_bad_error():
    """
    Vulnerable: Different error messages reveal if user exists
    """
    username = request.form['username']
    password = request.form['password']
    
    if username not in users_db:
        return "User not found"  # Reveals user doesn't exist!
    
    if users_db[username] != password:
        return "Password incorrect"  # Reveals user exists!
    
    return "Login successful"


# ============================================
# VULNERABLE: Session Management
# ============================================

@app.route('/login_bad_session', methods=['POST'])
def login_bad_session():
    """
    Vulnerable: Session ID in URL, not invalidated on logout
    """
    username = request.form['username']
    
    # Vulnerable: predictable session ID
    session_id = str(hash(username))
    
    # Store in URL (exposed to referer, logs, etc.)
    return f"<a href='/dashboard?sid={session_id}'>Dashboard</a>"


# ============================================
# VULNERABLE: SQL Injection
# ============================================

import sqlite3

def get_user_vulnerable(username):
    """
    Vulnerable: SQL injection via string concatenation
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Dynamic SQL with user input
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    
    return cursor.fetchone()

# Payload: admin' OR '1'='1
# Result: SELECT * FROM users WHERE username = 'admin' OR '1'='1'
# This returns all users!


# ============================================
# VULNERABLE: File Upload - Path Traversal
# ============================================

@app.route('/upload_file', methods=['POST'])
def upload_file_vulnerable():
    """
    Vulnerable: Using user input directly for file path
    """
    file = request.files['file']
    filename = request.form.get('filename')
    
    # VULNERABLE: No path validation
    filepath = f"uploads/{filename}"
    file.save(filepath)
    
    return "File uploaded"

# Payload: filename = "../../../etc/passwd"
# Result: File saved to /etc/passwd


# ============================================
# VULNERABLE: Hardcoded Credentials
# ============================================

API_KEY = "sk-abcd1234efgh5678ijkl9012"  # EXPOSED!

DB_PASSWORD = "MySecurePassword123"  # In source code!

@app.route('/api/data')
def get_api_data():
    """
    Vulnerable: API key in code
    """
    import requests
    response = requests.get(
        'https://api.example.com/data',
        headers={'Authorization': f'Bearer {API_KEY}'}
    )
    return response.json()


# ============================================
# VULNERABLE: No HTTPS/TLS
# ============================================

@app.route('/login_no_tls', methods=['POST'])
def login_no_tls():
    """
    Vulnerable: Transmitting credentials over HTTP
    """
    username = request.form['username']
    password = request.form['password']
    
    # If running on HTTP, credentials are sent in plaintext!
    # Man-in-the-middle attacker can capture them
    
    if authenticate(username, password):
        return "Login successful"


# ============================================
# VULNERABLE: Missing Access Control
# ============================================

@app.route('/user/<int:user_id>')
def get_user_profile(user_id):
    """
    Vulnerable: No ownership check (direct object reference)
    """
    # No check if current user owns this profile
    user = get_user_from_db(user_id)
    
    return {
        'name': user.name,
        'email': user.email,
        'ssn': user.ssn,  # Sensitive!
        'phone': user.phone  # Sensitive!
    }

# Attacker can access any user's profile by changing user_id


# ============================================
# VULNERABLE: No Rate Limiting
# ============================================

@app.route('/send_email', methods=['POST'])
def send_email_vulnerable():
    """
    Vulnerable: No rate limiting on email sends
    """
    email = request.form['email']
    
    # No checks - attacker can spam
    send_email_to(email)
    
    return "Email sent"


# ============================================
# VULNERABLE: Error Messages Expose Details
# ============================================

@app.route('/process_data', methods=['POST'])
def process_data_vulnerable():
    """
    Vulnerable: Stack traces and system details in error response
    """
    try:
        data = request.json
        # Process data
        query = f"SELECT * FROM data WHERE id = {data['id']}"
        result = db.execute(query)
    except Exception as e:
        # VULNERABLE: Returning full exception details
        import traceback
        return {
            'error': str(e),
            'traceback': traceback.format_exc(),
            'query': query  # Exposes database structure!
        }, 500


# ============================================
# VULNERABLE: Sensitive Data in Logs
# ============================================

import logging

logger = logging.getLogger(__name__)

@app.route('/authenticate', methods=['POST'])
def authenticate_bad_logging():
    """
    Vulnerable: Logging sensitive information
    """
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Logging password!
    logger.info(f"User {username} attempting login with password: {password}")
    
    if validate_credentials(username, password):
        return "Login successful"
    
    # VULNERABLE: Logging failed attempt with password
    logger.warning(f"Failed login for {username}, password was: {password}")


# ============================================
# VULNERABLE: Concurrent Access without Locking
# ============================================

import threading

class Counter:
    def __init__(self):
        self.value = 0  # No lock!
    
    def increment_vulnerable(self):
        """
        Vulnerable: Race condition due to no locking
        """
        # Read
        temp = self.value
        # Increment
        temp += 1
        # Write
        self.value = temp
        
        # Between read and write, another thread could modify value!
        # Result: Lost updates


counter = Counter()

def increment_from_multiple_threads():
    """
    Race condition: Expected 1000, but might be less
    """
    threads = []
    for _ in range(10):
        t = threading.Thread(target=counter.increment_vulnerable)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    print(counter.value)  # Might not be 1000!
