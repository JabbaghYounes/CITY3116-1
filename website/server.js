/**
 * VULNERABLE WEB APPLICATION - OWASP Top 10 2025 Demonstration
 *
 * WARNING: This application is INTENTIONALLY VULNERABLE for educational purposes.
 * DO NOT deploy this in any production environment!
 *
 * Vulnerabilities demonstrated:
 * - A01: Broken Access Control (IDOR, missing authorization)
 * - A02: Security Misconfiguration (debug mode, default creds, verbose errors)
 * - A03: Supply Chain (simulated vulnerable dependency)
 * - A04: Cryptographic Failures (MD5 passwords, no HTTPS)
 * - A05: Injection (SQL injection, command injection)
 * - A06: Insecure Design (no rate limiting, business logic flaws)
 * - A07: Authentication Failures (weak sessions, no lockout)
 * - A08: Integrity Failures (unsigned cookies, no verification)
 * - A09: Logging Failures (minimal logging)
 * - A10: Exception Handling (fail-open, verbose errors)
 */

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const multer = require('multer');
const Database = require('better-sqlite3');
const md5 = require('md5');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// A02: Security Misconfiguration - Debug mode enabled in production
const DEBUG_MODE = true;

// A04: Cryptographic Failures - Weak secret key, hardcoded
const JWT_SECRET = 'super_secret_key_123';
const SESSION_SECRET = 'keyboard_cat';

// Initialize database
const db = new Database('./database.sqlite');

// A02: Security Misconfiguration - Verbose error messages
app.use((err, req, res, next) => {
    if (DEBUG_MODE) {
        // A10: Exception Handling - Exposing stack traces
        res.status(500).json({
            error: err.message,
            stack: err.stack,
            query: req.query,
            body: req.body,
            database: './database.sqlite',
            server_path: __dirname
        });
    } else {
        res.status(500).send('An error occurred');
    }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// A07: Authentication Failures - Weak session configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,  // A04: No HTTPS requirement
        httpOnly: false, // A01: Cookie accessible via JavaScript
        maxAge: 24 * 60 * 60 * 1000 * 30 // 30 days - too long!
    }
}));

// File upload configuration
const upload = multer({
    dest: 'uploads/',
    // A02: No file type validation
});

// A09: Logging Failures - Minimal logging
const log = (message) => {
    if (DEBUG_MODE) {
        console.log(`[${new Date().toISOString()}] ${message}`);
    }
    // No persistent logging, no alerting
};

// ============================================
// ROUTES
// ============================================

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// A05: INJECTION VULNERABILITIES
// ============================================

// SQL Injection - Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    // A04: Using MD5 for password hashing (weak)
    const hashedPassword = md5(password);

    // A05: SQL Injection vulnerability - string concatenation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashedPassword}'`;

    log(`Login attempt for user: ${username}`);
    // A09: Not logging failed attempts count

    try {
        const user = db.prepare(query).get();

        if (user) {
            req.session.user = user;
            req.session.isAuthenticated = true;

            // A08: Integrity Failures - Unsigned user data in cookie
            res.cookie('user_data', JSON.stringify({
                id: user.id,
                username: user.username,
                role: user.role
            }));

            res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
        } else {
            // A07: No account lockout after failed attempts
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        // A10: Exception Handling - Exposing SQL errors
        res.status(500).json({
            success: false,
            message: error.message,
            query: DEBUG_MODE ? query : undefined
        });
    }
});

// SQL Injection - Search
app.get('/api/search', (req, res) => {
    const { q } = req.query;

    // A05: SQL Injection in search
    const query = `SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;

    try {
        const products = db.prepare(query).all();
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message, query: DEBUG_MODE ? query : undefined });
    }
});

// Command Injection - Ping utility
app.get('/api/ping', (req, res) => {
    const { host } = req.query;

    // A05: Command Injection vulnerability
    exec(`ping -c 2 ${host}`, (error, stdout, stderr) => {
        if (error) {
            res.json({ success: false, error: error.message, stderr });
        } else {
            res.json({ success: true, output: stdout });
        }
    });
});

// ============================================
// A01: BROKEN ACCESS CONTROL
// ============================================

// IDOR - Get user profile by ID (no authorization check)
app.get('/api/users/:id', (req, res) => {
    const { id } = req.params;

    // A01: No check if current user is authorized to view this profile
    const query = `SELECT id, username, email, role, address, phone, ssn FROM users WHERE id = ?`;

    try {
        const user = db.prepare(query).get(id);
        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// IDOR - Update user (no authorization)
app.put('/api/users/:id', (req, res) => {
    const { id } = req.params;
    const { role, email } = req.body;

    // A01: No check if user can modify this account or change roles
    try {
        db.prepare(`UPDATE users SET role = ?, email = ? WHERE id = ?`).run(role || 'user', email, id);
        res.json({ success: true, message: 'User updated' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Missing function level access control
app.get('/api/admin/users', (req, res) => {
    // A01: No admin check!
    const users = db.prepare('SELECT id, username, email, role, created_at FROM users').all();
    res.json(users);
});

app.delete('/api/admin/users/:id', (req, res) => {
    // A01: No admin check!
    const { id } = req.params;
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    res.json({ success: true, message: 'User deleted' });
});

// ============================================
// A06: INSECURE DESIGN
// ============================================

// No rate limiting on sensitive endpoints
app.post('/api/transfer', (req, res) => {
    const { from_account, to_account, amount } = req.body;

    // A06: Business logic flaw - no verification that user owns from_account
    // A06: No transaction limits
    // A06: No rate limiting

    try {
        // Check balance (but don't verify ownership!)
        const fromAcc = db.prepare('SELECT * FROM accounts WHERE id = ?').get(from_account);

        if (!fromAcc) {
            return res.status(404).json({ error: 'Source account not found' });
        }

        if (fromAcc.balance < amount) {
            return res.status(400).json({ error: 'Insufficient funds' });
        }

        // Perform transfer
        db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?').run(amount, from_account);
        db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?').run(amount, to_account);

        res.json({ success: true, message: `Transferred $${amount}` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Password reset without proper verification
app.post('/api/reset-password', (req, res) => {
    const { email, new_password } = req.body;

    // A06: Insecure Design - No token, no email verification
    // Just resets the password directly!

    const hashedPassword = md5(new_password);

    try {
        const result = db.prepare('UPDATE users SET password = ? WHERE email = ?').run(hashedPassword, email);
        if (result.changes > 0) {
            res.json({ success: true, message: 'Password reset successful' });
        } else {
            res.status(404).json({ error: 'Email not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// A07: AUTHENTICATION FAILURES
// ============================================

// Weak password requirements
app.post('/api/register', (req, res) => {
    const { username, password, email } = req.body;

    // A07: No password complexity requirements
    // A07: No check for common passwords

    const hashedPassword = md5(password); // A04: Weak hashing

    try {
        db.prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)').run(
            username, hashedPassword, email, 'user'
        );
        res.json({ success: true, message: 'Registration successful' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// JWT with weak secret
app.post('/api/token', (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = md5(password);
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, hashedPassword);

    if (user) {
        // A04: Weak JWT secret, algorithm not specified
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '30d' } // A07: Token valid too long
        );
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// ============================================
// A08: INTEGRITY FAILURES
// ============================================

// Insecure deserialization
app.post('/api/preferences', (req, res) => {
    const { prefs } = req.body;

    try {
        // A08: Dangerous - evaluating user input
        const userPrefs = eval('(' + prefs + ')');
        res.json({ success: true, preferences: userPrefs });
    } catch (error) {
        res.status(400).json({ error: 'Invalid preferences format' });
    }
});

// No integrity check on uploaded files
app.post('/api/upload', upload.single('file'), (req, res) => {
    // A08: No file integrity verification
    // A02: No file type restrictions

    if (req.file) {
        res.json({
            success: true,
            filename: req.file.filename,
            path: `/uploads/${req.file.filename}`
        });
    } else {
        res.status(400).json({ error: 'No file uploaded' });
    }
});

// ============================================
// A10: EXCEPTION HANDLING FAILURES
// ============================================

// Fail-open authentication
app.get('/api/secure-data', (req, res) => {
    try {
        // Simulating auth service check
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            throw new Error('No authorization header');
        }

        // This might fail if auth service is down
        const isValid = checkAuthService(authHeader);

        if (isValid) {
            res.json({ data: 'Sensitive information here' });
        } else {
            res.status(403).json({ error: 'Unauthorized' });
        }
    } catch (error) {
        // A10: FAIL OPEN - Granting access on error!
        log(`Auth error (granting access anyway): ${error.message}`);
        res.json({
            data: 'Sensitive information here',
            warning: 'Auth service unavailable, access granted by default'
        });
    }
});

function checkAuthService(token) {
    // Simulating unreliable auth service
    if (Math.random() < 0.3) {
        throw new Error('Auth service unavailable');
    }
    return token === 'valid_token';
}

// Unhandled exception causing DoS
app.get('/api/process', (req, res) => {
    const { data } = req.query;

    // A10: No try-catch, will crash on invalid input
    const parsed = JSON.parse(data);
    const result = parsed.value * 2;
    res.json({ result });
});

// ============================================
// A02: SECURITY MISCONFIGURATION
// ============================================

// Debug endpoint exposed
app.get('/api/debug', (req, res) => {
    // A02: Debug info in production
    res.json({
        environment: process.env,
        database: './database.sqlite',
        config: {
            jwt_secret: JWT_SECRET,
            session_secret: SESSION_SECRET,
            debug_mode: DEBUG_MODE
        },
        routes: app._router.stack.filter(r => r.route).map(r => ({
            path: r.route.path,
            methods: Object.keys(r.route.methods)
        }))
    });
});

// Directory listing enabled
app.use('/uploads', express.static('uploads', {
    dotfiles: 'allow',  // A02: Serving dotfiles
    index: true         // A02: Directory listing
}));

// ============================================
// A03: SUPPLY CHAIN (Simulated)
// ============================================

// Simulating vulnerable dependency behavior
app.get('/api/format', (req, res) => {
    const { template, data } = req.query;

    // A03: Simulating a "vulnerable template library"
    // This mimics how supply chain attacks work
    try {
        // Dangerous: executing template as code
        const result = new Function('data', `return \`${template}\``)(JSON.parse(data || '{}'));
        res.json({ result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ============================================
// A04: CRYPTOGRAPHIC FAILURES
// ============================================

// Exposing sensitive data without encryption
app.get('/api/export', (req, res) => {
    // A04: Sensitive data transmitted without encryption indication
    const users = db.prepare('SELECT username, email, ssn, address, phone FROM users').all();

    res.json({
        exported_at: new Date().toISOString(),
        data: users,
        // A04: No encryption, plain JSON
    });
});

// Weak random token generation
app.get('/api/reset-token', (req, res) => {
    const { email } = req.query;

    // A04: Weak random - predictable token
    const token = Math.random().toString(36).substring(2, 8);

    res.json({
        email,
        reset_token: token,
        expires: new Date(Date.now() + 3600000).toISOString()
    });
});

// ============================================
// SERVER START
// ============================================

// Ensure uploads directory exists
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║     VULNERABLE WEB APPLICATION - OWASP Top 10 2025 Demo       ║
╠═══════════════════════════════════════════════════════════════╣
║  WARNING: This application is INTENTIONALLY VULNERABLE!       ║
║  For educational and testing purposes ONLY.                   ║
║  DO NOT expose to the internet or use in production!          ║
╠═══════════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:${PORT}                     ║
║  Debug endpoint:    http://localhost:${PORT}/api/debug           ║
╚═══════════════════════════════════════════════════════════════╝
    `);
});

module.exports = app;
