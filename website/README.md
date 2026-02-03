# VulnShop - OWASP Top 10 2025 Vulnerable Web Application

⚠️ **WARNING: This application is INTENTIONALLY VULNERABLE for educational purposes only!**

Do NOT deploy this application in any production environment or expose it to the internet.

## Overview

VulnShop is a deliberately vulnerable e-commerce web application designed to demonstrate all 10 categories from the OWASP Top 10 2025. It's intended for security education, penetration testing practice, and understanding common web vulnerabilities.

## Installation

### Prerequisites
- Node.js 18+
- npm

### Setup

```bash
# Navigate to the website directory
cd /home/vt/Documents/BSC/advanced-computer-forensics/website

# Install dependencies
npm install

# Initialize the database with sample data
npm run init-db

# Start the server
npm start
```

The application will be available at: http://localhost:3000

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| john | password123 | user |
| jane | letmein | user |
| bob | qwerty | manager |
| alice | 123456 | user |

## Implemented Vulnerabilities

### A01:2025 - Broken Access Control
- **IDOR**: Access any user's profile via `/api/users/{id}`
- **Missing Authorization**: Admin endpoints accessible without authentication
- **Privilege Escalation**: Modify user roles via PUT request

### A02:2025 - Security Misconfiguration
- **Debug Mode**: Enabled in production (`/api/debug` endpoint)
- **Default Credentials**: admin:admin123
- **Verbose Errors**: Stack traces exposed in error responses
- **Directory Listing**: `/uploads` directory listing enabled

### A03:2025 - Software Supply Chain Failures
- **Simulated Vulnerable Library**: `/api/format` endpoint demonstrates template injection
- **No Dependency Verification**: Dependencies installed without integrity checks

### A04:2025 - Cryptographic Failures
- **MD5 Password Hashing**: Easily crackable
- **Hardcoded Secrets**: JWT_SECRET and SESSION_SECRET in code
- **Weak Random Tokens**: Math.random() for reset tokens
- **No HTTPS**: All traffic unencrypted

### A05:2025 - Injection
- **SQL Injection (Login)**: Username field vulnerable to SQLi
- **SQL Injection (Search)**: Product search vulnerable
- **Command Injection**: `/api/ping` endpoint vulnerable to OS command injection

### A06:2025 - Insecure Design
- **No Rate Limiting**: Unlimited login attempts, API calls
- **Insecure Password Reset**: No email verification required
- **Business Logic Flaws**: Transfer money from any account

### A07:2025 - Authentication Failures
- **No Account Lockout**: Brute force possible
- **Weak Password Policy**: Any password accepted
- **Long Session Duration**: 30-day sessions
- **Accessible Session Cookies**: httpOnly=false

### A08:2025 - Software/Data Integrity Failures
- **Insecure Deserialization**: eval() used on user input
- **Unsigned Cookies**: user_data cookie without signature
- **No File Verification**: Uploaded files not validated

### A09:2025 - Security Logging & Alerting Failures
- **Minimal Logging**: Only console.log in debug mode
- **No Failed Login Tracking**: Brute force goes undetected
- **No Alerting**: No security event notifications

### A10:2025 - Mishandling of Exceptional Conditions
- **Fail-Open Authentication**: Grants access on auth service error
- **Unhandled Exceptions**: `/api/process` crashes on invalid input
- **Verbose Error Messages**: Internal details exposed

## Testing Guide

### SQL Injection
```
# Login bypass
Username: ' OR '1'='1' --
Password: anything

# Data extraction via search
Search: ' UNION SELECT 1,username,password,4 FROM users--
```

### Command Injection
```
# Read system files
Host: localhost; cat /etc/passwd

# Execute arbitrary commands
Host: localhost && id
```

### IDOR
```
# Access admin profile (should be restricted)
GET /api/users/1

# Access any user's SSN
GET /api/users/2
```

### Business Logic
```
# Transfer money without owning the account
POST /api/transfer
{"from_account": 1, "to_account": 2, "amount": 10000}
```

## Project Structure

```
website/
├── server.js           # Main Express server with vulnerabilities
├── init-db.js          # Database initialization script
├── package.json        # Dependencies
├── database.sqlite     # SQLite database (created on init)
├── public/
│   ├── index.html      # Home page
│   ├── login.html      # Login page (SQLi)
│   ├── products.html   # Product search (SQLi)
│   ├── admin.html      # Admin panel (Broken Access)
│   ├── banking.html    # Banking (Insecure Design)
│   ├── tools.html      # Security tools (Command Injection, etc.)
│   ├── register.html   # Registration (Weak passwords)
│   ├── css/
│   │   └── style.css   # Styling
│   └── js/
│       └── app.js      # Frontend JavaScript
└── uploads/            # File upload directory
```

## Legal Disclaimer

This application is provided for educational purposes only. Use it only in isolated, controlled environments. The authors are not responsible for any misuse or damage caused by this software.

## License

MIT License - For educational use only.
