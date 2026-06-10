# OWASP Top 10 & Web Application Security Cheat Sheet

---

# What is the OWASP Top 10?

The **OWASP Top 10** is a list of the most critical web application security risks published by the:

```text
OWASP
(Open Worldwide Application Security Project)
```

Purpose:

```text
Educate Developers
↓
Identify Risks
↓
Improve Security
```

It is widely used by:

- Security Engineers
- Penetration Testers
- Developers
- Security Auditors

---

# OWASP Top 10 (2021)

| Rank | Category |
|--------|--------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery (SSRF) |

---

# OWASP 2021 vs Future OWASP Releases

OWASP updates periodically as threats evolve.

Common trends since 2021:

```text
Traditional Web Vulnerabilities
            ↓
Cloud Risks
            ↓
API Risks
            ↓
Supply Chain Risks
            ↓
AI/Automation Risks
```

Modern security assessments increasingly focus on:

- APIs
- Cloud infrastructure
- Authentication systems
- Third-party dependencies
- Supply chain security

---

# What is Injection?

Injection occurs when untrusted user input is interpreted as code or commands.

```text
User Input
      ↓
Application
      ↓
Database / Interpreter
```

Examples:

- SQL Injection
- Command Injection
- LDAP Injection
- NoSQL Injection

---

# Why is Injection Dangerous?

Because attackers may execute unintended commands.

Example:

```sql
SELECT * FROM users
WHERE username='admin'
```

Attacker input:

```sql
' OR 1=1 --
```

Result:

```sql
SELECT * FROM users
WHERE username='' OR 1=1 --
```

Potential impact:

```text
Read Data
Modify Data
Delete Data
Authentication Bypass
Remote Code Execution
```

---

# Preventing Injection

Use:

```text
Parameterized Queries
Prepared Statements
Input Validation
Least Privilege
```

Example:

```python
cursor.execute(
    "SELECT * FROM users WHERE id=?",
    (user_id,)
)
```

---

# What is XSS?

**Cross-Site Scripting (XSS)** occurs when attacker-controlled JavaScript executes in another user's browser.

Flow:

```text
Attacker
    ↓
Malicious Script
    ↓
Website
    ↓
Victim Browser
```

Example:

```html
<script>alert("XSS")</script>
```

---

# How Does XSS Affect Applications?

Potential impact:

```text
Session Theft
Cookie Theft
Account Takeover
Defacement
Phishing
Malware Delivery
```

---

# Types of XSS

## Stored XSS

Saved permanently:

```text
Database
 ↓
Every Visitor Executes Script
```

---

## Reflected XSS

Returned immediately:

```text
Request
 ↓
Response
 ↓
Victim Executes Script
```

---

## DOM-Based XSS

Occurs in client-side JavaScript.

```text
Browser
 ↓
Unsafe DOM Manipulation
 ↓
Script Execution
```

---

# Preventing XSS

Use:

```text
Output Encoding
Input Validation
Content Security Policy (CSP)
Safe Framework APIs
```

---

# What is Broken Authentication?

Authentication mechanisms fail to properly verify identity.

Examples:

```text
Weak Passwords
Credential Stuffing
Session Hijacking
Poor MFA Implementation
```

---

# Risks of Broken Authentication

Attackers may:

```text
Impersonate Users
Steal Accounts
Gain Admin Access
Access Sensitive Data
```

Example:

```text
Password = "admin123"
```

Easy compromise.

---

# Preventing Authentication Failures

Implement:

```text
Strong Password Policies
MFA
Secure Session Management
Rate Limiting
Password Hashing
```

---

# What is Sensitive Data Exposure?

Known in OWASP 2021 as:

```text
Cryptographic Failures
```

Occurs when sensitive information is improperly protected.

Examples:

```text
Passwords
Credit Cards
Medical Records
Tokens
API Keys
```

---

# Example

Bad:

```text
HTTP
```

Good:

```text
HTTPS/TLS
```

Bad:

```text
Plaintext Passwords
```

Good:

```text
Bcrypt
Argon2
PBKDF2
```

---

# Impact

```text
Identity Theft
Fraud
Data Breaches
Regulatory Violations
```

---

# What is Security Misconfiguration?

Improperly configured systems create vulnerabilities.

Examples:

```text
Default Credentials
Debug Mode Enabled
Open Cloud Storage
Unnecessary Services
Verbose Errors
```

---

# Example

Bad:

```text
Admin/Admin
```

Bad:

```text
Directory Listing Enabled
```

Bad:

```text
Stack Traces Exposed
```

---

# Prevention

```text
Secure Defaults
Hardening
Patch Management
Regular Audits
```

---

# What is XML External Entity (XXE)?

XXE occurs when XML parsers process external entities supplied by users.

Example:

```xml
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

Application:

```xml
<name>&xxe;</name>
```

---

# Impact of XXE

Potential consequences:

```text
Read Local Files
Internal Network Scanning
SSRF
Credential Theft
Denial of Service
```

---

# Prevention

```text
Disable External Entities
Use Safer Parsers
Validate Input
```

---

# What is Broken Access Control?

Access control determines:

```text
Who Can Access What
```

Broken access control allows users to perform actions they should not.

---

# Example

Normal User:

```text
/account
```

Admin:

```text
/admin
```

Broken access control:

```text
User changes URL
      ↓
Accesses Admin Panel
```

---

# Impact

```text
Privilege Escalation
Data Theft
Unauthorized Actions
Account Compromise
```

---

# Prevention

Always enforce:

```text
Server-Side Authorization
Role Checks
Least Privilege
```

Never trust:

```text
Client-Side Controls
```

---

# Common Web Application Security Flaws

Most frequent findings:

```text
Broken Access Control
Injection
XSS
Weak Authentication
Security Misconfiguration
SSRF
Sensitive Data Exposure
Outdated Components
```

---

# Visualizing Common Flaws

```text
User Input
     │
     ▼
+------------------+
| Validation Fail? |
+------------------+
      │
      ├── Injection
      ├── XSS
      └── SSRF

Authentication Fail?
      │
      ├── Account Takeover
      └── Privilege Escalation

Authorization Fail?
      │
      └── Broken Access Control
```

---

# What is Insecure Deserialization?

Deserialization converts stored data back into objects.

```text
Serialized Data
      ↓
Application
      ↓
Object Created
```

If attacker-controlled:

```text
Malicious Object
      ↓
Application
      ↓
Unexpected Behavior
```

Potential impact:

```text
Privilege Escalation
Data Tampering
Remote Code Execution
```

---

# Preventing Insecure Deserialization

Use:

```text
Integrity Validation
Digital Signatures
Allowlists
Safe Serialization Formats
```

Avoid:

```text
Trusting User-Supplied Serialized Objects
```

---

# What is Security Logging and Monitoring?

Security logging records events.

Monitoring analyzes those events.

```text
Application Activity
        ↓
Logs
        ↓
Monitoring
        ↓
Alerts
```

---

# Why Is It Important?

Without logs:

```text
Attack Happens
      ↓
Nobody Knows
```

With logs:

```text
Attack Happens
      ↓
Alert Triggered
      ↓
Investigation Begins
```

---

# What Should Be Logged?

Examples:

```text
Authentication Events
Failed Logins
Privilege Changes
API Access
Security Errors
Configuration Changes
```

---

# Risks of Poor Logging

```text
Delayed Detection
Missed Breaches
No Forensics
No Incident Response
```

---

# Vulnerable and Outdated Components

Modern applications depend heavily on third-party software.

Example:

```text
Application
 ├─ Framework
 ├─ Library
 ├─ Package
 └─ Dependency
```

---

# Risks

Outdated components may contain:

```text
Known Vulnerabilities
Remote Code Execution
Privilege Escalation
Authentication Bypass
```

---

# Example

```text
Library Version
      ↓
Known CVE Published
      ↓
Attacker Exploits Vulnerability
```

---

# Prevention

```text
Patch Frequently
Monitor CVEs
Maintain Asset Inventory
Use Dependency Scanners
Remove Unused Components
```

---

# What Are APIs?

APIs allow systems to communicate.

```text
Client
   ↓
API
   ↓
Application
```

Modern applications often expose:

```text
REST APIs
GraphQL APIs
Mobile APIs
Microservices APIs
```

---

# How APIs Increase Security Risks

Every endpoint becomes a potential target.

Example:

```text
Website
 10 Pages

API
 100 Endpoints
```

Larger attack surface.

---

# Common API Risks

```text
Broken Authentication
Broken Authorization
Excessive Data Exposure
Rate Limit Failures
Mass Assignment
SSRF
Injection
```

---

# What is SSRF?

Server-Side Request Forgery.

Occurs when an attacker tricks the server into making requests on their behalf.

---

# SSRF Flow

```text
Attacker
    ↓
Malicious URL
    ↓
Application Server
    ↓
Internal Resource
```

---

# Example

Application fetches URLs:

```text
https://example.com/image.jpg
```

Attacker supplies:

```text
http://internal-server/
```

Server accesses internal systems.

---

# SSRF Impact

```text
Cloud Metadata Access
Internal Reconnaissance
Credential Theft
Lateral Movement
Firewall Bypass
```

---

# Modern SSRF Targets

Examples:

```text
Cloud Metadata Services
Internal APIs
Container Services
Microservices
Management Interfaces
```

---

# Modern APIs and Attack Surface Expansion

Traditional Application:

```text
Browser
   ↓
Web Server
```

Modern Application:

```text
Browser
Mobile App
Partner API
Microservices
Cloud Services
Third Parties
```

Result:

```text
More Components
More Endpoints
More Trust Relationships
More Risk
```

---

# Secure Development Checklist

```text
✓ Validate Input
✓ Use Parameterized Queries
✓ Implement Strong Authentication
✓ Enforce Authorization Checks
✓ Encrypt Sensitive Data
✓ Disable Dangerous Features
✓ Patch Dependencies
✓ Log Security Events
✓ Monitor Systems
✓ Secure APIs
✓ Prevent SSRF
✓ Review Access Controls
```

---

# High-Level Security Assessment Workflow

```text
1. Map Application
          ↓
2. Identify Endpoints
          ↓
3. Review Authentication
          ↓
4. Review Authorization
          ↓
5. Test Input Handling
          ↓
6. Check Data Protection
          ↓
7. Review Dependencies
          ↓
8. Analyze Logging
          ↓
9. Assess APIs
          ↓
10. Document Findings
```

---

# Core Concept

```text
Authentication
     ↓
Who Are You?

Authorization
     ↓
What Can You Do?

Validation
     ↓
What Can You Submit?

Logging
     ↓
What Happened?

Monitoring
     ↓
Who Notices?

Patching
     ↓
Known Vulnerabilities Removed
```

Strong web application security requires all of these layers working together.