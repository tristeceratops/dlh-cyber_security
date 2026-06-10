# Burp Suite Cheat Sheet & Web Application Testing Guide

---

# What is Burp Suite?

**Burp Suite** is a web application security testing platform used to:

- Intercept HTTP/HTTPS traffic
- Analyze requests and responses
- Test web applications
- Discover vulnerabilities
- Automate security assessments

It is one of the most widely used tools by:

- Penetration Testers
- Security Engineers
- Bug Bounty Hunters
- Web Application Auditors

---

# How Burp Suite Works

Burp acts as a **proxy** between your browser and the target website.

```text
Browser
    │
    ▼
+-----------+
| Burp Suite|
+-----------+
    │
    ▼
Web Server
```

Every request can be:

```text
Captured
Modified
Forwarded
Dropped
Repeated
```

---

# Main Burp Suite Components

```text
Burp Suite
│
├── Proxy
├── Target
├── Repeater
├── Intruder
├── Scanner
├── Comparer
├── Decoder
├── Logger
└── Extensions
```

Each component serves a different purpose during testing.

---

# Proxy

The Proxy is the heart of Burp Suite.

Purpose:

```text
Intercept Browser Traffic
```

Flow:

```text
Browser
    ↓
Burp Proxy
    ↓
Target Website
```

Capabilities:

- View requests
- Modify requests
- Modify responses
- Save traffic
- Analyze sessions

---

# Setting Up a Proxy in Burp Suite

## Step 1

Start Burp Suite.

---

## Step 2

Verify listener:

```text
Proxy
  ↓
Options
  ↓
127.0.0.1:8080
```

Default listener:

```text
127.0.0.1:8080
```

---

## Step 3

Configure browser proxy.

Example:

```text
HTTP Proxy:
127.0.0.1

Port:
8080
```

---

## Step 4

Enable interception.

```text
Proxy
 ↓
Intercept
 ↓
Intercept is ON
```

---

## Traffic Flow

```text
Browser
   ↓
127.0.0.1:8080
   ↓
Burp Proxy
   ↓
Internet
```

---

# Target

The Target tab helps map applications.

Features:

```text
Site Map
Scope
Discovered URLs
Directories
Parameters
```

Example:

```text
example.com
│
├── /
├── /login
├── /admin
├── /profile
└── /api
```

Useful for:

```text
Application Reconnaissance
```

---

# Spider (Crawler)

## What is Spider?

Spider automatically discovers content within a web application.

Purpose:

```text
Find Hidden Pages
```

---

## How Spider Works

```text
Page
 ↓
Extract Links
 ↓
Visit Links
 ↓
Extract More Links
 ↓
Repeat
```

Visual:

```text
Home
├── Login
├── About
│   └── Team
└── Products
    ├── Item1
    └── Item2
```

---

## Spider Discovers

```text
Pages
Directories
Parameters
Forms
Resources
```

---

## Why Use Spider?

Helps identify:

```text
Hidden Functionality
Forgotten Pages
Attack Surface
```

---

# Repeater

## Purpose

Repeater allows manual testing of requests.

Think:

```text
Capture Once
Send Many Times
```

---

## Workflow

```text
Request
   ↓
Send to Repeater
   ↓
Modify Request
   ↓
Send Again
```

---

## Example

Original:

```http
GET /profile?id=1
```

Modified:

```http
GET /profile?id=2
```

---

## Useful For

```text
Parameter Testing
Authentication Testing
Input Validation
SQL Injection Testing
XSS Testing
```

---

# Intruder

## What is Intruder?

Intruder automates sending many modified requests.

Purpose:

```text
Automated Input Testing
```

---

# How Intruder Works

```text
Request Template
      ↓
Payloads
      ↓
Generate Requests
      ↓
Analyze Responses
```

---

# Common Uses

## Parameter Fuzzing

Example:

```text
id=1
id=2
id=3
...
```

---

## Content Discovery

Example:

```text
/admin
/dashboard
/backup
/config
```

---

## Password Auditing

Example:

```text
password1
password2
password3
```

Only test systems you are authorized to assess.

---

## Input Validation Testing

Example:

```text
'
"
<
>
../
```

Observe application behavior.

---

# Intruder Attack Types

## Sniper

One parameter changes.

```text
username=VALUE
```

---

## Battering Ram

Same payload everywhere.

```text
admin
admin
admin
```

---

## Pitchfork

Multiple payload lists move together.

```text
user1 -> pass1
user2 -> pass2
```

---

## Cluster Bomb

All combinations.

```text
user1 + pass1
user1 + pass2
user2 + pass1
user2 + pass2
```

---

# Scanner

## What is Burp Scanner?

Automated vulnerability scanner.

Available in Burp Professional.

---

## Purpose

Identify potential:

```text
XSS
SQL Injection
CSRF
Misconfigurations
Information Disclosure
```

---

## When Should You Use It?

After:

```text
Mapping Application
```

Before:

```text
Manual Validation
```

---

## Scanner Workflow

```text
Discover Content
        ↓
Analyze Requests
        ↓
Send Test Payloads
        ↓
Report Findings
```

---

# Interpreting Scanner Results

Scanner findings usually include:

```text
Issue Name
Severity
Confidence
Evidence
Remediation
```

---

# Severity Levels

```text
High
Medium
Low
Information
```

---

# Confidence Levels

```text
Certain
Firm
Tentative
```

---

# Example Finding

```text
Issue:
Reflected XSS

Severity:
High

Confidence:
Firm
```

Meaning:

```text
Likely Vulnerability
Requires Validation
```

---

# How to Interpret Burp Results

Always ask:

```text
Is it exploitable?
```

---

## High Severity + Certain

Usually investigate immediately.

---

## Informational

May indicate:

```text
Interesting Behavior
Missing Headers
Technology Disclosure
```

Not always exploitable.

---

## Verify Findings

Never trust automation blindly.

```text
Scanner
   ↓
Human Verification
   ↓
Conclusion
```

---

# Common Issues Burp Can Identify

## Cross-Site Scripting (XSS)

Example:

```html
<script>alert(1)</script>
```

---

## SQL Injection

Example:

```sql
' OR 1=1 --
```

---

## Cross-Site Request Forgery (CSRF)

Missing protections.

---

## Information Disclosure

Examples:

```text
Version Numbers
Stack Traces
Error Messages
```

---

## Missing Security Headers

Examples:

```text
CSP
HSTS
X-Frame-Options
```

---

## Authentication Weaknesses

Examples:

```text
Weak Session Management
Missing MFA
Predictable Tokens
```

---

## Access Control Problems

Examples:

```text
Privilege Escalation
IDOR
Unauthorized Access
```

---

## Insecure Cookies

Examples:

```text
Missing Secure Flag
Missing HttpOnly Flag
```

---

# HTTPS Traffic in Burp Suite

## Why HTTPS Requires Extra Configuration

HTTPS uses TLS encryption.

Without configuration:

```text
Browser
      ↓
Certificate Error
```

Because Burp performs:

```text
TLS Interception
```

---

# HTTPS Interception Process

```text
Browser
    ↓
TLS
    ↓
Burp
    ↓
TLS
    ↓
Server
```

Burp decrypts traffic for analysis.

---

# Configure HTTPS in Burp

## Step 1

Start Burp Proxy.

---

## Step 2

Open browser through Burp.

---

## Step 3

Visit:

```text
http://burp
```

or

```text
http://burpsuite
```

(depending on Burp version)

---

## Step 4

Download Burp CA Certificate.

---

## Step 5

Import certificate into browser trust store.

Result:

```text
Browser Trusts Burp
```

---

# HTTPS Flow After Setup

```text
Browser
   │
   ▼
Burp Certificate
   │
   ▼
Burp Proxy
   │
   ▼
Target Website
```

Now Burp can display:

```text
Requests
Responses
Headers
Cookies
Parameters
```

even for HTTPS sites.

---

# Common HTTPS Troubleshooting

## Certificate Errors

Cause:

```text
Burp CA Not Installed
```

---

## No Traffic Visible

Cause:

```text
Browser Proxy Misconfigured
```

Verify:

```text
127.0.0.1:8080
```

---

## HSTS Issues

Some applications enforce strict HTTPS rules.

May require:

```text
Browser Profile Reset
Dedicated Testing Browser
```

---

# Typical Burp Testing Workflow

```text
1. Configure Proxy
          ↓
2. Install Burp CA
          ↓
3. Browse Application
          ↓
4. Map Target
          ↓
5. Run Spider/Crawler
          ↓
6. Analyze Requests
          ↓
7. Use Repeater
          ↓
8. Use Intruder
          ↓
9. Run Scanner
          ↓
10. Validate Findings
          ↓
11. Report Results
```

---

# Burp Suite Component Summary

| Component | Purpose |
|------------|----------|
| Proxy | Intercept Traffic |
| Target | Map Application |
| Spider/Crawler | Discover Content |
| Repeater | Manual Request Testing |
| Intruder | Automated Request Manipulation |
| Scanner | Vulnerability Detection |
| Comparer | Compare Data |
| Decoder | Encode/Decode Data |
| Logger | Review Traffic |
| Extensions | Add Functionality |

---

# Core Concept

```text
Browser
   ↓
Proxy
   ↓
Observe
   ↓
Modify
   ↓
Replay
   ↓
Automate
   ↓
Analyze
   ↓
Validate
```

Burp Suite is most effective when automated discovery and scanning are combined with careful manual testing and validation.