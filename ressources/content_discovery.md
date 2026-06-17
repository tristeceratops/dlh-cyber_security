# Content Discovery Cheat Sheet & Web Enumeration Guide

---

# What is Content Discovery?

**Content Discovery** is the process of finding web resources that are not immediately visible through normal browsing.

Examples:

```text
Directories
Files
Admin Panels
APIs
Backups
Development Pages
```

Visible Website:

```text
/
├── About
├── Contact
└── Login
```

Discovered Content:

```text
/admin
/backup.zip
/dev
/test
/api
/old-site
```

---

# Why is Content Discovery Important?

Web applications often contain hidden functionality.

Developers may leave:

```text
Unused Pages
Backup Files
Admin Panels
Old Versions
Debug Interfaces
```

These resources may contain:

```text
Sensitive Data
Credentials
Configuration Files
Source Code
Administrative Functions
```

---

# Example

Normal User Sees:

```text
https://example.com
```

Content Discovery Finds:

```text
https://example.com/admin
https://example.com/backup.zip
https://example.com/dev
```

Potentially expanding the attack surface.

---

# What is the Attack Surface?

The attack surface is every reachable component.

```text
Visible Website
      ↓
Small Surface

Discovered Content
      ↓
Larger Surface
```

More content means:

```text
More Features
More Parameters
More Risk
```

---

# How Directory Bruteforcing Works

Directory bruteforcing attempts many paths against a web server.

Process:

```text
Wordlist
   ↓
Generate Requests
   ↓
Check Responses
   ↓
Identify Valid Content
```

---

# Example

Wordlist:

```text
admin
backup
test
api
config
```

Generated Requests:

```text
/admin
/backup
/test
/api
/config
```

Server Responses:

```text
/admin   → 200
/backup  → 403
/test    → 404
/api     → 200
/config  → 404
```

Discovered:

```text
/admin
/backup
/api
```

---

# Visualizing Directory Bruteforcing

```text
Wordlist
    │
    ▼
+---------+
| Gobuster|
+---------+
    │
    ▼
Requests
    │
    ▼
Web Server
    │
    ▼
Responses
```

---

# HTTP Status Codes During Discovery

Most important:

| Code | Meaning |
|--------|--------|
| 200 | Exists |
| 301 | Redirect |
| 302 | Redirect |
| 401 | Authentication Required |
| 403 | Forbidden |
| 404 | Not Found |

---

# Example

```text
/admin → 403
```

Interesting because:

```text
Resource Exists
But Access Denied
```

Often worth investigating.

---

# What is Gobuster?

Gobuster is a fast content discovery tool written in Go.

Common uses:

```text
Directory Discovery
DNS Enumeration
Virtual Host Discovery
S3 Enumeration
```

---

# Basic Gobuster Directory Scan

```bash
gobuster dir \
-u https://example.com \
-w wordlist.txt
```

Meaning:

```text
dir  → Directory mode
-u   → Target URL
-w   → Wordlist
```

---

# Example Workflow

```text
Target
    ↓
Gobuster
    ↓
Wordlist
    ↓
HTTP Requests
    ↓
Valid Paths Found
```

---

# Useful Gobuster Options

## Extensions

```bash
-x php,txt,bak
```

Tests:

```text
admin.php
admin.txt
admin.bak
```

---

## Threads

```bash
-t 50
```

Increase speed.

---

## Show Specific Codes

```bash
-s 200,301,302,403
```

Display interesting responses.

---

# Content Discovery Using Gobuster

Example:

```bash
gobuster dir \
-u https://target.com \
-w common.txt
```

Potential output:

```text
/admin      (403)
/login      (200)
/backup.zip (200)
/api         (301)
```

---

# What are Hidden Directories?

Directories not linked publicly.

Examples:

```text
/admin
/internal
/private
/dev
/staging
```

Users cannot easily find them through navigation.

---

# What are Hidden Files?

Files not intended for public access.

Examples:

```text
backup.zip
database.sql
config.php.bak
.env
old.tar.gz
```

These can expose:

```text
Credentials
Source Code
API Keys
Database Dumps
```

---

# Why Hidden Files Matter

Example:

```text
/.env
```

May contain:

```text
DB_PASSWORD=
API_KEY=
SECRET_TOKEN=
```

One exposed file can lead to complete compromise.

---

# What are Wordlists?

Wordlists are collections of common names used during discovery.

Example:

```text
admin
login
backup
config
test
api
```

Tools try each entry.

---

# Why Wordlists Matter

The quality of the wordlist often determines success.

Small list:

```text
Fast
Less Coverage
```

Large list:

```text
Slower
More Coverage
```

---

# Common Wordlist Categories

## Common Directories

```text
admin
login
api
uploads
images
```

---

## Backup Files

```text
bak
old
zip
tar
sql
```

---

## Technology Specific

PHP:

```text
index.php
config.php
admin.php
```

ASP.NET:

```text
web.config
admin.aspx
```

---

# Content Discovery Workflow

```text
Wordlist
      ↓
Candidate Paths
      ↓
HTTP Requests
      ↓
Analyze Responses
      ↓
Valid Content
```

---

# What is DirBuster?

DirBuster is a content discovery tool that uses wordlists to find hidden resources.

Purpose:

```text
Discover Directories
Discover Files
```

---

# How DirBuster Works

```text
Wordlist
     ↓
Generate Paths
     ↓
Send Requests
     ↓
Analyze Responses
```

Very similar to:

```text
Gobuster
Feroxbuster
ffuf
Dirsearch
```

---

# DirBuster Features

```text
Recursive Discovery
GUI Interface
Multithreading
File Discovery
Directory Discovery
```

---

# Burp Suite and Content Discovery

Burp can assist content discovery in several ways.

---

# Spider / Crawler

Automatically follows links.

```text
Homepage
     ↓
Find Links
     ↓
Visit Links
     ↓
Find More Links
```

---

# Site Map

Displays discovered resources.

Example:

```text
example.com
├── /
├── /login
├── /admin
├── /api
└── /profile
```

---

# Burp Intruder

Can perform targeted discovery.

Example:

```text
/admin
/dashboard
/dev
/test
```

Useful for:

```text
Custom Discovery
Parameter Discovery
Endpoint Discovery
```

---

# Burp Content Discovery Workflow

```text
Browse Site
      ↓
Spider/Crawl
      ↓
Review Site Map
      ↓
Manual Testing
      ↓
Intruder Discovery
```

---

# OWASP ZAP and Content Discovery

OWASP ZAP provides automated crawling and discovery.

---

# Traditional Spider

Follows links found in HTML.

```text
Page
 ↓
Links
 ↓
More Pages
```

---

# AJAX Spider

Useful for modern applications.

Discovers content generated by:

```text
JavaScript
Single Page Apps
AJAX Requests
```

---

# Why AJAX Spider Matters

Modern websites often build pages dynamically.

Traditional spider:

```text
May Miss Content
```

AJAX Spider:

```text
Executes JavaScript
Discovers Hidden Routes
```

---

# ZAP Discovery Workflow

```text
Target
   ↓
Spider
   ↓
AJAX Spider
   ↓
Site Tree
   ↓
Discovered Endpoints
```

---

# What is Fuzzing?

Fuzzing means providing many inputs and observing behavior.

General idea:

```text
Input
 ↓
Application
 ↓
Response
```

---

# Fuzzing in Web Security

Used to discover:

```text
Directories
Files
Parameters
Headers
Endpoints
```

---

# Example Directory Fuzzing

Payloads:

```text
admin
backup
config
test
```

Requests:

```text
/admin
/backup
/config
/test
```

---

# Example Parameter Fuzzing

URL:

```text
/profile?FUZZ=1
```

Payloads:

```text
id
user
uid
account
```

Generated Requests:

```text
/profile?id=1
/profile?user=1
/profile?uid=1
/profile?account=1
```

---

# Example Header Fuzzing

Header:

```text
X-Forwarded-For
```

Testing:

```text
Internal IPs
Special Values
Unexpected Inputs
```

---

# Why Fuzzing is Effective

Applications often expose functionality that developers forgot.

Examples:

```text
Hidden Endpoints
Hidden Parameters
Debug Features
Legacy APIs
```

---

# Common Content Discovery Findings

## Administrative Interfaces

```text
/admin
/dashboard
/manage
```

---

## Development Resources

```text
/dev
/staging
/test
```

---

## Backup Files

```text
backup.zip
site.tar.gz
db.sql
```

---

## Configuration Files

```text
.env
config.php.bak
web.config.old
```

---

## APIs

```text
/api
/api/v1
/graphql
/swagger
```

---

# Typical Content Discovery Process

```text
1. Browse Application
          ↓
2. Crawl / Spider
          ↓
3. Build Site Map
          ↓
4. Directory Bruteforce
          ↓
5. File Discovery
          ↓
6. Parameter Fuzzing
          ↓
7. API Discovery
          ↓
8. Investigate Findings
```

---

# Tool Comparison

| Tool | Primary Use |
|---------|---------|
| Gobuster | Fast Directory/DNS Discovery |
| DirBuster | GUI Directory Discovery |
| Burp Suite | Manual + Assisted Discovery |
| OWASP ZAP | Automated Crawling |
| ffuf | Flexible Fuzzing |
| Feroxbuster | Recursive Content Discovery |
| Dirsearch | Directory Enumeration |

---

# Core Concept

```text
Visible Website
        ↓
Crawling
        ↓
More Pages Found
        ↓
Bruteforcing
        ↓
Hidden Content Found
        ↓
Fuzzing
        ↓
Hidden Parameters Found
        ↓
Expanded Attack Surface
```

Content discovery is one of the first phases of web application testing because vulnerabilities cannot be tested if the underlying pages, files, directories, APIs, and parameters have not yet been discovered.