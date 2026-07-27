# The TLS Audit

## Introduction

### Goal
Evaluate real-world TLS configurations using SSL Labs, produce a remediation plan for MedDefense's patient portal, and write a hardened TLS configuration.

### Context
Finding 005 from your vulnerability assessment (1x02) identified that the patient portal still supports TLS 1.0 alongside TLS 1.2. That finding has been sitting on the remediation list for 3 weeks. Now you have the knowledge to fix it. But before you write the configuration, you need to understand what a good TLS configuration looks like and what a bad one looks like, using real data from real websites.

## Answer

### Part 1

| Category | Website 1 (A / A+) | Website 2 (B or Below) |
|----------|---------------------|-------------------------|
| Website URL | nasa.org | dh512.badssl.com |
| Overall Grade | A | F |
| TLS Protocol Support | 1.2; 1.3 | 1.0; 1.1; 1.2|
| Key Exchange Strength | 90 | 0 |
| Cipher Suite Strength | 90 | 60 |
| Certificate Issuer | E8 | R13 |
| Certificate Subject / Common Name | nasa.org | *.badssl.com |
| Certificate Validity (From → To) | Wed, 27 May 2026 20:54:06 UTC -> Tue, 25 Aug 2026 20:54:05 UTC (expires in 29 days, 7 hours)| Tue, 26 May 2026 20:02:50 UTC -> Mon, 24 Aug 2026 20:02:49 UTC (expires in 28 days, 6 hours)|
| Signature Algorithm | SHA384withECDSA | SHA256withRSA |
| Key Size | 384 bits| 256 |
| Warnings / Weaknesses Flagged | / | insecure Diffie-Hellman (DH) key exchange parameters; supports TLS 1.0 and TLS 1.1; does not support TLS 1.3; does not support PQC (Post-Quantum Cryptography) key exchange |

### Part 2

| Finding                                                   | SSL Labs impact                                                                                                                                                 | Grade effect                                      |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **TLS 1.0 supported**                                     | TLS 1.0 is deprecated. Since version **2009q**, *any server supporting TLS 1.0 or TLS 1.1 is capped at **B***.                                                  | **Maximum grade: B**                              |
| **Expiring TLS certificate / missing renewal automation** | SSL Labs does **not** grade certificate expiration risk unless the certificate is actually expired (or otherwise invalid). Missing automation is not evaluated. | **No reduction** (unless the certificate expires) |

It is important to note that when the expiring certificate will be expired, the overall score would be set to 0.

Source: (https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)[https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide]

### Part 3

Nginx config:

```
server {
    listen 443 ssl;
    server_name patient.meddefense.example;

    # Certificate
    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/private.key;

    # Supported TLS versions
    ssl_protocols TLSv1.2 TLSv1.3;
    # Reason: Only TLS 1.2 and TLS 1.3 are enabled because older versions are deprecated and vulnerable to known attacks.

    # Cipher suites (TLS 1.2)
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:
                 ECDHE-RSA-AES256-GCM-SHA384:
                 ECDHE-ECDSA-CHACHA20-POLY1305:
                 ECDHE-RSA-CHACHA20-POLY1305:
                 ECDHE-ECDSA-AES128-GCM-SHA256:
                 ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    # Cipher reasoning:
    # 1. AES-256-GCM: Preferred for strong 256-bit authenticated encryption and Perfect Forward Secrecy.
    # 2. ChaCha20-Poly1305: Preferred on devices without AES hardware acceleration while providing equivalent security.
    # 3. AES-128-GCM: Included for compatibility while still offering strong authenticated encryption.

    # HTTP Strict Transport Security (HSTS)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    # Reason: Forces browsers to use HTTPS for one year, protecting against SSL stripping and downgrade attacks.

    # Additional TLS hardening
    ssl_session_tickets off;
    # Reason: Disabling session tickets reduces the risk of compromised ticket keys affecting multiple sessions.

    # Reason: TLS compression remains disabled by default to prevent CRIME attacks.

    # Reason: Insecure TLS renegotiation is disabled by default in modern Nginx/OpenSSL versions, preventing renegotiation attacks.
}
```

### Part 4

A TLS downgrade attack occurs when an attacker intercepts the connection between a client and a server and manipulates the TLS handshake so that both sides agree to use an older, weaker protocol version instead of the strongest one they support. If the MedDefense portal supports both TLS 1.0 and TLS 1.2, the attacker can interfere with the initial handshake, causing the client to retry the connection using TLS 1.0, which is more vulnerable to known attacks. Once the weaker protocol is in use, the attacker may be able to exploit its security weaknesses to decrypt or tamper with the communication. The simplest way to prevent this attack is to disable support for TLS 1.0 and TLS 1.1, allowing only TLS 1.2 and TLS 1.3.
