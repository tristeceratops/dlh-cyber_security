# The Algorithm Landscape

## Introduction

### Goal
Build the definitive reference table of cryptographic algorithms, mapped against MedDefense's current and recommended usage, identifying every deprecated algorithm still in production.

### Context
The Security+ exam expects you to know which algorithms are current, which are deprecated and which are broken. More importantly, it expects you to know WHY certain algorithms are inappropriate for certain uses. This task builds the reference you will carry into the exam and into your career.

Every algorithm in the table connects to something you have already seen in MedDefense.

## Answer

### Symmetric Algorithms

| Algorithm | Type | Key Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|-----------|------|----------|------------------|--------|-----------------------|------------------|
| AES-128 | Symmetric | 128-bit | Encrypting files, databases, and network traffic | Current | N/A | TLS sessions, EHR database encryption, backups |
| AES-192 | Symmetric | 192-bit | Data encryption requiring a larger security margin | Current | N/A | Optional for highly sensitive internal data |
| AES-256 | Symmetric | 256-bit | High-security data encryption | Current | N/A | Patient records, encrypted backups, VPNs |
| DES | Symmetric | 56-bit | Legacy encryption | Broken | Key size is too small and can be brute-forced. | Do not use |
| 3DES | Symmetric | 168-bit (112-bit effective) | Legacy replacement for DES | Deprecated | Slow and vulnerable to modern attacks such as Sweet32. | Replace on legacy systems |
| ChaCha20-Poly1305 | Symmetric | 256-bit | Fast authenticated encryption | Current | N/A | Mobile devices, VPNs, TLS |
| RC4 | Symmetric | 40-2048 bits (typically 128-bit) | Legacy stream cipher | Broken | Serious biases allow attackers to recover encrypted data. | Do not use |
| Blowfish | Symmetric | 32-448 bits | Legacy file encryption | Deprecated | Small block size makes it unsuitable for modern applications. | Replace with AES |

---

### Asymmetric Algorithms

| Algorithm | Type | Key Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|-----------|------|----------|------------------|--------|-----------------------|------------------|
| RSA-2048 | Asymmetric | 2048-bit | Digital signatures, certificates, key exchange | Current | N/A | TLS certificates, document signing |
| RSA-4096 | Asymmetric | 4096-bit | Higher-security certificates and signatures | Current | N/A | High-value servers and certificate authorities |
| ECC P-256 | Asymmetric | 256-bit | Key exchange and digital signatures | Current | N/A | TLS, VPNs, medical devices |
| ECC P-384 | Asymmetric | 384-bit | Higher-security ECC operations | Current | N/A | Critical healthcare infrastructure |
| Diffie-Hellman | Asymmetric | 2048+ bits | Secure key exchange | Current (when authenticated) | Vulnerable to man-in-the-middle attacks if not authenticated. | VPN key exchange with certificates |
| ECDHE | Asymmetric | 256/384-bit | Ephemeral key exchange with forward secrecy | Current | N/A | HTTPS and VPN connections |

---

### Hash Algorithms

| Algorithm | Type | Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|-----------|------|-------------|------------------|--------|-----------------------|------------------|
| MD5 | Hash | 128-bit | Legacy checksums | Broken | Practical collision attacks exist. | Do not use |
| SHA-1 | Hash | 160-bit | Legacy integrity verification | Deprecated | Collision attacks have been demonstrated. | Replace with SHA-256 |
| SHA-256 | Hash | 256-bit | File integrity and digital signatures | Current | N/A | Software verification, digital signatures |
| SHA-512 | Hash | 512-bit | High-security integrity checking | Current | N/A | Long-term integrity verification |
| SHA-3 | Hash | 224/256/384/512-bit | Modern hashing | Current | N/A | Future applications requiring SHA-3 support |

---

### Key Derivation Functions (KDF)

| Algorithm | Type | Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|-----------|------|-------------|------------------|--------|-----------------------|------------------|
| PBKDF2 | KDF | Variable | Password hashing | Current | N/A | Legacy application password storage |
| bcrypt | KDF | 192-bit hash | Password hashing | Current | N/A | Existing web applications |
| Argon2id | KDF | Variable | Password hashing | Current (Recommended) | N/A | New MedDefense applications and patient portal |
| scrypt | KDF | Variable | Password hashing | Current | N/A | Systems requiring memory-hard password protection |

---

### MedDefense Crypto Gap Analysis

| Current MedDefense Practice | Issue | Recommended Replacement |
|-----------------------------|-------|-------------------------|
| Kerberos supports DES (Finding 018) | DES is broken and can be brute-forced. | Disable DES and allow only AES-based Kerberos encryption. |
| Kerberos supports RC4 (Finding 018) | RC4 is insecure and enables more effective offline password attacks. | Use AES-128 or AES-256 Kerberos encryption types only. |
| Patient Portal supports TLS 1.0 (Gap-023 / Finding 005) | TLS 1.0 is deprecated and vulnerable to downgrade attacks. | Disable TLS 1.0 and require TLS 1.2 or TLS 1.3 with modern cipher suites. |
| DICOM traffic is not encrypted (Finding 024) | Medical data is transmitted in plaintext across the network. | Protect DICOM traffic using TLS with AES-GCM or ChaCha20-Poly1305. |
| MD5 and SHA-1 may still exist on legacy systems | Both are vulnerable to collision attacks and no longer provide adequate security. | Replace with SHA-256 or SHA-3. |
| Legacy VPN or certificates using RSA with weak settings | Older configurations may not provide forward secrecy. | Use ECDHE with AES-256-GCM or ChaCha20-Poly1305 and modern ECC certificates. |