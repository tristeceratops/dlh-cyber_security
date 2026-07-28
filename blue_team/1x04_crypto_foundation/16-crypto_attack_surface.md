# The Cryptographic Attack Surface

## Introduction

### Goal
Map the cryptographic attacks to MedDefense's specific weaknesses, showing which attacks are viable today and which controls would neutralize them.

### Context
Downgrade attacks, collision attacks, birthday attacks and more. These are not abstract concepts. Every one of them maps to a real weakness at MedDefense.

## Answer

# MedDefense Cryptographic Attack Analysis

| Attack | Mechanism | MedDefense Vulnerability | Evidence | Viable Today | Mitigation |
|---|---|---|---|---|---|
| TLS Downgrade (forcing TLS 1.0 on patient portal) | An attacker forces a client and server to negotiate an older TLS version instead of a secure protocol. TLS 1.0 contains weaknesses that allow downgrade attacks and weaker encryption negotiation. | Patient portal/web server still supports TLS 1.0, allowing attackers to target outdated cryptographic protocols. | Finding 005: TLS 1.0 support enables deprecated cryptographic protocols. Gap-023: Patient portal allows legacy TLS configuration. | **Yes.** An attacker with network visibility could attempt downgrade attacks against users connecting to the portal. | Disable TLS 1.0/1.1 completely. Require TLS 1.2 or TLS 1.3 using AES-256-GCM or ChaCha20-Poly1305 cipher suites. Automate certificate renewal (Finding 013). |
| Collision Attack (MD5 in Kerberos tickets) | A collision attack creates two different inputs that produce the same hash value. Because MD5 is mathematically broken, attackers can generate matching hashes and bypass integrity assumptions. | Legacy authentication systems may still rely on weak hashing algorithms. MedDefense has outdated cryptographic configurations that allow insecure algorithms. | Crypto audit: MD5 is deprecated. Finding 018 identified weak Kerberos encryption types (DES/RC4), although MD5 specifically is not recommended for security use. | **No/Low.** MD5 collision attacks are generally not the direct attack path against current Kerberos, but any remaining MD5 use creates unnecessary cryptographic weakness. | Remove MD5 from all systems. Use SHA-256/SHA-3 for integrity checks and modern AES-based Kerberos encryption. |
| Birthday Attack (hash collision probability) | A birthday attack exploits the mathematics behind hash collisions. The probability of finding two matching hashes increases much faster than expected because attackers compare many possible combinations (approximately 2^(n/2) attempts for an n-bit hash). | MedDefense legacy systems using weak hashes could become vulnerable to forged integrity checks or certificates. | Crypto analysis: MD5 and SHA-1 are deprecated due to practical collision attacks. Legacy systems should not depend on them. | **Mostly No.** Current MedDefense systems using SHA-256/AES are not realistically vulnerable, but legacy applications could be exposed. | Replace MD5/SHA-1 with SHA-256 or SHA-3. Require modern certificate signatures and integrity validation methods. |
| Kerberoasting (RC4/DES Kerberos cracking) | Attackers request Kerberos service tickets and extract encrypted ticket material. They then perform offline password cracking against weak Kerberos encryption types such as RC4 or DES. | Active Directory allows legacy Kerberos encryption types. Weak service account passwords could allow attackers to recover credentials offline. | Finding 018: Weak Kerberos encryption types (DES and RC4) enabled. Data Protection Map: Credentials protected by NT hashes and legacy Kerberos options. | **Yes.** Attackers with domain access could request tickets and attempt offline cracking. | Disable DES and RC4 Kerberos encryption. Require AES-128/AES-256 Kerberos. Enforce strong service account passwords and monitor abnormal ticket requests. |
| On-path/MITM on unencrypted channels (DICOM/MySQL/PostgreSQL) | An attacker positioned on the network intercepts plaintext traffic, reads sensitive information, or modifies communications before they reach the destination. | PACS DICOM traffic is unencrypted. MySQL connections are plaintext. PostgreSQL allows non-SSL connections through hostnossl rules. | Finding 024: DICOM traffic without TLS encryption. Finding 003: PostgreSQL insecure access configuration. Crypto audit: MySQL SSL not enforced. | **Yes.** A compromised internal device on MedDefense's flat network could capture patient or financial data. | Encrypt all sensitive communications using TLS 1.2/1.3. Enable DICOM TLS with AES-GCM. Require PostgreSQL/MySQL SSL connections and remove plaintext communication paths. |
| Key Recovery from Memory (AES keys in RAM) | If an attacker gains administrator/root privileges, they may dump system memory and search for encryption keys temporarily stored by running applications. Disk encryption does not protect data while it is actively decrypted in memory. | If billing-srv-01 is compromised, attackers with root access may inspect MySQL processes and recover encryption keys from memory. | Risk 4: Billing Server Ransomware. Finding 001: Billing server compromise path. Data Protection Map: Billing data has no in-use encryption protection. | **Yes.** Root compromise provides sufficient privileges to inspect memory and running processes. | Reduce privileged access, deploy EDR, enable database key isolation through KMS/HSM, rotate keys regularly, patch billing systems, and limit administrator access. For high-value keys, use HSM-backed storage so keys are not directly exposed in application memory. |

# Top Cryptographic Priorities for MedDefense

1. **Encrypt patient and financial communications**
   - Addresses Finding 024 (DICOM plaintext traffic) and MySQL/PostgreSQL plaintext connections.
   - Prevents internal attackers from intercepting PHI and financial information.

2. **Remove weak authentication cryptography**
   - Addresses Finding 018 (Kerberos DES/RC4).
   - Prevents Kerberoasting and credential compromise.

3. **Strengthen encryption key protection**
   - Addresses EHR, billing, and backup encryption requirements.
   - Prevents attackers with administrator access from easily recovering encryption keys.

# Overall Assessment

MedDefense's strongest cryptographic risk is not broken modern encryption algorithms but incorrect deployment: plaintext databases, unencrypted medical traffic, and legacy authentication settings create avoidable exposure. Modern algorithms such as AES-256, SHA-256, and TLS 1.3 should be combined with proper key management to reduce the impact of system compromise.