# Hardware Security and Key Management

## Introduction

### Goal
Evaluate TPM, HSM and secure enclave technologies, and design a key management strategy for MedDefense that solves the "where do you keep the keys ?" problem.

### Context
Every encryption scheme has a fatal weakness: the key. If you encrypt 50,000 patient records with AES-256 and store the key in a plaintext configuration file on the same server, you have not actually protected anything. You have added a speed bump.

Sec+ 1.4 identifies three hardware security technologies designed to solve this problem: TPM (Trusted Platform Module), HSM (Hardware Security Module) and secure enclaves. Each operates at a different scale and cost, and MedDefense needs to choose which is appropriate for its budget and risk profile.

## Answer

# MedDefense Cryptographic Foundation and Key Management Plan

## Part 1 - Technology Comparison

| Technology | What It Is | What It Protects | Typical Cost | Typical Deployment |
|---|---|---|---|---|
| TPM (Trusted Platform Module) | A hardware security chip built into computers that stores cryptographic keys and performs secure operations without exposing private keys to the operating system. | Protects device encryption keys, authentication secrets, and boot integrity. At MedDefense, TPM supports laptop full-disk encryption to protect cached EHR data if a physician or nurse laptop is stolen. | Usually included in enterprise laptops/servers (€0 additional cost). | Deployed on employee laptops and servers with BitLocker or similar disk encryption. |
| HSM (Hardware Security Module) | A dedicated hardware appliance designed to generate, store, and protect high-value cryptographic keys with strict access controls. | Protects critical encryption keys from theft or unauthorized administrators. At MedDefense, an HSM could protect the PostgreSQL EHR encryption key used for patient PHI protection. | Hardware: €5,000-€50,000+; HSM-as-a-Service: approximately €1-2/key/month. | Used for high-value systems such as EHR databases, certificate authorities, and financial systems. |
| Secure Enclave | A hardware-isolated processor area that stores sensitive keys separately from the main operating system. | Protects user authentication keys and application secrets. At MedDefense, it could protect credentials on physician mobile devices accessing clinical applications. | Usually included in modern devices (€0 additional cost). | Commonly deployed in smartphones, tablets, and modern computers. |
| KMS (Software Key Management System) | A centralized software service that creates, stores, rotates, and controls access to encryption keys. | Protects encryption keys for databases, backups, and cloud services. At MedDefense, KMS manages keys for ehr-db-01, NAS-01 backups, and portal TLS certificates. | Open-source: low cost; enterprise KMS: €10,000-€50,000/year. | Deployed as a centralized security service integrated with databases, backups, and cloud platforms. |

---

# Part 2 - MedDefense Key Management Design

## Key Storage and Ownership Plan

| Encryption Target | Key Storage Location | Key Owner / Access Role | Rotation Process | Compromise Response | Lost Key Recovery |
|---|---|---|---|---|---|
| PostgreSQL ehr-db-01 Patient Database Encryption | Enterprise KMS/Vault system; HSM recommended for future upgrade | CISO approves access; Security Engineer manages keys; Database Administrator uses keys only through approved database processes | Rotate master encryption key annually; emergency rotation after suspected exposure | Disable compromised key, revoke database access, generate replacement key, re-encrypt database using new key | Maintain encrypted backup of keys through approved escrow process managed by Security Officer |
| NAS-01 Backup Encryption | KMS-managed volume encryption key stored separately from NAS device | Backup Administrator manages backup operations; Security Team controls key access | Rotate yearly and after administrator changes | Disable old encryption key, restore using backup key copy, generate replacement key | Store recovery key in offline escrow controlled by CISO and IT Director |
| Patient Portal TLS Certificates | Certificate Management System / KMS | Network Administrator manages certificates; Security Officer approves changes | Automatic certificate renewal every 90 days | Revoke certificate through CA, issue replacement certificate, update portal configuration | Maintain certificate inventory and recovery documentation |
| VPN Tunnel Encryption Keys (FortiGate) | FortiGate secure key storage integrated with enterprise KMS | Network Administrator manages VPN; CISO reviews privileged access | Rotate automatically according to VPN policy or after staff departure | Terminate affected VPN sessions, revoke keys, generate new tunnel credentials | Maintain secure backup configuration containing encrypted recovery information |

---

## Key Management Procedures

### Access Control
- Encryption keys are never stored on the same system as encrypted data.
- MedDefense follows least privilege:
  - Database administrators manage databases but cannot directly export encryption keys.
  - Security administrators manage encryption keys but do not modify patient data.
  - CISO approves emergency access.

### Key Rotation
- Standard rotation:
  - Database and backup keys: every 12 months.
  - TLS certificates: every 90 days.
  - VPN keys: according to security policy or after personnel changes.
- Rotation is documented through change management records.

### Key Compromise Procedure
If a key is suspected compromised:
1. Security Team immediately disables the affected key.
2. Access logs are reviewed to identify unauthorized usage.
3. A replacement key is generated.
4. Systems are re-encrypted or migrated to the new key.
5. Incident response procedures are activated if patient data exposure is possible.

### Key Loss Procedure
If a key is lost:
1. Security Team checks approved key escrow storage.
2. Recovery key is restored under dual approval.
3. If recovery fails, encrypted data is considered unavailable.
4. New backup and recovery procedures are reviewed.

---

# Part 3 - HSM Investment Decision

## Relevant Risk

Risk affected:
RISK-001 – EHR Data Breach

Current ALE:
$2,994,750/year

Cause:
- GAP-004: Lack of centralized monitoring
- GAP-006: Weak segmentation
- GAP-016: Vulnerable entry points

A database encryption key compromise could allow attackers who gain database access to decrypt patient records, increasing the impact of an EHR breach.

---

## HSM Cost Estimate

Cloud HSM-as-a-Service:
- Approximately $1-2/key/month
- Estimated 5 critical keys:
  - PostgreSQL encryption key
  - Backup encryption key
  - TLS key
  - VPN key
  - Future PACS key

Estimated annual cost:

5 keys × €2/month × 12 months = €120/year

Even with enterprise service fees and administration costs, expected cost remains significantly below the potential financial impact of an EHR breach.

---

## Decision

MedDefense should adopt HSM protection for the highest-value encryption keys, especially the PostgreSQL EHR encryption key.

The investment is justified because:
- The EHR breach ALE is $2,994,750.
- Patient records are MedDefense's most sensitive asset.
- Encryption without strong key protection creates a single point of failure.
- HSM provides stronger protection against stolen administrator credentials and insider misuse.

However, HSM should not replace higher-priority controls such as MFA, SIEM/MDR, and segmentation because those controls reduce the probability of attackers reaching the encrypted systems in the first place.

Recommended priority:
1. MFA + monitoring deployment
2. Network segmentation
3. KMS implementation
4. HSM protection for critical encryption keys