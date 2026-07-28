# The HIPAA Crypto Checkpoint

## Introduction

### Goal
Map HIPAA encryption requirements to MedDefense's current state and identify every compliance gap

### Context
MedDefense is a covered entity under HIPAA. The HIPAA Security Rule (45 CFR §164.312) has specific requirements for encryption of electronic Protected Health Information (ePHI). These requirements are "addressable," meaning MedDefense must either implement the specified encryption or document why an equivalent alternative is in place. "We did not know" is not an acceptable alternative.

## Answer

# HIPAA Crypto Compliance Table – MedDefense

| HIPAA Requirement | Citation | Current MedDefense State | Compliant? | Gap / Remediation |
|---|---|---|---|---|
| Encryption and decryption of ePHI | §164.312(a)(2)(iv) | HIPAA requires a mechanism to encrypt and decrypt ePHI when appropriate. MedDefense currently stores EHR PostgreSQL data (ehr-db-01), billing MySQL data, PACS images, and NAS backups without encryption at rest. Data Protection Map shows patient records, financial data, medical images, and backups as "Absent" for encryption at rest. | No | Implement encryption at rest for all sensitive ePHI repositories. Use AES-256 encryption for ehr-db-01 PostgreSQL, billing-srv-01 MySQL, PACS storage, and NAS-01 backups. Manage encryption keys through KMS, with HSM protection considered for high-value EHR keys. |
| Transmission Security | §164.312(e)(1) | HIPAA requires technical controls that protect ePHI while transmitted over networks. MedDefense has partial protection: VPN uses IPSec AES-256/SHA-256, but internal medical communications remain exposed. PostgreSQL allows plaintext connections, MySQL does not enforce SSL, and DICOM traffic is unencrypted. | No | Require encryption for all ePHI transmissions. Enable TLS 1.2/1.3 for PostgreSQL and MySQL connections, deploy DICOM TLS for PACS imaging transfers, and remove all plaintext communication paths. |
| Encryption of ePHI in transit | §164.312(e)(2)(ii) | Encryption in transit is an addressable requirement where appropriate. MedDefense protects some traffic through VPN encryption and Microsoft 365 TLS, but patient imaging and database communications lack encryption. Finding 024 identified unencrypted DICOM traffic, and Finding 003 identified insecure PostgreSQL access. | No | Apply AES-256-GCM or ChaCha20-Poly1305 encryption through TLS 1.2/1.3. Configure PACS to use DICOM TLS, enforce encrypted database connections, and monitor for plaintext healthcare traffic. |
| Person or Entity Authentication | §164.312(d) | HIPAA requires verification that users accessing ePHI are who they claim to be. MedDefense has passwords, account lockout, and limited MFA, but MFA is not deployed across VPN, EHR, and privileged accounts. Finding GAP-017 identified missing MFA at scale. | No | Deploy MFA for all privileged users, VPN users, and clinical access to sensitive systems. Implement stronger identity management, remove inactive accounts, and enforce unique user accounts (especially PACS, where shared credentials exist). |

# Additional HIPAA Encryption Observations

| Area | Current Status | HIPAA Impact |
|---|---|---|
| EHR Database (PostgreSQL) | No encryption at rest; internal exposure exists (Finding 003) | High risk because patient PHI can be accessed if the database files are stolen or compromised |
| PACS Medical Images | DICOM traffic unencrypted (Finding 024) | High risk because medical images contain PHI and can be intercepted internally |
| Backup Storage (NAS-01) | Backups stored without encryption (Finding 015) | High risk because stolen backups provide direct access to historical patient records |
| Billing Database | MySQL data stored without encryption | Financial and patient-related information exposure risk |
| VPN | Strong IPSec encryption currently deployed | Partially compliant, but endpoint and authentication weaknesses remain |
| Microsoft 365 | Microsoft-managed encryption and TLS available | Mostly adequate, but sensitive PHI requires additional controls such as S/MIME or client-side encryption |

# HIPAA Audit Readiness Assessment

MedDefense would likely not pass a HIPAA Security Rule audit today because several addressable encryption safeguards are not implemented for systems containing ePHI. The most critical deficiency an auditor would identify is the lack of encryption protection for stored and transmitted patient information, especially the unencrypted EHR database, PACS medical images, and NAS backups. While HIPAA does not require encryption in every situation, MedDefense would need to demonstrate a documented risk assessment explaining why encryption was not necessary; given the existing risks (RISK-001 EHR breach, RISK-007 backup compromise, and RISK-005 medical device exposure), the absence of encryption would be difficult to justify. The priority remediation should be AES-256 encryption at rest, TLS encryption for healthcare communications, and centralized key management.