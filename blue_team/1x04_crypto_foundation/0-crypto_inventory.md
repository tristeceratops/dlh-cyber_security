# The Crypto Inventory

## Introduction

### Goal
Map every data flow at MedDefense against its current cryptographic protection state, exposing every gap in one document.

### Context
Before you can fix MedDefense's cryptographic posture, you need to see the full picture in one place. The vulnerability findings from 1x02 identified individual crypto weaknesses (TLS 1.0 on the portal, unencrypted backups, cleartext DICOM). The risk register in 1x03 tracked some of these as risks. But nobody has produced a systematic inventory that maps every category of data, in every state, to its current level of protection.

This is the document that makes the invisible visible. When you finish, every cell where it says "None" is a gap that the rest of this project will address.

## Answer

# MedDefense – Data Protection Map

| Data Category | At Rest (stored) | In Transit (network) | In Use (processing/display) |
|----------------|------------------|----------------------|-----------------------------|
| **1. Patient medical records (EHR – PostgreSQL)** | **Protection:** None (unencrypted ext4 filesystem)<br>**Evidence:** Crypto audit – PostgreSQL encryption at rest: NONE; Finding 003 (ehr-db-01 exposure)<br>**Status:** **Absent** | **Protection:** PostgreSQL SSL (optional/partial)<br>**Evidence:** Crypto audit – `ssl=on` but `hostnossl` entries allow plaintext connections; Finding 003<br>**Status:** **Weak** | **Protection:** None<br>**Evidence:** Crypto audit – data decrypted in memory; clinician workstations never auto-lock (Group Policy)<br>**Status:** **Absent** |
| **2. Financial/Billing data (MySQL – billing-srv-01)** | **Protection:** None (unencrypted ext4 filesystem)<br>**Evidence:** Crypto audit; 1x00 crypto-miner forensic observation confirmed database files readable directly from disk<br>**Status:** **Absent** | **Protection:** Plaintext MySQL protocol (SSL not enforced)<br>**Evidence:** Crypto audit; billing application communicates without SSL; Finding 001 related attack path<br>**Status:** **Weak** | **Protection:** None documented<br>**Evidence:** Crypto audit provides no runtime protection or secure processing controls<br>**Status:** **Absent** |
| **3. Medical images (DICOM on PACS)** | **Protection:** None<br>**Evidence:** Crypto audit – PACS stores DICOM files unencrypted with readable patient identifiers<br>**Status:** **Absent** | **Protection:** None (DICOM TLS not configured)<br>**Evidence:** Crypto audit; Related to Finding 024 (referenced in Finding 004) – unencrypted DICOM traffic<br>**Status:** **Absent** | **Protection:** None documented<br>**Evidence:** Images processed and displayed without additional protection mechanisms noted in audit<br>**Status:** **Absent** |
| **4. Credentials (Active Directory / application passwords)** | **Protection:** NT Hash (MD4); Kerberos supports AES-256/AES-128 but RC4 and DES remain enabled<br>**Evidence:** Crypto audit; Finding 018 (legacy crypto enabled)<br>**Status:** **Weak** | **Protection:** Kerberos (AES-256/AES-128 available), LDAP not encrypted/signing not enforced<br>**Evidence:** Crypto audit; Finding 007 (LDAP signing disabled)<br>**Status:** **Weak** | **Protection:** None documented for credential use in memory<br>**Evidence:** Crypto audit contains no runtime credential protection controls<br>**Status:** **Absent** |
| **5. Backup data (NAS-01)** | **Protection:** None (NAS encryption disabled)<br>**Evidence:** Crypto audit; Finding 015 (NAS exposed); backups readable in plaintext<br>**Status:** **Absent** | **Protection:** None documented<br>**Evidence:** Audit notes describe backup storage only; no encrypted backup transfer documented<br>**Status:** **Absent** | **Protection:** None documented<br>**Evidence:** No runtime protection identified in audit notes<br>**Status:** **Absent** |
| **6. Email (Microsoft O365)** | **Protection:** BitLocker + Microsoft mailbox encryption (Microsoft-managed keys)<br>**Evidence:** Crypto audit – Exchange Online encryption at rest<br>**Status:** **Adequate** | **Protection:** TLS 1.2 (Exchange Online)<br>**Evidence:** Crypto audit – Microsoft enforces TLS 1.2; S/MIME/OME not deployed for message-level encryption<br>**Status:** **Adequate** | **Protection:** None for active message viewing or PHI handling<br>**Evidence:** Crypto audit notes sensitive PHI is emailed in plaintext between physicians; no S/MIME/OME deployed<br>**Status:** **Weak** |
| **7. VPN traffic (Site-to-Site IPSec tunnels)** | **Protection:** N/A (traffic not stored)<br>**Evidence:** No storage state identified in crypto audit<br>**Status:** **Absent** | **Protection:** IPSec (AES-256, SHA-256, IKEv2, DH Group 14)<br>**Evidence:** Crypto audit; note regarding unknown firmware on Netgear endpoint<br>**Status:** **Adequate** | **Protection:** IPSec traffic decrypted only at tunnel endpoints; no additional runtime protection documented<br>**Evidence:** Crypto audit; consumer router introduces implementation risk despite strong algorithms<br>**Status:** **Weak** |

---

# Gap Summary

| Status | Count |
|--------|------:|
| **Adequate** | **3** |
| **Weak** | **6** |
| **Absent** | **12** |
| **Total Cells** | **21** |

## Overall Cryptographic Coverage

- **Adequately protected cells:** 3 / 21
- **Cryptographic coverage:** **14.3%**

### Cross-reference to Other Resources

- **1x00 Observation**
  - Billing server forensic review confirmed MySQL database files were readable directly from the filesystem after the crypto-miner incident, validating the lack of encryption at rest.

- **1x02 Vulnerability Findings**
  - **Finding 003:** EHR PostgreSQL database broadly exposed internally, increasing the impact of missing encryption.
  - **Finding 001:** Billing server compromise path amplifies the risk of plaintext financial data.
  - **Finding 004:** References unencrypted DICOM traffic (Finding 024), confirming exposure of medical images.
  - **Finding 007:** LDAP signing disabled, supporting the weak protection assessment for credentials in transit.

- **1x03 Risk Register**
  - **Risk 1 (EHR Data Breach)** and **Risk 4 (Billing Server Ransomware)** directly reflect the business impact of absent encryption for patient and billing databases.
  - **Risk 2 (VPN Compromise)** highlights that although VPN cryptography is strong, endpoint weaknesses remain a significant residual risk.

- **1x03 Security Strategy**
  - The strategy explicitly identifies **Data Protection** as requiring improvement and states that **Project 1x04** will implement encryption standards, key management, certificate management, and secure communications, directly addressing the gaps identified in this protection map.