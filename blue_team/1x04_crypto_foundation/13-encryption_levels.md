# The Encryption Levels

## Introduction

### Goals
Compare the six encryption levels defined and recommend the appropriate level for every MedDefense data store.

### Context
"Encrypt the database" sounds simple, but there are at least three ways to do it: encrypt the entire disk the database sits on (full-disk), encrypt the database files (file-level), or encrypt individual fields within the database (record-level). Each has radically different properties: scope of protection, performance impact, key management complexity and what happens when someone with legitimate database access queries the data.

Choosing the wrong level either leaves data exposed or creates operational problems that the clinical staff will not tolerate.

## Answer

## Encryption Levels Comparison

| Level | Scope | Performance Impact | Key Management | Use Case |
|-------|-------|--------------------|----------------|----------|
| Full-disk | Entire physical/virtual disk | Low | One key per disk/device (TPM/BitLocker/LUKS) | Protects lost or stolen devices |
| Partition | One logical partition | Low | One key per partition | Protects specific OS or data partitions |
| Volume | Logical volume (may span disks) | Low-Medium | One key per volume | Encrypts storage pools or server volumes |
| File | Individual files | Medium | Per file or user keys | Protects selected sensitive documents |
| Database | Entire database or tablespace | Medium | Database-managed keys/KMS | Protects structured application data |
| Record | Individual fields or records | High | Fine-grained application/KMS keys | Protects highly sensitive data such as PHI or PII |

**Best choice:**
- **Full-disk:** Best for laptops and servers to protect data if the device is stolen.
- **Partition:** Best when only one partition requires encryption without affecting the whole disk.
- **Volume:** Best for shared storage or virtualized environments with multiple disks.
- **File:** Best when only selected files need protection or secure sharing.
- **Database:** Best for enterprise databases containing sensitive business or healthcare data.
- **Record:** Best when only the most sensitive fields (e.g., SSNs or diagnoses) require extra protection.

---

## MedDefense Encryption Level Map

## MedDefense Encryption Level Map

| MedDefense Data Store | Encryption Level | Justification |
|-----------------------|------------------|---------------|
| **PostgreSQL (ehr-db-01) – Patient Records** | **Database + Record** | Use database encryption for all data and record/field encryption for highly sensitive PHI (e.g., SSNs, diagnoses) to meet HIPAA requirements. |
| **NAS-01 – Backup Data** | **Full-disk** | Encrypt the entire backup repository so all stored backups remain protected if the NAS is stolen or accessed without authorization. |
| **MySQL (billing-srv-01) – Financial Records** | **Database** | Database encryption protects all billing and financial data while maintaining application performance and centralized key management. |
| **PACS (pacs-srv-01) – Medical Images** | **Volume** | PACS stores very large imaging datasets, so volume encryption secures the entire image repository with lower overhead than file-level encryption. |
| **Microsoft 365 (Email Data)** | **Database** | Exchange Online stores mailbox data in encrypted databases, making database-level encryption the most appropriate protection for email at rest. |
| **Employee Laptops** | **Full-disk** | Full-disk encryption (e.g., BitLocker) protects all local data if a laptop is lost or stolen. |
| **BD Alaris Pump Firmware / Configuration** | **File** | Encrypt and digitally protect firmware/configuration files so only authorized updates and configurations can be installed on the devices. |