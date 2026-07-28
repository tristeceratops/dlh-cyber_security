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

| Data Store | Recommended Level | Justification |
|------------|-------------------|---------------|
| Patient records (ehr-db-01) | Database + Record | Encrypt the database and sensitive PHI fields for HIPAA compliance. |
| Backup data (NAS-01) | Full-disk | Protects all backup data if the NAS is stolen or compromised. |
| Financial records (billing-srv-01) | Database | Secures MySQL financial data while maintaining application performance. |
| Medical images (pacs-srv-01) | Volume | Efficiently protects large imaging repositories across storage volumes. |
| Email data (O365) | File | Microsoft 365 encrypts individual mailbox content and attachments. |
| Employee laptops | Full-disk | Prevents data exposure from lost or stolen laptops. |
| BD Alaris pump firmware/configuration | File | Protects firmware and configuration files from unauthorized modification. |