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

| MedDefense Data Store | Recommended Encryption Level | Justification |
|-----------------------|------------------------------|---------------|
| **PostgreSQL (ehr-db-01) – Patient Records** | **Record** | Patient records contain the most sensitive PHI (diagnoses, treatments, SSNs, insurance data). Record-level encryption ensures that even if the database or an administrator account is compromised, only authorized applications can decrypt individual patient records, providing the highest level of confidentiality for HIPAA-regulated data. |
| **NAS-01 – Backup Data** | **Full-disk** | The backup NAS stores complete copies of multiple critical systems, including the EHR, billing, and Active Directory. Full-disk encryption protects the entire repository from offline theft or unauthorized physical access without adding complexity to backup and recovery operations. |
| **MySQL (billing-srv-01) – Financial Records** | **Database** | Billing data is accessed only through the billing application, making database encryption the most appropriate choice. It protects all financial records at rest while maintaining good performance, centralized key management, and transparent operation for users. |
| **PACS (pacs-srv-01) – Medical Images** | **Volume** | PACS stores very large radiology images that require fast read/write performance. Volume encryption secures the complete imaging repository while minimizing performance overhead compared to encrypting every image individually, making it well suited for high-volume clinical workloads. |
| **Microsoft 365 (Email Data)** | **File** | Emails and attachments are stored as individual objects that may contain PHI, financial information, or confidential communications. File-level encryption protects each message independently, allowing secure sharing while limiting exposure if a single mailbox or exported file is compromised. |
| **Employee Laptops** | **Full-disk** | Laptops are frequently used outside the hospital and are at the highest risk of loss or theft. Full-disk encryption ensures that all locally stored patient data, cached credentials, and business documents remain unreadable if the device falls into unauthorized hands. |
| **BD Alaris Pump Firmware / Configuration** | **Partition** | The pump's firmware and configuration are stored in dedicated system partitions that should remain isolated from user-accessible data. Encrypting the firmware partition helps prevent unauthorized modification of device software and configuration while preserving reliable device operation and update processes. |