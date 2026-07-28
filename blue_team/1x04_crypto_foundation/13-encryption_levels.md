# The Encryption Levels

## Introduction

### Goals
Compare the six encryption levels defined and recommend the appropriate level for every MedDefense data store.

### Context
"Encrypt the database" sounds simple, but there are at least three ways to do it: encrypt the entire disk the database sits on (full-disk), encrypt the database files (file-level), or encrypt individual fields within the database (record-level). Each has radically different properties: scope of protection, performance impact, key management complexity and what happens when someone with legitimate database access queries the data.

Choosing the wrong level either leaves data exposed or creates operational problems that the clinical staff will not tolerate.

## Answer

### Encryption Levels Comparison

| Level | Scope | Performance Impact | Key Management | Use Case |
|-------|-------|--------------------|----------------|----------|
| Full-disk | Entire physical or virtual disk | Low impact because encryption is applied at the storage layer and is usually hardware-assisted | Usually one main key per device managed through TPM, BitLocker, LUKS, or enterprise key management | Protects complete devices such as laptops and servers against data exposure if the hardware is lost, stolen, or removed from service |
| Partition | One logical partition on a disk | Low impact because only the selected partition is encrypted instead of the entire disk | Separate encryption key managed for each protected partition | Useful when an organization needs to isolate and protect a specific operating system or sensitive data partition while leaving other partitions accessible |
| Volume | A logical storage volume that may combine multiple disks | Low to medium impact depending on storage size and encryption method | Encryption key managed per volume, often integrated with enterprise storage or cloud key management systems | Better than partition encryption for servers, storage arrays, and virtual environments where data is organized into large shared storage volumes |
| File | Individual files or groups of files | Medium impact because encryption and decryption occur each time protected files are accessed or shared | Keys may be assigned per file, user, group, or managed through enterprise rights management systems | Best when only specific documents require protection, especially when files must be securely shared without encrypting the entire storage location |
| Database | Entire database, tables, or database structures | Medium impact because encryption occurs during database operations, but modern systems optimize performance | Keys are usually managed through database encryption features, KMS, or enterprise key management platforms | Better than file encryption for applications storing structured sensitive information because it protects large amounts of organized data while allowing normal application access |
| Record | Individual fields, rows, or specific records inside a database | Highest impact because each protected element requires additional encryption and access processing | Requires detailed key management, often with application-level encryption and separate keys for sensitive fields | Best for extremely sensitive information such as medical diagnoses, financial identifiers, or personal data where only specific values require stronger protection |

### When Each Level Is the Better Choice

- **Full-disk encryption:** The best option when the main concern is physical loss or theft because it protects everything on the device with minimal management complexity, making it preferable to file-level protection for laptops and portable systems.

- **Partition encryption:** A better choice than full-disk encryption when only a dedicated area requires protection, such as separating sensitive data from a standard operating system partition while reducing unnecessary encryption overhead.

- **Volume encryption:** More suitable than partition encryption for enterprise servers and storage systems because it protects large-scale data repositories while supporting flexible storage expansion and virtualization.

- **File encryption:** Preferred over database or volume encryption when only selected documents need confidentiality, such as protecting exported patient reports or financial documents that must be shared securely.

- **Database encryption:** Usually the strongest balance for healthcare and business applications because it protects structured data at rest without requiring every user or application to manage encrypted individual files.

- **Record encryption:** The strongest and most targeted option because it protects only the highest-value information, but it is usually reserved for extremely sensitive fields due to higher complexity, performance cost, and key management requirements.

---

### MedDefense Encryption Level Map

| MedDefense Data Store | Recommended Encryption Level | Justification |
|-----------------------|------------------------------|---------------|
| **PostgreSQL (ehr-db-01) – Patient Records** | **Record** | Patient records contain the most sensitive PHI (diagnoses, treatments, SSNs, insurance data). Record-level encryption ensures that even if the database or an administrator account is compromised, only authorized applications can decrypt individual patient records, providing the highest level of confidentiality for HIPAA-regulated data. |
| **NAS-01 – Backup Data** | **Full-disk** | The backup NAS stores complete copies of multiple critical systems, including the EHR, billing, and Active Directory. Full-disk encryption protects the entire repository from offline theft or unauthorized physical access without adding complexity to backup and recovery operations. |
| **MySQL (billing-srv-01) – Financial Records** | **Database** | Billing data is accessed only through the billing application, making database encryption the most appropriate choice. It protects all financial records at rest while maintaining good performance, centralized key management, and transparent operation for users. |
| **PACS (pacs-srv-01) – Medical Images** | **Volume** | PACS stores very large radiology images that require fast read/write performance. Volume encryption secures the complete imaging repository while minimizing performance overhead compared to encrypting every image individually, making it well suited for high-volume clinical workloads. |
| **Microsoft 365 (Email Data)** | **File** |O365 already protects data using Microsoft-managed encryption for data at rest and during transmission. For additional MedDefense-controlled protection of sensitive patient information, confidential emails and attachments should be encrypted with GPG before being uploaded or sent through O365. MedDefense would maintain ownership of the encryption keys separately from Microsoft’s encryption system, ensuring that patient data remains protected even if Microsoft encryption keys are exposed, accessed by unauthorized parties, or subject to external requests. The main impact is a small processing overhead for each encrypted message, while significantly improving control over PHI confidentiality.|
| **Employee Laptops** | **Full-disk** | Laptops are frequently used outside the hospital and are at the highest risk of loss or theft. Full-disk encryption ensures that all locally stored patient data, cached credentials, and business documents remain unreadable if the device falls into unauthorized hands. |
| **Medical device firmware & configuration (Ex: BD Alaris Pump Firmware)** | **Partition** | For medical devices, MedDefense should activate the encryption features provided by the manufacturer whenever they are supported. Many newer FDA-approved devices include built-in encryption for stored data, with the device handling its own internal encryption keys. If a device cannot support encryption, protection must rely on compensating controls such as dedicated network segmentation, blocking unnecessary internet access, and restricting physical access. Legacy devices cannot realistically be upgraded by MedDefense with third-party encryption, so improving their security remains primarily a vendor responsibility. Device encryption helps prevent unauthorized recovery of sensitive information if equipment is retired, lost, or stolen.|