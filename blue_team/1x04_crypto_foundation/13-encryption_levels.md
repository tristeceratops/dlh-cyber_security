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
| **PostgreSQL (ehr-db-01) – Patient Records** | **Record Encryption** | Patient records contain the most sensitive PHI (diagnoses, treatments, SSNs, insurance data). Record-level encryption ensures that even if the database or an administrator account is compromised, only authorized applications can decrypt individual patient records, providing the highest level of confidentiality for HIPAA-regulated data. |
| **NAS-01 – Backup Data** | **Volume Encryption** | Volume encryption is the most appropriate choice because NAS systems contain large backup repositories that need protection as a complete storage unit. File encryption would create unnecessary management overhead because thousands of backup files would require separate encryption handling. Full-disk encryption would protect the entire device but provides less flexibility for storage environments where multiple volumes may exist. Volume encryption provides strong protection while maintaining backup and restore performance. |
| **MySQL (billing-srv-01) – Financial Records** | **Database Encryption** | Database encryption is selected because billing information is stored in relational tables and requires protection while remaining available to billing applications. File encryption would create unnecessary complexity because applications would need to handle encrypted files directly, while full-disk encryption alone would not provide enough database-level protection. Using database encryption also creates consistency with the EHR database security model and simplifies key management across critical business systems. |
| **PACS (pacs-srv-01) – Medical Images** | **Volume Encryption** | Volume encryption is chosen because PACS stores very large imaging datasets that require high availability and fast access by clinical systems. File encryption would be inefficient because thousands of DICOM image files would need individual encryption operations. Database encryption alone would not protect the complete imaging repository because PACS often separates image storage from metadata databases. Volume encryption protects the entire imaging storage area while minimizing disruption to radiology workflows. |
| **Microsoft 365 (Email Data)** | **File Encryption** | File-level encryption is selected because MedDefense needs direct control over sensitive patient information shared through O365. Microsoft already provides platform encryption, but client-side file encryption ensures MedDefense controls the encryption keys instead of relying only on Microsoft-managed keys. Full-disk or volume encryption would not protect data after it is uploaded to the cloud. File encryption is better because it protects individual PHI documents and attachments during storage and sharing. |
| **Employee Laptops** | **Full-disk Encryption** | Full-disk encryption is the best option because laptops can be lost, stolen, or accessed outside hospital facilities. Encrypting individual files would leave cached credentials, temporary EHR files, and operating system data exposed. Full-disk encryption protects the entire device without requiring employees to manually encrypt important files. It provides the strongest practical protection with minimal performance impact on modern devices. |
| **Medical device firmware & configuration (Ex: BD Alaris Pump Firmware)** | **Device Encryption** | Device-level encryption is preferred because medical devices are specialized systems controlled by vendors and cannot usually be modified like normal computers. File or database encryption is not practical because MedDefense does not manage the internal firmware architecture. If supported, manufacturer encryption protects stored configuration and sensitive device information. For legacy devices without encryption support, MedDefense must rely on compensating controls such as medical VLAN isolation, restricted access, and physical security because encryption cannot be retrofitted safely. |