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
| **PostgreSQL (ehr-db-01) – Patient Records** | **Database Encryption** | Database encryption is the best fit because PostgreSQL stores patient information in structured tables that are accessed directly by the EHR application. It protects the entire database at rest while allowing normal application queries and user workflows. Record-level encryption would provide more granular protection but would add significant complexity and performance overhead for thousands of daily patient transactions. Database encryption provides a practical balance between PHI protection, performance, and centralized key management. |
| **NAS-01 – Backup Data** | **Volume Encryption** | Volume encryption is appropriate because NAS-01 stores large backup repositories that function as complete storage volumes. Encrypting the volume protects all backup files together without requiring individual encryption management for every backup object. File encryption would increase complexity during backup and recovery operations, while full-disk encryption would provide less flexibility if multiple storage volumes are used. Volume encryption provides strong protection while maintaining efficient backup restoration. |
| **MySQL (billing-srv-01) – Financial Records** | **Record Encryption** | Record encryption is selected because financial records may contain highly sensitive fields such as payment information, employee identifiers, and billing details that require fine-grained protection. Unlike database encryption, record encryption allows specific sensitive fields to remain encrypted even when the database is accessed by authorized users or administrators. The additional complexity is justified because financial records require stronger confidentiality controls than general business data. |
| **PACS (pacs-srv-01) – Medical Images** | **Volume Encryption** | Volume encryption is the best choice because PACS stores large collections of medical images that require fast availability for doctors and radiology systems. Encrypting individual image files would create unnecessary processing overhead because thousands of DICOM files are accessed continuously. Database encryption alone would not protect the entire image repository because PACS separates image files from metadata. Volume encryption secures the complete storage area while preserving clinical performance. |
| **Microsoft 365 (Email Data)** | **File Encryption** | File encryption is appropriate because MedDefense needs additional protection for specific emails and attachments containing PHI rather than encrypting the entire Microsoft 365 environment. Client-side file encryption allows MedDefense to control encryption keys independently from Microsoft-managed encryption. Full-disk or volume encryption would not protect files once they are stored in Microsoft's cloud environment. File encryption provides targeted protection for sensitive documents while keeping normal email operations available. |
| **Employee Laptops** | **Full-Disk Encryption** | Full-disk encryption is the best option because laptops contain many types of sensitive information, including cached credentials, temporary EHR files, and local documents. Encrypting only selected files would leave other system data exposed if a device is lost or stolen. Full-disk encryption protects the entire storage device automatically with minimal user involvement, making it the most practical solution for a large clinical workforce. |
| **Medical Device Firmware & Configuration (Example: BD Alaris Pump Firmware)** | **Partition Encryption** | Partition encryption is the closest fit because medical devices often store firmware and configuration data in dedicated system partitions rather than normal user files. Encrypting the entire device may not be supported by vendors, while file encryption would not protect the complete firmware environment. If the manufacturer supports partition-level encryption, it protects critical configuration data while allowing the device to continue operating normally. For older devices without encryption support, MedDefense must rely on compensating controls such as medical VLAN isolation, restricted access, and physical protection. |