# The Data Classification Matrix

## Introduction

### Goal
Apply data protection principles to produce a comprehensive data classification policy for MedDefense that drives every encryption decision.

### Context
Encryption is not binary ("encrypted" or "not encrypted"). It is a spectrum driven by the sensitivity of the data. A hospital cafeteria menu does not need AES-256. A patient's HIV status does. The data classification determines the protection level, and the protection level determines the algorithm, the key management rigor and the access controls.

## Answer

# MedDefense Data Classification Framework

======================================================================
PART 1 - DATA TYPE INVENTORY
======================================================================

| Data Type | MedDefense Examples | Classification Level | Related Systems |
|---|---|---|---|
| Regulated (HIPAA/PHI) | Patient records, diagnoses, medical images, EHR data, DICOM files, infusion pump data | Restricted | ehr-db-01, PACS, medical devices |
| PII | Employee records, patient names, addresses, phone numbers, identifiers, credentials | Confidential / Restricted depending on sensitivity | HR systems, EHR, Active Directory |
| Financial | Billing records, insurance information, payment data, vendor invoices | Confidential | billing-srv-01, MySQL |
| Intellectual Property | Research data, internal procedures, security designs, system configurations | Confidential | File servers, internal systems |
| Legal | HIPAA documentation, contracts, compliance records, audit reports | Confidential | Compliance storage, legal systems |
| Operational | Network diagrams, schedules, policies, system logs, incident reports | Internal / Confidential | SIEM, IT systems, management platforms |


======================================================================
PART 2 - MEDDEFENSE CLASSIFICATION LEVELS
======================================================================

| Level | Examples | Access | Encryption Requirements | Exposure Impact |
|---|---|---|---|---|
| Public | Hospital address, visiting hours, public website information | Anyone | HTTPS required in transit; encryption at rest not required | Low impact; limited reputation damage |
| Internal | Staff directory, meeting schedules, internal procedures | Employees and approved contractors | Encryption recommended for stored data; TLS required for systems communicating internally | Could expose operations or assist attackers |
| Confidential | Financial reports, vendor contracts, HR records, security documentation | Authorized departments only based on role | AES-256 encryption at rest; TLS 1.2+ in transit | Financial loss, legal issues, competitive damage |
| Restricted | Patient records, credentials, encryption keys, medical images | Only authorized users with business need and MFA | AES-256 encryption at rest, TLS 1.2/1.3 in transit, strong key management using KMS/HSM where needed | HIPAA violation, patient harm, major financial and reputation damage |


======================================================================
PART 3 - DATA CLASSIFICATION DECISION TREE
======================================================================

START
 |
 |-- Does the data contain patient information, medical records,
 |   diagnoses, imaging, or PHI?
 |        |
 |        YES --> CLASSIFY AS RESTRICTED
 |                 Examples:
 |                 - EHR PostgreSQL records
 |                 - PACS medical images
 |                 - BD Alaris device data
 |
 |        NO
 |
 |-- Does the data contain credentials, encryption keys,
 |   authentication information, or security secrets?
 |        |
 |        YES --> CLASSIFY AS RESTRICTED
 |                 Examples:
 |                 - VPN credentials
 |                 - Database encryption keys
 |
 |        NO
 |
 |-- Does the data contain financial information,
 |   contracts, HR records, or sensitive business information?
 |        |
 |        YES --> CLASSIFY AS CONFIDENTIAL
 |                 Examples:
 |                 - billing-srv-01 records
 |                 - vendor contracts
 |
 |        NO
 |
 |-- Is the data used for internal hospital operations,
 |   employee communication, or internal processes?
 |        |
 |        YES --> CLASSIFY AS INTERNAL
 |                 Examples:
 |                 - staff schedules
 |                 - internal procedures
 |
 |        NO
 |
 |-- Is the information intended for public release?
          |
          YES --> CLASSIFY AS PUBLIC
                  Examples:
                  - hospital address
                  - visiting hours


======================================================================
PART 4 - DATA SOVEREIGNTY AND GEOLOCATION
======================================================================

Healthcare data sovereignty matters because patient information is protected by
HIPAA requirements and may be subject to additional state or national privacy
laws. MedDefense must know where backups are stored because different regions
may have different legal access requirements and regulatory obligations.

If AWS backups are stored in another state, MedDefense must verify that the
provider maintains HIPAA-compliant controls and appropriate agreements such as
a Business Associate Agreement (BAA). If stored in another country, additional
privacy laws and government access requirements may apply.

Encryption reduces the impact of unauthorized access because stolen backup data
remains unreadable without the encryption keys. However, encryption does not
remove sovereignty requirements because regulators still care where healthcare
data is physically stored and which legal authorities can access it.

======================================================================
MEDDEFENSE RECOMMENDATION
======================================================================

Based on the 6-month security roadmap:

- Month 2: Immutable backups should be encrypted before cloud migration.
- Month 2: Backup encryption keys should be managed separately through KMS.
- Month 3-4: Network segmentation should protect backup infrastructure.
- Future AWS migration should use a healthcare-approved region with documented
  HIPAA compliance and a signed BAA.

Final classification priorities:
1. Protect Restricted data first:
   - EHR database
   - PACS images
   - Medical device information
   - Encryption keys

2. Protect Confidential business data:
   - Billing database
   - Contracts
   - Security documentation

3. Maintain availability of Internal operational data:
   - Logs
   - Policies
   - Staff information