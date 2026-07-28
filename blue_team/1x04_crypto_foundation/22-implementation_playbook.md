# The Implementation Playbook

## Introduction

### Goal
Produce a step-by-step operational playbook for the first 5 cryptographic changes to be deployed in production.

### Context
This is the document Sarah Park takes to her IT team on Monday morning. It is not a strategy. It is not a report. It is a playbook: do this, then this, then verify, then proceed. Each action has prerequisites, steps, validation criteria and a rollback plan.

## Answer

# MedDefense Cryptographic Implementation Playbook

======================================================================
Action #1: Enable EHR Database Encryption
======================================================================

Priority: Immediate

System Affected:
- ehr-db-01 (PostgreSQL EHR Database) - CRYPTO-001

Prerequisites:
- Enterprise KMS deployed
- Database backup verified before encryption
- Maintenance window approved
- Database administrator access confirmed

Steps:
1. Enable PostgreSQL database encryption using AES-256 encryption.
2. Configure the database to retrieve encryption keys from the enterprise KMS.
3. Remove unrestricted database access rules identified in Finding 003.
4. Test EHR application connectivity after encryption is enabled.
5. Document key ownership and rotation procedures.

Validation:
- Confirm database files are unreadable without encryption keys.
- Verify clinicians can still access patient records normally.
- Confirm database performance remains within acceptable limits.

Rollback:
- Restore database from pre-encryption backup.
- Disable encryption configuration if application compatibility issues occur.
- Maximum downtime before rollback: 2 hours.

Maintenance Window:
- Overnight maintenance window required due to critical patient systems.

Communication:
- Notify Clinical Operations, DBA team, Security Team, and IT Director before change.
- Provide completion report after validation.


======================================================================
Action #2: Encrypt NAS Backup Storage
======================================================================

Priority: Phase 1

System Affected:
- NAS-01 Backup Storage - CRYPTO-002

Prerequisites:
- Backup inventory completed
- KMS key created
- Successful backup restoration test completed

Steps:
1. Enable AES-256 volume encryption on NAS backup storage.
2. Move encryption keys from NAS storage to centralized KMS.
3. Restrict NAS administrative access.
4. Encrypt backup replication traffic.
5. Perform a full backup recovery test.

Validation:
- Confirm backup files cannot be accessed without encryption keys.
- Verify successful backup creation and restoration.
- Confirm ransomware recovery process remains functional.

Rollback:
- Restore NAS configuration from saved backup.
- Temporarily disable encryption if backup jobs fail.
- Maximum downtime before rollback: 4 hours.

Maintenance Window:
- Overnight required because backup services are critical.

Communication:
- Notify Backup Administrator, IT Director, and Security Team before deployment.
- Report recovery test results after completion.


======================================================================
Action #3: Disable TLS 1.0 on Patient Portal
======================================================================

Priority: Immediate

System Affected:
- Patient Portal Web Server - CRYPTO-003

Prerequisites:
- Valid TLS certificate installed
- Certificate monitoring enabled
- Patient portal compatibility testing completed

Steps:
1. Disable TLS 1.0 and TLS 1.1 protocols.
2. Require TLS 1.2 minimum and enable TLS 1.3 where supported.
3. Configure AES-256-GCM modern cipher suites.
4. Enable automated certificate renewal.
5. Scan externally to verify secure TLS configuration.

Validation:
- Confirm external TLS scans show TLS 1.2/1.3 only.
- Verify patients can still access the portal.
- Confirm certificate expiration monitoring works.

Rollback:
- Re-enable previous TLS configuration if compatibility failures occur.
- Restore previous web server configuration.
- Maximum downtime before rollback: 30 minutes.

Maintenance Window:
- Business hours acceptable with monitoring because downtime impact is low.

Communication:
- Notify Web Administrator, Security Team, and Patient Services.
- Announce successful security upgrade after testing.


======================================================================
Action #4: Encrypt PACS DICOM Communications
======================================================================

Priority: Phase 1

System Affected:
- pacs-srv-01 (PACS Medical Imaging System) - CRYPTO-005

Prerequisites:
- PACS vendor confirms TLS support
- Certificates issued for PACS devices
- Medical workflow testing completed

Steps:
1. Install trusted TLS certificates on PACS servers.
2. Enable DICOM TLS communication.
3. Configure AES-256-GCM encryption for image transfers.
4. Disable unencrypted DICOM connections.
5. Test communication with imaging devices.

Validation:
- Confirm DICOM traffic is encrypted using network monitoring.
- Verify radiologists can access images normally.
- Confirm connected medical devices support TLS.

Rollback:
- Temporarily allow internal encrypted/plain DICOM communication during troubleshooting.
- Restore previous PACS communication settings.
- Maximum downtime before rollback: 1 hour.

Maintenance Window:
- Overnight required because radiology services are patient-impacting.

Communication:
- Notify Radiology Department, Clinical Engineering, PACS Administrator, and Security Team.


======================================================================
Action #5: Remove Weak Kerberos Encryption Types
======================================================================

Priority: Immediate

System Affected:
- Active Directory Authentication Services - CRYPTO-008 

Prerequisites:
- Authentication testing completed
- Inventory of legacy systems using Kerberos completed
- MFA rollout in progress

Steps:
1. Disable DES and RC4 Kerberos encryption types.
2. Require AES-128/AES-256 Kerberos encryption.
3. Update affected service accounts.
4. Reset passwords for accounts using weak encryption.
5. Monitor authentication failures after deployment.

Validation:
- Confirm no Kerberos tickets use DES or RC4.
- Verify users can authenticate normally.
- Review authentication logs for failures.

Rollback:
- Temporarily re-enable legacy encryption for affected systems.
- Replace incompatible systems instead of maintaining weak encryption.
- Maximum downtime before rollback: 1 hour.

Maintenance Window:
- Overnight required because authentication affects all users.

Communication:
- Notify IT administrators, Security Team, and department managers.
- Provide user support if authentication issues appear.


======================================================================
Implementation Priority Summary
======================================================================

Immediate:
1. EHR database encryption
2. Disable TLS 1.0
3. Remove weak Kerberos encryption

Phase 1:
4. NAS backup encryption
5. PACS DICOM TLS encryption

Expected Security Improvement:
- Reduces RISK-002 (EHR PHI breach)
- Reduces RISK-007 (backup compromise)
- Reduces RISK-010 (internet-facing vulnerabilities)
- Improves HIPAA encryption compliance posture
