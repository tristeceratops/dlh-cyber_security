# Certificate Lifecycle Management

## Introduction

### Goal
Design the certificate management program that prevents MedDefense from ever facing another "certificate expires in 18 days" emergency.

### Context
The patient portal certificate is a symptom, not the disease. The disease is that MedDefense has no certificate inventory, no expiration monitoring, no renewal process and no policy on certificate types. This task creates the program.

## Answer

# MedDefense Certificate Lifecycle Management Plan

## 1. Certificate Inventory

| Certificate | Current Issuer | Estimated Expiration | Responsible Owner | Purpose |
|---|---|---|---|---|
| Patient Portal TLS Certificate | Public CA (unknown; Finding 013 indicates certificate management weakness) | Unknown / potentially expiring soon | IT Director Sarah Park | Protects patient portal HTTPS connections and PHI submitted by ~800 daily patients |
| EHR Internal TLS Certificate (ehr-db-01 / ehr-srv-01) | Internal CA or self-signed (needs validation) | Unknown | Clinical Data Owner + Deputy CISO James Chen | Encrypts EHR application and PostgreSQL database communications |
| VPN Gateway Certificate (FortiGate VPN) | Public CA or vendor certificate | Unknown | IT Director Sarah Park | Authenticates remote access VPN connections |
| PACS/DICOM TLS Certificate | Not currently deployed (Finding 024: DICOM traffic unencrypted) | N/A | Radiology Department Head + Clinical Engineering | Required to encrypt medical image transfers |
| Email Signing Certificate (S/MIME) | Not currently deployed | N/A | Microsoft 365 Administrator | Provides signed and encrypted email for sensitive PHI communication |
| Code Signing Certificate | Not currently deployed | N/A | Development/Application Owner | Signs internal applications/scripts to verify integrity before deployment |
| Backup System Certificate (NAS-01) | Unknown / likely self-managed | Unknown | IT Operations Manager | Secures backup management interfaces and encrypted backup communication |
| Medical Device Certificates (MRI, BD Alaris Pumps) | Manufacturer/vendor CA | Vendor-controlled | Clinical Engineering Manager | Supports device authentication and secure firmware communication |

# 2. Auto-Renewal Strategy

| Certificate Type | Recommended Approach | Reason |
|---|---|---|
| Patient Portal | Commercial CA with ACME automation | The portal handles patient PHI and serves 800 daily users. A certificate expiration would immediately block access to healthcare services, create patient disruption, and damage trust. A commercial CA provides stronger validation, support, and automated renewal reduces expiration risk. |
| Internal EHR Services | Internal CA + automated renewal | Internal systems do not require public trust. MedDefense controls the CA and can automate renewal through enterprise certificate management. |
| VPN Certificate | Commercial CA + automated renewal | VPN access protects remote healthcare operations. Expiration could prevent clinicians and administrators from accessing systems during emergencies. |
| PACS/DICOM Certificates | Internal CA + automated renewal | These are internal medical workflows and require trusted encryption rather than public internet validation. |
| Email Signing Certificates | Commercial CA | Email trust requires compatibility with external organizations and healthcare partners. |
| Code Signing Certificate | Commercial CA | Signed software requires external trust validation to prove application authenticity. |

Recommended Standard:
- Use ACME automation wherever technically supported.
- Use commercial CA certificates for internet-facing and externally trusted systems.
- Use MedDefense Internal CA for internal infrastructure.

# 3. Monitoring and Alerting

Monitoring System:
- Deploy certificate monitoring through SIEM/MDR platform.
- Integrate with Microsoft Defender, FortiGate monitoring, and internal certificate management tools.
- Maintain a centralized certificate inventory database.

| Alert Threshold | Action | Notification Recipient |
|---|---|---|
| 90 days before expiration | Early warning; renewal process begins | IT Operations Manager |
| 60 days before expiration | Renewal must be scheduled | Certificate Owner + IT Operations Manager |
| 30 days before expiration | Escalation; renewal becomes priority task | IT Director Sarah Park + Certificate Owner |
| 7 days before expiration | Critical escalation; immediate remediation required | Deputy CISO James Chen + IT Director + System Owner |
| Expired | Incident response process begins | Security Team + Business Owner |

Key Performance Indicator:
- 100% of production certificates tracked.
- 0 unexpected certificate expirations.
- Renewal completed at least 30 days before expiration.

# 4. MedDefense Certificate Policy Rules

1. All production systems must use certificates issued by a trusted public CA or the MedDefense internal CA.
   Self-signed certificates are prohibited in production environments.

2. All certificates must be recorded in the centralized certificate inventory with:
   - owner,
   - purpose,
   - issuer,
   - expiration date,
   - renewal process.

3. Internet-facing systems, including the patient portal and VPN gateway, must use automated certificate renewal whenever supported.

4. Certificate private keys must be protected using approved key management controls.
   High-value keys (EHR encryption, VPN, signing certificates) must use KMS or HSM-backed storage when possible.

5. Certificates must be renewed before expiration.
   Systems with certificates expiring within 30 days require priority remediation and owner notification.

# MedDefense Priority Actions

1. Replace the current patient portal certificate management process.
   - Finding 013 identified certificate expiration and renewal weaknesses.
   - Implement automated monitoring and renewal.

2. Deploy TLS certificates for currently unencrypted medical communication.
   - Address Finding 024 by enabling DICOM TLS for PACS.

3. Create centralized certificate ownership.
   - Every certificate must have a named technical owner and business owner.

Expected Result:
MedDefense moves from reactive certificate management to a controlled lifecycle process that prevents outages, protects PHI, and supports HIPAA security requirements.