# The Three Scenarios

## Introduction

These scenarios combine the threat actors, attack vectors, architecture weaknesses, STRIDE analysis, ATT&CK techniques, and documented security gaps identified throughout the MedDefense assessment. Each scenario represents a realistic attack path that could occur if current weaknesses remain unresolved.

---

# Scenario 1 – BlackReef Ransomware Locks Down MedDefense

## Threat Actor
**Organized crime / Ransomware-as-a-Service group – BlackReef (T6 Ransomware Actor Profile)**

## Motivation
**Financial gain through ransom payment and double extortion**

## Initial Vector
**Exploitation of internet-facing remote access systems (VPN) – Vector-to-Asset Matrix**

## Attack Surface Exploited
**External**

## Attack Sequence

**Step 1 – Attacker exploits an unpatched VPN appliance exposed to the internet to gain initial access.**  
*ATT&CK T1190 – Exploit Public-Facing Application (Initial Access)*

BlackReef affiliates compromise MedDefense's remote access infrastructure and establish a foothold inside the network.

**Step 2 – Attackers use stolen credentials and move through the internal environment.**  
*ATT&CK T1078 – Valid Accounts (Defense Evasion / Persistence)*

Because MFA is incomplete, compromised credentials allow access to internal systems without additional verification.

**Step 3 – Attackers perform reconnaissance and identify critical systems including Active Directory, EHR servers, and backups.**  
*ATT&CK T1018 – Remote System Discovery (Discovery)*

The attackers map the environment and identify:
- ehr-srv-01
- ehr-db-01
- ad-dc-01 / ad-dc-02
- backup infrastructure

**Step 4 – Attackers escalate privileges and move laterally across the hospital network.**  
*ATT&CK T1068 – Exploitation for Privilege Escalation (Privilege Escalation)*  
*ATT&CK T1021 – Remote Services (Lateral Movement)*

The flat network allows compromised systems to communicate with critical servers.

**Step 5 – Attackers exfiltrate patient data and deploy ransomware across reachable systems.**  
*ATT&CK T1041 – Exfiltration Over C2 Channel*  
*ATT&CK T1486 – Data Encrypted for Impact (Impact)*

EHR systems, file servers, and clinical systems become unavailable while stolen PHI is used for extortion.

---

## STRIDE Categories Triggered

- **Spoofing:** Stolen VPN credentials used to impersonate legitimate users.
- **Tampering:** Patient records and system configurations may be modified.
- **Information Disclosure:** PHI is stolen before encryption.
- **Denial of Service:** Ransomware disables clinical systems.
- **Elevation of Privilege:** Attackers gain administrative control.

## MedDefense Assets Impacted

- **A-001 – ehr-srv-01**
- **A-002 – ehr-db-01**
- **A-017/A-018/A-019 – Windows Workstations**
- **A-033 – Microsoft 365 Tenant**
- **Active Directory Servers (ad-dc-01/ad-dc-02)**
- Backup infrastructure

## Business Impact

**Clinical:**  
EHR downtime prevents normal patient documentation, medication verification, and clinical workflows.

**Financial:**  
Ransom payment, recovery costs, overtime, and operational disruption.

**Regulatory:**  
PHI exposure triggers HIPAA breach investigation and notification requirements.

**Reputational:**  
Loss of patient trust and negative media attention following healthcare disruption.

## Gaps Exploited

- **GAP-016 – Internet-facing systems lack formal vulnerability management**  
  Allows exploitation of vulnerable VPN infrastructure.

- **GAP-017 – MFA not deployed at scale**  
  Allows stolen credentials to authenticate successfully.

- **GAP-006 – Flat network and permissive access**  
  Enables lateral movement from one compromised system.

- **GAP-005 – Backup resilience weaknesses**  
  Reduces recovery capability after encryption.

- **GAP-004 – Lack of centralized monitoring**  
  Prevents early detection of reconnaissance and privilege escalation.

## Detection Opportunities

**Step 1:**  
Detect abnormal VPN activity through:
- MFA enforcement
- VPN login monitoring
- Impossible travel alerts

**Step 3:**  
Detect reconnaissance using:
- SIEM
- Network monitoring
- Endpoint behavior analytics

**Step 4:**  
Detect privilege escalation through:
- Privileged account monitoring
- Domain controller alerts
- UEBA

**Step 5:**  
Detect ransomware activity through:
- EDR alerts
- File encryption monitoring
- Backup integrity monitoring

---

# Scenario 2 – Malicious Insider Exfiltrates Patient Records

## Threat Actor
**Malicious insider – Curious Employee profile (T3 Insider Threat Assessment)**

## Motivation
**Personal gain / unauthorized disclosure of sensitive information**

## Initial Vector
**Legitimate access abused**

## Attack Surface Exploited
**Internal / Human**

## Attack Sequence

**Step 1 – Employee uses legitimate EHR credentials to access patient records outside their job responsibilities.**  
*ATT&CK T1078 – Valid Accounts (Initial Access)*

The employee abuses authorized access to search sensitive patient information.

**Step 2 – Employee accesses large numbers of records unrelated to normal workflow.**  
*ATT&CK T1087 – Account Discovery (Discovery)*

The employee identifies valuable patient information available through the EHR.

**Step 3 – Employee exports patient information from the EHR system.**  
*ATT&CK T1567 – Exfiltration Over Web Service (Exfiltration)*

Records are copied to personal storage or transferred outside MedDefense.

**Step 4 – Employee attempts to remove evidence of activity.**  
*ATT&CK T1070 – Indicator Removal (Defense Evasion)*

The employee relies on weak logging and limited monitoring to avoid detection.

**Step 5 – Patient information is disclosed externally.**  
*ATT&CK T1530 – Data from Information Repositories (Collection)*

Protected health information becomes exposed.

---

## STRIDE Categories Triggered

- **Spoofing:** Misuse of legitimate identity.
- **Repudiation:** Employee can deny actions without strong audit trails.
- **Information Disclosure:** Patient data is exposed.
- **Tampering:** Records could potentially be altered.

## MedDefense Assets Impacted

- **A-001 – ehr-srv-01**
- **A-002 – ehr-db-01**
- Patient records database
- Microsoft 365 storage if used for transfer

## Business Impact

**Clinical:**  
Potential loss of confidence in patient records.

**Financial:**  
Investigation costs, legal expenses, and regulatory penalties.

**Regulatory:**  
HIPAA violation due to unauthorized PHI access.

**Reputational:**  
Patient trust damaged due to insider privacy breach.

## Gaps Exploited

- **GAP-014 – Sensitive data exports lack DLP and behavioral monitoring**  
  Allows unusual data access and export activity to continue.

- **GAP-004 – No centralized security monitoring**  
  Prevents correlation of suspicious user behavior.

- **GAP-018 – Weak accountability around shared clinical access**  
  Reduces confidence in audit trails.

## Detection Opportunities

**Step 1-2:**  
Detect unusual EHR access through:
- UEBA
- EHR audit monitoring
- Role-based access alerts

**Step 3:**  
Detect data theft using:
- DLP
- File transfer monitoring
- Database activity monitoring

**Step 4:**  
Detect suspicious log activity through:
- Centralized SIEM
- Immutable audit logs

---

# Scenario 3 – MedTech Solutions Vendor Compromise Becomes Hospital Breach

## Threat Actor
**External attacker using vendor access as a stepping stone – Supply Chain Threat Actor (T6 Third-Party Risk Profile)**

## Motivation
**Financial gain through ransomware deployment or data theft**

## Initial Vector
**Compromised vendor remote access pathway**

## Attack Surface Exploited
**Third-party / External**

## Attack Sequence

**Step 1 – Attacker compromises a MedTech Solutions support account.**  
*ATT&CK T1078 – Valid Accounts (Initial Access)*

The attacker obtains credentials used for EHR maintenance.

**Step 2 – Attacker connects to MedDefense through trusted vendor access.**  
*ATT&CK T1133 – External Remote Services (Initial Access)*

The attacker appears as a legitimate maintenance user.

**Step 3 – Attacker compromises ehr-srv-01 and collects credentials.**  
*ATT&CK T1003 – OS Credential Dumping (Credential Access)*

The EHR server becomes the attacker's internal foothold.

**Step 4 – Attacker moves toward Active Directory and database systems.**  
*ATT&CK T1021 – Remote Services (Lateral Movement)*

The attacker exploits weak segmentation and broad internal access.

**Step 5 – Attacker steals PHI or deploys ransomware.**  
*ATT&CK T1041 – Exfiltration Over C2 Channel*  
*ATT&CK T1486 – Data Encrypted for Impact*

The vendor compromise becomes a MedDefense-wide incident.

---

## STRIDE Categories Triggered

- **Spoofing:** Vendor credentials used to impersonate trusted support staff.
- **Tampering:** EHR systems or configurations modified.
- **Information Disclosure:** Patient records exposed.
- **Denial of Service:** Ransomware disrupts EHR availability.
- **Elevation of Privilege:** Vendor access becomes administrator access.

## MedDefense Assets Impacted

- **A-001 – ehr-srv-01**
- **A-002 – ehr-db-01**
- Active Directory infrastructure
- Patient database
- Clinical systems connected to EHR

## Business Impact

**Clinical:**  
Loss of EHR availability delays patient care.

**Financial:**  
Incident response costs, recovery expenses, and potential ransom demand.

**Regulatory:**  
PHI breach reporting obligations.

**Reputational:**  
Patients lose confidence in MedDefense's vendor security practices.

## Gaps Exploited

- **GAP-006 – Flat network architecture**  
  Allows vendor compromise to spread internally.

- **GAP-004 – Lack of centralized monitoring**  
  Makes abnormal vendor activity difficult to identify.

- **GAP-017 – Weak MFA coverage**  
  Allows compromised vendor credentials to be reused.

- **GAP-003 – Legacy and unsupported systems**  
  Increases opportunities for compromise of connected systems.

## Detection Opportunities

**Step 1-2:**  
Detect vendor compromise through:
- MFA enforcement
- Vendor access monitoring
- Conditional access policies

**Step 3:**  
Detect suspicious EHR server activity through:
- EDR
- Server integrity monitoring
- Privileged access alerts

**Step 4:**  
Detect lateral movement through:
- Network segmentation monitoring
- IDS/IPS
- SIEM correlation

**Step 5:**  
Detect data theft or ransomware through:
- DLP
- File activity monitoring
- Backup monitoring

---

# Conclusion

These three scenarios demonstrate the primary ways MedDefense could experience a major cybersecurity incident:

1. **External ransomware attackers** exploiting technical weaknesses.
2. **Internal users** abusing legitimate access to sensitive information.
3. **Third-party vendors** becoming indirect entry points into critical systems.

Across all scenarios, the highest-risk weaknesses are the lack of centralized monitoring, insufficient identity controls, weak segmentation, and inadequate protection of sensitive data. Closing these gaps would significantly reduce the likelihood and impact of a major security event.