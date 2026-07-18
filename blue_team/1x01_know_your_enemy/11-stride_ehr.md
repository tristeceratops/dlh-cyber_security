# STRIDE on the EHR

## Introduction

### Goal
Apply the STRIDE threat model in depth to MedDefense's most critical system to systematically identify every category of threat.

### Context
STRIDE is a structured approach to threat identification. Instead of brainstorming threats randomly, you walk through six categories systematically, ensuring nothing is missed. Applied to a specific system with a known architecture, it produces a comprehensive threat inventory that no amount of ad-hoc thinking would match.

The EHR system is MedDefense's most critical asset. It consists of **ehr-srv-01** (application server), **ehr-db-01** (PostgreSQL database), the clinical workstations that access it, and the network paths between all of them. Based on the 1x00 Asset Registry, Control Matrix, Gap Analysis, and Vector-to-Asset Matrix, the following STRIDE analysis identifies the most realistic threats against the environment.

## Answer

---

## Spoofing (S)

### Threat ID: EHR-S1

- **Category:** Spoofing
- **Description:** A clinician's Microsoft 365 or VPN credentials are stolen through a spear-phishing campaign, allowing an attacker to authenticate as a legitimate user and access the EHR.
- **Attack Vector:** Phishing / Spear Phishing (Task 9)
- **Impact:** Unauthorized access to patient records, fraudulent medical record access, potential HIPAA breach.
- **Existing Control:** C-005 (Password Policy), C-011 (Security Awareness Training)
- **Gap:** **G-004** (No routine phishing simulations or continuous security oversight)

---

### Threat ID: EHR-S2

- **Category:** Spoofing
- **Description:** A terminated contractor continues authenticating through an active VPN account (similar to Incident F), impersonating a legitimate employee.
- **Attack Vector:** Insider (Negligent) / VPN Access
- **Impact:** Unauthorized internal network access leading to EHR compromise.
- **Existing Control:** C-006 (Account Lockout Policy)
- **Gap:** **G-004** (Lack of administrative oversight and access review)

---

## Tampering (T)

### Threat ID: EHR-T1

- **Category:** Tampering
- **Description:** An attacker modifies patient allergy or medication records after compromising the EHR application server.
- **Attack Vector:** VPN Exploit followed by lateral movement
- **Impact:** Incorrect treatment decisions, patient safety incidents, legal liability.
- **Existing Control:** C-003 (SSH Key Authentication), C-004 (Root Login Disabled)
- **Gap:** **G-001** (No centralized monitoring to detect unauthorized changes)

---

### Threat ID: EHR-T2

- **Category:** Tampering
- **Description:** A malicious database administrator alters billing or clinical records directly within PostgreSQL.
- **Attack Vector:** Malicious Insider
- **Impact:** Fraudulent billing, inaccurate patient history, compliance violations.
- **Existing Control:** C-005 (Password Policy)
- **Gap:** **G-004** (No routine audit review or privileged activity monitoring)

---

## Repudiation (R)

### Threat ID: EHR-R1

- **Category:** Repudiation
- **Description:** A clinician accesses sensitive patient records but later denies doing so because centralized log collection is absent.
- **Attack Vector:** Legitimate user misuse
- **Impact:** Difficulty investigating HIPAA violations and insider abuse.
- **Existing Control:** C-012 (System and Security Logging)
- **Gap:** **G-001** (No SIEM or centralized log management)

---

### Threat ID: EHR-R2

- **Category:** Repudiation
- **Description:** Shared workstation sessions in clinical areas make it impossible to determine which staff member viewed or modified a patient's record.
- **Attack Vector:** Insider (Negligent)
- **Impact:** Loss of accountability during security or legal investigations.
- **Existing Control:** C-005 (Password Policy)
- **Gap:** **G-004** (Insufficient administrative oversight and audit processes)

---

## Information Disclosure (I)

### Threat ID: EHR-I1

- **Category:** Information Disclosure
- **Description:** An attacker exploits the flat internal network and broad database exposure to extract the entire PostgreSQL patient database.
- **Attack Vector:** VPN Exploit / Lateral Movement
- **Impact:** Exposure of protected health information (PHI), mandatory HIPAA breach notification, reputational damage.
- **Existing Control:** C-001 (Perimeter Firewall)
- **Gap:** **G-006** (Overly permissive internal network access)

---

### Threat ID: EHR-I2

- **Category:** Information Disclosure
- **Description:** Malware installed on a compromised clinical workstation captures patient information displayed in active EHR sessions.
- **Attack Vector:** Phishing delivering malware
- **Impact:** Continuous theft of patient records and user credentials.
- **Existing Control:** C-007 (Sophos Endpoint Protection)
- **Gap:** **G-003** (Incomplete protection for all endpoints and unsupported assets)

---

## Denial of Service (D)

### Threat ID: EHR-D1

- **Category:** Denial of Service
- **Description:** Ransomware encrypts ehr-srv-01, ehr-db-01, and local backup storage.
- **Attack Vector:** VPN Exploit or Phishing
- **Impact:** Hospital-wide loss of EHR availability, manual patient documentation, delayed care.
- **Existing Control:** C-008 (Scheduled Backups)
- **Gap:** **G-002** (No offsite or immutable backups)

---

### Threat ID: EHR-D2

- **Category:** Denial of Service
- **Description:** A compromised endpoint launches excessive database queries against ehr-db-01, exhausting server resources and preventing legitimate access.
- **Attack Vector:** Insider misuse or compromised workstation
- **Impact:** Slow or unavailable EHR during clinical operations.
- **Existing Control:** C-001 (Perimeter Firewall)
- **Gap:** **G-006** (Internal network lacks segmentation and traffic restrictions)

---

## Elevation of Privilege (E)

### Threat ID: EHR-E1

- **Category:** Elevation of Privilege
- **Description:** After compromising a workstation, an attacker harvests Active Directory credentials and gains Domain Administrator privileges.
- **Attack Vector:** Phishing followed by credential harvesting
- **Impact:** Full control of EHR servers, workstations, and authentication infrastructure.
- **Existing Control:** C-005 (Password Policy), C-006 (Account Lockout)
- **Gap:** **G-001** (Limited monitoring) and **G-006** (Flat internal network)

---

### Threat ID: EHR-E2

- **Category:** Elevation of Privilege
- **Description:** An attacker exploits broad trust relationships between the EHR application server and PostgreSQL database to obtain database administrative privileges.
- **Attack Vector:** Vulnerable Software Exploit
- **Impact:** Complete compromise of patient records, application configuration, and authentication data.
- **Existing Control:** C-003 (SSH Key Authentication), C-004 (Root Login Disabled)
- **Gap:** **G-006** (Overly permissive network access) and **G-001** (Weak monitoring)