# The Kill Chains

## Introduction

### Goal
Construct complete attack chains from initial access to final impact for the 5 most critical threat paths against MedDefense.

### Context
An attack is never a single event. It is a sequence: an entry, a foothold, a progression, an objective. Each step exploits a different weakness. Each step is also a point where the chain can be broken. Understanding kill chains is how you stop thinking about threats as abstract categories and start thinking about them as operational sequences with specific intervention points.

## Answer

---

## Kill Chain #1: Spear Phishing Leading to Active Directory Compromise

**Threat Actor:** Financially motivated ransomware group (e.g., initial access broker/ransomware affiliate targeting healthcare organizations)

**Target Asset:** A-005 ad-dc-01 (Primary Domain Controller)

**Expected Impact:** Complete compromise of enterprise identity, enabling ransomware deployment across clinical systems. Primarily impacts **Confidentiality, Integrity, and Availability**.

### Step 1 – Initial Access

- **Vector:** Spear phishing email impersonating Fortinet or Microsoft support
- **Surface:** Human
- **Detail:** An IT administrator receives a convincing phishing email requesting an urgent security update. The fake portal captures Microsoft 365 or VPN credentials.

### Step 2 – Establish Foothold

- **Action:** The attacker authenticates using stolen credentials through VPN or Microsoft 365 and establishes persistence using stolen session tokens or additional user accounts.
- **MedDefense Weakness:** MFA is only deployed for James Chen's account, leaving most privileged accounts protected only by passwords.

### Step 3 – Lateral Movement / Escalation

- **Action:** The attacker enumerates Active Directory, harvests cached credentials, and compromises ad-dc-01.
- **MedDefense Weakness:** Flat 10.10.0.0/16 network, weak internal monitoring (C-012), and insufficient privileged access controls.

### Step 4 – Objective Execution

- **Action:** Domain administrator privileges are used to distribute ransomware via Group Policy and disable security controls.
- **Data/System Affected:** Active Directory, Windows workstations, EHR servers, file shares, and authentication services.

### Step 5 – Impact

- **Business Impact:** Hospital-wide outage, inability to authenticate users, cancelled appointments, delayed patient treatment, HIPAA breach notifications, regulatory penalties, and major financial losses.
- **CIA Pillars:**
  - **Confidentiality:** Credential theft and sensitive data exposure.
  - **Integrity:** Directory objects and policies modified.
  - **Availability:** Organization-wide service disruption.

**Gaps Exploited:**

- Gap G-001: Limited MFA deployment.
- Gap G-002: Weak centralized logging/SIEM capability.
- Gap G-003: Flat internal network architecture.
- Gap G-005: Weak privileged account management.

**Break Points:**

- **Step 1:** Organization-wide MFA and phishing-resistant authentication could prevent credential theft.
- **Step 3:** Centralized monitoring (C-012 improvement), privileged access management, and network segmentation could detect or stop lateral movement before domain compromise.

---

## Kill Chain #2: VPN Exploit to EHR Database Ransomware

**Threat Actor:** Ransomware operator exploiting vulnerable perimeter infrastructure.

**Target Asset:** A-002 ehr-db-01 (EHR Database)

**Expected Impact:** Encryption of patient records and disruption of clinical operations. Primarily affects **Availability** and **Integrity**.

### Step 1 – Initial Access

- **Vector:** Exploitation of an unpatched FortiGate VPN vulnerability.
- **Surface:** External
- **Detail:** The attacker exploits a known FortiOS vulnerability to obtain unauthorized VPN access.

### Step 2 – Establish Foothold

- **Action:** Internal reconnaissance identifies application servers, databases, and Active Directory.
- **MedDefense Weakness:** Broad internal network visibility and weak detective controls.

### Step 3 – Lateral Movement / Escalation

- **Action:** The attacker pivots from the VPN session to ehr-srv-01 and then accesses ehr-db-01 through exposed PostgreSQL connectivity.
- **MedDefense Weakness:** No meaningful network segmentation and overly permissive database exposure.

### Step 4 – Objective Execution

- **Action:** Patient databases are encrypted and backup systems targeted.
- **Data/System Affected:** EHR database, EHR application, backup repository.

### Step 5 – Impact

- **Business Impact:** Loss of access to approximately 50,000 patient records, interruption of clinical care, cancelled procedures, manual charting, and potential ransom payment.
- **CIA Pillars:**
  - **Availability:** Clinical systems unavailable.
  - **Integrity:** Database contents encrypted or corrupted.
  - **Confidentiality:** Data may be stolen before encryption.

**Gaps Exploited:**

- Gap G-003: Flat network.
- Gap G-004: Broad database exposure.
- Gap G-006: Weak backup strategy (same-site storage).
- Gap G-002: Weak monitoring.

**Break Points:**

- **Step 1:** Timely FortiGate patch management and MFA-protected VPN access.
- **Step 3:** Internal segmentation (C-015) restricting database access only to the EHR application tier.
- **Step 4:** Offline/off-site backups and immutable backup storage could prevent catastrophic recovery failure.

---

## Kill Chain #3: Supply Chain Compromise of MedTech Solutions

**Threat Actor:** Advanced persistent threat (APT) compromising a trusted third-party vendor.

**Target Asset:** A-001 ehr-srv-01 (EHR Application Server)

**Expected Impact:** Unauthorized access to clinical applications and patient records. Primarily affects **Confidentiality** and **Integrity**.

### Step 1 – Initial Access

- **Vector:** Supply chain compromise.
- **Surface:** External
- **Detail:** Attackers compromise MedTech Solutions and steal credentials used for remote EHR maintenance.

### Step 2 – Establish Foothold

- **Action:** Legitimate vendor credentials are used to connect to the EHR server through approved maintenance channels.
- **MedDefense Weakness:** Trusted vendor access with limited continuous monitoring.

### Step 3 – Lateral Movement / Escalation

- **Action:** The attacker harvests credentials from the application server and expands into Active Directory and database systems.
- **MedDefense Weakness:** Flat network and insufficient segmentation between administrative systems.

### Step 4 – Objective Execution

- **Action:** Large-scale exfiltration of patient records and deployment of persistence mechanisms.
- **Data/System Affected:** EHR application, patient records, authentication infrastructure.

### Step 5 – Impact

- **Business Impact:** HIPAA reportable breach, regulatory investigations, patient notification costs, reputational damage, and operational disruption.
- **CIA Pillars:**
  - **Confidentiality:** Massive PHI disclosure.
  - **Integrity:** Patient records may be altered.
  - **Availability:** Potential disruption if systems are sabotaged.

**Gaps Exploited:**

- Gap G-003: Lack of segmentation.
- Gap G-002: Weak logging.
- Gap G-005: Limited privileged access monitoring.
- Gap G-007: Vendor access governance gaps.

**Break Points:**

- **Step 2:** Vendor-specific MFA, just-in-time privileged access, and monitored maintenance sessions.
- **Step 3:** Network segmentation and behavioral monitoring to detect abnormal vendor activity.

---

## Kill Chain #4: Shared Radiology Credentials to Legacy MRI Workstation

**Threat Actor:** Malicious insider or external attacker using stolen shared credentials.

**Target Asset:** A-021 MRI-CTRL-WS (Windows XP MRI Control Workstation)

**Expected Impact:** Disruption of diagnostic imaging and potential compromise of patient imaging data. Primarily affects **Availability** and **Integrity**.

### Step 1 – Initial Access

- **Vector:** Shared credentials ("raduser/radiology1").
- **Surface:** Human/Internal
- **Detail:** The attacker obtains shared Radiology credentials through observation, phishing, or insider knowledge.

### Step 2 – Establish Foothold

- **Action:** The attacker authenticates to the MRI workstation using legitimate shared credentials.
- **MedDefense Weakness:** Shared accounts eliminate accountability and prevent effective auditing.

### Step 3 – Lateral Movement / Escalation

- **Action:** The attacker exploits Windows XP vulnerabilities to gain local administrative privileges and pivot toward PACS infrastructure.
- **MedDefense Weakness:** End-of-life operating system and flat network connectivity.

### Step 4 – Objective Execution

- **Action:** MRI studies are altered, deleted, or prevented from reaching PACS.
- **Data/System Affected:** MRI workstation, PACS server, diagnostic imaging workflows.

### Step 5 – Impact

- **Business Impact:** Delayed diagnoses, cancelled imaging appointments, patient safety concerns, and operational disruption in Radiology.
- **CIA Pillars:**
  - **Integrity:** Diagnostic images manipulated.
  - **Availability:** MRI services disrupted.
  - **Confidentiality:** Imaging data may be copied.

**Gaps Exploited:**

- Gap G-003: Flat network.
- Gap G-008: Shared accounts.
- Gap G-009: Legacy Windows XP system.
- Gap G-002: Weak audit logging.

**Break Points:**

- **Step 1:** Eliminate shared accounts and enforce unique user authentication (C-017).
- **Step 3:** MRI segmentation (C-015), IDS monitoring (C-016), and strict access controls could prevent movement beyond the workstation.

---

## Kill Chain #5: Business Email Compromise Targeting Finance

**Threat Actor:** Business Email Compromise (BEC) fraud group.

**Target Asset:** A-033 Microsoft 365 Tenant and Finance Department

**Expected Impact:** Financial fraud, credential theft, and possible expansion into broader enterprise compromise. Primarily affects **Integrity** and **Confidentiality**.

### Step 1 – Initial Access

- **Vector:** CEO impersonation email requesting an urgent confidential wire transfer.
- **Surface:** Human
- **Detail:** The CFO receives a spoofed email appearing to originate from the CEO requesting an immediate transfer.

### Step 2 – Establish Foothold

- **Action:** The attacker gains the CFO's trust and may also capture Microsoft 365 credentials through a fake login page.
- **MedDefense Weakness:** Limited phishing resistance and incomplete MFA deployment.

### Step 3 – Lateral Movement / Escalation

- **Action:** Compromised Microsoft 365 accounts are used to send additional internal phishing emails and harvest more credentials.
- **MedDefense Weakness:** Organization-wide reliance on Microsoft 365 identities without comprehensive MFA.

### Step 4 – Objective Execution

- **Action:** Fraudulent wire transfers are completed while mailbox rules hide communications from finance staff.
- **Data/System Affected:** Microsoft 365 tenant, executive email accounts, finance operations.

### Step 5 – Impact

- **Business Impact:** Direct financial loss, executive impersonation, business disruption, reputational damage, and possible compromise of sensitive communications.
- **CIA Pillars:**
  - **Integrity:** Financial processes manipulated.
  - **Confidentiality:** Executive communications exposed.
  - **Availability:** Email workflows disrupted through malicious mailbox rules.

**Gaps Exploited:**

- Gap G-001: Limited MFA deployment.
- Gap G-010: Lack of formal wire-transfer verification procedures.
- Gap G-002: Weak monitoring of cloud account activity.

**Break Points:**

- **Step 1:** Security awareness training (C-011), email authentication (SPF, DKIM, DMARC), and anti-phishing protections.
- **Step 2:** Organization-wide MFA and conditional access policies would significantly reduce account compromise.
- **Step 4:** Mandatory out-of-band verification for financial transfers would prevent fraudulent payments even if email is compromised.