# The Insider File

## Introduction

### Goal
Distinguish malicious from negligent insider threats, identify behavioral indicators and connect each scenario to existing control gaps.

### Context
Not every threat comes through the firewall. James Chen brings this up over coffee: "When the Board hears 'cybersecurity,' they picture a hoodie-wearing hacker in a dark room. They do not picture a billing clerk who copies patient records to a USB drive because she's angry about being passed over for a promotion. But our incident log from last year tells a different story."

The insider threat is particularly dangerous in healthcare because clinical staff need broad access to patient data to do their jobs. The challenge is not restricting access, it is detecting when legitimate access becomes illegitimate use.

## Answer

# Insider Threat Assessment – MedDefense

## Scenario 1 – The Shared Login

### Classification

**Negligent**

Although there is no evidence of malicious intent, the routine use of shared credentials and failure to log out between patients creates an environment where unauthorized access cannot be attributed to an individual user. The practice violates basic accountability requirements and significantly increases insider risk.

### Behavioral Indicators

- Multiple users authenticating with the same account throughout the day.
- Continuous login sessions with no user logoff events.
- Simultaneous or overlapping activity from different PACS workstations using identical credentials.

### Existing Control (from Project 1x00)

- **C-017 – Strict Access Control and Privileged Account Management (Weak)**
- **C-012 – System and Security Logging (Weak)**

While these controls should enforce individual accountability, they are ineffective because authentication is shared and logging cannot identify individual users.

### Gap Exploited (from Project 1x00)

**GAP-018 – Shared PACS credentials eliminate accountability in Radiology**

This gap was specifically identified in the Gap Analysis. It prevents reliable auditing of imaging access and makes insider investigations extremely difficult.

### Recommended Mitigation

Implement **individual user accounts with role-based access control** for every radiology technician, combined with automatic workstation locking after periods of inactivity. Eliminate all shared clinical accounts.

---

## Scenario 2 – The Ghost Account

### Classification

**Negligent**

The continued use of a contractor account after contract termination resulted from inadequate identity lifecycle management rather than deliberate insider abuse by MedDefense personnel. However, the subsequent off-hours authentications represent potentially malicious activity enabled by administrative negligence.

### Behavioral Indicators

- Successful VPN authentication after employee or contractor termination.
- Off-hours VPN logins from dormant accounts.
- Accounts remaining active despite HR termination records.

### Existing Control (from Project 1x00)

- **C-005 – Password Policy**
- **C-006 – Account Lockout Policy**

Neither control addresses timely account deprovisioning.

### Gap Exploited (from Project 1x00)

**GAP-013 – Offboarding is manual and vulnerable to retained access**

This scenario directly mirrors **Incident F** identified during the 1x00 incident review and demonstrates the operational impact of delayed account removal.

### Recommended Mitigation

Implement **automated identity lifecycle management** that integrates HR termination events with Active Directory, VPN, Microsoft 365, and other critical systems to disable accounts immediately upon separation.

---

## Scenario 3 – The Personal NAS

### Classification

**Negligent**

Dr. Patel appears motivated by convenience and research productivity rather than malicious intent. Nevertheless, copying regulated patient information onto an unmanaged storage device creates significant security and compliance exposure.

### Behavioral Indicators

- Unknown storage device appearing during network asset discovery.
- Large file transfers between the EHR environment and an unmanaged device.
- Persistent network communications from an asset absent from the official Asset Registry.

### Existing Control (from Project 1x00)

No existing control adequately governs this scenario.

The device exists outside the scope of:

- **C-007 – Endpoint Protection**
- **C-008 – Scheduled Backups**
- **C-012 – System and Security Logging**

### Gap Exploited (from Project 1x00)

**GAP-009 – Personal NAS in Cardiology stores unmanaged research data**

This finding was documented in both the **Gap Analysis** and **Shadow Systems Assessment**, where the device was added to the Asset Registry as **A-034 DrPatel-Personal-NAS (Shadow IT)**.

### Recommended Mitigation

Implement a **formal Shadow IT governance policy** supported by network access control (NAC) and approved research storage. Personal storage devices should be prohibited from connecting to clinical networks.

---

## Scenario 4 – The Curious Employee

### Classification

**Malicious**

Although the employee did not alter medical records, deliberately accessing a patient's information without a legitimate clinical purpose constitutes intentional misuse of authorized access. Disclosing the information to another individual further demonstrates deliberate policy violation and creates a reportable privacy breach.

### Behavioral Indicators

- Access to high-profile patient records unrelated to assigned duties.
- Repeated access to records without corresponding clinical workflow.
- Access occurring shortly before external disclosure or media attention.

### Existing Control (from Project 1x00)

- **C-012 – System and Security Logging (Weak)**
- **C-011 – Security Awareness Training (Adequate)**

Logging may record access events, but MedDefense lacks effective monitoring capable of identifying inappropriate viewing of patient records in real time.

### Gap Exploited (from Project 1x00)

**GAP-014 – Sensitive data exports lack DLP and behavioral monitoring**

Although the incident involves viewing rather than exporting records, the underlying weakness remains insufficient behavioral monitoring of legitimate user activity involving sensitive patient information.

### Recommended Mitigation

Deploy **User and Entity Behavior Analytics (UEBA)** with automated alerts for abnormal EHR access patterns, particularly access to VIP patients, celebrities, employees, or individuals outside a user's normal clinical responsibilities.

---

## Scenario 5 – The Overworked Admin

### Classification

**Negligent**

The administrator intended to improve operational efficiency rather than facilitate unauthorized access. However, storing Domain Administrator credentials in plaintext and distributing them through email creates a critical security exposure affecting the organization's identity infrastructure.

### Behavioral Indicators

- Administrative scripts containing embedded passwords.
- Domain Administrator credentials stored in plaintext files.
- Administrative scripts transmitted through standard email rather than secure repositories.

### Existing Control (from Project 1x00)

- **C-017 – Strict Access Control and Privileged Account Management (Weak)**

This control should prohibit insecure credential handling but is insufficiently implemented.

### Gap Exploited (from Project 1x00)

**GAP-021 – Change management is informal and ungoverned**

The lack of structured administrative procedures and secure development practices allowed privileged credentials to be handled outside approved processes.

### Recommended Mitigation

Implement a **Privileged Access Management (PAM)** solution combined with secure scripting standards that eliminate embedded credentials through managed service accounts or credential vault integration.

---

# Pattern Assessment

The insider threat at MedDefense is elevated because the organization depends heavily on trust-based operational practices while lacking the detective controls needed to identify misuse of legitimate access. The **Data Map** shows that highly sensitive Protected Health Information is distributed across the EHR, PACS, billing systems, research storage, Microsoft 365, and multiple departmental workflows, giving many employees legitimate access to regulated information. At the same time, the **Gap Analysis** identifies systemic weaknesses including **GAP-004 (No centralized security monitoring or SIEM)**, **GAP-013 (Manual offboarding)**, **GAP-014 (No DLP or behavioral monitoring)**, and **GAP-018 (Shared PACS credentials)**. The **Control Matrix** further demonstrates that detective controls (C-002, C-012, and C-016) are consistently rated **Weak**, meaning suspicious insider activity is unlikely to be identified before significant damage occurs. Combined with the Shadow IT findings—particularly the unmanaged Cardiology NAS and other ungoverned assets—the environment provides numerous opportunities for legitimate access to become unauthorized use without timely detection. Strengthening identity governance, centralized monitoring, privileged access management, and user behavior analytics should therefore be considered strategic priorities alongside traditional external cybersecurity defenses.