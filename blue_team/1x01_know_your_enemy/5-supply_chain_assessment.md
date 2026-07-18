# The Supply Chain Question

## Introduction

### Goal
Map and evaluate third-party risk exposure across MedDefense's vendor ecosystem.

### Context
In December 2020, SolarWinds taught the world a lesson that most organizations still have not fully internalized: your security is only as strong as your least secure vendor. MedDefense does not operate in isolation. It depends on a network of technology providers, service contractors and building managers, each with some level of access to MedDefense's environment or data. If any of them is compromised, MedDefense inherits the consequences.

James Chen's question is specific: "If MedTech Solutions gets breached tomorrow, what happens to us ? They have maintenance access to our EHR server. What exactly can they reach ?"

## Answer

# Third-Party Risk Assessment – MedDefense

## Vendor: MedTech Solutions

**Service**

Third-party maintenance and support provider for the Electronic Health Record (EHR) platform. Annual contract value: **$145,000** with a **4-hour SLA** for production incidents.

**Access Type**

- Network access (remote maintenance)
- Application administration
- Server-level administrative access

**Access Scope**

MedTech Solutions has direct maintenance access to:

- **A-001 – ehr-srv-01 (EHR Application Server)**
- Indirect access to **A-002 – ehr-db-01 (PostgreSQL Database)**
- Patient records, clinical workflows, user authentication integration, application logs, and EHR configuration.

Because the EHR communicates with Active Directory and numerous clinical systems, compromise of the application server could become a pivot point into broader hospital infrastructure.

**Compromise Scenario**

If MedTech Solutions suffers a supply-chain compromise or one of its privileged support accounts is stolen, an attacker could authenticate directly to **ehr-srv-01**, install malware or a remote access tool, harvest credentials, move laterally toward **ad-dc-01**, and ultimately gain access to the EHR database and other critical hospital systems. Given MedDefense's flat network (**GAP-006**) and limited centralized monitoring (**GAP-004**), this activity could remain undetected long enough to facilitate ransomware deployment or large-scale patient data theft.

**Existing Controls**

- **C-001 – Perimeter Firewall**
- **C-003 – SSH Key-Based Authentication**
- **C-005 – Password Policy**
- **C-012 – System and Security Logging (Weak)**

These controls provide basic access protection but do not adequately monitor privileged vendor activity or restrict lateral movement once access is obtained.

**Risk Assessment**

**Critical**

This vendor maintains privileged access to MedDefense's most critical business system. Compromise could directly affect patient care, expose Protected Health Information (PHI), and provide an attacker with an initial foothold inside the hospital network.

---

## Vendor: Microsoft

**Service**

Microsoft 365 E3 cloud platform providing Exchange Online, SharePoint, OneDrive, Teams, and enterprise identity services.

**Access Type**

- Cloud application access
- Identity services
- Enterprise data hosting

**Access Scope**

Supports:

- **A-033 – Microsoft 365 Tenant**
- Organization-wide email
- SharePoint document repositories
- OneDrive files
- User identities and authentication
- Executive, HR, Finance, Legal, and Clinical collaboration data

If Entra ID is integrated with Active Directory, identity compromise could extend to on-premises systems.

**Compromise Scenario**

A compromise of Microsoft's cloud platform or MedDefense's Microsoft 365 administrative tenant could expose corporate email, confidential documents, executive communications, authentication tokens, and cloud identities. Attackers could leverage trusted accounts to launch Business Email Compromise (BEC), steal sensitive documents, or pivot into hybrid identity infrastructure.

**Existing Controls**

- **C-005 – Password Policy**
- **C-013 – MFA (limited deployment)**

Current protection is weakened because MFA has only been deployed for James Chen rather than organization-wide.

**Risk Assessment**

**High**

Microsoft itself maintains strong security, making provider compromise unlikely. However, the organization's heavy dependence on Microsoft 365 means tenant compromise or administrative credential theft would have enterprise-wide consequences.

---

## Vendor: Sophos

**Service**

Endpoint Detection and Endpoint Protection platform deployed across managed Windows systems.

**Access Type**

- Endpoint management
- Security agent administration
- Remote configuration and software deployment

**Access Scope**

Sophos agents are installed on:

- **A-017 – Central Windows Workstations**
- **A-018 – HQ Workstations**
- **A-019 – Laptop Fleet**
- Numerous managed Windows servers

The platform has authority to deploy software, modify endpoint security policies, quarantine files, and update endpoint configurations.

**Compromise Scenario**

If Sophos management infrastructure or administrative credentials were compromised, an attacker could disable endpoint protection, deploy malicious software through trusted update mechanisms, or weaken security policies before launching ransomware. This would significantly reduce MedDefense's ability to detect or stop endpoint compromise.

**Existing Controls**

- **C-007 – Endpoint Protection (Sophos)**
- **C-012 – System and Security Logging (Weak)**

While endpoint protection reduces ordinary malware risk, MedDefense has limited independent monitoring capable of identifying abuse of the management platform itself.

**Risk Assessment**

**High**

A trusted endpoint security platform possesses broad administrative authority. Although vendor compromise is relatively uncommon, the impact would extend to nearly every managed endpoint in the organization.

---

## Vendor: Siemens

**Service**

Manufacturer and maintenance provider for the Siemens MAGNETOM MRI system and associated Windows XP control workstation.

**Access Type**

- Application maintenance
- Physical maintenance
- Network access during service visits

**Access Scope**

Supports:

- **A-021 – MRI Control Workstation**
- **A-022 – Siemens MAGNETOM MRI**

Vendor engineers may perform firmware updates, diagnostics, and maintenance on the legacy Windows XP workstation that interfaces with PACS.

**Compromise Scenario**

If Siemens remote maintenance tools or engineer credentials were compromised, attackers could gain access to the Windows XP workstation, which already represents a high-risk legacy asset (**GAP-003**). Because the MRI workstation resides on MedDefense's largely flat network, attackers could move toward the PACS server and potentially other clinical infrastructure.

**Existing Controls**

- **C-015 – Network Segmentation and Firewall ACLs (Weak)**
- **C-016 – Network Intrusion Detection (Weak)**
- **C-017 – Privileged Access Management (Weak)**
- **C-018 – Physical Security Controls**

These compensating controls partially reduce exposure but remain weaker than a modern, fully supported architecture.

**Risk Assessment**

**High**

Although the scope is largely limited to Radiology, the combination of legacy operating systems and limited segmentation significantly increases the impact of any vendor-related compromise.

---

## Vendor: Greenfield Building Management

**Service**

Building management provider for Corporate HQ. Operates shared network infrastructure while providing MedDefense with a dedicated VLAN and physical facilities management.

**Access Type**

- Network infrastructure
- Physical infrastructure

**Access Scope**

Controls:

- Corporate HQ switching infrastructure
- Shared building network
- MedDefense VLAN
- Connectivity supporting site-to-site VPN to Central Hospital

While Greenfield does not directly administer MedDefense servers, it manages the infrastructure carrying HQ network traffic.

**Compromise Scenario**

If Greenfield's network management environment were compromised, attackers could potentially intercept traffic, attack MedDefense's HQ VLAN, manipulate network configurations, or establish a foothold leading toward the VPN connection to Central Hospital. The risk is amplified because the onboarding assessment identifies the HQ VPN ACLs as never having been formally audited.

**Existing Controls**

- **C-001 – Perimeter Firewall**
- **C-002 – Firewall Logging (Weak)**
- **C-014 – HID Badge Access System**

The environment lacks comprehensive visibility into third-party managed infrastructure.

**Risk Assessment**

**Medium**

Greenfield has limited direct access to patient systems, but compromise of shared network infrastructure could provide an indirect path into MedDefense's corporate environment and administrative users.