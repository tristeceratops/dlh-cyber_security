# The CVSS Contextualizer

## Introduction

### Goal
Recalculate CVSS scores with environmental metrics to produce threat-informed, business-contextualized priorities.

### Context
This is the keystone task of the project. Everything converges here: CVSS technical scoring, asset criticality from 1x00, kill chain positioning from 1x01 and exploit availability from earlier in this project.

Open the NIST CVSS Calculator one more time.

## Answer

# Contextual Priority Reassessment (Top 8 Actionable Findings)

## Finding 001 – CVE-2021-44790 (Apache mod_lua RCE)

**CVSS Base Score:** 9.8

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** A-004 billing-srv-01
- **CIA Rating:** High / High / Medium
- **Criticality Impact on Priority:** Raises urgency because the server stores restricted billing data.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** Vulnerable Software Exploit
- **Chain Role:** Initial access
- **Kill Chain Impact on Priority:** Raises urgency.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 5/5
- **CISA KEV:** No
- **Exploit Impact on Priority:** Raises urgency due to public RCE exploits.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** Firewall, logging, backups
- **Control Impact on Priority:** Limited mitigation because the internal network is flat.

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** High confidentiality requirement, high integrity requirement, flat internal network.
- **Adjusted Score:** **10.0**

### Final Priority
**Critical**

**Final Justification:** Public RCE on a high-value billing server with unrestricted lateral movement makes exploitation highly impactful despite existing perimeter controls.

---

## Finding 003 – PostgreSQL Broad Network Exposure

**CVSS Base Score:** Scanner Critical (N/A)

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** A-002 ehr-db-01
- **CIA Rating:** Critical / Critical / High
- **Criticality Impact on Priority:** Strongly raises urgency.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** VPN Exploit, Vulnerable Software Exploit
- **Chain Role:** Lateral movement / Final target
- **Kill Chain Impact on Priority:** Raises urgency.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 4/5
- **CISA KEV:** N/A
- **Exploit Impact on Priority:** High because any compromised host can connect.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** Authentication, firewall
- **Control Impact on Priority:** Weak due to missing segmentation (GAP-002).

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** Critical asset, unrestricted internal access.
- **Adjusted Score:** **9.8**

### Final Priority
**Critical**

**Final Justification:** The database stores all PHI and is reachable from the entire hospital network, making lateral movement extremely dangerous.

---

## Finding 004 – Windows XP MRI Workstation

**CVSS Base Score:** Critical (Multiple CVEs)

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** A-021 MRI-CTRL-WS
- **CIA Rating:** Critical / Critical / Critical
- **Criticality Impact on Priority:** Maximum increase.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** Vulnerable Software Exploit
- **Chain Role:** Initial access and lateral movement
- **Kill Chain Impact on Priority:** Raises urgency.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 5/5
- **CISA KEV:** Yes (EternalBlue, BlueKeep)
- **Exploit Impact on Priority:** Maximum increase.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** Segmentation planned, monitoring, physical security
- **Control Impact on Priority:** Partial mitigation only.

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** Patient safety requirement, EOL system.
- **Adjusted Score:** **10.0**

### Final Priority
**Critical**

**Final Justification:** The workstation is both patient-critical and permanently vulnerable because it cannot be fully patched.

---

## Finding 007 – LDAP Signing Disabled

**CVSS Base Score:** High (Scanner)

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** A-005 ad-dc-01
- **CIA Rating:** Critical / Critical / Critical
- **Criticality Impact on Priority:** Raises urgency.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** Phishing, VPN, Credential Abuse
- **Chain Role:** Privilege escalation
- **Kill Chain Impact on Priority:** Raises urgency.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 4/5
- **CISA KEV:** No
- **Exploit Impact on Priority:** Moderate increase.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** Password policy, logging
- **Control Impact on Priority:** Limited mitigation.

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** Critical identity infrastructure.
- **Adjusted Score:** **9.5**

### Final Priority
**Critical**

**Final Justification:** Compromise of Active Directory would affect every clinical and business system.

---

## Finding 010 – BD Alaris Infusion Pumps

**CVSS Base Score:** 7.5

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** A-024 BD Alaris Pump Fleet
- **CIA Rating:** Critical / Critical / Critical
- **Criticality Impact on Priority:** Strong increase.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** Vulnerable Software Exploit
- **Chain Role:** Initial access
- **Kill Chain Impact on Priority:** Raises urgency.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 4/5
- **CISA KEV:** No
- **Exploit Impact on Priority:** Increased by default credentials.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** Recommended VLAN isolation not implemented.
- **Control Impact on Priority:** No meaningful mitigation.

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** Patient safety impact.
- **Adjusted Score:** **9.6**

### Final Priority
**Critical**

**Final Justification:** Although the base CVSS is moderate, patient safety and default credentials significantly increase the real-world risk.

---

## Finding 016 – Philips IntelliVue Interfaces

**CVSS Base Score:** Medium (Scanner)

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** Medical IoT Fleet
- **CIA Rating:** Critical / High / High
- **Criticality Impact on Priority:** Raises urgency.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** Vulnerable Software Exploit
- **Chain Role:** Initial access
- **Kill Chain Impact on Priority:** Raises urgency.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 3/5
- **CISA KEV:** No
- **Exploit Impact on Priority:** Moderate increase.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** None beyond network trust.
- **Control Impact on Priority:** No reduction.

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** Medical device environment, flat network.
- **Adjusted Score:** **8.8**

### Final Priority
**High**

**Final Justification:** Exposure is amplified because every internal host can reach unauthenticated management interfaces.

---

## Finding 031 – CVE-2020-1938 (Ghostcat)

**CVSS Base Score:** 9.8

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** A-001 ehr-srv-01
- **CIA Rating:** Critical / Critical / Critical
- **Criticality Impact on Priority:** Maximum increase.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** Vulnerable Software Exploit
- **Chain Role:** Initial access
- **Kill Chain Impact on Priority:** Raises urgency.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 5/5
- **CISA KEV:** No
- **Exploit Impact on Priority:** Public exploit available.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** Firewall, logging
- **Control Impact on Priority:** Minimal because AJP is internally reachable.

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** Critical healthcare application, unrestricted internal access.
- **Adjusted Score:** **10.0**

### Final Priority
**Critical**

**Final Justification:** Exposure of EHR configuration and credentials can lead directly to compromise of patient records.

---

## Finding 002 – CVE-2019-0211 (Apache Privilege Escalation)

**CVSS Base Score:** 7.8

### Factor 1 – Asset Criticality (from 1x00)
- **Asset:** A-004 billing-srv-01
- **CIA Rating:** High / High / Medium
- **Criticality Impact on Priority:** Raises urgency.

### Factor 2 – Kill Chain Position (from 1x01)
- **Appears in Kill Chain(s):** Vulnerable Software Exploit
- **Chain Role:** Privilege escalation
- **Kill Chain Impact on Priority:** Raises urgency because it follows Finding 001.

### Factor 3 – Exploitability (from T4)
- **Exploitability Score:** 4/5
- **CISA KEV:** No
- **Exploit Impact on Priority:** High due to exploit chain.

### Factor 4 – Compensating Controls (from 1x00)
- **Existing Controls:** Logging and backups
- **Control Impact on Priority:** Limited mitigation.

### Environmental CVSS (recalculated)
- **Environmental Metrics Applied:** Chained exploitation with RCE.
- **Adjusted Score:** **9.4**

### Final Priority
**Critical**

**Final Justification:** While local by itself, it reliably completes the remote attack chain initiated by Finding 001.

---

# Priority Comparison Table

| Finding | CVSS Base | Adjusted Priority | Change Direction |
|---------|-----------|------------------|------------------|
| 001 | 9.8 | Critical (10.0) | Same |
| 003 | N/A (Critical) | Critical (9.8) | Same |
| 004 | Critical | Critical (10.0) | Same |
| 007 | High | Critical (9.5) | **Higher** |
| 010 | 7.5 | Critical (9.6) | **Higher** |
| 016 | Medium | High (8.8) | **Higher** |
| 031 | 9.8 | Critical (10.0) | Same |
| 002 | 7.8 | Critical (9.4) | **Higher** |

> **Significant changes:** Findings **002, 007, 010 and 016** increase in priority after contextual analysis because of asset criticality, flat network architecture, kill-chain relevance, and limited compensating controls.