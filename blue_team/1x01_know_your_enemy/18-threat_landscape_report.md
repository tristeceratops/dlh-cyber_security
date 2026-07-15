# The Threat Landscape Report

## Introduction

### Goal
Produce a professional-grade Threat Landscape Report suitable for executive review and operational use.

### Context
This is the companion document to the Security Posture Assessment you produced in Project 0x00. Together, they form the complete picture: what MedDefense looks like from the inside (posture) and what it looks like from the outside (threats). The Board will read them side by side.

## Answer

# MedDefense Health Systems - Threat Landscape Report

## 1. Executive Summary

Healthcare remains one of the highest-value targets for cyber attackers because it combines regulated patient data, life-critical systems, operational urgency, and a large attack surface of users, devices, and third parties. MedDefense's threat profile is primarily driven by ransomware operators, credential-based attacks, and exploitation of weak internal segmentation.

The single most dangerous threat is a ransomware group using stolen credentials or an unpatched internet-facing system (especially VPN/firewall infrastructure), moving laterally through the flat 10.10.0.0/16 network, compromising Active Directory, and encrypting EHR, PACS, and business systems.

Top recommendations:
1. Deploy MFA across VPN, EHR, cloud services, and privileged accounts (GAP-017).
2. Implement network segmentation and restrict lateral movement paths (GAP-006).
3. Establish centralized monitoring through MDR/SIEM capability (GAP-004).

The Board should view cybersecurity as patient-care resilience. The main risk is not a single failed control, but an attacker entering through one weakness and reaching multiple critical systems before detection.

---

# 2. Scope and Methodology

## Intelligence Sources Used

Analysis used:
- MedDefense Asset Registry and Data Map.
- Control Matrix and Gap Analysis from 1x00.
- Threat actors from T6.
- Attack vectors and kill chains from T10.
- STRIDE analysis from T11/T12.
- Threat scenarios from T14.
- Threat Priority Assessment from T16.
- Healthcare ransomware and breach trends.

## Analytical Frameworks

Applied frameworks:
- STRIDE for systematic threat identification.
- MITRE ATT&CK concepts for attacker behavior.
- Cyber Kill Chain analysis for attack progression.
- Gap-threat correlation to prioritize defensive investment.

This report extends the Security Posture Assessment by answering not only "what is weak?" but "which attackers will exploit those weaknesses?"

---

# 3. Healthcare Sector Threat Overview

Healthcare is targeted because:

1. Patient records have high value on criminal markets.
2. Hospitals cannot tolerate downtime because clinical operations continue.
3. Healthcare environments contain legacy medical devices and unsupported systems.
4. Large user populations increase phishing and credential theft opportunities.

Current threat trends:
- Ransomware groups increasingly combine data theft with encryption.
- Attackers prioritize VPN exploitation and stolen credentials.
- Healthcare organizations face increasing third-party and supply-chain risk.
- Medical devices create persistent security challenges.

MedDefense matches these sector risk patterns:
- No MFA at scale (GAP-017).
- Flat internal network (GAP-006).
- Limited monitoring (GAP-004).
- Legacy Windows XP MRI workstation (GAP-003).
- Weak recovery resilience (GAP-005).

---

# 4. MedDefense Threat Actor Profiles

| Rank | Actor | Likelihood | Priority |
|---|---|---|---|
| 1 | Ransomware Groups | Critical | Critical |
| 2 | Cybercriminal Credential Theft Groups | High | Critical |
| 3 | Malicious/Negligent Insiders | High | High |
| 4 | Nation-State Actors | Medium | High |
| 5 | Hacktivists | Low | Medium |
| 6 | Opportunistic Attackers | Medium | Medium |

## 1. Ransomware Groups

Likelihood: Critical.

Reason:
Healthcare ransomware remains common because downtime creates pressure to pay.

MedDefense exposure:
- GAP-006 allows lateral movement.
- GAP-005 limits recovery.
- GAP-016 exposes possible initial access points.
- GAP-004 delays detection.

Likely attack:
Exploit VPN/firewall weakness → steal credentials → move through network → compromise AD → encrypt EHR/PACS.

## 2. Credential Theft Groups

Likelihood: High.

Reason:
Phishing and password reuse remain effective healthcare attack methods.

MedDefense exposure:
- GAP-017 lacks MFA.
- GAP-013 allows retained access.
- GAP-004 limits detection.

Likely attack:
Spear phishing clinician → obtain Microsoft 365/VPN credentials → access EHR.

## 3. Insider Threats

Likelihood: High.

Reason:
Healthcare employees already have legitimate access to sensitive records.

MedDefense exposure:
- GAP-001 unattended EHR sessions.
- GAP-013 weak offboarding.
- GAP-014 missing behavioral monitoring.

Likely attack:
Employee or former employee accesses/export patient records without detection.

---

# 5. Attack Surface Analysis

## External Surface

Key exposures:
- FortiGate-100F VPN.
- Patient portal.
- Microsoft 365.
- Westside Clinic connectivity.

Primary risks:
- VPN exploitation.
- Credential theft.
- Public application compromise.

Evidence:
GAP-016 identifies missing vulnerability management.

## Internal Surface

Key exposures:
- Flat 10.10.0.0/16 network.
- Active Directory.
- EHR database.
- PACS.

Primary risks:
- Lateral movement.
- Privilege escalation.
- Data theft.

Evidence:
GAP-006 enables broad attacker movement after initial compromise.

## Human Surface

Key exposures:
- Clinicians.
- Contractors.
- Remote users.

Primary risks:
- Phishing.
- Password compromise.
- Accidental disclosure.

Evidence:
GAP-017 and GAP-013 show identity weaknesses.

---

# 6. Critical Attack Paths

## Kill Chain 1: Ransomware Operation

Entry:
VPN exploit or phishing.

Path:
FortiGate → internal network → AD → EHR/PACS → encryption.

Break points:
MFA, segmentation, MDR monitoring.

## Kill Chain 2: Credential Theft

Entry:
Spear phishing.

Path:
User account → Microsoft 365 → VPN → EHR.

Break points:
MFA, phishing training, anomaly detection.

## Kill Chain 3: Legacy Medical Device Compromise

Entry:
Windows XP MRI workstation.

Path:
MRI workstation → PACS → hospital network.

Break points:
Isolation, monitoring, replacement.

## Kill Chain 4: Insider Data Theft

Entry:
Legitimate account.

Path:
EHR/PACS → bulk export → external storage.

Break points:
DLP, logging, access reviews.

## Kill Chain 5: Web Exploitation

Entry:
Patient portal vulnerability.

Path:
Web server → internal services.

Break points:
Patch management, segmentation.

Most connected assets:
1. Active Directory.
2. FortiGate firewall.
3. EHR environment.

Most versatile attack vectors:
1. Stolen credentials.
2. Network lateral movement.
3. Phishing.

---

# 7. STRIDE Analysis Summary

## EHR System

Top findings:

Spoofing:
- Stolen VPN/M365 credentials allow unauthorized EHR access.

Tampering:
- Attackers modifying medication or allergy records creates patient safety risk.

Repudiation:
- Missing centralized logs prevent reliable investigation.

Information Disclosure:
- Broad database exposure enables PHI theft.

Denial of Service:
- Ransomware could stop clinical operations.

Elevation:
- Compromised accounts can escalate through AD.

Key evidence:
T11 identified EHR as vulnerable through GAP-001, GAP-002, GAP-004, GAP-006, and GAP-017.

## PACS

Top threats:
- Shared credentials.
- Legacy MRI workstation compromise.
- Ransomware disruption.

Primary gaps:
GAP-003 and GAP-018.

## Active Directory

Top threats:
- Domain compromise.
- Privilege escalation.
- Credential theft.

Primary gaps:
GAP-017 and GAP-004.

## Network Infrastructure

Top threats:
- VPN compromise.
- Configuration tampering.
- Lateral movement.

Primary gap:
GAP-006.

---

# 8. Threat Scenarios

## Scenario 1: Ransomware Attack

Attack:
Criminal group exploits VPN weakness and encrypts EHR, PACS, and billing.

Impact:
- Patient-care disruption.
- Regulatory reporting.
- Financial loss.

Relevant gaps:
GAP-005, GAP-006, GAP-016.

## Scenario 2: Clinical Research Expansion

Attack:
Research data becomes targeted by espionage actors and criminal groups.

Impact:
- Intellectual property theft.
- Patient privacy violations.

New risks:
Need stronger research-data governance.

## Scenario 3: Public Ransomware Disclosure

Attack:
Media exposure increases reputation pressure and attacker interest.

Impact:
- Loss of patient trust.
- Increased regulatory scrutiny.

Relevant gaps:
GAP-012 and GAP-014.

---

# 9. Gap-Threat Correlation

Threat analysis changed priorities because some gaps enable multiple attack paths.

## Critical Three Gaps

## GAP-006: Flat Network and Permissive Remote Access

Appears across:
- Ransomware.
- Credential theft.
- Medical device compromise.

Closing it disrupts the largest number of attack chains.

## GAP-017: Missing MFA at Scale

Appears across:
- Phishing.
- Insider misuse.
- Remote compromise.

Stops stolen passwords from becoming full access.

## GAP-004: No Centralized Monitoring

Appears across:
- Every major threat.

Without detection, preventive controls can fail silently.

## The Surprise

GAP-011 (Raspberry Pi monitor) was originally Medium.

Threat analysis shows it could become an internal attacker foothold because it bypasses enterprise management and monitoring.

It remains lower priority than EHR and identity gaps, but its role as an unmanaged network device increases concern.

---

# 10. Prioritized Recommendations

## Threat 1: Ransomware Groups

Actor:
Cybercriminal ransomware operators.

Vector:
VPN exploitation and stolen credentials.

Target:
EHR, AD, PACS.

Likelihood:
Critical due to healthcare targeting and MedDefense gaps.

Impact:
Critical because clinical operations depend on these systems.

Key gap:
GAP-006.

Action:
Implement network segmentation and restrict VPN access.
Timeline: Long-term.

---

## Threat 2: Credential Theft

Actor:
Cybercriminal access brokers.

Vector:
Phishing.

Target:
VPN, Microsoft 365, EHR.

Likelihood:
High due to no MFA.

Impact:
Critical due to patient data exposure.

Key gap:
GAP-017.

Action:
Deploy MFA enterprise-wide.
Timeline: Short-term.

---

## Threat 3: Undetected Intrusion

Actor:
Ransomware groups and advanced attackers.

Vector:
Compromised account/device.

Target:
All critical systems.

Likelihood:
High.

Impact:
Critical because attackers can remain undetected.

Key gap:
GAP-004.

Action:
Deploy MDR/SOC monitoring.
Timeline: Short-term.

---

## Threat 4: Medical Device Compromise

Actor:
Cybercriminals and advanced attackers.

Vector:
Legacy MRI workstation.

Target:
MRI/PACS.

Likelihood:
High due to unsupported Windows XP.

Impact:
Critical due to patient-care dependency.

Key gap:
GAP-003.

Action:
Isolate legacy medical devices and create monitored access paths.
Timeline: Long-term.

---

## Threat 5: Insider Data Theft

Actor:
Malicious or negligent insiders.

Vector:
Legitimate access.

Target:
EHR/PACS/data exports.

Likelihood:
High.

Impact:
High/Critical due to PHI exposure.

Key gap:
GAP-014.

Action:
Deploy DLP and behavioral monitoring.
Timeline: Long-term.

---

# Strategic Recommendation

If MedDefense can fund only two initiatives next quarter, the highest-value investments are MFA deployment and outsourced security monitoring. MFA directly reduces the most common entry path: stolen credentials. MDR monitoring provides visibility across EHR, AD, network, and medical systems, reducing attacker dwell time. Together, these two initiatives address the highest-probability attacks while improving detection and response before larger segmentation and architecture projects are completed.