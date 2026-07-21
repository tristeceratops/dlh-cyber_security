# The Validation Plan

## Introduction

### Goal
Design a post-remediation validation and continuous monitoring strategy.

### Context
Patching is not the end. Verification is the end. A patch that was deployed but failed silently is worse than no patch at all because everyone thinks the problem is solved.

## Answer

# MedDefense Health Systems - Vulnerability Management Validation Plan

## 1. Post-Patch Verification

| Immediate Remediation | Verification Test | Expected Result |
|---|---|---|
| GAP-016 - Internet-facing vulnerabilities (VPN, portal, exposed services) | Run OpenVAS rescan on affected hosts. Verify service versions, TLS configuration, and exposed ports. Confirm known vulnerable versions are removed. | Vulnerability is no longer detected and exposed services run supported, secure versions. |
| GAP-017 - Missing MFA for VPN, EHR, cloud and privileged access | Attempt login using only username/password. Review MFA enrollment and authentication logs. | Password-only authentication fails; MFA is enforced for all required accounts. |
| GAP-001 - Unattended EHR workstation sessions | Leave a clinical workstation inactive for the configured timeout period. Verify automatic lock and forced reauthentication. | Open sessions are automatically locked and patient records cannot be accessed by unauthorized users. |

---

## 2. Compensating Control Validation

### MRI Control Workstation (Windows XP)

Controls:
- Network segmentation.
- Restricted administrative access.
- IDS monitoring.
- Physical security restrictions.

Validation:
- Perform a network scan from unauthorized VLANs and confirm the MRI workstation cannot be reached.
- Review firewall rules and confirm only required MRI/PACS communication is allowed.
- Generate test traffic and verify IDS alerts are produced.
- Review access permissions quarterly.

Expected Result:
The MRI workstation remains isolated and monitored despite the unsupported operating system.

Residual Risk:
The workstation remains vulnerable because Windows XP cannot receive normal security updates.

---

### Medical IoT Devices (BD Alaris and Philips IntelliVue)

Controls:
- Network isolation.
- Vendor security management.
- Restricted device access.

Validation:
- Scan medical device VLANs and confirm only approved ports are accessible.
- Verify default credentials have been replaced.
- Compare installed firmware versions with vendor security bulletins.
- Review administrator access lists.

Expected Result:
Only authorized systems and users can interact with medical device management functions.

Residual Risk:
Medical devices remain dependent on vendor updates and clinical availability requirements.

---

## 3. Rescan Schedule

Recommended frequency:

| Asset Type | Frequency |
|---|---|
| Internet-facing systems (VPN, portal, firewall) | Weekly |
| Critical clinical assets (EHR, AD, MRI, PACS) | Weekly |
| Internal servers and workstations | Monthly |
| After major changes or patches | Immediate targeted scan |

Justification:

MedDefense operates critical healthcare systems where delayed detection can affect patient care. Weekly scanning of high-risk assets provides faster detection while limiting operational disruption.

---

## 4. Continuous Intelligence

MedDefense should integrate external security intelligence into the vulnerability process.

Sources:
- CISA KEV alerts.
- Vendor security advisories.
- Threat intelligence feeds.
- Healthcare sector alerts.

Process:

1. Security Analyst reviews new vulnerabilities and alerts.
2. Affected MedDefense assets are identified.
3. Vulnerabilities are prioritized using:
   - Exploit availability.
   - Asset criticality.
   - Internet exposure.
   - Business impact.
4. IT Operations or vendors apply remediation.
5. Security validates the fix and updates the risk register.

Example:
A new CISA KEV entry affecting the FortiGate VPN would trigger immediate asset review, emergency mitigation if exposed, patching, and validation scanning.

---

## 5. Continuous Vulnerability Management Lifecycle

| Step | Responsible Team | Activities |
|---|---|---|
| Scan | Security Analyst | Run OpenVAS scans, collect findings, identify affected systems. |
| Triage | Security Analyst | Validate findings, remove false positives, classify severity. |
| Prioritize | Security Analyst + Management | Evaluate CVSS, asset criticality, threat intelligence, and business impact. |
| Remediate | IT Operations / Vendor | Apply patches, change configurations, deploy compensating controls. |
| Validate | Security Analyst | Rescan systems, test fixes, confirm controls work. |
| Repeat | Security + Management | Continue monitoring, update priorities, improve security posture. |

---

## Final Recommendation

MedDefense should move from periodic vulnerability scanning to a continuous vulnerability management process. Weekly scanning of critical systems, integration of threat intelligence, rapid remediation of exploited vulnerabilities, and validation testing will reduce the probability of attackers exploiting known weaknesses before defenses are improved.