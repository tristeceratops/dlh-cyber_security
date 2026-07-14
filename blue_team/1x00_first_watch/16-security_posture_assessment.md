# The Security Posture Assessment

## Introduction

### Goal
Produce a professional-grade security posture assessment document suitable for executive review.

### Context
James Chen calls you into his office.

"Friday morning. Board meeting is Monday. I need the full report by end of day. This document will determine whether the Board approves the security budget increase I've been asking for since I was hired. If it's good, we get resources. If it's vague or unconvincing, we get another year of 'security is IT's problem.'"

"Make it count."

## Answer

## 1. Executive Summary

MedDefense has meaningful point controls in place, but the overall posture is not yet resilient enough for a healthcare organization that depends on electronic records, connected medical devices, and remote access. The core problem is not the absence of controls; it is the combination of flat or weakly segmented access, inconsistent identity controls, thin detection, and brittle recovery. In practical terms, a single stolen credential, unpatched internet-facing system, or unattended clinical workstation can still become a hospital-wide incident.

The single most critical finding is that MedDefense can be breached, moved through, and remain undetected because the environment still lacks strong segmentation, MFA at scale, and centralized monitoring. If nothing changes, the most likely outcome is not a dramatic single failure but a slow-moving event that disrupts patient care, exposes regulated data, and forces expensive recovery.

Top priorities are to enforce MFA and automated offboarding, harden exposed systems through patch governance and segmentation, and restore detection/recovery depth through outsourced monitoring and resilient backups. The recommended first-year plan fits within the $120,000 budget by using lower-cost process fixes, one outsourced monitoring service, and deferring the largest capital projects until next year.

## 2. Scope and Methodology

**What was assessed**

- Central Hospital core infrastructure, clinical systems, radiology/MRI workflow, medical IoT, business systems, Westside Clinic systems, Corporate HQ systems, cloud services, and identified shadow IT.
- Sensitive data categories including patient medical records, imaging, billing, HR, credentials, logs, backups, and internal documents.
- Existing security controls, control gaps, and treatment options across the documented environment.

**Sources used**

- Asset Registry, Control Inventory, Control Gaps, Compensating Controls, Data Map, Gap Analysis, Reality Check, Risk Decisions, Shadow Systems, and Predecessor Review.
- Physical assessment findings, incident classification, environment summary, and the network scan notes embedded in the project.
- Marcus Webb's draft assessment and the provided healthcare breach summaries used for validation.

**Limitations and assumptions**

- The assessment relies on project artifacts and documented observations rather than live penetration testing.
- Some inventory counts are approximate and reflect older administrative reports plus later scan evidence.
- Where systems were described as shadow IT or unmanaged, they were treated as real risks until formally brought under governance.
- The report assumes the documented controls and gaps are accurate unless later tasks showed a contradiction or missing context.

## 3. Asset Landscape

**Asset inventory summary**

MedDefense's current inventory contains 36 documented assets across seven major types. The environment is dominated by Central Hospital systems, with smaller but still material footprints at Westside Clinic, Corporate HQ, and in cloud-hosted services.

| Type | Count | Examples |
|---|---:|---|
| Servers | 11 | EHR server, domain controllers, file server, MRI control workstation, shadow servers |
| Data Stores | 3 | EHR database, backup NAS, Cardiology personal NAS |
| Applications | 4 | Web server/patient portal, EHR portal service, Microsoft 365 tenant, Marketing Google Drive |
| Network Devices | 5 | FortiGate firewall, Westside router, core switch, AP fleet, Raspberry Pi monitor |
| Endpoints | 5 | Clinical workstations, HQ workstations, laptops, thin clients |
| IoT Medical | 6 | MRI, PACS-related imaging, monitors, infusion pumps, CT, X-ray workstation |
| Physical Infrastructure | 2 | Nurse-call system, HID badge access system |

| Site / Primary Location | Count | Notes |
|---|---:|---|
| Central Hospital | 26 | Core clinical, radiology, network, and shadow systems |
| Westside Clinic | 4 | Clinic server, router, shadow host, imaging workstation |
| Corporate HQ | 2 | HQ workstation fleet and laptop fleet |
| Cloud / Internet-hosted | 3 | Patient portal, Microsoft 365 tenant, Marketing Google Drive |
| Mobile / Unassigned | 1 | Physician iPad fleet |

**Top 5 critical assets**

| Asset | Why it matters |
|---|---|
| [A-001 ehr-srv-01](./7-asset_registry.md) | Primary EHR application layer; loss or compromise would disrupt orders, results, and bedside workflows. |
| [A-002 ehr-db-01](./7-asset_registry.md) | System of record for the EHR; the most sensitive clinical data and downstream integrity dependency. |
| [A-005 ad-dc-01](./7-asset_registry.md) | Core identity service for the hospital; if it fails, users cannot authenticate cleanly into critical systems. |
| [A-021 MRI-CTRL-WS (WS-RAD-01)](./7-asset_registry.md) | Legacy MRI control path; unsupported, patient-critical, and the bridge to PACS transfer. |
| [A-013 FortiGate-100F](./7-asset_registry.md) | Perimeter control for the hospital network; if it is bypassed or misused, segmentation and access control collapse. |

**Data classification summary**

The sensitive-data profile is dominated by Restricted and Confidential information. Restricted data includes patient records, imaging, billing records, credentials, backups, and medical-device telemetry. Confidential data includes HR records, audit logs, strategic documents, and unmanaged research/marketing content. There is no meaningful evidence that the core sensitive-data set is safely confined to low-impact material; the organization is handling regulated data at multiple points of failure.

## 4. Current Security Controls

The formal control matrix documents 18 controls across technical, administrative, and physical categories. The environment is strongest where it has basic hardening and prevention, and weakest where it needs detection, recovery, and disciplined governance.

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---:|---:|---:|---:|---:|
| Technical | 6 | 3 | 1 | 0 | 0 |
| Administrative | 4 | 0 | 0 | 0 | 0 |
| Physical | 3 | 1 | 0 | 0 | 0 |

**Overall maturity assessment**

MedDefense is prevention-heavy and response-light. It has some strong foundational controls, including SSH key authentication on `ehr-srv-01`, password policy, account lockout, endpoint protection on managed Windows systems, and basic perimeter firewalling. However, those controls do not offset the organization’s weak segmentation, limited MFA, no centralized security monitoring, weak backup resilience, and inconsistent physical security around sensitive spaces.

**Key control effectiveness findings**

- Strong: SSH hardening on `ehr-srv-01`, root login disabled on Linux servers, and some managed endpoint protection.
- Adequate: perimeter firewalling, password policy, account lockout, visitor control, CCTV, and security training.
- Weak: logging without central review, backups without offsite immutability, HID badge access, MFA coverage, and the MRI compensating controls that substitute for a safe baseline architecture.

## 5. Gap Analysis

MedDefense's most important gaps fall into four repeating themes: exposed entry points, weak identity lifecycle control, missing detection, and brittle recovery. The table below lists the critical and high-priority issues first, followed by the one medium-priority issue that remains relevant.

### Critical Gaps

| Gap ID | Finding | Affected Assets | Potential Impact | Recommended Treatment |
|---|---|---|---|---|
| GAP-001 | Unattended EHR session at the nurse station | EHR server, clinical workstations | Live chart data can be viewed or altered at the point of care, causing patient-safety and HIPAA exposure. | Mitigate |
| GAP-003 | MRI control workstation remains a legacy, flat-network choke point | MRI control workstation, MRI scanner | Radiology downtime, lateral movement into clinical systems, and compromise of an unsupported legacy host. | Mitigate |
| GAP-004 | No centralized security monitoring or SIEM | All critical/high assets | Attackers can dwell for hours or days without timely detection. | Transfer |
| GAP-005 | Backups are not resilient enough for recovery | EHR, billing, identity, file services, PACS | Ransomware or site failure can destroy both production and recovery copies. | Mitigate |
| GAP-006 | Flat network and permissive remote access still expose critical systems | Firewall, core switch, web server, clinical and billing systems | One compromise can become a hospital-wide lateral movement event. | Mitigate |
| GAP-007 | Network closet and switch admin credentials are physically exposed | Core switch, firewall, internal segmentation | Unauthorized reconfiguration, interception, or outage of the core network. | Mitigate |
| GAP-012 | No formal incident response plan or tested breach playbooks | Critical and high assets across the enterprise | Containment becomes improvisation; legal/compliance handling slows down. | Mitigate |
| GAP-013 | Offboarding is manual and vulnerable to retained access | Domain controllers, VPN, EHR, cloud apps | Former staff can keep access long enough to download data or act as insiders. | Mitigate |
| GAP-014 | Sensitive data exports lack DLP and behavioral monitoring | EHR, billing, HR, Microsoft 365 | Large-scale exfiltration can occur through legitimate accounts without detection. | Mitigate |
| GAP-015 | Default credentials on medical device management interfaces | Pumps, monitors, nurse-call systems | Patient-safety risk and unauthorized access to clinical device management. | Mitigate |
| GAP-016 | Internet-facing systems lack explicit vulnerability and patch management coverage | FortiGate, patient portal, web server, Netgear router | Known vulnerabilities on exposed systems can be used for initial access. | Mitigate |
| GAP-017 | Remote access and clinical access lack MFA at scale | VPN, EHR, AD, workstations | Stolen passwords remain enough to reach sensitive systems. | Mitigate |
| GAP-018 | Shared PACS credentials eliminate accountability in Radiology | PACS server, MRI workflow | Loss of auditability, unauthorized viewing or manipulation of imaging access. | Mitigate |

### High Gaps

| Gap ID | Finding | Affected Assets | Potential Impact | Recommended Treatment |
|---|---|---|---|---|
| GAP-002 | EHR database exposure is too broad | EHR database | PHI exposure or tampering through an overly exposed database path. | Mitigate |
| GAP-008 | Billing server remains an EOL high-value target | Billing server | Claims disruption, ransomware recurrence, and compliance exposure. | Mitigate |
| GAP-009 | Personal NAS in Cardiology stores unmanaged research data | Shadow IT NAS | Data loss or exfiltration of research files and possible PHI. | Avoid |
| GAP-010 | Marketing uses a personal-Gmail Google Drive | Shadow IT cloud storage | Strategic communications or internal marketing material can leak outside governance. | Avoid |
| GAP-020 | Building management infrastructure is third-party controlled and not visible to MedDefense | HQ building / site connectivity | Hidden dependency and weak trust boundary around shared infrastructure. | Transfer |
| GAP-021 | Change management is informal and ungoverned | Servers, network devices, backups | Uncontrolled changes break backups, introduce outages, and create drift. | Mitigate |
| GAP-023 | Patient portal allows legacy TLS configuration | Patient portal, web server | Downgrade or interception risk for portal sessions and credentials. | Mitigate |

### Medium Gap

| Gap ID | Finding | Affected Assets | Potential Impact | Recommended Treatment |
|---|---|---|---|---|
| GAP-011 | Unmanaged Raspberry Pi monitor is an unknown foothold | Central Hospital second floor network | Hidden telemetry capture or an attacker-controlled device on the internal network. | Avoid |

**Gap distribution analysis**

- The highest-risk concentration is in EHR/clinical systems, identity and access, network/core infrastructure, and recovery.
- Detection and recovery are the most consistent functional weaknesses; prevention exists, but it is often too broad or too easy to bypass.
- Shadow IT adds a second layer of risk because it bypasses the control environment entirely.

## 6. Risk Treatment Recommendations

The seven recommended actions below are the best use of the current budget because they reduce the broadest set of risks for the least cost and effort.

| Gap ID | Treatment Strategy | Cost Estimate | Timeline | Why it is in the top 7 |
|---|---|---:|---|---|
| GAP-016 | Mitigate | $1-10K | Short-term < 1 month | Removes the most obvious initial-access path for exposed VPN, portal, and edge systems. |
| GAP-017 | Mitigate | $10-50K | Short-term < 1 month | Stops stolen or retained passwords from being enough to reach sensitive systems. |
| GAP-013 | Mitigate | $1-10K | Short-term < 1 month | Automates deprovisioning and closes a common insider-threat path. |
| GAP-004 | Transfer | $10-50K | Short-term < 1 month | Uses outsourced detection coverage instead of buying an $80K SIEM this year. |
| GAP-006 | Mitigate | $10-50K | Long-term > 1 month | Cuts lateral movement and reduces the blast radius of any one compromise. |
| GAP-005 | Mitigate | $10-50K | Long-term > 1 month | Makes recovery possible after ransomware or site failure. |
| GAP-001 | Mitigate | $0-1K | Quick Win < 1 week | Eliminates the most visible point-of-care exposure for patient data. |

**Budget allocation**

| Item | Estimated Cost |
|---|---:|
| GAP-016 patch/vulnerability process | $8,000 |
| GAP-017 MFA rollout | $30,000 |
| GAP-013 automated offboarding | $5,000 |
| GAP-004 MDR/SOC transfer | $15,000 |
| GAP-006 segmentation / VPN tightening | $20,000 |
| GAP-005 resilient backup improvements | $35,000 |
| GAP-001 workstation auto-lock / privacy controls | $1,000 |
| **Total** | **$114,000** |

That leaves roughly $6,000 for contingency, rollout friction, or unplanned remediation support.

**Quick wins within 1 week**

- GAP-001 workstation auto-lock and idle timeout enforcement.

**Short-term priorities within 1 month**

- GAP-016 patch/vulnerability governance for exposed systems.
- GAP-017 MFA for VPN, EHR, cloud, and privileged access.
- GAP-013 automated offboarding.
- GAP-004 outsourced detection coverage.

**Long-term roadmap items**

- GAP-006 network segmentation and VPN tightening.
- GAP-005 offsite/immutable backups and restore testing.
- Defer MRI redesign and any full billing-server replacement to next fiscal year because they are higher-cost projects that are already partially buffered by compensating controls.

## 7. Conclusion and Next Steps

MedDefense is not starting from zero, but it is still operating with a security model that depends too much on prevention, too little on detection, and too much on hope that legacy systems and manual processes will not fail at the same time. In business terms, the organization can be disrupted by a single unpatched device, a stolen password, or an unattended workstation, and may not know quickly enough to stop the damage.

If these recommendations are not implemented, the likely outcome is a longer outage, higher recovery cost, and a material patient-safety and compliance event rather than a contained IT incident. The Board should understand that this is a resilience decision as much as a cybersecurity decision.

The logical next phase is the External Threat Landscape Assessment. Marcus's unfinished notes were pointing in that direction for a reason: once internal posture is mapped, the next question is which adversaries are most likely to target these gaps and which tactics they will use. That external view will turn this posture assessment into a complete risk strategy.