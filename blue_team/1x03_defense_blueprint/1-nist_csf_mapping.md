# The NIST CSF Mapping

## Introduction

### Goal
Apply NIST CSF 2.0 to MedDefense by mapping the organization's current security posture to each of the six core functions.

### Context
NIST CSF 2.0 organizes all security activities into six functions: Govern (establish and monitor the security strategy), Identify (understand what you need to protect), Protect (implement safeguards), Detect (find incidents when they happen), Respond (act on detected incidents), Recover (restore operations after an incident). Each function contains categories and subcategories that describe specific outcomes.

This is not a theoretical exercise. You are building MedDefense's Current Profile, a realistic snapshot of where the organization stands today against each function. This profile will become the foundation for the Target Profile (where MedDefense needs to be), and the gap between them drives the entire strategy.

## Answer

# NIST CSF 2.0 Current Profile – MedDefense Health Systems

| Function | Current Level | Evidence | Key Gaps | Target Level (6 months) |
|---|---|---|---|---|
| **Govern (GV)** | **Partial** | 1x00 identified no formal incident response plan (GAP-012), informal change management (GAP-021), weak offboarding (GAP-013), and no documented governance framework. | No formal cybersecurity governance, policies, or risk review process. | **Managed** – Define governance roles, security policies, risk register, and regular Board reporting. |
| **Identify (ID)** | **Partial** | The asset inventory, criticality matrix, and risk assessment were created during Projects 1x00–1x02, indicating they were previously incomplete. Shadow IT (GAP-009 to GAP-011) also shows poor asset visibility. | Incomplete asset inventory and no continuous risk assessment process. | **Managed** – Maintain a living asset inventory, continuous risk assessments, and regular asset reviews. |
| **Protect (PR)** | **Partial** | 1x02 found missing MFA (GAP-017), flat network (GAP-006), EOL systems, legacy TLS, weak medical device security, and unsupported operating systems. Basic firewalling and endpoint protection exist but are insufficient. | Weak identity controls and lack of network segmentation. | **Managed** – Deploy MFA, implement segmentation, improve patch governance, and retire EOL systems. |
| **Detect (DE)** | **Not Implemented** | GAP-004 identified no SIEM or centralized monitoring. Marcus's assessment confirmed logs are local and reviewed only after problems occur. | No centralized logging, alerting, or continuous monitoring capability. | **Managed** – Deploy MDR/SIEM, centralize logs, and establish continuous monitoring. |
| **Respond (RS)** | **Partial** | GAP-012 identified no formal incident response plan or tested playbooks. Existing response relies on ad hoc IT activities. | No documented or exercised incident response process. | **Managed** – Develop IR plans, communication procedures, and conduct tabletop exercises. |
| **Recover (RC)** | **Partial** | GAP-005 found backups exist but are not immutable, offsite, or regularly tested. No defined RTO/RPO or recovery exercises were identified. | Recovery capability is incomplete and untested. | **Managed** – Implement resilient backups, recovery testing, and documented business continuity objectives. |

### Overall Assessment

MedDefense currently operates at an overall **Partial** maturity level under the NIST CSF 2.0. Asset visibility has improved significantly through Projects **1x00–1x02**, but governance, detection, response, and recovery remain immature. The highest priority over the next six months is to strengthen **Protect** and **Detect**, as these directly address the major risks identified in the threat landscape (ransomware, credential theft, and lateral movement).