# The Control Selection

## Introduction

### Goal
Select and justify specific security controls for each risk in the register, mapping every choice to CIS Controls and NIST CSF.

### Context
The Risk Register tells you WHAT risks exist. Now you decide WHAT to do about each one. Every control you select must satisfy three criteria: it must reduce the specific risk it targets (effectiveness), it must be affordable within the budget (efficiency) and it must map to a recognized framework so auditors can verify it (traceability).

## Answer

RISK: RISK-001
Selected Control: MFA deployment on VPN and administrative accounts
CIS Control Mapping: CIS Control 6.3, 6.4, 6.5
NIST CSF Mapping: PR.AA (Identity Management, Authentication, and Access Control)
Control Type: Preventive
Control Category: Technical
Implementation Cost: $8,000/year (existing O365 licenses + configuration labor)
Expected Risk Reduction: Reduces credential-based ransomware likelihood; lowers ARO from ~0.30 to ~0.10 for VPN compromise.
Dependencies: Requires account inventory and privileged account review.

RISK: RISK-002
Selected Control: Network segmentation (server, workstation, medical device, guest VLANs)
CIS Control Mapping: CIS Control 12.2, 12.4
NIST CSF Mapping: PR.IR (Technology Infrastructure Resilience)
Control Type: Preventive
Control Category: Technical
Implementation Cost: $20,000 initial implementation
Expected Risk Reduction: Reduces ransomware lateral movement impact across EHR, billing, and medical devices; decreases EF of major compromise.
Dependencies: Requires updated network architecture diagrams and firewall rules.

RISK: RISK-003
Selected Control: Enterprise SIEM deployment (Wazuh)
CIS Control Mapping: CIS Control 8.1, 8.2, 13.1
NIST CSF Mapping: DE.CM (Continuous Monitoring)
Control Type: Detective
Control Category: Technical
Implementation Cost: $25,000/year (labor, deployment, maintenance)
Expected Risk Reduction: Improves detection of ransomware, insider activity, and unauthorized access; reduces incident duration.
Dependencies: Requires centralized logging from servers, endpoints, and network devices.

RISK: RISK-004
Selected Control: Offsite immutable backup replication
CIS Control Mapping: CIS Control 11.2, 11.3, 11.4
NIST CSF Mapping: RC.RP (Incident Recovery Plan Execution)
Control Type: Corrective
Control Category: Technical
Implementation Cost: $18,000/year (cloud storage + administration)
Expected Risk Reduction: Reduces ransomware recovery impact by preventing backup destruction; lowers recovery ALE.
Dependencies: Requires defined backup schedule and recovery testing.

RISK: RISK-005
Selected Control: Sophos Intercept X EDR upgrade
CIS Control Mapping: CIS Control 10.1, 10.2
NIST CSF Mapping: DE.CM / PR.PS
Control Type: Preventive and Detective
Control Category: Technical
Implementation Cost: $35,000/year (endpoint/server licensing)
Expected Risk Reduction: Improves malware prevention and endpoint containment; reduces ransomware spread.
Dependencies: Requires endpoint inventory and deployment process.

RISK: RISK-006
Selected Control: Dedicated firewall for Westside Clinic
CIS Control Mapping: CIS Control 12.1, 12.3
NIST CSF Mapping: PR.IR (Technology Infrastructure Resilience)
Control Type: Preventive
Control Category: Technical
Implementation Cost: $10,000/year (firewall appliance + maintenance)
Expected Risk Reduction: Removes insecure consumer router exposure and reduces external attack paths.
Dependencies: Requires network architecture review.

RISK: RISK-007
Selected Control: Medical device network isolation and monitoring
CIS Control Mapping: CIS Control 12.2, 13.3
NIST CSF Mapping: PR.IR / DE.CM
Control Type: Preventive and Detective
Control Category: Technical
Implementation Cost: $45,000/year
Expected Risk Reduction: Reduces medical device compromise probability and limits patient safety impact.
Dependencies: Requires network segmentation before device isolation.

RISK: RISK-008
Selected Control: Identity lifecycle management and automated offboarding
CIS Control Mapping: CIS Control 5.3, 6.2
NIST CSF Mapping: PR.AA
Control Type: Preventive
Control Category: Administrative
Implementation Cost: $12,000/year
Expected Risk Reduction: Reduces insider misuse and unauthorized former employee access.
Dependencies: Requires HR, IT, and department head coordination.

RISK: RISK-009
Selected Control: Data Loss Prevention (DLP) and USB restrictions
CIS Control Mapping: CIS Control 3.3, 3.6
NIST CSF Mapping: PR.DS (Data Security)
Control Type: Preventive and Detective
Control Category: Technical
Implementation Cost: $30,000/year
Expected Risk Reduction: Reduces PHI theft and accidental data exposure from endpoints.
Dependencies: Requires data classification and user access review.

RISK: RISK-010
Selected Control: Security awareness training program
CIS Control Mapping: CIS Control 14.1, 14.2, 14.6
NIST CSF Mapping: PR.AT (Awareness and Training)
Control Type: Preventive
Control Category: Administrative
Implementation Cost: $10,000/year
Expected Risk Reduction: Reduces phishing success and negligent insider incidents.
Dependencies: Requires management support and employee participation tracking.


CONTROL DEPENDENCY MAP:
```
1. Foundation Controls
----------------------
Asset Inventory
      |
      +--> Identity Review
      |        |
      |        +--> MFA Deployment
      |        |
      |        +--> Automated Offboarding
      |
      +--> Network Architecture Review
               |
               +--> Network Segmentation
                        |
                        +--> Medical Device Isolation
                        |
                        +--> Dedicated Firewall


2. Detection and Response Controls
----------------------------------
Centralized Logging
      |
      v
SIEM Deployment
      |
      v
Security Monitoring Capability
      |
      v
Future 24/7 SOC Capability


Endpoint Inventory
      |
      v
EDR Deployment
      |
      v
Endpoint Malware Detection and Containment


3. Resilience Controls
----------------------
Backup Process
      |
      v
Immutable Offsite Backups
      |
      v
Ransomware Recovery Capability


4. Data Protection Controls
---------------------------
Data Classification
      |
      v
Access Review
      |
      v
DLP and USB Restrictions
      |
      v
PHI Theft Reduction


5. Overall Implementation Order
-------------------------------
Phase 1:
- Asset inventory
- Identity review
- Network architecture review
- Centralized logging

        |
        v

Phase 2:
- MFA deployment
- Network segmentation
- Immutable backups
- SIEM deployment
- EDR deployment

        |
        v

Phase 3:
- Medical device isolation
- DLP implementation
- Automated offboarding
- Security awareness improvements

        |
        v

Phase 4:
- Advanced monitoring
- 24/7 SOC integration
- Continuous improvement
```