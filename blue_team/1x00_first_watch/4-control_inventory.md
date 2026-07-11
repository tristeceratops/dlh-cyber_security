# 4. The Control Landscape

## Introduction

### Goal
Identify, classify and document existing security controls using the professional dual-axis taxonomy: category (Technical / Administrative / Physical) and function (Preventive / Detective / Corrective).

### Context
James Chen sends you an email after the walk-through:

"Good observations today. Now I need you to do the other half: document what we DO have, not just what's wrong. I've asked Sarah Park to give you access to our existing documentation. She's sending over config extracts, policy documents and anything else she can find. Put together a complete picture of our current security controls."

Security controls are the mechanisms an organization uses to protect its assets. They are classified along two axes:
Category (what the control is made of):

-    Technical: Implemented through technology. Firewalls, encryption, access control lists, antivirus, log monitoring.

-    Administrative: Implemented through policies, procedures and human processes. Security training, background checks, acceptable use policies, incident response plans.

-    Physical: Implemented in the physical world. Locks, cameras, fences, fire suppression, badge readers.

Function (what the control does):

-    Preventive: Stops an incident from occurring. A firewall blocking unauthorized traffic.

-    Detective: Identifies an incident during or after it occurs. An IDS alerting on suspicious traffic.

-    Corrective: Repairs damage or restores operations after an incident. A backup restoration procedure.

Two additional functions you will encounter:

-    Deterrent: Discourages an attacker from attempting an action. A "Premises Under Surveillance" sign.

-    Compensating: An alternative control used when the ideal control is not feasible. Network isolation for a system that cannot be patched.

## Answers
| Control ID | Control Name                 | Description                                                                                                                   | Category       | Function   | Asset(s) Protected                    | Source     |
| ---------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------- | ---------- | ------------------------------------- | ---------- |
| **C-001**  | Perimeter Firewall           | FortiGate firewall enforces network access rules, including a default deny policy for unauthorized traffic.                   | Technical      | Preventive | Internal network, DMZ, servers        | Artifact 1 |
| **C-002**  | Firewall Logging             | Firewall logs network traffic and security events for monitoring and investigation.                                           | Technical      | Detective  | Network traffic                       | Artifact 1 |
| **C-003**  | SSH Key-Based Authentication | SSH on **ehr-srv-01** requires public key authentication and disables password authentication.                                | Technical      | Preventive | ehr-srv-01                            | Artifact 2 |
| **C-004**  | Root Login Disabled          | Direct SSH login as the root user is prohibited.                                                                              | Technical      | Preventive | Linux servers                         | Artifact 2 |
| **C-005**  | Password Policy              | Password policy enforces minimum length, complexity, password history, and regular password changes.                          | Administrative | Preventive | User accounts                         | Artifact 3 |
| **C-006**  | Account Lockout Policy       | Accounts are locked after five failed login attempts for 30 minutes to reduce brute-force attacks.                            | Administrative | Preventive | User accounts                         | Artifact 3 |
| **C-007**  | Endpoint Protection (Sophos) | Sophos Endpoint Protection detects and blocks malware on managed Windows workstations.                                        | Technical      | Preventive | Windows workstations                  | Artifact 4 |
| **C-008**  | Scheduled Backups            | Veeam performs nightly full backups of critical virtual machines with 14-day retention.                                       | Technical      | Corrective | Critical servers and virtual machines | Artifact 5 |
| **C-009**  | Visitor Access Control       | Security guard verifies visitor identity, registers visitors, and checks badges before entry.                                 | Physical       | Preventive | Main hospital entrance                | Artifact 6 |
| **C-010**  | CCTV Surveillance            | Security cameras monitor building entrances and record footage for later review.                                              | Physical       | Detective  | Hospital entrances and parking areas  | Artifact 6 |
| **C-011**  | Security Awareness Training  | Annual mandatory cybersecurity awareness training covers phishing, passwords, physical security, and incident reporting.      | Administrative | Preventive | Employees                             | Artifact 7 |
| **C-012**  | System and Security Logging  | Firewalls, Windows servers, Linux servers, and the EHR system generate security logs for auditing and incident investigation. | Technical      | Detective  | Network devices, servers, EHR system  | Artifact 8 |

### Control Summary Matrix
| Category           | Preventive                 | Detective    | Corrective | Compensating | Deterrent |
| ------------------ | -------------------------- | ------------ | ---------- | ------------ | --------- |
| **Technical**      | C-001, C-003, C-004, C-007 | C-002, C-012 | C-008      | —            | —         |
| **Administrative** | C-005, C-006, C-011        | —            | —          | —            | —         |
| **Physical**       | C-009                      | C-010        | —          | —            | —         |

