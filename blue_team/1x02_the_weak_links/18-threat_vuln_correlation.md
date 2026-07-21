# The Threat-Vulnerability Correlation

## Introduction

### Goal
Connect every prioritized vulnerability to the specific threat actors and attack scenarios that would exploit it.

### Context
A vulnerability in isolation is a technical fact. A vulnerability connected to a threat actor with a known preference for exploiting it is an intelligence product. This task completes the three-project synthesis.

## Answer
# Threat–Vulnerability Correlation Matrix

| Finding | Threat Actor(s) (1x01 T6) | Vector (1x01) | Kill Chain (1x01 T10) | Scenario (1x01 T14) | Gap (1x00) |
|---------|----------------------------|---------------|------------------------|---------------------|------------|
| **F001** - Apache mod_lua RCE (CVE-2021-44790) | Cybercriminal, Ransomware group | Vulnerable Software Exploit | Initial Access | Billing server compromise → lateral movement | GAP-008, GAP-006 |
| **F002** - Apache Privilege Escalation (CVE-2019-0211) | Cybercriminal, Ransomware group | Vulnerable Software Exploit | Privilege Escalation | Root compromise after web exploitation | GAP-008 |
| **F003** - PostgreSQL unrestricted access | Cybercriminal, Malicious Insider | VPN Exploit / Lateral Movement | Lateral Movement | Pivot from compromised host to EHR database | GAP-002, GAP-006 |
| **F004** - Windows XP MRI Workstation (EOL) | Ransomware group, Nation-state | Vulnerable Software Exploit | Initial Access / Lateral Movement | Compromise MRI workstation then pivot across radiology | GAP-003, GAP-006 |
| **F007** - LDAP Signing Disabled / SMBv1 | Cybercriminal, Ransomware group | Credential Relay / Vulnerable Software | Privilege Escalation | LDAP relay leading to Active Directory compromise | GAP-017, GAP-006 |
| **F010** - BD Alaris Pumps (default credentials) | Malicious Insider, Nation-state | Default Credentials | Initial Access | Unauthorized access to infusion pump management | GAP-015 |
| **F011** - Ubuntu 18.04 without ESM | Cybercriminal | Vulnerable Software Exploit | Persistence | Unsupported billing server remains permanently exposed | GAP-008, GAP-016 |
| **F031** - Ghostcat (CVE-2020-1938) | Cybercriminal, Ransomware group | Vulnerable Software Exploit | Initial Access | Read EHR configuration → steal DB credentials → access PHI | GAP-002, GAP-006, GAP-016 |

## Most Damaging Vulnerability

**Finding 031 (Ghostcat - CVE-2020-1938)** would cause the greatest damage. It targets **ehr-srv-01 (A-001)**, a Critical asset directly connected to the **EHR database (A-002)**. An attacker can exploit Ghostcat to read configuration files, recover database credentials, then access patient records through the flat network. Combined with **GAP-002 (broad database exposure)** and **GAP-006 (lack of segmentation)**, this provides a realistic path from initial compromise to large-scale PHI theft or ransomware affecting the hospital's core clinical services.