# The Gap-to-Framework Bridge

## Introduction

### Goal
Connect every significant gap from prior projects to a specific framework control, transforming raw findings into structured, framework-aligned action items.

### Context
You have gaps from 1x00, threats from 1x01, vulnerabilities from 1x02, and framework scores from T1 and T2. Right now, they exist in separate documents. This task connects them into a single traceability chain: Gap → Vulnerability → Threat → Framework Control → Recommended Action.

This bridge is what makes a strategy credible. When the Board asks, "Why should we implement network segmentation ?", the answer is not "because it is a best practice." The answer is: "Because Gap GAP-003 (flat network) enables Kill Chain #1 (ransomware), is exploited by Vulnerability Finding 003 (PostgreSQL unrestricted access), maps to CIS Control 12 (Network Infrastructure Management) at IG1, and closing it reduces our ransomware ALE by an estimated $180,000 per year."

## Answer

| Gap Reference | Description | Vulnerability Evidence (1x02) | Threat Context (1x01) | NIST CSF Function | CIS Control | Recommended Action |
|---------------|-------------|-------------------------------|-----------------------|-------------------|-------------|--------------------|
| **GAP-004** | No centralized security monitoring or SIEM | Multiple exploitable findings remained undetected (e.g., F017 Tomcat Disclosure, F031 Ghostcat) | All threat actors • All kill chains | **DE – Detect** | **CIS 13 – Network Monitoring and Defense** | Deploy an MDR/SIEM platform and centralize log collection for critical systems. |
| **GAP-006** | Flat network enables unrestricted lateral movement | Multiple internal hosts reachable across 10.10.0.0/16 | Ransomware, Supply-chain attackers, Insiders • Ransomware & Supply Chain kill chains | **PR – Protect** | **CIS 12 – Network Infrastructure Management** | Segment the network by business function and isolate medical devices from IT systems. |
| **GAP-016** | Internet-facing systems lack vulnerability management | F031 Ghostcat (CVE-2020-1938), F017 Tomcat Information Disclosure, legacy TLS findings | Ransomware groups, External attackers • External Intrusion & Ransomware kill chains | **PR – Protect** | **CIS 7 – Continuous Vulnerability Management** | Establish monthly vulnerability scanning and rapid patch management for exposed services. |
| **GAP-017** | MFA missing for remote and privileged access | VPN and authentication weaknesses identified during assessment | Credential theft groups, Ransomware • Credential Abuse & Ransomware kill chains | **PR – Protect** | **CIS 6 – Access Control Management** | Enforce MFA for VPN, privileged accounts and all external-facing applications. |
| **GAP-005** | Backup infrastructure lacks immutable recovery | Weak backup resilience identified during posture assessment | Ransomware groups • Ransomware kill chain | **RC – Recover** | **CIS 11 – Data Recovery** | Deploy immutable offline backups and perform regular restore testing. |
| **GAP-014** | No DLP or behavioral monitoring | PHI exposure and unrestricted data exports identified | Malicious insiders, Ransomware • Data Theft kill chain | **PR – Protect** | **CIS 3 – Data Protection** | Deploy DLP and user behavior monitoring for sensitive clinical data. |
| **GAP-013** | Manual identity offboarding | Retained account risk identified during assessment | Malicious insiders, External attackers • Credential Abuse kill chain | **PR – Protect** | **CIS 5 – Account Management** | Automate account deprovisioning through HR-integrated identity management. |
| **GAP-015** | Medical devices use weak/default credentials | F010, F016 and F024 (medical IoT findings) | External attackers, Supply-chain attackers • Medical Device Compromise kill chain | **PR – Protect** | **CIS 4 – Secure Configuration of Enterprise Assets and Software** | Replace default credentials, harden device configurations and isolate medical IoT devices. |

## Traceability Summary

| Gap | 1x02 Vulnerability | 1x01 Threat Actor | Kill Chain | NIST CSF | CIS Control | Priority Action |
|-----|---------------------|------------------|------------|----------|-------------|-----------------|
| GAP-004 | F017, F031 | All attackers | All | Detect | CIS 13 | Deploy SIEM/MDR |
| GAP-006 | Flat internal exposure | Ransomware, Supply-chain | Ransomware | Protect | CIS 12 | Network segmentation |
| GAP-016 | F017, F031, TLS findings | External attackers | External Intrusion | Protect | CIS 7 | Patch management |
| GAP-017 | Authentication weaknesses | Credential thieves | Credential Abuse | Protect | CIS 6 | Enterprise MFA |
| GAP-005 | Weak backup resilience | Ransomware | Ransomware | Recover | CIS 11 | Immutable backups |
| GAP-014 | PHI exposure findings | Insiders | Data Theft | Protect | CIS 3 | DLP deployment |
| GAP-013 | Identity lifecycle weaknesses | Insiders | Credential Abuse | Protect | CIS 5 | Automated offboarding |
| GAP-015 | F010, F016, F024 | External/Supply-chain | Medical Device | Protect | CIS 4 | Secure medical IoT configurations |