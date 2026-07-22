# The Risk Register

## Introduction

### Goal

### Context

## Answer

| Risk ID | Risk Description | Risk Category | Threat Source | Vulnerability | Affected Asset(s) | Likelihood | Impact | Inherent Risk Score | ALE | Risk Owner | Treatment Decision | Treatment Justification | Planned Control(s) | Residual Risk | KRI | Review Date |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| RISK-001 | Ransomware compromises internal systems and disrupts hospital operations. | Operational | RaaS groups (BlackReef-style attackers) | GAP-016, GAP-006, GAP-017 | FortiGate VPN, servers, EHR, billing systems | 5 (Very Likely) | 5 (Critical) | 25 | ~$300,000 | Deputy CISO James | Mitigate | Ransomware is the highest business-impact threat and requires layered controls. | MFA, Network Segmentation, SIEM, EDR, Immutable Backups | Medium | Number of critical vulnerabilities older than SLA | Monthly |
| RISK-002 | Patient PHI is stolen from the EHR environment. | Compliance | External attackers, malicious insiders | GAP-002, GAP-014, GAP-017 | EHR servers, EHR database | 4 (Likely) | 5 (Critical) | 20 | ~$3.1M | Deputy CISO James + Clinical Data Owner | Mitigate | PHI exposure creates regulatory, financial, and reputation damage. | MFA, SIEM, DLP roadmap, Access Control | Medium | Number of unauthorized PHI access events | Monthly |
| RISK-003 | Attackers gain access through stolen VPN credentials. | Operational | External attackers, ransomware affiliates | GAP-017, GAP-016 | FortiGate VPN | 5 (Very Likely) | 5 (Critical) | 25 | ~$1M+ | IT Director Sarah Park | Mitigate | VPN compromise is a common healthcare initial access method. | MFA, Vulnerability Management, SIEM | Low-Medium | Failed VPN login attempts | Monthly |
| RISK-004 | Flat network allows attackers to move between systems after compromise. | Operational | RaaS groups, supply-chain attackers | GAP-006 | 10.10.0.0/16 internal network, servers, medical devices | 4 (Likely) | 5 (Critical) | 20 | Included in ransomware ALE | IT Director Sarah Park | Mitigate | Segmentation reduces attack spread across critical systems. | VLAN segmentation, Firewall rules | Medium | Unauthorized internal traffic between zones | Quarterly |
| RISK-005 | Medical devices are compromised and affect patient care. | Operational | External attackers, supply-chain attackers | GAP-003, GAP-015 | MRI workstation, BD Alaris infusion pumps | 3 (Possible) | 5 (Critical) | 15 | ~$300,000 | Clinical Engineering Manager | Mitigate | Medical devices create direct patient safety risks. | Medical device segmentation, credential management | Medium | Number of unmanaged medical devices | Quarterly |
| RISK-006 | Security incidents remain undetected due to lack of monitoring. | Strategic | All threat actors | GAP-004 | Enterprise network, servers, endpoints | 5 (Very Likely) | 4 (Major) | 20 | Included in multiple ALE scenarios | Deputy CISO James | Mitigate | Visibility is required to detect ransomware and insider activity. | Enterprise SIEM, logging process | Medium | Mean time to detect security events | Monthly |
| RISK-007 | Weak backup protection prevents recovery after ransomware. | Financial | RaaS groups | GAP-005 | Backup infrastructure, critical servers | 4 (Likely) | 5 (Critical) | 20 | Included in ransomware ALE | IT Director Sarah Park | Mitigate | Recovery capability limits ransomware financial impact. | Immutable offsite backups, backup testing | Low-Medium | Backup restore test failures | Quarterly |
| RISK-008 | Former employees retain access to sensitive systems. | Compliance | Malicious insiders, credential attackers | GAP-013 | Active Directory, EHR accounts | 3 (Possible) | 4 (Major) | 12 | ~$120,000 | HR Director + IT Director | Mitigate | Identity lifecycle failures create unnecessary access risk. | Account review process, MFA, access removal workflow | Low | Number of inactive accounts | Quarterly |
| RISK-009 | Shared PACS credentials allow unauthorized imaging access. | Compliance | Negligent insiders, malicious insiders | GAP-018 | PACS imaging system | 3 (Possible) | 4 (Major) | 12 | Not calculated | Radiology Department Head | Mitigate | Shared accounts remove accountability for patient data access. | Unique accounts, access monitoring | Low-Medium | Number of shared accounts detected | Quarterly |
| RISK-010 | Internet-facing vulnerable systems provide attacker entry points. | Operational | Opportunistic attackers, ransomware groups | GAP-016, 1x02 critical findings | Public-facing applications, billing server | 4 (Likely) | 4 (Major) | 16 | ~$300,000 | IT Director Sarah Park | Mitigate | External exposure must be reduced through patching and monitoring. | Vulnerability Management, Patch Management, SIEM | Medium | Critical external vulnerabilities open over SLA | Monthly |

Risk Scale:
Likelihood:
1 = Rare, 2 = Unlikely, 3 = Possible, 4 = Likely, 5 = Very Likely.
Impact:
1 = Minor, 2 = Moderate, 3 = Significant, 4 = Major, 5 = Critical.

Risk Register Governance Note:
The Risk Register is maintained by Deputy CISO James with support from the Security Analyst and IT Director Sarah Park. It is reviewed monthly for critical risks and quarterly for the full register. An out-of-cycle review is triggered by a security incident, major vulnerability disclosure, regulatory change, major infrastructure change, or KRI threshold breach. When a KRI threshold is exceeded, the risk owner must reassess the risk score, define corrective actions, and report progress to executive management.