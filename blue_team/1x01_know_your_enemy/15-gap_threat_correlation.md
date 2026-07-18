# The Gap-Threat Correlation

## Introduction

This analysis updates the original Gap Analysis by adding threat intelligence from the actor profiles, kill chains, STRIDE assessments, and completed threat scenarios. The goal is to identify which weaknesses are most dangerous when viewed from an attacker's perspective.

A gap becomes more urgent when it appears repeatedly across multiple attack paths. Gaps that enable ransomware, insider abuse, and supply-chain compromise receive higher priority because they represent common points where multiple threats converge.

---

# Threat-Informed Gap Correlation

| Gap ID | Gap Description | Original Risk Level | Threat Actors | Kill Chains | Scenarios | Updated Risk Level | Justification |
|---|---|---|---|---|---|---|---|
| GAP-001 | Unattended EHR sessions allow unauthorized access to active patient records | Critical | Malicious insiders, negligent insiders | Insider Data Access Chain | Scenario 2 | Same | Remains critical because EHR access directly affects patient safety and PHI protection. Threat analysis confirms insider misuse remains realistic. |
| GAP-002 | Broad EHR database exposure allows unnecessary database access paths | High | RaaS groups, external attackers, malicious insiders | Ransomware Chain, Data Theft Chain | Scenario 1, Scenario 2 | Upgraded | EHR database access appears in multiple STRIDE threats, including information disclosure and tampering. Attackers gaining internal access can directly target PHI. |
| GAP-003 | Legacy MRI workstation creates a clinical network foothold | Critical | External attackers, supply-chain attackers | Medical Device Compromise Chain, Supply Chain Chain | Scenario 3 | Same | STRIDE analysis confirms the Windows XP MRI workstation is a high-value pivot point. Risk remains critical because compromise can spread beyond Radiology. |
| GAP-004 | No centralized SIEM or security monitoring | Critical | All threat actors | All five kill chains | Scenario 1, Scenario 2, Scenario 3 | Same | This gap appears across every attack path because attackers rely on low visibility to maintain persistence and avoid detection. |
| GAP-005 | Backup infrastructure lacks immutable/offsite recovery capability | Critical | RaaS groups | Ransomware Chain | Scenario 1 | Same | BlackReef specifically targets backups before encryption. Threat evidence confirms this remains a major recovery weakness. |
| GAP-006 | Flat network enables unrestricted lateral movement | Critical | RaaS groups, supply-chain attackers, malicious insiders | Ransomware Chain, Supply Chain Chain, Internal Abuse Chain | Scenario 1, Scenario 3 | Same | Nearly every serious attack requires movement between systems. Network segmentation would disrupt multiple attack paths. |
| GAP-007 | Exposed network credentials and unsecured infrastructure access | Critical | External attackers, insiders | Network Compromise Chain | Scenario 1, Scenario 3 | Same | Direct access to network infrastructure can bypass higher-level controls and create enterprise-wide compromise. |
| GAP-008 | End-of-life billing server remains exposed | High | Ransomware actors, opportunistic attackers | Ransomware Chain | Scenario 1 | Same | Remains a risk but appears less frequently than EHR, identity, and network weaknesses. |
| GAP-009 | Personal NAS stores unmanaged research data | High | Malicious insiders, external attackers | Data Theft Chain | Scenario 2 | Same | Threat analysis confirms unmanaged storage creates a realistic exfiltration path, especially for insider scenarios. |
| GAP-010 | Personal Gmail/Google Drive used for business data | High | Malicious insiders, external attackers | Data Theft Chain | Scenario 2 | Same | External storage remains outside security monitoring and creates uncontrolled disclosure risk. |
| GAP-011 | Unmanaged Raspberry Pi creates unknown internal foothold | Medium | External attackers | Network Compromise Chain | None directly | Upgraded | Originally viewed as limited risk, but threat modeling shows unmanaged devices can become attacker footholds for lateral movement. |
| GAP-012 | Lack of tested incident response process | Critical | All threat actors | All kill chains | Scenario 1, Scenario 2, Scenario 3 | Same | Every scenario becomes more damaging without practiced containment and recovery procedures. |
| GAP-013 | Manual offboarding allows retained access | Critical | Malicious insiders, external attackers using stolen accounts | Insider Chain, Credential Compromise Chain | Scenario 2 | Same | Identity lifecycle weaknesses remain a major healthcare threat because legitimate accounts provide trusted access. |
| GAP-014 | No DLP or behavioral monitoring for sensitive data | Critical | Malicious insiders, ransomware actors | Data Theft Chain, Ransomware Chain | Scenario 1, Scenario 2 | Same | Confirmed as a key enabler of PHI theft and double-extortion ransomware. |
| GAP-015 | Medical devices use weak/default credentials | Critical | External attackers, supply-chain attackers | Medical Device Chain, Supply Chain Chain | Scenario 3 | Same | Medical devices remain high-impact targets because compromise can affect patient care. |
| GAP-016 | Internet-facing systems lack vulnerability management | Critical | RaaS groups, external attackers | Ransomware Chain, External Intrusion Chain | Scenario 1 | Same | BlackReef's preferred entry method directly matches this gap. |
| GAP-017 | MFA missing for remote and privileged access | Critical | RaaS groups, supply-chain attackers, malicious insiders | Credential Abuse Chain, Ransomware Chain | Scenario 1, Scenario 3 | Same | Stolen credentials remain one of the most common initial access methods. |
| GAP-018 | Shared PACS credentials remove accountability | Critical | Malicious insiders, negligent insiders | Insider Abuse Chain, Medical Imaging Chain | Scenario 2 | Same | STRIDE confirms shared accounts create both repudiation and unauthorized access risks. |
| GAP-019 | USB storage unrestricted on endpoints | High | Malicious insiders | Data Theft Chain | Scenario 2 | Same | Provides a simple exfiltration method for users with legitimate access. |
| GAP-020 | Third-party building infrastructure lacks visibility | High | Supply-chain attackers | Supply Chain Chain | Scenario 3 | Same | Third-party dependencies remain difficult to monitor and control. |
| GAP-021 | Informal change management creates configuration risk | High | Insiders, external attackers | Operational Disruption Chain | Scenario 1, Scenario 3 | Same | Poor change governance can weaken backups, security controls, and recovery capabilities. |
| GAP-022 | End-of-life print server remains unpatched | Low | Opportunistic attackers | Internal Compromise Chain | None directly | Same | Limited business impact compared with clinical and identity systems. |
| GAP-023 | Patient portal uses legacy TLS configuration | High | External attackers | External Application Attack Chain | Scenario 1 | Same | Public-facing patient systems remain attractive targets, but this gap is less central than VPN and identity weaknesses. |

---

# Re-Prioritized Gap List

## Critical Priority

1. **GAP-004 – No centralized security monitoring or SIEM**  
   - Appears across all scenarios and kill chains.
   - Prevents detection of ransomware, insider abuse, and vendor compromise.

2. **GAP-006 – Flat network and permissive remote access**
   - Enables lateral movement in ransomware and supply-chain attacks.
   - Increases the impact of every initial compromise.

3. **GAP-016 – Internet-facing systems lack vulnerability management**
   - Direct ransomware entry point.
   - Matches BlackReef operational methods.

4. **GAP-017 – Lack of MFA at scale**
   - Enables credential theft attacks.
   - Impacts external attackers and compromised vendors.

5. **GAP-005 – Weak backup resilience**
   - Determines whether ransomware becomes a short outage or a major operational crisis.

6. **GAP-014 – No DLP or behavioral monitoring**
   - Enables large-scale PHI theft and insider data abuse.

7. **GAP-013 – Manual identity offboarding**
   - Creates persistent access opportunities.

8. **GAP-015 – Weak medical device credential controls**
   - Creates direct patient-safety risks.

9. **GAP-018 – Shared PACS credentials**
   - Creates accountability and integrity failures.

10. **GAP-012 – No tested incident response capability**
   - Increases damage from every incident type.

---

## High Priority

11. GAP-002 – Broad EHR database exposure  
12. GAP-003 – Legacy MRI workstation dependency  
13. GAP-007 – Network credential exposure  
14. GAP-008 – End-of-life billing server  
15. GAP-009 – Personal NAS storage  
16. GAP-010 – Personal Gmail/Google Drive usage  
17. GAP-019 – Unrestricted USB storage  
18. GAP-020 – Third-party infrastructure visibility  
19. GAP-021 – Informal change management  
20. GAP-023 – Legacy TLS configuration  

---

## Medium / Low Priority

21. GAP-011 – Raspberry Pi unmanaged device (**Upgraded from Medium**)  
22. GAP-022 – End-of-life print server (**Stayed Low**)  

---

# The Critical Three

## 1. GAP-004 – No Centralized Security Monitoring or SIEM

**Why it matters:**

This gap appears in every major attack scenario:

- Ransomware:
  - Detects reconnaissance, privilege escalation, and encryption behavior.

- Insider:
  - Detects unusual patient record access.

- Supply Chain:
  - Detects abnormal vendor activity.

Closing this gap improves visibility across the entire environment.

---

## 2. GAP-006 – Flat Network and Permissive Remote Access

**Why it matters:**

This gap is the main reason a small compromise can become a hospital-wide incident.

It enables:

- VPN attacker movement into EHR systems.
- Vendor compromise spreading beyond the vendor-accessed server.
- Medical device compromise affecting other clinical systems.

Network segmentation would disrupt multiple kill chains.

---

## 3. GAP-017 – Missing MFA at Scale

**Why it matters:**

Credential abuse is present in nearly every realistic attack path.

It protects against:

- Ransomware affiliates using stolen credentials.
- Vendor account compromise.
- Former employee access.
- Phishing-based attacks.

Enterprise-wide MFA would eliminate many easy attack paths.

---

# The Surprise

## GAP-011 – Unmanaged Raspberry Pi Monitor

### Original Rating
**Medium**

### Updated Rating
**Upgraded**

### Why the Threat View Changed

Initially, the Raspberry Pi appeared low impact because it did not directly store PHI or control clinical systems.

Threat modeling changed this assessment.

An unmanaged internal device can become:

- A hidden attacker foothold.
- A location for credential harvesting.
- A persistent access point that bypasses normal endpoint security.

Modern attackers do not always target the most valuable system first. They often compromise the weakest unmanaged device and use it as a stepping stone.

The lesson from the threat analysis is that asset visibility itself is a security control. Unknown devices increase uncertainty and create opportunities for attackers.

---

# Final Assessment

The threat-informed analysis shows that MedDefense's highest-risk weaknesses are not isolated technical problems. They are attack-path enablers.

The most important remediation priorities are:

1. Improve visibility through centralized monitoring.
2. Reduce attacker movement through network segmentation.
3. Strengthen identity protection through MFA and lifecycle management.
4. Improve resilience through secure backups and recovery planning.
5. Control sensitive data movement through DLP and behavioral monitoring.

These changes would interrupt the greatest number of realistic attack scenarios and provide the highest reduction in enterprise risk.