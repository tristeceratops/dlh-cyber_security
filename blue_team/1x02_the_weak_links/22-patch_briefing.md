# The Patch Briefing

## Introduction

### Goal
Compress the assessment into an executive briefing focused on urgent action items.

### Context
James Chen has his routine now. Board meeting Monday. Five minutes. Three hundred words. This time, the message is about what needs to happen this week, not this quarter.

"The Board approved our security budget last week based on your threat landscape. Now they want to see us moving. Give me the 3 things we patch this week and what happens if we do not."

## Answer

# MedDefense Health Systems - Patch Briefing

## Immediate Action Required (24-48 hours)

### 1. GAP-017 - Missing MFA for Critical Access

**What it is:**  
Many MedDefense systems still rely only on passwords. If an employee password is stolen through phishing, an attacker can log in as that user.

**Business impact if exploited:**  
An attacker could access VPN, EHR, Microsoft 365, or internal systems using stolen credentials. This could lead to patient data exposure, ransomware deployment, and disruption of clinical operations.

**Fix cost:**  
- Time: Start immediately; initial rollout within days, full deployment over weeks.
- Cost: Estimated $10K-$50K for MFA deployment and configuration.

---

### 2. GAP-016 - Internet-Facing Systems Missing Patch Governance

**What it is:**  
Public-facing systems such as VPN, firewall-related services, and patient portal components may contain known weaknesses because patching is not managed through a formal process.

**Business impact if exploited:**  
Attackers could gain an entry point into MedDefense's network from the internet, then move toward patient records, billing systems, and critical infrastructure.

**Fix cost:**  
- Time: Emergency review and patching within 24-48 hours.
- Cost: Estimated $1K-$10K for assessment, updates, and validation.

---

### 3. GAP-003 - Unsupported MRI Control Workstation (Windows XP)

**What it is:**  
The MRI workstation runs an operating system that no longer receives security updates. New vulnerabilities cannot be reliably fixed.

**Business impact if exploited:**  
A compromised MRI workstation could interrupt radiology services, affect patient imaging workflows, and provide attackers a path into the hospital network.

**Fix cost:**  
- Time: Immediate isolation and monitoring; replacement requires longer planning.
- Cost: Short-term controls: $1K-$10K. Full replacement may exceed $50K.

---

## Security Progress After 3 Weeks

In three weeks, MedDefense moved from identifying internal weaknesses (posture assessment), to understanding likely attackers and attack paths (threat landscape), to ranking and prioritizing vulnerabilities with business impact (vulnerability assessment), creating a clear security improvement roadmap.