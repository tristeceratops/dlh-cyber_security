# The Risk Decisions

## Introduction

### Goal
Apply risk treatment strategies to prioritized gaps under realistic budget and operational constraints.

### Context
James Chen sits down with you for a strategy session.

"OK. We've identified the problems. Now the hard part: what do we actually DO about them ? I have a security budget of $120,000 for this fiscal year. That sounds like a lot until you realize that one enterprise SIEM license costs $80,000. We cannot fix everything. We need to be strategic."

"For each of our top gaps, we need a treatment decision. And 'fix it' is not a strategy."

The four risk treatment strategies:

-    Mitigate: Implement controls to reduce the risk to an acceptable level. Costs money and/or effort.

-    Transfer: Shift the financial consequence to a third party (insurance, outsourcing). Does not eliminate the risk, changes who pays.

-    Accept: Acknowledge the risk and take no action. Requires documented justification and management sign-off. Valid when the cost of mitigation exceeds the potential loss.

-    Avoid: Eliminate the risk by eliminating the activity or asset that creates it. Sometimes the right answer, but often not feasible.

## Answer

The seven gaps below are the highest-priority items after the Task 13 reality check. They are ordered by practical urgency: the fastest ways an attacker could get in, spread, or cause patient-impacting damage.

### GAP-016

**Gap ID:** GAP-016  
**Gap Title:** Internet-facing systems lack explicit vulnerability and patch management coverage  
**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** This is the cleanest way to close the same initial-access pattern seen in real breaches: exposed perimeter and DMZ services that remain unpatched long enough to be exploited. MedDefense can implement a disciplined patch/vulnerability process without buying a giant platform, so this is high leverage and operationally feasible.

**If Mitigate:**
- **Proposed Control(s):** Technical - Preventive vulnerability scanning and patch SLAs for exposed systems; Technical - Detective verification after patching.
- **Estimated Cost:** $1-10K
- **Implementation Effort:** Short-term < 1 month
- **Expected Risk Reduction:** High. It removes the most obvious entry path for VPN, portal, and edge-device exploitation and gives IT a defined maintenance cadence instead of ad hoc patching.

**Trade-offs:** Requires maintenance windows and some downtime coordination for perimeter systems.

### GAP-017

**Gap ID:** GAP-017  
**Gap Title:** Remote access and clinical access lack MFA at scale  
**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Stolen or retained passwords should not be enough to reach EHR, VPN, or cloud systems. MFA is a direct control against the exact insider/credential abuse pattern seen in the breach data and is one of the strongest risk reducers MedDefense can buy.

**If Mitigate:**
- **Proposed Control(s):** Technical - Preventive enterprise MFA for VPN, EHR, cloud, and privileged access.
- **Estimated Cost:** $10-50K
- **Implementation Effort:** Short-term < 1 month
- **Expected Risk Reduction:** High. It turns a password-only compromise into a much harder attack and significantly reduces the value of phishing and retained credentials.

**Trade-offs:** User friction and rollout support burden, especially for clinical workflows that need careful exception handling.

### GAP-013

**Gap ID:** GAP-013  
**Gap Title:** Offboarding is manual and vulnerable to retained access  
**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** This is a relatively cheap control to automate compared with the damage a former employee can cause if their VPN, EHR, or cloud access stays active. The main problem is process, not technology.

**If Mitigate:**
- **Proposed Control(s):** Administrative - Preventive joiner-mover-leaver workflow linked to HR; Technical - Preventive automated disablement for VPN/EHR/cloud accounts.
- **Estimated Cost:** $1-10K
- **Implementation Effort:** Short-term < 1 month
- **Expected Risk Reduction:** High. It closes one of the most common insider-threat paths by ensuring termination events trigger deprovisioning instead of relying on human memory.

**Trade-offs:** Requires coordination between HR, IT, and department managers; exceptions must be handled carefully.

### GAP-004

**Gap ID:** GAP-004  
**Gap Title:** No centralized security monitoring or SIEM  
**Risk Level:** Critical

**Treatment Strategy:** Transfer

**Justification:** A full enterprise SIEM is too expensive to be the first purchase in a $120,000 year, but doing nothing leaves MedDefense blind. The right interim move is to transfer the monitoring burden to an outsourced managed detection service that can ingest key logs, triage alerts, and escalate incidents without buying the full platform outright.

**If Transfer:**
- **Transfer Mechanism:** Managed Detection and Response (MDR) / outsourced SOC contract with log review and escalation.
- **Residual Risk:** Detection quality still depends on the provider, log coverage, and tuning; niche systems may still be slow to surface.

**Trade-offs:** Less direct control than an internal SIEM and continued dependence on a vendor for alert triage.

### GAP-006

**Gap ID:** GAP-006  
**Gap Title:** Flat network and permissive remote access still expose critical systems  
**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Segmentation and tighter VPN rules reduce blast radius across multiple breach scenarios, not just one. This is a high-value architectural fix because it limits how far an attacker can move once they get in.

**If Mitigate:**
- **Proposed Control(s):** Technical - Preventive internal VLAN segmentation; Technical - Preventive tighter VPN ACLs and service allowlisting; Technical - Detective change validation on firewall rules.
- **Estimated Cost:** $10-50K
- **Implementation Effort:** Long-term > 1 month
- **Expected Risk Reduction:** High. It contains compromise and makes lateral movement materially harder across clinical, billing, and identity systems.

**Trade-offs:** Network change complexity and coordination with application owners who are accustomed to unrestricted reachability.

### GAP-005

**Gap ID:** GAP-005  
**Gap Title:** Backups are not resilient enough for recovery  
**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Backups are the last line of defense when prevention fails. MedDefense already has backup tooling, so the best use of money is to harden the recovery path rather than buy a completely new backup stack.

**If Mitigate:**
- **Proposed Control(s):** Technical - Corrective offsite/immutable backup storage; Administrative - Corrective restore testing and disaster recovery documentation.
- **Estimated Cost:** $10-50K
- **Implementation Effort:** Long-term > 1 month
- **Expected Risk Reduction:** High. It prevents a single ransomware or site failure from destroying both production and recovery copies.

**Trade-offs:** Ongoing storage and test overhead, plus the need to prove restores actually work.

### GAP-001

**Gap ID:** GAP-001  
**Gap Title:** Unattended EHR session at the nurse station  
**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** This is a direct patient-safety and privacy problem, but it is also one of the least expensive to improve. A quick lockout and workstation-use policy change can eliminate a common point-of-care exposure.

**If Mitigate:**
- **Proposed Control(s):** Technical - Preventive workstation auto-lock and idle timeout enforcement; Physical - Preventive privacy screens and local awareness signage.
- **Estimated Cost:** $0-1K
- **Implementation Effort:** Quick Win < 1 week
- **Expected Risk Reduction:** High. It closes the most obvious in-use exposure and makes shoulder-surfing or walk-up misuse much harder.

**Trade-offs:** Compliance depends on staff behavior and consistent workstation configuration enforcement.

### Budget Summary

Planned annual spend for the mitigations and transfer decision is approximately $114,000:

- GAP-016: $8,000
- GAP-017: $30,000
- GAP-013: $5,000
- GAP-004: $15,000 transferred MDR/SOC service
- GAP-006: $20,000
- GAP-005: $35,000
- GAP-001: $1,000

That leaves about $6,000 as contingency for rollout support, training, or unplanned remediation work.

What gets deferred: the MRI platform redesign behind GAP-003 and any full billing-server replacement work from GAP-008 should move to next fiscal year. Both are important, but they are more capital-intensive and already have some compensating controls in place, so this year’s budget is better spent reducing the higher-probability enterprise entry points and restoring detection/recovery depth.