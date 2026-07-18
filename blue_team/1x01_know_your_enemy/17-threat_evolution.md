# The What-If

## Introduction

### Goal
Demonstrate how business decisions and external events can reshape MedDefense's threat landscape.

### Context
Cyber risk changes as the organization changes. New partnerships, technology migrations, and public incidents can introduce new attackers, create new attack paths, and change which weaknesses matter most. The following scenarios evaluate how MedDefense's threat profile would evolve under three realistic business conditions.

## Answer

# Scenario A: Clinical Trial Partnership with University and International Research Institutions

## Situation

MedDefense launches a cardiac clinical trial involving:

- 500 patients.
- Proprietary research protocols.
- Three international research institutions.
- A dedicated research data server hosted at Central Hospital.

The trial introduces new sensitive data types beyond normal patient records, including experimental treatment information, intellectual property, and international collaboration data.

---

## New Threat Actors

**Yes. New adversaries become relevant.**

### State-sponsored groups
Foreign intelligence organizations may target the research because experimental medical treatments and clinical research data have strategic value.

### Academic and research competitors
Competitors may attempt to steal proprietary protocols, trial results, or intellectual property.

### Cybercriminal data brokers
Attackers may target trial participants because medical research data combined with PHI has high resale value.

### Insider researchers
Researchers, contractors, or collaborators with legitimate access could intentionally or accidentally expose trial information.

---

## Changed Vectors

### More Relevant

- **Compromised researcher accounts**
  - International collaborators increase the number of identities requiring access.
  - Phishing becomes more attractive because researchers are less likely to follow hospital security processes.

- **Cloud collaboration and file sharing abuse**
  - Research documents may move through external platforms.

- **Insider data exfiltration**
  - Large research datasets become attractive targets.

- **Third-party compromise**
  - University systems and research partners become additional trust relationships.

### Less Relevant

- Traditional ransomware targeting only operational systems becomes slightly less dominant because attackers gain additional value from stealing research data before encryption.

---

## Shifted Priorities

### Top 5 Threat Changes

| Previous Rank | Threat | New Position |
|---|---|---|
| 1 | Ransomware causing clinical outage | Remains #1 |
| 2 | Credential compromise | Remains #2 |
| 3 | PHI/data theft | Moves higher as research theft becomes possible |
| 4 | Vendor compromise | Remains important |
| 5 | Legacy medical systems | Moves down |

A new concern emerges:

**Research data theft becomes nearly equal in priority to ransomware.**

The combination of PHI, intellectual property, and international collaboration increases the value of a successful breach.

---

## New Gaps

### New Gap: Research environment lacks dedicated access governance

The existing environment did not previously manage:

- External researcher identities.
- International access requirements.
- Research dataset permissions.
- Intellectual property protection.

### Related Existing Gaps

- GAP-014 – Sensitive data exports lack DLP and behavioral monitoring.
- GAP-013 – Offboarding is manual and vulnerable to retained access.
- GAP-009 – Unmanaged research data storage risk.

---

## Net Assessment

**Threat exposure increases because MedDefense gains valuable research data and additional external identities that expand the attack surface beyond traditional healthcare operations.**

---

# Scenario B: EHR Migration to MedTech Solutions Cloud SaaS Platform

## Situation

MedDefense moves the EHR from:

- A-001 ehr-srv-01
- A-002 ehr-db-01

to a cloud-hosted SaaS environment managed by MedTech Solutions.

On-premises EHR infrastructure is retired and all access occurs through the vendor cloud platform.

---

## New Threat Actors

**Yes. The threat landscape shifts toward cloud and identity attackers.**

### Cloud-focused cybercriminal groups
Attackers increasingly target SaaS accounts because compromising one identity can provide access without needing internal network access.

### Vendor compromise actors
MedTech Solutions becomes a more important target because compromise affects multiple healthcare customers.

### Account takeover groups
Credential theft becomes more valuable because cloud access replaces direct server exploitation.

---

## Changed Vectors

### More Relevant

- **Identity compromise**
  - User accounts become the primary security boundary.

- **Phishing and MFA bypass**
  - Attackers target cloud authentication workflows.

- **Vendor compromise**
  - MedTech Solutions becomes a critical dependency.

- **API abuse**
  - SaaS integrations may create additional access paths.

### Less Relevant

- Direct exploitation of ehr-srv-01 and ehr-db-01 decreases because those assets no longer exist.

- Internal database attacks become less relevant because MedDefense no longer manages the database infrastructure directly.

---

## Shifted Priorities

### Top 5 Threat Changes

| Previous Rank | Threat | New Position |
|---|---|---|
| 1 | Ransomware causing hospital outage | Remains high but changes form |
| 2 | Credential compromise | Moves to #1 |
| 3 | PHI theft | Moves higher |
| 4 | Vendor compromise | Moves to #2 or #3 |
| 5 | Legacy medical systems | Unchanged |

The biggest change is that identity becomes the primary security perimeter.

---

## New Gaps

### New Gap: SaaS identity governance maturity

MedDefense would need controls for:

- Cloud administrator privileges.
- SaaS audit logging.
- Conditional access policies.
- Vendor security assurance.
- API permissions.

### Related Existing Gaps

- GAP-017 – Remote access and clinical access lack MFA at scale.
- GAP-004 – No centralized security monitoring.
- GAP-013 – Manual identity lifecycle management.

---

## Net Assessment

**Threat exposure shifts rather than simply increasing: infrastructure risks decrease, but identity, cloud configuration, and vendor dependency risks become significantly more important.**

---

# Scenario C: National Media Coverage of January Ransomware Incident

## Situation

A regional news outlet reports that MedDefense suffered a ransomware attack against billing-srv-01. Former patients express concerns about possible data exposure, and national healthcare media amplify the story.

---

## New Threat Actors

**Yes. Public attention attracts additional adversaries.**

### Extortion groups
Attackers may view MedDefense as a proven target and attempt repeat attacks.

### Opportunistic cybercriminals
Public reporting confirms that MedDefense has been breached before, increasing attacker interest.

### Regulatory investigators
Government agencies may become involved due to possible patient data exposure.

### Reputation-focused attackers
Hacktivists or individuals may target the organization because of public visibility.

---

## Changed Vectors

### More Relevant

- **Phishing campaigns**
  - Attackers may use the incident publicly as social engineering material.

- **Credential attacks**
  - Employees may receive fake breach notifications or password reset requests.

- **Ransomware reinfection**
  - Attackers know MedDefense has already experienced compromise.

- **Data leak exploitation**
  - Previously stolen data may be reused or resold.

### Less Relevant

- Lower-value opportunistic attacks become less important because attackers focus on a known healthcare victim.

---

## Shifted Priorities

### Top 5 Threat Changes

| Previous Rank | Threat | New Position |
|---|---|---|
| 1 | Ransomware | Becomes even more urgent |
| 2 | Credential compromise | Moves higher due to targeted phishing |
| 3 | PHI theft | Remains high because breach concerns increase |
| 4 | Vendor compromise | Slightly decreases |
| 5 | Legacy medical systems | Slightly decreases |

The previous ransomware incident creates a "repeat victim" effect.

Attackers know:

- MedDefense pays attention to recovery pressure.
- Some weaknesses may still exist.
- Public concern increases extortion leverage.

---

## New Gaps

### New Gap: Crisis communication and breach response readiness

A public incident exposes weaknesses beyond technology:

- Lack of coordinated public response.
- Limited patient communication planning.
- Potential regulatory response delays.

### Related Existing Gaps

- GAP-012 – No formal incident response plan or tested breach playbooks.
- GAP-004 – No centralized security monitoring.
- GAP-014 – Sensitive data exports lack DLP and behavioral monitoring.

---

## Net Assessment

**Threat exposure increases because public disclosure makes MedDefense a higher-value target while increasing pressure from regulators, patients, and attackers.**

---

# Overall Threat Landscape Changes

| Scenario | Overall Effect | Main Security Shift |
|---|---|---|
| Clinical trial partnership | Increase | More valuable data and more external identities |
| EHR SaaS migration | Shift | Identity and vendor security become dominant risks |
| Public ransomware disclosure | Increase | Higher attacker attention and reputational pressure |

## Final Assessment

MedDefense's threat profile is not fixed. Expanding research increases the value of information assets, cloud migration changes the security boundary from servers to identities, and public breach disclosure increases attacker motivation. The consistent theme across all three scenarios is that identity protection, monitoring, vendor governance, and data protection become increasingly important as the organization becomes more connected.