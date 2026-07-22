# The ALE Workshop

## Introduction

### Goal

### Context

## Answer

# MedDefense Quantitative Risk Register

================================================================================
Risk 1: EHR Data Breach
================================================================================
Source: GAP-004, GAP-006, GAP-016 + F-002 (EHR exposure) + Ransomware/Credential Theft

Asset: EHR (ehr-srv-01 + ehr-db-01)

AV = $9,075,000
- Breach response (50,000 × $165): $8,250,000
- HIPAA notification: $25,000
- Litigation: $200,000
- Reputation/patient loss: $600,000

EF: 100%
Reasoning: A successful breach incurs nearly all costs.

SLE = $9,075,000 × 100% = $9,075,000

ARO = 0.33 (1 breach every ~3 years)
Reasoning: No SIEM, flat network, weak patching.

ALE = $9,075,000 × 0.33 = $2,994,750

Proposed Control: MFA + SIEM/MDR + vulnerability management
Control Annual Cost: $45,000
Estimated ALE After Control: $907,500 (ARO reduced to 0.10)

Net Benefit = $2,994,750 − $907,500 − $45,000 = $2,042,250

================================================================================
Risk 2: VPN Compromise Leading to Enterprise Ransomware
================================================================================
Source: GAP-016, GAP-017 + F-001 (FortiGate exposure) + BlackReef ransomware

Asset: FortiGate VPN / Internal Network

AV = $9,548,000
- Billing impact: $473,000
- EHR breach impact: $9,075,000

EF: 100%
Reasoning: VPN compromise enables full network compromise.

SLE = $9,548,000

ARO = 0.30
Reasoning: VPN is a common healthcare attack vector.

ALE = $9,548,000 × 0.30 = $2,864,400

Proposed Control: Enterprise MFA + FortiGate patching
Control Annual Cost: $30,000
Estimated ALE After Control: $954,800 (ARO reduced to 0.10)

Net Benefit = $2,864,400 − $954,800 − $30,000 = $1,879,600

================================================================================
Risk 3: Negligent Insider Data Theft
================================================================================
Source: GAP-014, GAP-019 + F-008 (No DLP) + Insider Threat

Asset: Clinical Workstations / PHI

AV = $120,000
- Investigation, remediation, reporting and fines

EF: 100%
Reasoning: Most response costs occur once data leaves the organization.

SLE = $120,000

ARO = 2.5
Reasoning: 2–3 incidents/year expected.

ALE = $120,000 × 2.5 = $300,000

Proposed Control: DLP + USB restrictions + awareness training
Control Annual Cost: $20,000
Estimated ALE After Control: $60,000 (ARO reduced to 0.5)

Net Benefit = $300,000 − $60,000 − $20,000 = $220,000

================================================================================
Risk 4: Billing Server Ransomware
================================================================================
Source: GAP-005, GAP-016 + F-004 (Outdated server) + Ransomware

Asset: billing-srv-01

AV = $473,000
- Recovery: $85,000
- Downtime: $288,000
- HIPAA penalty: $100,000

EF: 90%
Reasoning: Most business value is temporarily lost.

SLE = $425,700

ARO = 0.30

ALE = $127,710

Proposed Control: Patching + immutable backups
Control Annual Cost: $35,000
Estimated ALE After Control: $42,570 (ARO reduced to 0.10)

Net Benefit = $127,710 − $42,570 − $35,000 = $50,140

================================================================================
Risk 5: Medical Device Compromise
================================================================================
Source: GAP-015 + F-010 (Default credentials) + Opportunistic Attacker

Asset: BD Alaris Infusion Pumps

AV = $2,900,000
- Liability: $2,750,000
- FDA investigation: $150,000

EF: 100%
Reasoning: A successful patient-safety event incurs full costs.

SLE = $2,900,000

ARO = 0.02 (1 event every ~50 years)

ALE = $58,000

Proposed Control: Change default credentials + isolate medical devices
Control Annual Cost: $15,000
Estimated ALE After Control: $14,500 (ARO reduced to 0.005)

Net Benefit = $58,000 − $14,500 − $15,000 = $28,500

================================================================================
Risk Prioritization by ALE
================================================================================

| Rank | Risk | ALE |
|-----:|--------------------------------------------|-----------:|
| 1 | EHR Data Breach | $2,994,750 |
| 2 | VPN Compromise / Enterprise Ransomware | $2,864,400 |
| 3 | Negligent Insider Data Theft | $300,000 |
| 4 | Billing Server Ransomware | $127,710 |
| 5 | Medical Device Compromise | $58,000 |