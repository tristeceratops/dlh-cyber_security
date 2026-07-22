# The Cost-Benefit Analysis

## Introduction

### Goal
Evaluate 8 proposed security controls using formal cost-benefit analysis to determine which investments are financially justified.

### Context
Security controls cost money. Some are worth every cent. Some cost more than the risk they mitigate. The CFO does not care about "best practices." The CFO cares about return on investment.

A control is financially justified when: (ALE before control) minus (ALE after control) is greater than (annual cost of the control).

If the control costs more than the risk reduction it provides, the rational decision is to accept the risk or find a cheaper control. This is not an opinion. It is math.

## Answer

# MedDefense Cost-Benefit Analysis of Proposed Security Controls

================================================================================
Control 1: Network Segmentation (VLANs)
================================================================================
CIS Control: 12 – Network Infrastructure Management
Annual Cost: ~$20,000 ($15K implementation + $5K maintenance)
Risk(s): VPN compromise, EHR breach, ransomware, medical device compromise
ALE Reduction: ~$1,200,000 (reduces lateral movement; lowers VPN/EHR ARO)
Net Value: $1,200,000 − $20,000 = $1,180,000
Verdict: Justified
Recommendation: **Implement** – breaks multiple ransomware kill chains with relatively low cost.

================================================================================
Control 2: MFA for VPN & Administrative Accounts
================================================================================
CIS Control: 6 – Access Control Management
Annual Cost: ~$8,000 ($3K deployment + $5K administration; O365 licensing already owned)
Risk(s): VPN compromise, EHR breach, credential theft
ALE Reduction: ~$1,600,000
Net Value: $1,600,000 − $8,000 = $1,592,000
Verdict: Justified
Recommendation: **Implement immediately** – highest return on investment.

================================================================================
Control 3: Enterprise SIEM (Wazuh)
================================================================================
CIS Control: 8 & 13 – Audit Logs / Network Monitoring
Annual Cost: ~$25,000 ($20K analyst labor + $5K infrastructure)
Risk(s): EHR breach, ransomware, insider threats
ALE Reduction: ~$900,000
Net Value: $900,000 − $25,000 = $875,000
Verdict: Justified
Recommendation: **Implement** – greatly improves detection using open-source software.

================================================================================
Control 4: Offsite Immutable Backups
================================================================================
CIS Control: 11 – Data Recovery
Annual Cost: ~$18,000 ($12K AWS Glacier + $6K testing/maintenance)
Risk(s): Ransomware, billing server compromise
ALE Reduction: ~$250,000
Net Value: $250,000 − $18,000 = $232,000
Verdict: Justified
Recommendation: **Implement** – dramatically reduces ransomware recovery costs.

================================================================================
Control 5: Sophos Intercept X (EDR)
================================================================================
CIS Control: 10 – Malware Defenses
Annual Cost: ~$35,000 (licenses $25K + administration $10K)
Risk(s): Ransomware, malware, credential theft
ALE Reduction: ~$400,000
Net Value: $400,000 − $35,000 = $365,000
Verdict: Justified
Recommendation: **Implement after MFA and SIEM** – strong additional protection but not the highest priority.

================================================================================
Control 6: Dedicated Firewall for Westside Clinic
================================================================================
CIS Control: 12 – Network Infrastructure Management
Annual Cost: ~$10,000 ($8K appliance + $2K support)
Risk(s): VPN compromise, external intrusion
ALE Reduction: ~$120,000
Net Value: $120,000 − $10,000 = $110,000
Verdict: Justified
Recommendation: **Implement** – removes a weak perimeter device at modest cost.

================================================================================
Control 7: Outsourced 24/7 SOC
================================================================================
CIS Control: 13 – Network Monitoring & Defense
Annual Cost: ~$90,000 (managed detection and response service)
Risk(s): All major cyber risks
ALE Reduction: ~$950,000
Net Value: $950,000 − $90,000 = $860,000
Verdict: Marginal
Recommendation: **Defer** – valuable, but difficult to justify within the $120K annual budget when SIEM + analyst provides similar coverage initially.

================================================================================
Control 8: Full Medical Device Network Isolation
================================================================================
CIS Control: 12 – Network Infrastructure Management
Annual Cost: ~$60,000 ($50K engineering + $10K monitoring)
Risk(s): Medical device compromise
ALE Reduction: ~$45,000
Net Value: $45,000 − $60,000 = -$15,000
Verdict: Not Justified
Recommendation: **Reject for this budget cycle** – patient safety impact is high, but the current ALE is too low to justify the investment under a fixed $120K budget.

================================================================================
Cost-Benefit Summary
================================================================================

| Rank | Control | Annual Cost | ALE Reduction | Net Value | Budget Fit |
|-----:|--------------------------------------|-----------:|--------------:|--------------:|:---------:|
| 1 | MFA (VPN/Admin) | $8,000 | $1,600,000 | **$1,592,000** | ✔ |
| 2 | Network Segmentation | $20,000 | $1,200,000 | **$1,180,000** | ✔ |
| 3 | Enterprise SIEM (Wazuh) | $25,000 | $900,000 | **$875,000** | ✔ |
| 4 | Outsourced 24/7 SOC | $90,000 | $950,000 | **$860,000** | ✖ (budget pressure) |
| 5 | Sophos Intercept X (EDR) | $35,000 | $400,000 | **$365,000** | ✔ |
| 6 | Offsite Immutable Backups | $18,000 | $250,000 | **$232,000** | ✔ |
| 7 | Westside Dedicated Firewall | $10,000 | $120,000 | **$110,000** | ✔ |
| 8 | Medical Device Isolation | $60,000 | $45,000 | **-$15,000** | ✖ |

Controls that fit within the $120,000 annual budget (recommended package):
- MFA ($8K)
- Network Segmentation ($20K)
- Enterprise SIEM ($25K)
- Offsite Immutable Backups ($18K)
- Dedicated Westside Firewall ($10K)
- Sophos Intercept X ($35K)

**Total Cost:** ~$116,000 (within the $120,000 budget, leaving ~$4,000 contingency).