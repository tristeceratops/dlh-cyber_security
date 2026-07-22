# The Budget Game

## Introduction

### Goal
Make binding resource allocation decisions under realistic budget constraints, demonstrating that every dollar has a reason behind it.

### Context
You have 8 controls evaluated, ranked by net value. You have $120,000. The math does not lie: you cannot fund everything. This task forces the trade-offs that every real security program faces.

James Chen frames it bluntly: "The Board gave us $120,000. Not $121,000. Every dollar we spend on one control is a dollar we cannot spend on another. Choose wisely."

## Answer

================================================================================
Part 1 – Final Security Investment Selection
================================================================================

### Fund (Recommended Portfolio)

| Control | Cost |
|---|---:|
| MFA on VPN and Administrative Accounts | $8,000 |
| Network Segmentation | $20,000 |
| Enterprise SIEM (Wazuh) | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Dedicated Firewall for Westside Clinic | $10,000 |
| EDR Upgrade (Sophos Intercept X) | $35,000 |

**Total spend:** $116,000  
**Budget:** $120000  
**Budget remaining:** $4,000

This portfolio is funded because it provides the highest risk reduction against ransomware, credential attacks, lateral movement, data loss, and endpoint compromise.

### Defer

| Control | Reason |
|---|---|
| 24/7 Managed SOC | Defer to next fiscal year because SIEM deployment provides internal visibility first and SOC services create a significant recurring cost. |
| Full Medical Device Network Isolation | Defer because segmentation reduces immediate exposure while full isolation requires additional clinical network redesign and funding. |

### Reject

| Control | Reason |
|---|---|
| Full penetration testing program | Reject for the current fiscal year because it provides less immediate risk reduction than preventive controls already selected. With no mature vulnerability management process, the return on investment is lower than funding MFA, backups, SIEM, and segmentation first. |

================================================================================
Part 2 – Opportunity Cost
================================================================================

By deferring 24/7 Managed SOC, MedDefense accepts an estimated $900,000 in annual risk exposure because slower detection increases the potential impact of ransomware and insider incidents.

By deferring Full Medical Device Network Isolation, MedDefense accepts an estimated $300,000 in annual risk exposure because medical devices remain exposed through the existing network architecture.

The remaining ALE after the funded controls is reduced, but these deferred risks represent the main unresolved exposure areas.

================================================================================
Part 3 – Alternative Allocation
================================================================================

### Alternative (Lower Cost Option)

| Control | Cost |
|---|---:|
| MFA | $8,000 |
| Network Segmentation | $20,000 |
| Enterprise SIEM | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Dedicated Firewall | $10,000 |
| Managed SOC (partial service) | $25,000 |

**Alternative spend:** $106,000  
**Budget remaining:** $14,000

| Plan | Spend | Estimated ALE Risk Reduction |
|---|---:|---:|
| Recommended Portfolio with EDR | $116,000 | ~$3.97M/year |
| Alternative with SOC | $106,000 | ~$3.80M/year |

The Alternative provides similar risk reduction at a lower cost, but replacing EDR with SOC reduces endpoint prevention, malware blocking, and ransomware containment capability. The trade-off is better detection and monitoring versus weaker host-level protection.

Final recommendation: fund the $116,000 portfolio because MedDefense needs stronger prevention and resilience with limited internal security resources. The Alternative is only suitable if management accepts the increased endpoint exposure.