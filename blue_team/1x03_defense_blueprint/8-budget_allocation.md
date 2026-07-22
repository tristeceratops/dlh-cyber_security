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

This portfolio is funded because it provides the highest combined risk reduction by addressing ransomware entry, lateral movement, data loss, detection gaps, and endpoint compromise.

### Defer

| Control | Reason |
|---|---|
| 24/7 Managed SOC | Defer to next fiscal year because SIEM deployment improves visibility first and a SOC requires additional recurring budget. |
| Full Medical Device Network Isolation | Defer because segmentation reduces immediate exposure while full device isolation requires a larger clinical network redesign. |

### Reject

| Control | Reason |
|---|---|
| None | All remaining controls provide security value; they are deferred rather than rejected because budget limits prevent immediate implementation. |

================================================================================
Part 2 – Opportunity Cost
================================================================================

By deferring 24/7 Managed SOC, MedDefense accepts an estimated $900,000 in annual risk exposure because delayed detection increases ransomware dwell time and incident impact.

By deferring Full Medical Device Network Isolation, MedDefense accepts an estimated $300,000 in annual risk exposure because medical devices remain exposed to compromise through the flat network.

The remaining ALE after funded controls is reduced, but these deferred risks represent the main unresolved exposure areas.

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

### Comparison

| Plan | Spend | Estimated ALE Risk Reduction |
|---|---:|---:|
| Recommended Portfolio with EDR | $116,000 | ~$3.97M/year |
| Alternative with SOC | $106,000 | ~$3.80M/year |

The Alternative achieves similar risk reduction at a lower cost, but it trades endpoint protection for monitoring. Removing EDR reduces malware prevention, host isolation capability, and ransomware containment speed.

Final recommendation: fund the $116,000 portfolio because MedDefense has limited security staff and needs both prevention and recovery controls. The Alternative is acceptable only if management accepts higher endpoint risk in exchange for lower cost.
