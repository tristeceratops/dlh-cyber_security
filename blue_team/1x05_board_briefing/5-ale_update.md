# The ALE Update

## Introduction

### Goal
Recalculate MedDefense's ransomware ALE using the new intelligence from the Crimson Tide advisory, demonstrating that threat intelligence directly changes risk quantification.

### Context
In 1x03 T6, you calculated the ALE for a ransomware attack on MedDefense using sector data from the intelligence dossier. The Crimson Tide advisory provides NEW data: 5 confirmed attacks on similar hospitals in 10 days, 3 in your geographic region. The ARO just changed. The ALE must be recalculated.

This is a powerful demonstration of why risk analysis is continuous, not one-time. New intelligence means new numbers. New numbers mean new priorities. New priorities mean new budget decisions.

## Answer

# MedDefense – Updated Ransomware ALE Analysis After Crimson Tide Intelligence

## Part 1 – Original vs Updated ALE

### Original 1x03 T6 Calculation

| Metric | Value |
|---|---:|
| Asset Value (AV) | $9,548,000 |
| Exposure Factor (EF) | 100% |
| Single Loss Expectancy (SLE) | $9,548,000 |
| Original ARO | 0.30 |
| Original ALE | $2,864,400 |

Calculation:
SLE = $9,548,000 × 100% = $9,548,000

ALE = $9,548,000 × 0.30 = $2,864,400


## Updated Calculation Using Crimson Tide Data

New intelligence:
- 5 ransomware attacks against similar healthcare organizations in 10 days.
- Healthcare remains a high-value ransomware target.
- VPN compromise is a common initial access method.
- MedDefense has known weaknesses: weak segmentation, limited monitoring, and exposed VPN infrastructure.

The original ARO was based on historical probability. Crimson Tide evidence shows the threat frequency is higher, so the ransomware likelihood must increase.

| Metric | Original | Updated |
|---|---:|---:|
| ARO | 0.30 | 0.75 |
| SLE | $9,548,000 | $9,548,000 |
| ALE | $2,864,400 | $7,161,000 |

Updated calculation:

ALE = $9,548,000 × 0.75

Updated ALE = $7,161,000


ALE Change:

$7,161,000 - $2,864,400 = +$4,296,600


Reason for change:
The impact of ransomware did not change. The probability increased because Crimson Tide demonstrates that ransomware attacks against healthcare organizations are occurring more frequently than originally estimated.


# Part 2 – Budget Impact

## Updated Control Evaluation

| Control | Original Decision | After Crimson Tide |
|---|---|---|
| MFA | Justified | Critical priority |
| Network Segmentation | Justified | Critical priority |
| SIEM/MDR | Justified | More valuable |
| Immutable Backups | Justified | More valuable |
| EDR | Justified | More valuable |
| Dedicated Firewall | Justified | More urgent |
| Outsourced SOC | Deferred | Now financially justified |
| Medical Device Isolation | Not justified | Still lower priority |

## Controls Previously Not Justified

### Medical Device Isolation

Original calculation:

ALE reduction: $45,000  
Control cost: $60,000  
Net value: -$15,000

Conclusion:
Still not the main investment priority because Crimson Tide primarily exploits:
- VPN access
- Credential compromise
- Enterprise systems
- Data theft paths

Medical device isolation remains important for patient safety but is a secondary investment.


## FortiGate Support Renewal ROI

Emergency support cost:

$2,400

Potential risk reduction:

$9,548,000 × 0.05 = $477,400

ROI:

($477,400 - $2,400) / $2,400 ≈ 19,700%

| Question | Answer |
|---|---|
| Renew FortiGate support? | Yes |
| Positive ROI? | Yes |
| Emergency approval required? | Yes |

The support contract is extremely cost-effective because it reduces exposure on the primary ransomware entry point.


# Board Spending Recommendation

Current security strategy:

| Item | Amount |
|---|---:|
| Approved security budget | $120,000 |
| Planned controls | $116,000 |
| Remaining budget | $4,000 |

Updated ransomware exposure:

Annual Loss Expectancy: $7.16M

Recommendation:

| Decision | Result |
|---|---|
| Approve FortiGate renewal | Yes |
| Approve emergency cybersecurity spending | Yes |
| Increase budget beyond $120K | Recommended |

Reason:
The organization is facing a multi-million-dollar expected ransomware loss. Small emergency investments provide a significant reduction in financial exposure.


# Final Assessment

Crimson Tide changes MedDefense's ransomware risk from a possible future event into an active and measurable threat.

Main changes:
- ALE increased from $2.86M to $7.16M.
- Existing ransomware controls become even more justified.
- FortiGate support renewal becomes an immediate requirement.
- Additional emergency funding should be approved.

The updated threat intelligence shows that delaying ransomware defenses creates a significantly larger financial and operational risk than the cost of immediate security improvements.