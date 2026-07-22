# The Budget Game

## Introduction

### Goal
Make binding resource allocation decisions under realistic budget constraints, demonstrating that every dollar has a reason behind it.

### Context
You have 8 controls evaluated, ranked by net value. You have $120,000. The math does not lie: you cannot fund everything. This task forces the trade-offs that every real security program faces.

James Chen frames it bluntly: "The Board gave us $120,000. Not $121,000. Every dollar we spend on one control is a dollar we cannot spend on another. Choose wisely."

## Answer

# MedDefense Security Investment Plan

================================================================================
Part 1 – Control Selection ($120,000 Budget)
================================================================================

### Funded Controls

| Control | Cost | Reason |
|---|---:|---|
| MFA for VPN & Administrative Accounts | $8,000 | Highest ROI; significantly reduces credential theft and VPN compromise. |
| Network Segmentation | $20,000 | Breaks ransomware and lateral movement kill chains. |
| Enterprise SIEM (Wazuh) | $25,000 | Improves detection across all critical systems. |
| Offsite Immutable Backups | $18,000 | Reduces ransomware recovery costs and improves resilience. |
| Dedicated Firewall for Westside Clinic | $10,000 | Removes a vulnerable perimeter entry point. |
| Sophos Intercept X (EDR) | $35,000 | Improves endpoint detection and malware prevention. |

**Total Spend:** $116,000

**Budget remaining:** $4,000

---

### Deferred Controls (Next Fiscal Year)

| Control | Cost | Reason |
|---|---:|---|
| Outsourced 24/7 SOC | $90,000 | Provides strong monitoring, but SIEM already delivers acceptable visibility within the current budget. Defer until internal monitoring maturity is established. |

---

### Rejected Controls

| Control | Reason |
|---|---|
| Full Medical Device Network Isolation | Current ALE reduction (~$45K/year) is lower than the implementation cost ($60K). Existing segmentation and credential improvements partially reduce this risk, making it a poor investment this year. |

================================================================================
Part 2 – Opportunity Cost
================================================================================

Opportunity cost is expressed as the **annual risk exposure (ALE) that remains because a control is not implemented**.

- **Outsourced 24/7 SOC:** By deferring this control, MedDefense accepts an estimated **$950,000 in annual risk exposure (ALE)** that could otherwise be reduced through faster detection, containment, and incident response.

- **Medical Device Network Isolation:** By rejecting this control, MedDefense accepts approximately **$45,000 in annual risk exposure (ALE)** associated with medical device compromise because the expected annual loss is lower than the implementation cost.

**Summary:** Deferring the managed SOC leaves the largest amount of residual annual risk ($950,000 ALE) and should be the highest-priority investment in the next fiscal year if additional funding becomes available. The medical device isolation project is intentionally rejected because its annual risk reduction ($45,000 ALE) does not justify its $60,000 implementation cost under MedDefense's fixed $120,000 security budget.

================================================================================
Part 3 – Alternative Allocation
================================================================================

### Alternative Investment

| Control | Cost |
|---|---:|
| MFA | $8,000 |
| Network Segmentation | $20,000 |
| SIEM | $25,000 |
| Immutable Backups | $18,000 |
| Dedicated Firewall | $10,000 |
| Managed SOC | $39,000 |

**Total spend:** $120000  
**Budget remaining:** $0

### Comparison

| Plan | Cost | Risk reduction |
|---|---:|---:|
| Primary plan (includes EDR) | $116,000 | ~$3.97M ALE reduction/year |
| Alternative (replaces EDR with SOC) | $120000 | ~$4.99M ALE reduction/year |

### Decision

The Alternative provides higher estimated risk reduction at the same budget by improving monitoring and response. However, the trade-off is clear: by removing EDR, MedDefense accepts weaker endpoint protection, including less malware prevention, slower host isolation, and reduced ransomware containment.

The primary plan keeps stronger endpoint controls, while the Alternative improves detection coverage. The choice depends on whether MedDefense prioritizes prevention at endpoints or faster detection through a SOC.

The Alternative achieves higher risk reduction at a lower cost than adding a full SOC plus EDR, but management must accept the remaining endpoint exposure.
