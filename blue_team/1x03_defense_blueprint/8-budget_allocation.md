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

**Budget Remaining:** $4,000

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

- **Outsourced 24/7 SOC:** By deferring this control, MedDefense accepts an estimated **$950,000/year** of additional residual risk reduction that could have been achieved through faster detection and response.

- **Medical Device Network Isolation:** By rejecting this control, MedDefense accepts approximately **$45,000/year** in residual medical device risk because the control is not cost-effective under the current budget.

================================================================================
Part 3 – Alternative Allocation
================================================================================

### Alternative Investment

| Control | Cost |
|---|---:|
| MFA | $8,000 |
| Network Segmentation | $20,000 |
| Enterprise SIEM | $25,000 |
| Offsite Immutable Backups | $18,000 |
| Dedicated Firewall | $10,000 |
| Outsourced 24/7 SOC | $39,000 (partial first-year managed service) |

**Total Cost:** $120,000

**Estimated Total ALE Reduction:** ~$4.99M/year

### Comparison

| Plan | Cost | Estimated ALE Reduction |
|---|---:|---:|
| Primary Recommendation (includes EDR) | $116,000 | ~$3.97M/year |
| Alternative (replace EDR with partial SOC) | $120,000 | ~$4.99M/year |

**Recommendation:** The **primary plan** provides the best balance of prevention, detection, and resilience while staying under budget. If MedDefense can negotiate a lower-cost managed SOC service, the **alternative plan** could deliver greater overall risk reduction by improving continuous monitoring instead of investing in a premium EDR upgrade.