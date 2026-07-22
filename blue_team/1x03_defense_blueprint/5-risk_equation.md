# The Risk Equation

## Introduction

### Goal
Master quantitative risk analysis by calculating SLE, ARO and ALE for concrete MedDefense scenarios.

### Context
Up to this point, you have assessed risk qualitatively: Critical, High, Medium, Low. That is useful for triage but useless for budgeting. A CFO does not fund "High risk." A CFO funds "$180,000 in expected annual loss that we can reduce to $12,000 for a $40,000 investment."

Quantitative risk analysis replaces opinions with math:

-    Asset Value (AV): What is the asset worth ? (Replacement cost + revenue loss + regulatory fines + reputation damage)

-    Exposure Factor (EF): If the threat materializes, what percentage of the asset value is lost ? (0% to 100%)

-    Single Loss Expectancy (SLE): AV × EF = the cost of one incident

-    Annualized Rate of Occurrence (ARO): How many times per year do we expect this incident ? (Can be less than 1, for example 0.2 means once every 5 years)

-    Annualized Loss Expectancy (ALE): SLE × ARO = the expected annual cost of this risk

The math is simple. The judgment behind the numbers is what matters.

## Answer

# MedDefense Quantitative Risk Analysis Summary

| Scenario | AV Calculation | EF | SLE | ARO | ALE | Confidence |
|---|---|---|---|---|---|---|
| 1. Billing ransomware | Downtime ($16K×18=$288K) + Recovery ($85K) + HIPAA ($100K) = $473K | 90% | $425.7K | 0.30 (1 attack/3-4 yrs) | $127.7K | Medium (downtime assumption changes result most) |
| 2. EHR breach | PHI (50K×$165=$8.25M) + Notification ($25K) + Legal ($200K) + Lost revenue ($600K) = $9.075M | 100% | $9.075M | 0.33 (1 breach/3 yrs) | $2.99M | Medium (number of exposed records changes result most) |
| 3. Negligent insider | Average healthcare insider incident cost = $120K | 100% | $120K | 2.5 incidents/year | $300K | High (incident frequency is main assumption) |
| 4A. Medical device DoS | Downtime ($20K×5=$100K) + FDA ($150K) = $250K | 100% | $250K | 0.10 (1/10 yrs) | $25K | Low (attack probability uncertain) |
| 4B. Patient safety event | Liability ($2.75M midpoint) + FDA ($150K) = $2.9M | 100% | $2.9M | 0.02 (1/50 yrs) | $58K | Low (probability of harm is uncertain) |
| 5. VPN compromise | Billing impact ($473K) + EHR breach ($9.075M) = $9.548M | 100% | $9.548M | 0.30 (VPN common ransomware entry) | $2.86M | Medium (VPN security posture changes ARO) |

Key conclusions:
- Highest risk: EHR breach ($2.99M ALE) because PHI exposure creates the largest financial impact.
- Second: VPN compromise ($2.86M ALE) because it enables ransomware + data theft across the entire hospital.
- Biggest uncertainty: medical device risk because probability is low but impact is catastrophic.
- Priority controls: MFA, network segmentation, monitoring, and vulnerability management reduce the highest ALE risks.