# The Framework Landscape

## Introduction

### Goal
Understand the purpose, scope and relationship of the three major security frameworks used in enterprise defense.

### Context
James Chen opens the strategy meeting with a question to Sarah Park: "Which framework should we use ?" Sarah answers: "NIST." James pushes: "NIST what ? CSF ? 800-53 ? RMF ? And what about CIS Controls ? The auditor mentioned ISO 27001 last month."

The framework landscape is confusing even for experienced professionals. Before you can build a strategy, you need to understand your tools: what each framework does, where they overlap and when to use which one.

## Answer

# Framework Comparison

## Part 1 - Three-Framework Summary

| Framework | Summary |
|---|---|
| **NIST CSF 2.0** | Published by **NIST (National Institute of Standards and Technology)**. It provides a cybersecurity risk management framework applicable to organizations of any size. It is organized into **6 Functions**: Govern, Identify, Protect, Detect, Respond and Recover. It is commonly used by healthcare, critical infrastructure and private organizations to prioritize cybersecurity improvements. |
| **CIS Controls v8** | Published by the **Center for Internet Security (CIS)**. It provides a prioritized list of **18 technical and operational controls** that reduce the most common cyber attacks. The controls include safeguards with Implementation Groups (IG1-IG3) based on organizational maturity. It is mainly used by IT and security teams to implement concrete security measures. |
| **ISO/IEC 27001** | Published by the **International Organization for Standardization (ISO)** and **IEC**. It specifies requirements for building and maintaining an **Information Security Management System (ISMS)**. It is structured around management clauses (4-10) and **Annex A controls**. Organizations use it to demonstrate governance and obtain third-party certification for customers, regulators and auditors. |

---

## Part 2 - Relationship Map

NIST CSF defines **what security outcomes** an organization should achieve (risk management objectives). CIS Controls provides **how to implement** those outcomes through practical technical safeguards such as MFA, asset management and vulnerability management. ISO 27001 demonstrates **that these controls are governed, documented and continuously managed** through an auditable ISMS. Together, NIST CSF provides strategy, CIS Controls provide implementation, and ISO 27001 provides governance and evidence.

---

## Part 3 - MedDefense Framework Selection

### Recommended Frameworks

| Framework | Role | Why |
|---|---|---|
| **NIST CSF 2.0** | Strategic framework | Simple risk-based structure suitable for a regional hospital and Board reporting. |
| **CIS Controls v8 (IG1/IG2)** | Operational implementation | Provides concrete actions for a small security team with limited resources. |
| **ISO 27001 (long-term)** | Governance & compliance | Builds audit readiness and regulatory evidence after core security improvements are in place. |

### Quantitative Example

| Item | Value | Calculation |
|---|---:|---|
| Asset Value (AV) | \$600,000 | Estimated impact of EHR outage and recovery |
| Exposure Factor (EF) | 30% | Expected damage from ransomware |
| Single Loss Expectancy (SLE) | \$180,000 | **AV × EF = 600,000 × 0.30** |
| Annual Rate of Occurrence (ARO) | 1 | One significant event/year |
| Annual Loss Expectancy (ALE) | \$180,000 | **SLE × ARO = 180,000 × 1** |

Deploying MFA (GAP-017) is estimated to reduce ARO from **1.0 to 0.07**.

New ALE:

- **SLE = \$180,000**
- **ARO = 0.07**
- **ALE = \$180,000 × 0.07 = \$12,600**

Annual risk reduction:

- **\$180,000 − \$12,600 = \$167,400**

Estimated MFA deployment cost:

- **\$4,000/year** (using existing Microsoft 365 licensing)

---

### Cross-Reference

| Recommendation | Gap (1x00) | Vulnerability (1x02) | Threat (1x01) |
|---|---|---|---|
| Deploy MFA | GAP-017 | Weak authentication findings | Phishing / Credential Theft / Kill Chain #1 |
| Network Segmentation | GAP-006 | Lateral movement across flat network | Ransomware / VPN Exploit |
| Patch Internet-facing Systems | GAP-016 | FortiGate, Tomcat, Ghostcat, TLS findings | Opportunistic Attackers / Ransomware |
| Central Monitoring (MDR/SIEM) | GAP-004 | Delayed detection across critical assets | Ransomware / Insider Threat |

### Budget

| Item | Estimated Cost |
|---|---:|
| MFA Deployment | \$4,000 |
| Network Segmentation (Phase 1) | \$45,000 |
| MDR Service | \$30,000 |
| Patch & Vulnerability Management | \$15,000 |
| **Total** | **\$94,000** |

The proposed roadmap stays **within the \$120,000 annual budget**, leaving approximately **\$26,000** for contingency and future ISO 27001 preparation.