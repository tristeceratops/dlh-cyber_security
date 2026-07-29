# The Risk Register Update

## Introduction

### Goal
Update the MedDefense Risk Register with the Crimson Tide threat, demonstrating that a Risk Register is a living document that responds to new intelligence.

### Context
Your Risk Register from 1x03 T10 had a ransomware entry. Crimson Tide is not just "ransomware." It is a specific campaign with specific TTPs targeting MedDefense's specific profile. The existing entry must be updated, and a new entry for the FortiGate vulnerability must be added.

## Answer

# Part 1 – Updated Existing Risk Entry (RISK-001)

| Field | Updated Value |
|------|---------------|
| **Risk ID** | RISK-001 |
| **Risk Description** | Ransomware compromises internal systems and disrupts hospital operations. |
| **Threat Source** | **Crimson Tide (CT) ransomware group** |
| **Likelihood** | **5 (Very Likely)** (Updated ARO = **0.75**) |
| **Impact** | 5 (Critical) |
| **Updated ALE** | **$7,161,000** |
| **Risk Owner** | Deputy CISO James |
| **Treatment Decision** | **Mitigate (unchanged)** |
| **Treatment Justification** | Existing decision remains valid but becomes more urgent. The ALE increased from **$2.86M** to **$7.16M**, making immediate implementation of MFA, segmentation, SIEM, EDR, immutable backups and emergency patching financially justified. |
| **Planned Controls** | MFA, Network Segmentation, SIEM, EDR, Immutable Backups, FortiGate patching |
| **Residual Risk** | Medium |
| **New KRI** | Detection of Crimson Tide IOCs, exploitation attempts against the FortiGate VPN, or abnormal VPN logins matching CT TTPs. |
| **Review Date** | Immediate (out-of-cycle) |

---

# Part 2 – New Risk Entry (RISK-NEW-001)

| Field | Value |
|------|-------|
| **Risk ID** | RISK-NEW-001 |
| **Risk Description** | Exploitation of CVE-2023-27997 on the FortiGate VPN resulting in remote code execution and enterprise compromise. |
| **Risk Category** | Operational |
| **Threat Source** | Crimson Tide / external attackers |
| **Vulnerability** | CVE-2023-27997 (FortiOS SSL-VPN) |
| **Affected Assets** | FortiGate VPN, internal network |
| **Likelihood** | 5 (Very Likely) |
| **Impact** | 5 (Critical) |
| **Inherent Risk Score** | 25 |
| **ALE** | **$7,161,000** |
| **Risk Owner** | IT Director Sarah Park |
| **Treatment Decision** | **Mitigate** |
| **Treatment Justification** | Renew FortiGate support (**$2,400**) and apply the security patch immediately. |
| **Planned Controls** | Renew support contract, install patched FortiOS release, verify firmware hash, enable MFA, continuous monitoring |
| **Residual Risk** | Low-Medium |
| **KRI** | SSL-VPN exploit attempts, VPN authentication anomalies, IDS alerts for CVE-2023-27997 |
| **Review Date** | Immediate after patch deployment |

### Cost Justification

- Patch cost = **$2,400**
- Current ALE = **$7,161,000**
- Cost/ALE ratio = **0.03%**
- **Decision:** Patching is overwhelmingly justified because the mitigation cost is negligible compared with the potential annual loss.

---

# Part 3 – Register Governance Test

**Governance Trigger (from 1x03):**

> *"An out-of-cycle review is triggered by a security incident, major vulnerability disclosure, regulatory change, major infrastructure change, or KRI threshold breach."*

**Does Crimson Tide qualify?** **Yes.**

Reasons:
- A **major vulnerability (CVE-2023-27997)** is being actively exploited.
- New threat intelligence significantly increases the ransomware **ARO (0.30 → 0.75)**.
- The ransomware **ALE increases from $2.86M to $7.16M**.
- The FortiGate VPN is a critical MedDefense asset directly affected by the advisory.

**Conclusion:** The Crimson Tide advisory satisfies the governance criteria for an **out-of-cycle risk register review**, requiring immediate reassessment of risk scores, KRIs, treatment decisions, and executive reporting.