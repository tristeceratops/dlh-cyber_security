# The Security Strategy Document

## Introduction

### Goal
Produce the comprehensive Security Strategy Document that synthesizes all analysis into a Board-ready deliverable.

### Context
This is the capstone deliverable of the project. It is the companion document to the Security Posture Assessment (1x00), the Threat Landscape Report (1x01) and the Vulnerability Assessment Summary (1x02). Together, the four documents form the complete security intelligence and strategy package for MedDefense.

## Answer

# MedDefense Health Systems – Security Strategy Document

==================================================
1. Executive Summary
==================================================

Current Risk Posture:
MedDefense has basic security controls but remains exposed to ransomware, insider threats, vendor compromise, and medical device risks due to weak segmentation, incomplete MFA, limited monitoring, and weak recovery controls.

Strategy:
Adopt NIST CSF + CIS Controls approach using risk-based prioritization, ALE analysis, threat modeling, and control cost-benefit evaluation.

Investment:
Requested budget: $120,000/year
Expected result: Major reduction of ransomware, credential compromise, and recovery risk.

Top 3 Actions:
1. Deploy MFA and improve identity lifecycle management.
2. Implement network segmentation and stronger access controls.
3. Improve monitoring and recovery through SIEM/MDR and immutable backups.

==================================================
2. Governance Framework
==================================================

Framework Selection:

| Framework | Reason |
|---|---|
| NIST CSF | Provides risk management structure for healthcare security. |
| CIS Controls | Provides practical technical safeguards and implementation priorities. |

NIST CSF Profile:

| Function | Current | Target |
|---|---|---|
| Identify | Partial asset visibility | Full inventory + risk ownership |
| Protect | MFA gaps, weak segmentation | Zero Trust access + segmentation |
| Detect | Limited logging | SIEM/MDR monitoring |
| Respond | No tested IR plan | Tested response procedures |
| Recover | Weak backups | Immutable recovery capability |

CIS Maturity:

| Area | Current | Target |
|---|---|---|
| Asset Management | Medium | High |
| Access Control | Low | High |
| Monitoring | Low | High |
| Data Protection | Medium | High |
| Incident Response | Low | Medium/High |

Governance Roles:

| Role | Responsibility |
|---|---|
| CEO | Risk acceptance, budget approval |
| Deputy CISO James | Security strategy, risk management |
| IT Director Sarah | Technical implementation |
| Department Heads | Business risk ownership |
| Security Analyst | Monitoring and reporting |

==================================================
3. Quantitative Risk Analysis
==================================================

Top ALE Risks:

| Risk | ALE |
|---|---:|
| VPN compromise → ransomware | ~$1.2M |
| EHR breach | ~$1M |
| Ransomware billing impact | ~$300K |
| Insider data theft | ~$240K |
| Medical device compromise | ~$100K+ |

Risk Register Summary:

| ID | Risk | Owner | Treatment |
|---|---|---|---|
| RISK-001 | Ransomware attack | CISO/IT | Mitigate |
| RISK-002 | EHR data breach | Data Owner | Mitigate |
| RISK-003 | Insider PHI theft | Dept Heads | Mitigate |
| RISK-004 | Medical device compromise | Clinical IT | Accept/Mitigate |
| RISK-005 | VPN compromise | IT Director | Mitigate |

Risk Appetite:

MedDefense accepts limited operational risk when mitigation cost exceeds expected benefit. The organization has zero tolerance for risks affecting patient safety, PHI protection, or regulatory compliance. Critical risks or ALE above $500,000 require executive approval before acceptance.

==================================================
4. Control Strategy
==================================================

Cost-Benefit Results:

| Control | Cost | Value |
|---|---:|---|
| Network segmentation | $20K | High |
| MFA deployment | $8K | Very High |
| SIEM/MDR | $25K | High |
| Immutable backups | $18K | Very High |
| EDR upgrade | $35K | Medium |

Budget Allocation:

| Funded Control | Cost |
|---|---:|
| MFA | $8K |
| Network segmentation | $20K |
| SIEM | $25K |
| Immutable backups | $18K |
| Dedicated firewall | $10K |
| EDR | $35K |
| TOTAL | $116K |

Deferred:
- Full medical device isolation
- Full SOC service
- Vendor access redesign

Rejected:
- Large replacement projects with low first-year ROI.

Control Mapping:

| Control | CIS | NIST |
|---|---|---|
| MFA | CIS 6 | PR.AC |
| Segmentation | CIS 12 | PR.AC |
| SIEM | CIS 8 | DE.CM |
| Backups | CIS 11 | RC.RP |
| EDR | CIS 10 | DE.CM |

==================================================
5. Architecture Recommendations
==================================================

Network Zones:

| Zone | Systems | Access |
|---|---|---|
| Server VLAN | EHR, AD, billing | Restricted |
| Clinical VLAN | Nurse/doctor PCs | Server only |
| Medical VLAN | MRI, pumps, PACS | Controlled only |
| Management VLAN | Admin tools | IT only |
| Guest/IoT VLAN | Visitors, IoT | Internet only |

Firewall Rules:

| Rule | Action |
|---|---|
| Clinical → EHR | Allow |
| Medical → Internet | Deny |
| Guest → Server | Deny |
| Admin → All zones | Allow |
| Vendor → EHR | Restricted |

Kill Chain Impact:

Segmentation breaks ransomware at:
- Lateral movement stage
- Privilege escalation stage
- Backup targeting stage

Estimated disruption:
~60-70% of major attack paths.

==================================================
6. Policy Foundation
==================================================

AUP Summary:

| Area | Requirement |
|---|---|
| Systems | Business use only |
| PHI | No personal storage |
| USB | Restricted and approved |
| Passwords | MFA required |
| Devices | Personal devices limited |
| Monitoring | Security activity logged |

Required Future Policies:

| Timeline | Policy |
|---|---|
| Month 1 | Incident Response Policy |
| Month 2 | Vendor Security Policy |
| Month 3 | Data Classification Policy |
| Month 6 | Disaster Recovery Policy |

==================================================
7. Residual Risk Assessment
==================================================

Red Team Findings:

| Finding | Status |
|---|---|
| Ransomware | Reduced |
| Credential attacks | Reduced |
| Vendor compromise | Remains possible |
| Insider theft | Remains possible |
| Medical device risk | Reduced but present |

Residual Risk:
HIGH

Accepted Risks:

| Risk | Reason |
|---|---|
| MRI legacy system | Low probability, high replacement cost |
| Vendor access | Deferred due to budget |
| DLP absence | Lower priority than ransomware controls |

Year 2 Priorities:
1. Vendor access management.
2. Medical device isolation.
3. Enterprise DLP.

==================================================
8. Implementation Roadmap
==================================================

Phase 1 (Month 1-2):

| Action | Success Metric |
|---|---|
| MFA rollout | 95%+ privileged accounts protected |
| Quick wins | Risks closed |
| Procurement | Contracts signed |

Phase 2 (Month 3-4):

| Action | Success Metric |
|---|---|
| Segmentation | VLAN controls active |
| SIEM | Alerts operational |
| Backups | Restore tested |

Phase 3 (Month 5-6):

| Action | Success Metric |
|---|---|
| Validation testing | Reduced attack paths |
| Policy updates | Approved governance |
| Metrics review | Board reporting |

==================================================
9. Next Steps
==================================================

Connection to Project 1x04:
The next phase will establish cryptographic foundations including encryption standards, key management, certificate management, and secure communication requirements.

Path Forward:
Assessment → Risk Prioritization → Control Deployment → Validation → Continuous Improvement.