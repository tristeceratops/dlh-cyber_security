# The Risk Appetite Debate

## Introduction

### Goal
Define MedDefense's risk appetite and demonstrate that risk acceptance is a legitimate, documented governance decision.

### Context
Not every risk is worth mitigating. Some risks cost more to fix than they cost if they happen. Some risks require accepting for operational reasons: the Windows XP MRI workstation cannot be replaced until the $2.1M scanner lease expires in 18 months. Accepting risk is not negligence. It is a governance decision made by an authorized person, documented, monitored and reviewed.

The Board must decide: What level of risk is MedDefense willing to live with ?

## Answer

PART 1 – RISK APPETITE STATEMENT

MedDefense accepts moderate operational and technology risk when the cost of mitigation is greater than the expected reduction in risk. The Board has zero tolerance for risks that could directly impact patient safety, patient data protection, or regulatory compliance. Any risk with a Critical rating or ALE above $500,000 must receive executive approval before acceptance. The CEO and Board Risk Committee have final authority to accept risks above the approved threshold.

==================================================

PART 2 – THE THREE DECISIONS

Risk: RISK-009 – Legacy MRI Workstation Vulnerability
Treatment Decision: Accept
Authority: CEO and Clinical Operations leadership approved acceptance because the system supports critical imaging workflows and immediate replacement creates operational disruption.
Justification: Full medical device isolation and replacement were high-cost controls with lower short-term ALE reduction compared with higher-priority investments such as MFA, SIEM, segmentation, and backups.
Compensating Measure: Restrict network access, monitor MRI traffic, limit user accounts, and maintain vendor support procedures.
Review Trigger: Any MRI security incident, vendor warning, patient safety concern, or replacement funding availability requires reassessment.

Risk: RISK-010 – Third-Party Vendor Access Exposure
Treatment Decision: Accept
Authority: Deputy CISO (James Chen) and executive leadership approved temporary acceptance because vendor access controls require additional budget and contract changes.
Justification: Immediate mitigation through full vendor access management provides value but was deferred because higher ALE risks, including ransomware and backup failures, received funding priority.
Compensating Measure: Review vendor accounts regularly, require MFA where available, and monitor vendor login activity.
Review Trigger: Vendor compromise, abnormal vendor activity, contract renewal, or new regulatory requirements require review.

Risk: RISK-011 – Limited Data Loss Prevention Capability
Treatment Decision: Accept
Authority: CEO and CFO approved temporary acceptance because enterprise DLP implementation cost exceeded available security budget.
Justification: DLP provides important insider threat reduction, but the first-year budget produced higher risk reduction by funding segmentation, SIEM, MFA, backups, and EDR.
Compensating Measure: Increase EHR audit reviews, monitor unusual data exports, enforce acceptable use policies, and restrict removable media where possible.
Review Trigger: PHI leakage event, increased insider incidents, or availability of additional security funding requires reassessment.

==================================================

PART 3 – THE DEBATE

James Chen – Argument for Mitigation:
The Windows XP MRI workstation creates unacceptable risk because it is an unsupported system connected to clinical operations. A compromise could affect patient safety, diagnostic accuracy, and hospital availability. Even if the probability is low, the impact of a medical device failure is too severe to ignore. MedDefense should isolate and replace the workstation to reduce this risk permanently.

Robert Kim – Argument for Acceptance:
The MRI workstation has operated for years without a major incident, and replacing or isolating it requires significant cost and operational effort. The probability of a targeted medical device attack is low compared with ransomware, identity, and backup risks. The security budget should focus on controls that reduce the highest ALE risks first. Temporary acceptance with monitoring is financially reasonable.

Verdict:
Robert's cost prioritization is reasonable because MedDefense has limited security funding and must address higher-frequency risks first. However, James's concern is stronger regarding patient safety because medical device failures can directly impact care. The best decision is conditional acceptance: maintain compensating controls now while creating a funded replacement plan for the MRI workstation.