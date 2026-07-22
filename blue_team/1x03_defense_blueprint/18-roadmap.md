# The Roadmap

## Introduction

### Goal
Transform the strategy into a visual, dependency-aware implementation timeline.

### Context
A strategy document says "what." A roadmap says "when." The IT Director, Sarah Park, needs a document she can pin to the wall and track weekly: what happens first, what depends on what, who owns each milestone and how she knows each phase is complete.

## Answer

MEDDEFENSE 6-MONTH SECURITY ROADMAP

======================================================================
MONTH-BY-MONTH PLAN
======================================================================

Month 1
Actions:
- Deploy MFA for VPN and privileged accounts
- Remove inactive accounts and improve offboarding
- Begin vulnerability patch process
Owner:
- James (Deputy CISO), Sarah (IT Director)
Dependencies:
- Executive approval
Completion Criteria:
- 100% VPN/admin accounts use MFA
- Disabled accounts removed
- Patch schedule documented


Month 2
Actions:
- Deploy SIEM/MDR monitoring
- Update incident response plan
- Begin immutable backup configuration
Owner:
- James, Security Analyst
Dependencies:
- MFA deployment completed
Completion Criteria:
- Security alerts monitored
- IR plan approved
- Backup replication active


Month 3
Actions:
- Implement network segmentation:
  - Server VLAN
  - Clinical workstation VLAN
  - Medical device VLAN
  - Guest VLAN
Owner:
- Sarah, Security Analyst
Dependencies:
- Asset inventory validated
- Firewall rules prepared
Completion Criteria:
- VLANs created
- Firewall rules tested
- Critical traffic flows verified


Month 4
Actions:
- Isolate medical devices
- Restrict vendor remote access
- Perform backup recovery test
Owner:
- Sarah, Clinical Engineering
Dependencies:
- Network segmentation completed
Completion Criteria:
- Medical devices separated
- Vendor access controlled
- Recovery test successful


Month 5
Actions:
- Deploy EDR upgrade
- Perform vulnerability scanning
- Remediate critical findings
Owner:
- Security Analyst, Sarah
Dependencies:
- SIEM operational
Completion Criteria:
- Endpoints protected
- Critical vulnerabilities reduced


Month 6
Actions:
- Conduct incident response exercise
- Review security metrics
- Present progress to Board
Owner:
- James, CEO, Department Heads
Dependencies:
- Security controls deployed
Completion Criteria:
- Tabletop exercise completed
- Risk metrics reported
- Next-year priorities approved


======================================================================
DEPENDENCY CHAIN
======================================================================

MFA Deployment
      |
      v
SIEM/MDR Monitoring
      |
      v
Incident Detection Improvement


Asset Inventory Validation
      |
      v
Network Segmentation
      |
      v
Medical Device Isolation


Immutable Backups
      |
      v
Recovery Testing
      |
      v
Ransomware Recovery Capability


======================================================================
MILESTONES
======================================================================

Milestone 1 - End of Month 1
Achievement:
- Identity security improvements completed
Success Metric:
- 100% VPN and admin accounts protected with MFA


Milestone 2 - End of Month 3
Achievement:
- Network segmentation completed
Success Metric:
- Critical zones separated and firewall rules validated


Milestone 3 - End of Month 4
Achievement:
- Recovery capability improved
Success Metric:
- Backup restoration completed successfully


Milestone 4 - End of Month 6
Achievement:
- Security program validation completed
Success Metric:
- Incident exercise completed and residual risk reviewed


======================================================================
RISKS TO TIMELINE
======================================================================

Risk 1:
Cause:
- Clinical systems cannot tolerate downtime during segmentation changes

Impact:
- Network project delays

Contingency:
- Use maintenance windows, phased deployment, and testing before production changes


Risk 2:
Cause:
- Limited IT staff availability

Impact:
- Security projects compete with daily operations

Contingency:
- Prioritize high-risk controls, use MDR/vendor support, and adjust timelines if needed


======================================================================
FINAL OBJECTIVE
======================================================================

After 6 months, MedDefense should have:
- Stronger identity protection through MFA
- Better threat detection through SIEM/MDR
- Reduced ransomware spread through segmentation
- Improved recovery through immutable backups
- Measurable reduction in cybersecurity risk