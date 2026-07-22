# The Quick Wins

## Introduction

### Goal
Identify and design 5 security improvements that can be implemented within 2 weeks at zero or minimal cost.

### Context
The full roadmap takes 6 months. The Board approved the budget last week. But James Chen has a more immediate concern: "What can we do THIS WEEK that makes us safer ? Not the big purchases. Not the architecture changes. What can we do with what we already have ?"

Quick wins matter because they demonstrate momentum, reduce risk immediately and build credibility with the Board before the big spending begins.

## Answer

Quick Win #1: Enable MFA for VPN and Administrative Accounts

Risk Addressed: RISK-001 (VPN compromise / credential abuse)

Action:
1. Identify all VPN and administrator accounts.
2. Enable MFA using existing O365 E3 licenses.
3. Test login with IT and security accounts.
4. Enforce MFA for all privileged and remote access users.

Owner: Deputy CISO (James) + IT Director (Sarah)

Timeline: 7 days

Cost: $0 (covered by existing Microsoft licensing)

Risk Reduction: Disrupts 1x01 Credential Abuse Chain by preventing attackers from using stolen passwords to access VPN and privileged systems.

Verification: Confirm MFA prompts appear during VPN and administrator logins and verify all privileged accounts are enrolled.

Quick Win #2: Disable Dormant and Unused Accounts

Risk Addressed: RISK-008 (insider access and unauthorized account use)

Action:
1. Export Active Directory user accounts.
2. Identify inactive accounts and former employees.
3. Disable accounts after department head confirmation.
4. Document account review results.

Owner: IT Director (Sarah) + Department Heads

Timeline: 5 days

Cost: $0 (existing administrative capability)

Risk Reduction: Disrupts 1x01 Insider Abuse Chain by removing unused identities that could be exploited by attackers or former employees.

Verification: Review account list and confirm inactive accounts are disabled.

Quick Win #3: Remove Unauthorized Data Storage Locations

Risk Addressed: RISK-009 (PHI leakage through shadow IT)

Action:
1. Identify known personal storage locations (Gmail, Google Drive, personal NAS).
2. Notify users that MedDefense data cannot be stored externally.
3. Move required files to approved storage.
4. Remove unauthorized access where possible.

Owner: Security Analyst + Department Heads

Timeline: 10 days

Cost: $0

Risk Reduction: Disrupts 1x01 Data Theft Chain by reducing unauthorized PHI exfiltration paths.

Verification: Department heads confirm business data is stored only in approved locations and spot checks are completed.

Quick Win #4: Enforce Workstation Auto-Lock

Risk Addressed: RISK-008 (unauthorized access to clinical systems)

Action:
1. Configure automatic screen lock after inactivity.
2. Apply policy to hospital workstations.
3. Test on clinical computers.
4. Communicate requirement to staff.

Owner: IT Director (Sarah)

Timeline: 7 days

Cost: $0 (existing operating system settings)

Risk Reduction: Disrupts 1x01 Insider Data Access Chain by preventing unauthorized users from accessing unattended EHR sessions.

Verification: Confirm workstation lock settings through policy checks and physical testing.

Quick Win #5: Begin Critical Vulnerability Patch Review

Risk Addressed: RISK-002 (ransomware exploitation of vulnerable systems)

Action:
1. Review current vulnerability scan findings.
2. Prioritize internet-facing and critical systems.
3. Confirm patch status with system owners.
4. Apply available security updates or document exceptions.

Owner: Security Analyst + IT Director (Sarah)

Timeline: 14 days

Cost: $0 (existing staff resources)

Risk Reduction: Disrupts 1x01 Ransomware Chain by reducing attacker entry points through known vulnerabilities.

Verification: Perform a follow-up vulnerability scan and confirm critical findings are remediated or formally accepted.

Quick wins matter because they create immediate risk reduction while establishing the foundation of a security program without waiting for budget cycles. They demonstrate measurable progress to leadership, improve security culture, create ownership between IT and business teams, and provide early evidence needed to justify larger investments. During the first month, quick wins build visibility, remove obvious weaknesses, and create repeatable processes that support long-term security maturity.