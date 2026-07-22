# Red Team Your Blueprint

## Introduction

### Goal
Attack your own security strategy to find its weaknesses before an adversary does.

### Context
Every plan has blind spots. The best way to find them is to think like the attacker. In this task, you switch sides: you are no longer the security architect defending MedDefense. You are the BlackReef ransomware affiliate (from 1x01) who has read your Security Strategy Document and needs to find a way in despite the new controls.

This adversarial thinking exercise is what separates good strategies from great ones. A plan that survives its own red team is a plan worth funding.

## Answer

PART 1 – THE ATTACKER'S PERSPECTIVE

1. Kill Chain Still Viable After Controls

The most viable remaining attack path is Kill Chain #3: Supply Chain Compromise of MedTech Solutions.

Reason:
Even after MFA, SIEM, segmentation, backups, firewall upgrades, and EDR are implemented, a compromised vendor account may still provide trusted access. The deferred controls (vendor access governance and full medical device isolation) leave a possible entry path.

Alternative Attack Path:
1. Attacker compromises a MedTech Solutions vendor account through phishing or stolen credentials.
2. Attacker uses approved vendor remote access to connect to MedDefense systems.
3. Attacker abuses legitimate access to reach EHR application servers.
4. Attacker attempts privilege escalation and searches for sensitive patient data.
5. Attacker exfiltrates PHI or disrupts clinical systems.

This path bypasses many controls because the attacker is using trusted access rather than directly exploiting a technical vulnerability.

Remaining Insider Threat:
A negligent or malicious insider remains dangerous because employees already have legitimate EHR access. Without full DLP, behavioral monitoring, and stronger data governance, an employee could still export patient records using approved systems or personal storage.

==================================================

PART 2 – THE HONEST ASSESSMENT

Residual Risk Rating: HIGH

The security improvements significantly reduce ransomware likelihood and improve detection, but MedDefense still has exposure from vendor access, insider misuse, legacy medical systems, and incomplete data-loss prevention.

Biggest Remaining Gap:
The biggest remaining gap is insufficient control over trusted access, including vendor accounts and privileged users. Attackers abusing valid credentials can bypass many perimeter defenses.

#1 Priority for Next Year's Budget:
MedDefense should prioritize Zero Trust access controls, including vendor access management, privileged access management, stronger identity monitoring, and expanded DLP. These controls address the remaining attack paths that current investments cannot fully prevent.