# The CVSS Deconstruction

## Introduction

### Goal
Master the CVSS v3.1 scoring system by deconstructing, constructing and comparing scores using the NIST Calculator.

### Context
A CVSS score without understanding is a number. A CVSS score with understanding is a decision tool. This task turns the former into the latter.

## Answer

### Exercise 1

Vector string: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`


| Metric | Abbreviation Stands For | Selected Value | What the Selected Value Means | Other Possible Values (Effect on Score) | Why This Value Was Selected |
|----------|----------|----------|----------|----------|----------|
| Attack Vector | AV | N (Network) | The vulnerability can be exploited remotely over a network without requiring local access. | A (Adjacent): requires same network segment, lowers score. L (Local): requires local system access, lowers score further. P (Physical): requires physical access, lowest score impact. | The vulnerability is reachable remotely, making exploitation easier and increasing risk. |
| Attack Complexity | AC | L (Low) | No special conditions are required for exploitation. An attacker can reliably exploit the vulnerability. | H (High): exploitation requires uncommon conditions or additional preparation, reducing the score. | Exploitation does not depend on difficult timing, race conditions, or unusual environmental factors. |
| Privileges Required | PR | N (None) | The attacker does not need an account or any privileges before exploitation. | L (Low): some user privileges required, lowers score. H (High): administrative or high privileges required, lowers score significantly. | An unauthenticated attacker can exploit the vulnerability directly. |
| User Interaction | UI | N (None) | No action from a legitimate user is required for exploitation. | R (Required): a user must perform an action such as opening a file or clicking a link, reducing the score. | The exploit can be triggered entirely by the attacker without user involvement. |
| Scope | S | U (Unchanged) | Exploitation only affects resources managed by the vulnerable component itself. | C (Changed): exploitation impacts resources beyond the vulnerable security authority, often increasing the score. | The vulnerability's impact remains within the same security boundary. |
| Confidentiality Impact | C | H (High) | Successful exploitation results in complete or near-complete disclosure of sensitive information. | N (None): no confidentiality impact. L (Low): limited information disclosure. H (High): maximum confidentiality impact. Higher values increase the score. | The attacker can obtain sensitive data from the affected system. |
| Integrity Impact | I | H (High) | Successful exploitation allows complete or near-complete modification of data. | N (None): no integrity impact. L (Low): limited modification possible. H (High): extensive modification possible. Higher values increase the score. | The attacker can alter critical data, configurations, or system state. |
| Availability Impact | A | H (High) | Successful exploitation can fully disrupt or deny access to the affected service or system. | N (None): no availability impact. L (Low): partial degradation. H (High): complete or significant service disruption. Higher values increase the score. | The attacker can cause a complete loss of service or system functionality. |

The actual NVD score is 9.8 but if we change Attack Vector to Local (L) then the score drop to 8.4. Severity will change from Critical to High.

### Exercise 2

CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
NVD score: 5.1
Severity: Medium

### Exercise 3

Comparing Finding 001 and Finding 018.


| Finding | CVSS Score | CVSS Vector |
|----------|------------|-------------|
| FINDING 001 – Apache mod_lua Buffer Overflow (CVE-2021-44790) | 9.8 (Critical) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| FINDING 018 – Kerberos Weak Encryption Types Supported | 5.7 (Medium) | CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |

The primary reason Finding 001 scores significantly higher than Finding 018 is that it can be exploited remotely (**AV:N**) without authentication (**PR:N**) and results in complete compromise of confidentiality, integrity, and availability (**C:H/I:H/A:H**) through remote code execution. In contrast, Finding 018 requires an attacker to already have network access and valid credentials (**AV:A/PR:L**) and only impacts confidentiality (**C:H**) by enabling offline password cracking attacks, with no direct effect on system integrity or availability (**I:N/A:N**). The components with the greatest influence on the score difference are therefore **Integrity Impact**, **Availability Impact**, **Privileges Required**, and **Attack Vector**.