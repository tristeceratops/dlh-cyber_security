# The Self-Audit

## Introduction

### Goal
Run a real security audit tool on your own machine, interpret the results, and project the findings onto the MedDefense environment.

### Context
You have been reading a scan report someone else produced. Now you generate your own. Lynis is an open-source security auditing tool that checks your system against hundreds of security best practices: kernel hardening, authentication, file permissions, networking, logging, malware detection and more.

Running it on your own machine teaches you what a scanner actually checks, how to read raw audit output and how to distinguish important findings from noise. Then you will project that understanding onto MedDefense.

## Answer

# Lynis Security Audit Analysis

## Hardening Index

| Metric | Result |
|---|---|
| Hardening Index | **64 / 100** |
| Tests Performed | 270 |
| Plugins Enabled | 1 |
| Security Assessment | Moderate hardening level with several missing security controls |

The system has basic security protections enabled, but significant improvements are needed in authentication hardening, service configuration, monitoring, logging, and system hardening.

---

# Top 5 Warnings

| Warning | What Lynis Checks | Why It Matters | Recommended Remediation |
|---|---|---|---|
| NETW-2705: Less than two responsive nameservers | Checks whether the system has redundant DNS resolvers configured. | A single DNS resolver creates availability and dependency risks. DNS failures can prevent updates, authentication, and network communication. | Configure at least two trusted DNS servers in `/etc/resolv.conf` or system network configuration. |
| BOOT-5122: GRUB password protection missing | Checks whether bootloader configuration is protected from unauthorized modification. | An attacker with physical access could modify boot parameters and boot into recovery mode to bypass security controls. | Configure a GRUB authentication password and restrict bootloader modification. |
| ACCT-9628: auditd not enabled | Checks whether Linux audit logging is configured. | Without audit logs, administrators cannot reliably investigate privilege abuse, malware activity, or unauthorized changes. | Install and enable `auditd`, configure audit rules for authentication and sensitive files. |
| HRDN-7230: Malware scanner not installed | Checks for endpoint malware/rootkit detection tools. | Lack of malware monitoring reduces detection capability, especially after compromise. | Deploy tools such as Wazuh, ClamAV, rkhunter, or another approved security monitoring solution. |
| FINT-4350: File integrity monitoring missing | Checks whether tools exist to detect unauthorized file changes. | Attackers modifying binaries or configuration files may remain undetected. | Install and configure file integrity monitoring such as AIDE or another integrity management solution. |

---

# Top 5 Suggestions

| Suggestion | Security Improvement Recommended |
|---|---|
| Install fail2ban | Automatically blocks repeated authentication failures and reduces brute-force attacks against exposed services. |
| Configure password strength modules (PAM) | Enforces stronger passwords and reduces the likelihood of weak credential compromise. |
| Harden system services using systemd security settings | Reduces service privileges and limits damage if a service is compromised. |
| Enable external logging | Sends logs to a separate system, preventing attackers from deleting local evidence after compromise. |
| Disable unnecessary USB storage drivers | Prevents unauthorized data transfer and malware introduction through removable media. |

---

# Category Breakdown

| Category | Assessment |
|---|---|
| Kernel | Relatively strong — kernel configuration checks mostly passed, but several sysctl hardening values differ from recommended profiles. |
| Authentication | Weak — missing password aging policies, password strength modules, and failed-login monitoring. |
| Networking | Medium — firewall is active, but DNS redundancy and unnecessary protocols require attention. |
| Services | Weak — many services are marked unsafe by systemd security analysis, including SSH, cron, and audit-related services. |
| Web Server | Medium — Apache is detected, but ModSecurity and mod_evasive are missing. |
| Logging and Monitoring | Weak — no remote logging, no auditd, no IDS/IPS tooling, and no file integrity monitoring. |
| File Permissions | Moderate — several permission checks require tightening, especially home directories and scheduled task directories. |
| Cryptography | Moderate — certificates are valid and no expired certificates were found, but entropy and hardware RNG improvements are suggested. |

## Security Posture Analysis

The strongest areas are **kernel protection, firewall configuration, user/group consistency, and basic filesystem security**, showing that the system has foundational Linux security controls in place. The weakest areas are **monitoring, authentication hardening, service isolation, and incident detection**, meaning the system may prevent some attacks but has limited ability to detect or respond to compromise. The absence of audit logging and integrity monitoring is particularly concerning because malicious changes could occur without reliable evidence.

---

# Predicted Lynis Findings on MedDefense billing-srv-01

Target System:
- Ubuntu 18.04 LTS
- Apache 2.4.29
- MySQL
- Previous crypto-miner compromise
- SSH password authentication enabled

| Expected Lynis Finding | Reasoning |
|---|---|
| Weak SSH authentication configuration | Lynis would likely flag SSH password authentication because password-based access increases brute-force risk. The OpenVAS report already identified SSH password authentication as a weakness on this host. Recommended fix: disable password authentication and require SSH keys. |
| Missing malware/rootkit detection | Due to previous crypto-miner compromise history, Lynis would likely identify the absence of malware scanning tools. A compromised server should have continuous detection capability such as Wazuh, ClamAV, or another monitoring platform. |
| Missing audit logging | Lynis would likely recommend enabling auditd because a production billing server requires traceability for authentication events, privilege changes, and suspicious activity. |
| Outdated operating system and packages | Ubuntu 18.04 reached standard support end in 2023. Lynis would likely identify missing security updates, outdated packages, and lack of automated patch management. |
| Apache hardening weaknesses | Lynis would likely flag missing web application protections because Apache 2.4.29 is old and the server lacks protections such as ModSecurity, mod_evasive, and stricter security headers. |

## Overall Prediction

Compared with the Kali Linux audit result, billing-srv-01 would likely receive a lower Hardening Index because it is an older production server running unsupported Ubuntu 18.04, exposed services (Apache, MySQL, SSH), weak authentication settings, and a history of compromise. Lynis would likely identify weaknesses mainly in **patch management, authentication, monitoring, web server hardening, and incident detection**, which align with the vulnerabilities identified by the OpenVAS scan.