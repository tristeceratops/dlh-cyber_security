# The Noise Filter

## Introduction

### Goal
Triage every finding in the scan report into action categories to separate signal from noise.

### Context
Thirty-one findings. You have investigated many of them individually. Now step back and sort the entire report. This is the daily discipline of vulnerability management: every scan produces more findings than you can act on. The triage determines what gets fixed, what gets monitored and what gets filed.

## Answer

# Vulnerability Finding Triage

| Finding | CVSS / Severity | Host | Category | Reason |
|---|---|---|---|---|
| Finding 001 | CVSS 9.8 Critical | billing-srv-01 (10.10.2.15) | AC | Remote code execution on a billing server can lead to full compromise and data exposure. |
| Finding 002 | CVSS 7.8 Critical | billing-srv-01 (10.10.2.15) | AC | Privilege escalation chains with Finding 001 to achieve root compromise. |
| Finding 003 | Critical (Misconfiguration) | ehr-db-01 (10.10.2.11) | AC | PHI database is reachable from the entire internal network, enabling unauthorized access risk. |
| Finding 004 | Critical (EOL) | WS-RAD-01 MRI Workstation (10.10.1.70) | AC | Unsupported Windows XP with weaponized RCE vulnerabilities affects a critical clinical asset. |
| Finding 005 | CVSS 7.5 High | web-srv-01 (10.10.2.50) | AS | Legacy TLS weakens patient portal security but does not directly compromise the server. |
| Finding 006 | High | billing-srv-01 (10.10.2.15) | AS | MySQL exposure increases risk of unauthorized database access. |
| Finding 007 | High | ad-dc-01 (10.10.2.20) | AC | LDAP signing weakness affects identity infrastructure and enables relay attacks. |
| Finding 008 | High (EOL) | print-srv-01 (10.10.2.31) | AS | Unsupported Windows Server increases long-term exposure but has lower business impact. |
| Finding 009 | High | billing-srv-01 (10.10.2.15) | AS | Password-based SSH authentication increases brute-force risk. |
| Finding 010 | High CVSS 7.5 | BD Alaris Pumps | AC | Medical devices with default credentials and firmware issues create patient safety risk. |
| Finding 011 | High (EOL) | billing-srv-01 (10.10.2.15) | AS | Unsupported Ubuntu requires upgrade or ESM activation. |
| Finding 012 | Medium | web-srv-01 (10.10.2.50) | AS | Missing security headers increase web attack exposure. |
| Finding 013 | Medium | web-srv-01 (10.10.2.50) | AS | Certificate expiration requires renewal process correction. |
| Finding 014 | Medium | Netgear Router (10.10.10.1) | AS | Consumer router is inappropriate for enterprise VPN and perimeter use. |
| Finding 015 | Medium | NAS-01 (10.10.2.41) | AS | Backup management interface is too broadly accessible. |
| Finding 016 | Medium | Philips IntelliVue Monitors | AC | Exposed medical device interfaces may expose patient data and allow device misuse. |
| Finding 017 | Medium | ehr-srv-01 (10.10.2.10) | AS | Version disclosure is a real weakness and enabled discovery of Finding 031. |
| Finding 018 | Medium | ad-dc-01/ad-dc-02 | AS | Weak Kerberos encryption increases credential attack opportunities. |
| Finding 019 | Medium | Multiple hosts | AS | RDP exposure increases attack surface but has NLA mitigation. |
| Finding 020 | CVSS 9.8 Medium (Scanner) | backup-srv-01 (10.10.2.40) | FP | Exploitation requires SSH agent forwarding conditions not confirmed in this environment. |
| Finding 021 | Medium | web-srv-01 (10.10.2.50) | AS | HTTP TRACE is enabled and should be disabled as hardening. |
| Finding 022 | Low | ehr-srv-01 (10.10.2.10) | I | Minor clock synchronization issue with limited security impact. |
| Finding 023 | Low | Clinical workstations | AS | USB restrictions are missing and create malware/data-loss risk. |
| Finding 024 | Low | pacs-srv-01 (10.10.2.12) | AS | Unencrypted DICOM traffic exposes medical imaging data. |
| Finding 025 | Low | ad-dc-01 (10.10.2.20) | AS | DNS zone transfer leaks internal infrastructure information. |
| Finding 026 | Low | billing-srv-01 (10.10.2.15) | AS | Outdated kernel increases local exploitation risk. |
| Finding 027 | Informational | Windows workstations | I | Endpoint security reporting issue requires monitoring. |
| Finding 028 | Informational | Unknown Linux host (10.10.2.99) | AS | Unknown device with exposed services requires asset identification. |
| Finding 029 | Informational | Unknown Linux host (10.10.10.200) | AS | Unauthorized Grafana system exposes potential vulnerable software. |
| Finding 030 | Informational | ehr-srv-01 (10.10.2.10) | I | Certificate mismatch is operational, not a security vulnerability. |
| Finding 031 | CVSS 9.8 High | ehr-srv-01 (10.10.2.10) | AC | Ghostcat exposes EHR server files and potentially database credentials. |

---

# Triage Summary

| Category | Count |
|---|---:|
| Actionable Critical (AC) | 8 |
| Actionable Standard (AS) | 18 |
| Informational (I) | 3 |
| False Positive (FP) | 1 |
| Total | 31 |

### Meaning of AC / AS / I / FP in the vulnerability triage

| Code | Full Name | Meaning | Required Action |
|---|---|---|---|
| **AC** | **Actionable Critical** | A real vulnerability that is exploitable, affects an important asset, and could cause major impact (data breach, outage, patient safety issue). | **Immediate remediation (24-48 hours)** |
| **AS** | **Actionable Standard** | A real vulnerability that should be fixed, but the risk is lower than AC or requires planned work. | **Scheduled remediation (7-30 days)** |
| **I** | **Informational** | A real observation or configuration issue with low direct risk. It should be tracked but does not require urgent remediation. | **Document and monitor** |
| **FP** | **False Positive** | The scanner reported a vulnerability, but technical analysis shows it is not exploitable or not applicable in this environment. | **Validate, document, and dismiss** |

---

# Actionable Findings List

## Actionable Critical (Immediate Remediation 24-48h)

| Priority | Finding | Reason |
|---|---|---|
| 1 | Finding 031 | Ghostcat on EHR server can expose patient data and credentials. |
| 2 | Finding 004 | Windows XP MRI workstation contains weaponized RCE vulnerabilities. |
| 3 | Finding 001 | Apache RCE allows remote compromise of billing server. |
| 4 | Finding 003 | EHR database is broadly exposed internally. |
| 5 | Finding 007 | Domain controller LDAP weakness threatens identity infrastructure. |
| 6 | Finding 002 | Privilege escalation completes billing server compromise chain. |
| 7 | Finding 010 | Medical device vulnerabilities create patient safety risk. |
| 8 | Finding 016 | Medical monitoring interfaces expose clinical systems. |

---

## Actionable Standard (Scheduled Remediation 7-30 days)

| Priority | Finding |
|---|---|
| 1 | Finding 005 |
| 2 | Finding 011 |
| 3 | Finding 008 |
| 4 | Finding 006 |
| 5 | Finding 009 |
| 6 | Finding 017 |
| 7 | Finding 014 |
| 8 | Finding 015 |
| 9 | Finding 018 |
| 10 | Finding 019 |
| 11 | Finding 021 |
| 12 | Finding 012 |
| 13 | Finding 013 |
| 14 | Finding 023 |
| 15 | Finding 024 |
| 16 | Finding 025 |
| 17 | Finding 026 |
| 18 | Finding 028 |
| 19 | Finding 029 |
