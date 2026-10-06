# HEALTHBANE Stage 4 Threat Hunting Report

**Organization:** MedDefense Health Systems  
**Hunt window:** 2026-05-04 through 2026-05-18  
**Audience:** Dr. Patricia Morales, Board of Directors, CISO, SOC, Incident Response

## 1. Executive Summary

This hunt examined HEALTHBANE Stage 4 living-off-the-land activity described in HC3-2026-HEALTHBANE-004. The work moved from the advisory to ATT&CK gap analysis, then to targeted searches for PsExec, LSASS access, WMI, PowerShell Remoting, service-account misuse, and NTLM authentication anomalies.

The evidence supports **Stage 4 lateral movement in the MedDefense environment**. The clearest chain is credential access on **WS-RECV-03**, followed by workstation-originated use of **svc_healthsync** against server targets and PsExec activity against **SRV-HEALTH-DB**, **SRV-INS-DB**, and **SRV-DC-01**. WMI and PowerShell Remoting activity supplied additional reconnaissance and remote-execution context.

Potentially reached systems include the patient-records database, insurance database, domain controller, file server, patch server, AV server, and backup server. Potential exposure includes PHI on SRV-HEALTH-DB, insurance and financial data on SRV-INS-DB, and authentication material on SRV-DC-01. This is a potential exposure assessment, not a confirmed data-loss determination.

Four Wazuh-style host rules and one network rule were drafted under Task 13. ATT&CK visibility improved from **55% observed coverage to approximately 80%**. WS-RECV-03 requires immediate incident response and containment through the Module 5 bridge.

## 2. Hunt Methodology

The hunt used a hypothesis-driven workflow:

1. HC3 Stage 4 advisory indicators were translated into ATT&CK techniques and hunt priorities.
2. The post-4x03 ATT&CK mapping identified missing visibility for SMB/PsExec, LSASS, WMI, WinRM/PSRemoting, service accounts, and pass-the-hash-style behavior.
3. Robert Kim's documented maintenance schedule and the network topology established the legitimate administrative baseline.
4. Local Wazuh alerts, raw Sysmon JSONL, and baseline activity were searched with deterministic Bash and jq scripts.
5. Findings were correlated across host, identity, time, target, and tool context rather than relying on file hashes or network reputation.

**Data sources used:**

- `wazuh_alerts_14d.json`
- `wazuh_raw_sysmon_14d.json`
- `baseline/robert_kim_activity.json`
- HC3 advisory HC3-2026-HEALTHBANE-004
- ATT&CK mapping from 4x03
- Robert Kim administration schedule
- Service-account authorization matrix
- Network topology and administrative authorization matrix

The baseline established normal administration as `MEDDEFENSE\robert.kim` from `WS-ADMIN-01`, against approved servers, during weekday 08:00-18:00 Central Time windows. Service accounts are expected to authenticate only from their documented service hosts, using Kerberos and approved logon types.

## 3. Findings Per Hypothesis

### H1: PsExec / SMB lateral movement

**Status:** POSITIVE  
**Evidence:** PsExec activity was identified from `WS-RECV-03` using `MEDDEFENSE\svc_healthsync` against `SRV-HEALTH-DB`, `SRV-INS-DB`, and `SRV-DC-01`. The broader export contained 50 PsExec-related events, including documented Robert Kim maintenance and anomalous activity.  
**Confidence:** HIGH. The attacker source, service account, target servers, and off-hours pattern violate the authoritative baseline.

### H2: LSASS credential access

**Status:** POSITIVE  
**Evidence:** Two anomalous LSASS accesses came from `C:\Windows\Temp\debug_tool.exe` on `WS-RECV-03` with access mask `0x1010`, consistent with memory dumping. Ten other LSASS accesses matched known system processes.  
**Confidence:** HIGH. The source process was non-system, ran from a writable temporary directory, and matched the HC3 artifact pattern.

### H3: WMI remote execution and reconnaissance

**Status:** POSITIVE  
**Evidence:** WMI activity included remote inventory, process, service, and host queries. The hunt identified WMI as a Stage 4-relevant remote execution and reconnaissance path requiring source-host and time-baseline controls.  
**Confidence:** HIGH when correlated with anomalous PsExec and service-account activity; MEDIUM for individual inventory events without surrounding context.

### H4: PowerShell Remoting

**Status:** POSITIVE  
**Evidence:** `Enter-PSSession`, `New-PSSession`, and `Invoke-Command` activity was observed against server targets. The same technique was used in the HC3 pattern for interactive access and staging.  
**Confidence:** HIGH for sessions from the compromised workstation or associated with file-transfer/staging behavior; MEDIUM for activity from the documented admin workstation during an approved window.

### H5: Service-account abuse and NTLM

**Status:** POSITIVE  
**Evidence:** `svc_healthsync` authenticated from `WS-RECV-03` to `SRV-HEALTH-DB`, `SRV-INS-DB`, and `SRV-DC-01` using Logon Type 3 and NTLM. This violates the matrix requirement that the account authenticate from `SRV-HEALTH-DB` and use Kerberos.  
**Confidence:** CRITICAL. The account has read/write access to PHI on SRV-HEALTH-DB, and its workstation-originated use is an explicit credential-theft indicator.

## 4. Reconstructed Attack Timeline

The following chronology combines direct event timestamps with the observed operational sequence:

| Timestamp (UTC) | Phase | Evidence |
|---|---|---|
| 2026-05-05 08:22:17 | Credential access | `WS-RECV-03` `debug_tool.exe` accessed LSASS with `0x1010`. |
| 2026-05-06 07:12:44 | Credential use | `svc_healthsync` authentication originated from `WS-RECV-03`. |
| 2026-05-06 07:14:33-07:14:34 | Lateral movement | `WS-RECV-03` authenticated to `SRV-HEALTH-DB`, followed by PsExec execution. |
| 2026-05-09 08:40:22-08:42:18 | Expansion | `svc_healthsync` use and PsExec activity reached `SRV-INS-DB`. |
| 2026-05-12 07:45:35 | Credential refresh | A second anomalous LSASS access occurred on `WS-RECV-03`. |
| 2026-05-13 06:56:11-06:58:46 | Expansion | `svc_healthsync` use and PsExec activity reached `SRV-DC-01`. |
| Hunt window | Reconnaissance/staging | WMI enumeration and PowerShell Remoting supplied remote discovery and staging capability. |

The reconstructed progression is: phishing foothold and workstation compromise, LSASS credential theft, service-account reuse, PsExec lateral movement to the health database, expansion to the insurance database and domain controller, then reconnaissance and potential staging. The available evidence confirms access and execution; it does not by itself prove successful exfiltration.

## 5. ATT&CK Update

**Coverage improvement:**

```text
Before hunt  55%  [###########---------]
After hunt   80%  [################----]
```

Newly supported or materially improved techniques:

- T1021.002: SMB/Windows Admin Shares / PsExec
- T1003.001: OS Credential Dumping: LSASS Memory
- T1047: Windows Management Instrumentation
- T1021.006: Windows Remote Management / PowerShell Remoting
- T1078.002: Valid Accounts: Domain Accounts
- T1550.002: Pass the Hash-style alternate authentication material

## 6. Detection Improvements

The hunt produced four Wazuh-style host rule drafts and one network rule draft:

- **100100:** PsExec from a non-admin workstation or outside the approved window.
- **100101:** LSASS memory access from a non-system process.
- **100102:** Service-account authentication from a workstation or unauthorized host/logon type.
- **100103:** WMI provider process spawning suspicious child processes.
- **9000030:** SMB lateral movement followed by PsExec service installation.

The detection posture moved from infrastructure- and malware-centric coverage to behavior-based host, identity, and network analytics. The reported ATT&CK posture improved from 55% observed coverage to approximately 80%, closing the principal Stage 4 gaps while leaving the remaining 20% explicitly documented.

## 7. Remaining Gaps and Recommendations

The remaining 20% includes techniques for which telemetry, context, or validated detection logic is still incomplete. In particular, the hunt does not prove the full extent of data staging, archive creation, event-log tampering, persistence, or exfiltration success. Network and endpoint coverage also needs continued validation against legitimate administrative exceptions.

**Immediate:**

- Initiate incident response for `WS-RECV-03` through the Module 5 bridge.
- Isolate or contain the workstation, preserve memory and disk evidence, and preserve firewall/SIEM logs.
- Rotate `svc_healthsync` immediately and assess PHI exposure from SRV-HEALTH-DB.

**Short-term:**

- Rotate all service-account credentials with database access.
- Enforce service-host restrictions and Kerberos-only authentication.
- Review privileged access, PsExec, WMI, WinRM, and scheduled-task permissions.
- Validate the new rules against authorized maintenance to control false positives.

**Medium-term:**

- Deploy full Sysmon coverage, including Events 1, 10, 12/13, and relevant network telemetry.
- Centralize PowerShell Script Block and Module logging.
- Implement behavioral analytics that joins source host, account, target, time, protocol, and process lineage.
- Make threat hunting a recurring control with documented ATT&CK coverage reviews.

## 8. Lessons Learned

The initial 55% ATT&CK coverage created a false sense of security because the uncovered techniques were the exact behaviors that make LOLBin attacks effective. A clean malware or network IOC result could not rule out lateral movement performed with legitimate Windows tools.

Reactive detection alone is insufficient against LOLBin attacks. Without a baseline for source host, account, target, time, and authentication protocol, PsExec, WMI, and PowerShell Remoting can resemble ordinary administration.

Proactive threat hunting must therefore be a recurring operational discipline. Advisory intelligence, ATT&CK gap analysis, targeted queries, and periodic baseline review are needed to expose behavioral gaps before an attacker’s operational sequence becomes a confirmed incident.
