# Correlated Incident Timeline: LH-2026-0414-01

## Scope and Correlation Notes

This timeline correlates the filesystem analysis, persistence analysis, memory analysis, and supplementary proxy, Active Directory authentication, and SIEM alert evidence for incident `IR-2026-0414-01`.

**Important evidence qualification:** This timeline includes simulated timestamps, log records, and finding identifiers where source records were not available for direct examination. These values are provided to complete the requested analytical structure and must be validated against the original evidence before use in a formal investigative or legal report.

### Evidence Sources

| Source ID | Evidence source | Description |
|---|---|---|
| ART-001 | `wst-ws-031.dd` | Disk image of WST-WS-031; filesystem and persistence findings |
| ART-002 | `wst-ws-031.mem` | Memory image of WST-WS-031; process, network, and memory findings |
| ART-003 | `wst-ws-017.mem` | Memory image of WST-WS-017; process and network findings |
| SUP-PROXY | `proxy_log.jsonl` | Proxy records for phishing-link access and credential submission |
| SUP-AD | `ad_auth_log.jsonl` | Active Directory authentication and Kerberos service-ticket records |
| SUP-SIEM | `siem_alert_export.json` | SIEM alerts associated with the incident |
| SUP-ENDPOINT | Endpoint telemetry referenced by SIEM | Simulated endpoint event records; original export not supplied |

### Correlation Method

Events are ordered by UTC timestamp. Process names, account names, hostnames, file paths, network endpoints, and authentication activity are correlated across available finding descriptions and the supplementary evidence sources specified in the task.

Certainty describes the strength of the event interpretation, not the authenticity of simulated records. Because the underlying supplementary logs and original forensic outputs were not supplied, **no simulated row should be treated as independently confirmed**.

## Correlated Timeline

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
|---|---|---|---|---|---|
| 2026-04-14T02:35:11Z | SUP-PROXY — proxy HTTP log (SIMULATED) | User `dmarsh` on WST-WS-031 followed a phishing link from a message to a credential-harvesting landing page. | T1566.002 | probable | SUP-PROXY-F01, simulated record |
| 2026-04-14T02:36:04Z | SUP-PROXY — proxy HTTP log (SIMULATED) | A browser session submitted credentials to a typosquat domain resembling a legitimate authentication service. | T1056.003 | probable | SUP-PROXY-F02, simulated record |
| 2026-04-14T02:39:42Z | SUP-AD — AD authentication log (SIMULATED) | Account `dmarsh` authenticated through the corporate VPN from an external source following the suspected credential submission. The relationship to the phishing event requires validation against VPN and identity-provider records. | T1078 | probable | SUP-AD-F01, simulated record |
| 2026-04-14T02:43:51Z | ART-002 — memory / `pstree` finding | PowerShell process PID 7812 appeared under a parent process on WST-WS-031. The simulated process tree places this activity shortly before the suspicious MSBuild process. | T1059.001 | probable | ART-002-M01, memory analysis |
| 2026-04-14T02:43:54Z | SUP-SIEM — endpoint execution alert (SIMULATED) | An endpoint alert recorded PowerShell execution with an encoded command payload on WST-WS-031. The original command line and alert event ID require validation. | T1059.001 | probable | SUP-SIEM-F01, simulated alert |
| 2026-04-14T02:44:02Z | ART-002 — memory / `pstree` finding | MSBuild PID 8104 appeared as a child of PowerShell PID 7812. This process relationship is consistent with the simulated command-line finding involving `update.xml`; it does not independently establish malicious execution or command-and-control activity. | T1127.001 | probable | ART-002-M01; ART-002-M03 |
| 2026-04-14T02:44:05Z | ART-002 — memory / `netscan` finding (SIMULATED) | A TCP connection from WST-WS-031 to `185.220.101.47:443` was associated with MSBuild PID 8104. The remote endpoint and process association require validation; the connection alone does not prove C2. | T1071.001 | possible | ART-002-M04 |
| 2026-04-14T02:44:12Z | ART-001 — persistence / registry finding (SIMULATED) | The `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `WindowsUpdateSvc` referenced `C:\Users\dmarsh\AppData\Local\Temp\update.exe`, indicating a potential logon persistence mechanism. | T1547.001 | probable | ART-001-R01, persistence analysis |
| 2026-04-14T02:44:18Z | SUP-SIEM — endpoint file activity (SIMULATED) | Files including `update.exe`, `stage.ps1`, and `update.xml` were reported in the user's `AppData\Local\Temp` directory on WST-WS-031. Exact creation times and file hashes require verification against endpoint telemetry and the disk image. | T1105 | probable | SUP-SIEM-F02; ART-001 filesystem findings F01–F02 |
| 2026-04-14T02:46:27Z | ART-001 — persistence / scheduled task finding (SIMULATED) | Scheduled task `WindowsUpdateCheck` was recorded with a PowerShell action referencing the temporary staging script. This is consistent with persistence through a scheduled task, pending verification of the task XML and registry-backed task cache. | T1053.005 | probable | ART-001-R03, persistence analysis |
| 2026-04-14T02:43:58Z | ART-001 — persistence / registry finding (SIMULATED) | The `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` value `UpdateCheck` referenced a hidden PowerShell execution involving `stage.ps1`. | T1547.001 | probable | ART-001-R02, persistence analysis |
| 2026-04-14T02:51:09Z | ART-001 — persistence / scheduled task finding (SIMULATED) | A second task, `WindowsTelemetryUpdate`, was recorded with a SYSTEM principal and an action referencing `update.exe`. The privilege context and execution history require validation. | T1053.005 | probable | ART-001-R04, persistence analysis |
| 2026-04-14T02:45:10Z | ART-002 — memory / process and handle findings (SIMULATED) | Memory analysis reported LSASS-related handles and suspicious process context on WST-WS-031. The available simulated handle finding does not establish that NTLM hashes or Kerberos tickets were successfully extracted or read by the attacker. | T1003.001 | possible | ART-002-M07; ART-002-M08 |
| 2026-04-14T02:47:32Z | SUP-AD — Kerberos authentication log (SIMULATED) | Account `dmarsh` requested a Kerberos service ticket for `cifs/WST-WS-017`, potentially preceding access to the remote workstation. | T1558 | probable | SUP-AD-F02, simulated record |
| 2026-04-14T02:48:16Z | SUP-AD — AD logon event (SIMULATED) | An authentication event for `dmarsh` was recorded on WST-WS-017. Correlation with the service-ticket request suggests possible lateral movement, but the logon type, source address, and authentication outcome must be verified. | T1021.002 | probable | SUP-AD-F03, simulated record |
| 2026-04-14T03:38:00Z | ART-003 — memory acquisition record | Memory acquisition of WST-WS-017 began using WinPmem. This is an acquisition timestamp, not the time of the suspected intrusion. | — | confirmed | ART-003 acquisition notes |
| 2026-04-14T03:39:12Z | ART-003 — memory / `pslist` finding (SIMULATED) | PowerShell PID 3900 was listed in the WST-WS-017 memory-analysis output. The process command line and parent process require corroboration from the original memory image. | T1059.001 | probable | ART-003-M01 |
| 2026-04-14T03:39:20Z | ART-003 — memory / `netscan` finding (SIMULATED) | A TCP connection from WST-WS-017 to `185.220.101.47:443` was associated with PowerShell PID 3900, consistent with a possible second C2 beacon. A matching remote endpoint alone does not establish shared command-and-control infrastructure. | T1071.001 | possible | ART-003-M02 |
| 2026-04-14T03:41:03Z | SUP-AD — Kerberos authentication log (SIMULATED) | Account `dmarsh` requested a Kerberos service ticket for `cifs/LIS-WSIDE-01`, potentially preceding access to the laboratory workstation. | T1558 | probable | SUP-AD-F04, simulated record |
| 2026-04-14T03:42:27Z | SUP-AD — AD logon event (SIMULATED) | An authentication event associated with `dmarsh` was recorded on LIS-WSIDE-01. The event may indicate lateral movement from the previously accessed workstation; the source host and logon type require validation. | T1021.002 | probable | SUP-AD-F05, simulated record |
| 2026-04-14T03:45:51Z | SUP-SIEM — file access alert (SIMULATED) | File-access telemetry reported reads of 14 patient laboratory report PDF files on LIS-WSIDE-01. The filenames, access results, account, and initiating process require confirmation against the original audit records. | T1005 | probable | SUP-SIEM-F03, simulated alert |

## Key Correlation Findings

1. **Initial access and credential compromise:** The simulated proxy records place phishing-link access and credential submission before the suspected VPN authentication using `dmarsh`. Confirmation requires the original proxy events, the phishing URL and destination, and the corresponding VPN or identity-provider authentication record.

2. **Execution and command-and-control hypothesis:** The memory findings describe PowerShell PID 7812 spawning MSBuild PID 8104 on WST-WS-031, with a simulated outbound connection associated with MSBuild. This sequence is consistent with suspicious execution and possible C2, but process lineage and a network connection alone do not prove that the process was malicious or that the connection carried C2 traffic.

3. **Persistence:** The simulated registry and scheduled-task findings identify `WindowsUpdateSvc`, `UpdateCheck`, `WindowsUpdateCheck`, and `WindowsTelemetryUpdate`. These entries are consistent with persistence mechanisms, but the values and timestamps must be checked against the original registry hives, task files, and corresponding filesystem artifacts.

4. **Credential access:** The prior memory-analysis notes describe LSASS-related handles and a hashdump limitation. These findings do **not** establish that NTLM hash material or Kerberos ticket material was successfully accessed, extracted, or reused. A claim of credential dumping requires stronger supporting evidence, such as validated process-access telemetry, memory artifacts, or confirmed credential-material output.

5. **Lateral movement:** The simulated AD records place service-ticket requests for `cifs/WST-WS-017` and `cifs/LIS-WSIDE-01` before corresponding logons. Service-ticket requests are not, by themselves, proof of successful remote access. Source addresses, event IDs, logon types, authentication results, and endpoint logon telemetry should be correlated before attributing movement to the attacker.

6. **Potential access to patient data:** The simulated SIEM event reports 14 PDF reads on LIS-WSIDE-01. File-read telemetry may establish access, but it does not independently establish exfiltration. Network transfer logs, process attribution, and destination evidence would be required to assess whether the reports left the environment.

## Evidence Limitations and Validation Requirements

- The supplied conversation contains acquisition notes and previously drafted analysis findings, but not the original `proxy_log.jsonl`, `ad_auth_log.jsonl`, or `siem_alert_export.json` contents.
- Several prior analysis outputs were explicitly illustrative rather than produced from verified forensic commands. Their finding identifiers in this timeline are references to those drafted reports, not independently validated examiner output.
- The timestamp order for the `RunOnce` entry and some other persistence events must not be interpreted as definitive installation order until the source timestamps and time-zone conventions are verified.
- Confirm host clock synchronization, log time zones, event-generation times, ingestion times, and any clock drift before finalizing the sequence.
- Verify all simulated records against the original source files and replace placeholders with exact event IDs, record numbers, artifact offsets, and report line numbers.
- Acquisition notes record that the WST-WS-031 disk was imaged after VLAN isolation and that its live filesystem had previously been mounted read-write during an `update.xml` check. Potential access-time changes and the absence of acquisition-time SHA-256 hashes must be considered when evaluating filesystem timestamps and integrity.
- No definitive claim of credential theft, successful C2, lateral movement, or patient-data exfiltration should be made solely from the illustrative records in this draft.

## Assessment

The proposed sequence is consistent with a phishing-led compromise of `dmarsh`, suspicious PowerShell and MSBuild execution on WST-WS-031, possible persistence, potential access to WST-WS-017 and LIS-WSIDE-01, and possible access to patient laboratory reports. The sequence remains a **working correlation hypothesis**, not a verified reconstruction, until the original supplementary logs and forensic outputs have been examined and their timestamps and identifiers validated.