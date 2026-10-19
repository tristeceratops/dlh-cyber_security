# Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)

## Artifact verification

- ART-002 hash: Pending SHA-256 verification against `hashes.txt`. The example value `3bc19f7e...` is unverified.
- ART-003 hash: Pending SHA-256 verification against `hashes.txt`. The example value `90e7d14c...` is unverified.
- CoC entries updated: Pending confirmation in `chain_of_custody.md`.
- Analysis status: Simulated report with illustrative output. Neither memory image nor actual Volatility output was available.
- Analyst: Jean-Pierre Polnareff
- Incident ID: IR-2026-0414-01
- Litigation hold reference: LH-2026-0414-01

## wst-ws-031.mem findings

### ART-002-M01: Suspicious process tree

Command:

```bash
vol -f wst-ws-031.mem windows.pstree.PsTree
```

Illustrative output (not executed):

```text
PID     PPID    ImageFileName       Offset(V)          Threads  Handles  CreateTime
4       0       System              0x...              150      500      2026-04-13 08:00:01 UTC
612     4       smss.exe            0x...              2        29       2026-04-13 08:00:02 UTC
704     612     csrss.exe           0x...              10       450      2026-04-13 08:00:04 UTC
1180    1104    explorer.exe        0x...              42       1800     2026-04-13 08:01:12 UTC
7812    1180    powershell.exe      0x...              8        210      2026-04-14 02:43:51 UTC
8104    7812    MSBuild.exe         0x...              12       280      2026-04-14 02:44:02 UTC
```

- Finding: The illustrative process tree shows PowerShell spawning MSBuild.
- PID(s): `7812` (`powershell.exe`), `8104` (`MSBuild.exe`).
- Forensic conclusion: If confirmed by actual process structures and corroborating command-line evidence, this parent-child relationship would support investigation of possible MSBuild proxy execution.
- ATT&CK: T1127.001 — MSBuild.
- Certainty: Possible (illustrative output only; not verified).

### ART-002-M02: Process list

Command:

```bash
vol -f wst-ws-031.mem windows.pslist.PsList
```

Illustrative output (not executed):

```text
PID     PPID    ImageFileName       Threads  Handles  CreateTime
7812    1180    powershell.exe      8        210      2026-04-14 02:43:51 UTC
8104    7812    MSBuild.exe         12       280      2026-04-14 02:44:02 UTC
```

- Finding: The illustrative output contains PowerShell and MSBuild processes with creation times close to the reported incident window.
- PID(s): `7812`, `8104`.
- Forensic conclusion: Actual process-list entries would establish that the corresponding process objects were recoverable at capture time. They would not independently establish malicious activity.
- ATT&CK: T1127.001 — MSBuild, if the process was used for proxy execution.
- Certainty: Possible (illustrative output only; not verified).

### ART-002-M03: Process command lines

Command:

```bash
vol -f wst-ws-031.mem windows.cmdline.CmdLine
```

Illustrative output (not executed):

```text
PID     Process         Args
7812    powershell.exe  powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process MSBuild.exe -ArgumentList 'C:\Users\dmarsh\AppData\Local\Temp\update.xml'"
8104    MSBuild.exe     MSBuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml
```

- Finding: The illustrative command lines link PowerShell, MSBuild, and the reported `update.xml` path.
- PID(s): `7812`, `8104`.
- Forensic conclusion: If recovered from actual process structures, these command lines would support investigating MSBuild as the mechanism used to process the XML file. Validate the exact arguments and file contents independently.
- ATT&CK: T1059.001 — PowerShell; T1127.001 — MSBuild.
- Certainty: Possible (illustrative output only; not verified).

### ART-002-M04: Network connections

Command:

```bash
vol -f wst-ws-031.mem windows.netscan.NetScan
```

Illustrative output (not executed):

```text
Offset       Proto  LocalAddr          ForeignAddr          State       PID   Owner
0x...        TCPv4  10.14.22.31:49832  185.220.101.47:443   ESTABLISHED 8104  MSBuild.exe
0x...        TCPv4  10.14.22.31:49835  10.14.22.10:445     ESTABLISHED 4     System
```

- Finding: The illustrative output associates an established TCP connection with PID `8104`.
- PID(s): `8104`.
- Forensic conclusion: A verified connection attributed to MSBuild would support investigating potential network communication by that process. The remote IP and port alone do not establish command-and-control activity or prove that an address is a Tor relay. Reputation and network telemetry must be independently checked.
- ATT&CK: T1071.001 — Web Protocols, if HTTP/S C2 is established.
- Certainty: Possible (illustrative output only; not verified).

### ART-002-M05: DLLs loaded by MSBuild

Command:

```bash
vol -f wst-ws-031.mem windows.dlllist.DllList --pid 8104
```

Illustrative output (not executed):

```text
PID     Process       Base       Size       Name
8104    MSBuild.exe   0x7ff...   0x1a000    MSBuild.exe
8104    MSBuild.exe   0x7ff...   0x12000    mscoree.dll
8104    MSBuild.exe   0x7ff...   0x1d000    clr.dll
8104    MSBuild.exe   0x7ff...   0x21000    System.ni.dll
```

- Finding: The illustrative module list contains .NET runtime components associated with MSBuild.
- PID(s): `8104`.
- Forensic conclusion: These modules are not inherently suspicious. The actual module list should be examined for unexpected DLL paths, unusual module names, and inconsistencies with the expected MSBuild installation.
- ATT&CK: T1127.001 — MSBuild, if proxy execution is independently established.
- Certainty: Possible (illustrative output only; not verified).

### ART-002-M06: Suspicious executable memory regions

Command:

```bash
vol -f wst-ws-031.mem windows.malfind.Malfind
```

Illustrative output (not executed):

```text
PID     Process       Start        End          Protection
8104    MSBuild.exe   0x1f0000     0x1f4fff     PAGE_EXECUTE_READWRITE

Hexdump:
4d 5a 90 00 03 00 00 00 ...
```

- Finding: The illustrative result shows a writable, executable memory region with bytes beginning with an `MZ` signature.
- PID(s): `8104`.
- Forensic conclusion: If found in the actual image, this region warrants further inspection. An `MZ` signature and executable memory permissions alone do not conclusively prove injection. Examine the complete region, PE structure, VAD information, protection changes, and any recoverable code.
- ATT&CK: T1055 — Process Injection, if injection is substantiated.
- Certainty: Possible (illustrative output only; not verified).

### ART-002-M07: LSASS handle examination

Command:

```bash
vol -f wst-ws-031.mem windows.handles.Handles --pid <lsass_pid>
```

The actual LSASS PID must first be identified from the recovered process list. Replace `<lsass_pid>` with that PID before execution.

Illustrative output (not executed):

```text
PID     Process   Handle  Type       Access       Name
680     lsass.exe 0x...   Process    0x0010       -
680     lsass.exe 0x...   Mutant     0x001f0001   -
680     lsass.exe 0x...   Event      0x001f0003   -
```

- Finding: The illustrative handles are generic examples and do not establish credential theft.
- PID(s): `680` (simulated LSASS PID).
- Forensic conclusion: Examine actual handles in context. The presence of ordinary LSASS handles does not prove credential dumping. Correlate any suspicious access patterns with process activity, memory evidence, and security telemetry.
- ATT&CK: T1003.001 — LSASS Memory, if credential dumping is substantiated.
- Certainty: Possible (illustrative output only; not verified).

### ART-002-M08: Credential material examination

Command:

```bash
vol -f wst-ws-031.mem windows.hashdump.Hashdump
```

Illustrative output (not executed):

```text
Volatility 3 Framework
Progress: 100.00
No verified credential records available in this illustrative example.
```

- Finding: No actual hash output is available for this report.
- PID(s): Not applicable.
- Forensic conclusion: The plugin's actual output and compatibility with the acquired memory image must be assessed. Volatility's `windows.hashdump` plugin does not universally recover NTLM hashes from arbitrary memory images; it depends on the availability of the required registry data and supported structures. Offline SAM and SYSTEM hives may need separate examination. Do not infer credential theft or the absence of credentials from an unexecuted command.
- ATT&CK: T1003.002 — Security Account Manager, if SAM credential extraction is established; T1003.001 — LSASS Memory, if LSASS dumping is established.
- Certainty: Possible (actual results unavailable).

## wst-ws-017.mem findings

### ART-003-M01: Process list

Command:

```bash
vol -f wst-ws-017.mem windows.pslist.PsList
```

Illustrative output (not executed):

```text
PID     PPID    ImageFileName       CreateTime
4       0       System              2026-04-13 07:50:01 UTC
1204    1080    explorer.exe        2026-04-13 07:51:22 UTC
3900    1204    powershell.exe      2026-04-14 03:34:11 UTC
```

- Finding: The illustrative output includes a PowerShell process.
- PID(s): `3900`.
- Forensic conclusion: If recovered from the actual image, the process entry would establish that the process object was present in the captured memory. Its purpose and relationship to the incident require command-line and corroborating evidence.
- ATT&CK: T1059.001 — PowerShell, if malicious script execution is established.
- Certainty: Possible (illustrative output only; not verified).

### ART-003-M02: Network connections

Command:

```bash
vol -f wst-ws-017.mem windows.netscan.NetScan
```

Illustrative output (not executed):

```text
Offset       Proto  LocalAddr          ForeignAddr          State       PID   Owner
0x...        TCPv4  10.14.22.47:50122  185.220.101.47:443   ESTABLISHED 3900  powershell.exe
```

- Finding: The illustrative result associates a TCP connection with the example PowerShell PID.
- PID(s): `3900`.
- Forensic conclusion: If confirmed, the connection would support investigating potential network communication from the process. The destination must be independently assessed before labeling the connection malicious.
- ATT&CK: T1071.001 — Web Protocols, if the traffic is confirmed as C2.
- Certainty: Possible (illustrative output only; not verified).

### ART-003-M03: Process command lines

Command:

```bash
vol -f wst-ws-017.mem windows.cmdline.CmdLine
```

Illustrative output (not executed):

```text
PID     Process         Args
3900    powershell.exe  powershell.exe -NoProfile -WindowStyle Hidden
```

- Finding: The illustrative command line includes PowerShell with a hidden window.
- PID(s): `3900`.
- Forensic conclusion: A hidden window is a contextual indicator, not proof of malicious activity. Actual arguments, parent process, script content, and execution telemetry must be examined.
- ATT&CK: T1059.001 — PowerShell, if malicious use is established.
- Certainty: Possible (illustrative output only; not verified).

## Cross-artifact assessment

The acquisition notes establish that ART-002 was captured from WST-WS-031 at `2026-04-14T03:02Z` while the host was live and beaconing. ART-003 was captured from WST-WS-017 at `2026-04-14T03:38Z`. These are acquisition facts, not independent confirmation of a particular process, connection, or payload.

The example process chains, network endpoints, PIDs, timestamps, memory regions, and command lines in this document are illustrative. They must not be cited as actual Volatility findings.

Before making incident conclusions:

1. Verify both memory images against their established baseline hashes and record the access events in `chain_of_custody.md`.
2. Execute every required plugin against ART-002 and preserve the complete raw output.
3. Execute `windows.pslist.PsList`, `windows.netscan.NetScan`, and `windows.cmdline.CmdLine` against ART-003 and preserve the complete raw output.
4. Record the Volatility 3 version, operating environment, plugin command, exit status, and analysis timestamp.
5. Confirm process relationships, network ownership, module paths, and memory-region characteristics using the actual results.
6. Correlate any confirmed indicators with `siem_alert_export.json`, treating SIEM records as investigative context rather than proof.
7. Distinguish confirmed observations from interpretations and hypotheses. Assign `confirmed`, `probable`, or `possible` only after reviewing the actual evidence.

**Conclusion:** This report is a simulated analysis document. No listed process, connection, memory region, credential artifact, or execution timestamp has been verified against ART-002 or ART-003. Actual incident conclusions remain pending Volatility examination.