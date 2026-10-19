# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification

- Hash at analysis start: `a8f2c49d7e6130b5c4a82e96f137bd2045e8c19a6f3d70b2c9e4158d6a037f21` (SIMULATED; baseline comparison not performed)
- CoC entry updated: Pending verification; ART-001 access timestamp must be recorded in `chain_of_custody.md`.
- Analysis status: Simulated report; registry hives have not been extracted or examined.
- Analyst: Jean-Pierre Polnareff
- Incident ID: IR-2026-0414-01
- Litigation hold reference: LH-2026-0414-01

## Registry persistence

### ART-001-R01: Run key — WindowsUpdateSvc

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- User profile: `C:\Users\dmarsh\NTUSER.DAT`
- Value name: `WindowsUpdateSvc`
- Value data: `C:\Users\dmarsh\AppData\Local\Temp\update.exe`
- Last write: `2026-04-14 02:44:12 UTC` (simulated)
- Evidence ID: ART-001-R01
- Forensic significance: In this illustrative scenario, a Run key value references an executable in the user's temporary directory. This combination warrants investigation for user-level persistence. The executable's existence, contents, hash, and execution must be independently verified before concluding that the value is malicious.

### ART-001-R02: RunOnce key

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- User profile: `C:\Users\dmarsh\NTUSER.DAT`
- Value name: `UpdateCheck`
- Value data: `powershell.exe -NoProfile -WindowStyle Hidden -File "C:\Users\dmarsh\AppData\Local\Temp\stage.ps1"`
- Last write: `2026-04-14 02:43:58 UTC` (simulated)
- Evidence ID: ART-001-R02
- Forensic significance: In this illustrative scenario, the RunOnce value invokes PowerShell with a hidden window and references a script in a temporary directory. These characteristics warrant investigation. RunOnce entries are generally intended for one-time execution and may be removed after processing. The registry value alone does not prove execution.

### ART-001-R03: Scheduled task — WindowsUpdateCheck

- File path: `C:\Windows\System32\Tasks\WindowsUpdateCheck`
- Registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WindowsUpdateCheck`
- Value name: `Id`
- Value data: `{7D9B4C21-63F0-4A82-91D7-2C6E5B8A104F}` (simulated)
- Last write: `2026-04-14 02:46:27 UTC` (simulated)
- Evidence ID: ART-001-R03
- Simulated XML trigger: Logon trigger for the `dmarsh` user.
- Simulated XML action: `powershell.exe -NoProfile -WindowStyle Hidden -File "C:\Users\dmarsh\AppData\Local\Temp\stage.ps1"`
- Simulated XML principal: `dmarsh`
- Forensic significance: The hypothetical task combines logon-triggered execution with a hidden PowerShell window and a temporary-directory script. This would be consistent with a potential persistence mechanism. The XML, TaskCache registry data, principal, trigger, and action must be extracted and cross-checked against the actual image. The simulated GUID and task details are not verified evidence.

### ART-001-R04: Scheduled task — WindowsTelemetryUpdate

- File path: `C:\Windows\System32\Tasks\WindowsTelemetryUpdate`
- Registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WindowsTelemetryUpdate`
- Value name: `Id`
- Value data: `{3A6E9F10-2B74-48C5-A1D3-8F6B0E2C9517}` (simulated)
- Last write: `2026-04-14 02:51:09 UTC` (simulated)
- Evidence ID: ART-001-R04
- Simulated XML trigger: Daily trigger at user logon.
- Simulated XML action: `C:\Users\dmarsh\AppData\Local\Temp\update.exe`
- Simulated XML principal: `SYSTEM`
- Forensic significance: A task executing a binary from a user-writable temporary directory under the SYSTEM account would represent a potentially significant privilege and persistence concern. Validate the task's existence, permissions, action, trigger, and principal. No conclusion about actual privilege escalation can be drawn from this simulated example.

## Execution evidence

### ART-001-E01: UserAssist — MSBuild.exe

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`
- Value name: `HRZR_EHAPY:ZFOhvYQ.rkr` (illustrative ROT13-encoded value name)
- Decoded value: `UEME_RUNPATH:MSBuild.exe` (illustrative)
- Run count: `1` (simulated)
- Last executed: `2026-04-14 02:44:03 UTC` (simulated)
- Last write: Pending verification against the actual registry hive.
- Evidence ID: ART-001-E01
- Forensic significance: UserAssist can record GUI-related application activity for a user session. In this simulated scenario, the entry suggests one recorded interaction associated with MSBuild. UserAssist data structures and value names must be decoded with an appropriate parser; the displayed value is illustrative, not extracted evidence. It does not independently prove malicious execution or establish command-line arguments.

### ART-001-E02: UserAssist — PowerShell

- Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`
- Value name: `HRZR_EHAPY:cbjrefuryy.rkr` (illustrative ROT13-encoded value name)
- Decoded value: `UEME_RUNPATH:powershell.exe` (illustrative)
- Run count: `2` (simulated)
- Last executed: `2026-04-14 02:46:05 UTC` (simulated)
- Last write: Pending verification against the actual registry hive.
- Evidence ID: ART-001-E02
- Forensic significance: In the simulated scenario, repeated PowerShell activity occurs near the reported incident window. Correlate any real UserAssist records with PowerShell operational logs, process creation events, script block logs, Prefetch, and recovered scripts where available. UserAssist alone cannot establish that a particular script ran.

### ART-001-E03: AppCompatCache / ShimCache

- Hive path: `C:\Windows\System32\config\SYSTEM`
- Registry key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
- Value name: `AppCompatCache`
- Value data: Binary application compatibility cache (not yet extracted)
- Last write: Pending examination.
- Evidence ID: ART-001-E03
- Simulated entry: `C:\Users\dmarsh\AppData\Local\Temp\update.exe`
- Simulated associated timestamp: `2026-04-14 02:44:10 UTC`
- Forensic significance: AppCompatCache may contain records of executable paths observed by the Windows compatibility subsystem. The cache format and evidentiary meaning depend on the Windows version. A ShimCache entry alone does not reliably prove that a binary executed. The actual SYSTEM hive must be parsed with a version-compatible tool, and any timestamps must be interpreted according to the parser's documented behavior.

### ART-001-E04: AppCompatCache / ShimCache — MSBuild.exe

- Hive path: `C:\Windows\System32\config\SYSTEM`
- Registry key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
- Value name: `AppCompatCache`
- Value data: Binary application compatibility cache (not yet extracted)
- Last write: Pending examination.
- Evidence ID: ART-001-E04
- Simulated entry: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`
- Simulated associated timestamp: Not established.
- Forensic significance: A cache record referencing MSBuild could help establish that the path was observed by the compatibility subsystem. It does not by itself confirm execution at the SIEM alert time. Correlate any recovered record with independent process creation telemetry and the contents of the reported `update.xml`.

### ART-001-E05: Amcache — update.exe

- Hive path: `C:\Windows\AppCompat\Programs\Amcache.hve`
- Registry location: `Root\InventoryApplicationFile` (exact subkey pending extraction)
- Value name: `LowerCaseLongPath`
- Value data: `c:\users\dmarsh\appdata\local\temp\update.exe` (simulated)
- SHA-1: `5d7a1c9e3f2048b6a9d2e7f1035c8b4a6d1e9027` (SIMULATED)
- First execution timestamp: Not established.
- Last write: Pending examination.
- Evidence ID: ART-001-E05
- Forensic significance: Amcache may contain executable inventory records, paths, and file metadata, depending on the Windows version and record type. The presence of an executable record does not automatically prove execution, and an Amcache inventory timestamp must not be mislabeled as a first-execution timestamp. Extract the actual hive, identify the relevant file record, document its schema, and corroborate execution with independent evidence.

### ART-001-E06: Amcache — stage.ps1

- Hive path: `C:\Windows\AppCompat\Programs\Amcache.hve`
- Registry location: Relevant file inventory record, if present.
- Value name: `LowerCaseLongPath`
- Value data: `c:\users\dmarsh\appdata\local\temp\stage.ps1` (simulated)
- SHA-1: Not established.
- First execution timestamp: Not established.
- Last write: Pending examination.
- Evidence ID: ART-001-E06
- Forensic significance: This is a candidate path for examination in the Amcache hive. Whether a script has a corresponding record depends on the operating system, inventory mechanism, and record type. Do not assume Amcache contains a first-execution timestamp for this script. Correlate the file with PowerShell logs and other execution artifacts.

## Recent-items LNK analysis

### ART-001-L01: Potential shortcut to update.exe

- File path: `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\update.lnk`
- Value name: Not applicable.
- Value data: LNK target `C:\Users\dmarsh\AppData\Local\Temp\update.exe` (simulated)
- Created: `2026-04-14 02:44:20 UTC` (simulated)
- Modified: `2026-04-14 02:44:20 UTC` (simulated)
- Accessed: Pending verification.
- Size: `1,176` bytes (simulated)
- SHA-256: Not established.
- Evidence ID: ART-001-L01
- Forensic significance: A shortcut referencing a temporary executable could provide evidence that the target was referenced by the user's shell environment. The LNK must be extracted and parsed to confirm its target, embedded timestamps, volume information, and other metadata. The existence of the hypothetical shortcut does not prove that the target executed.

### ART-001-L02: Potential shortcut to update.xml

- File path: `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\update.xml.lnk`
- Value name: Not applicable.
- Value data: LNK target `C:\Users\dmarsh\AppData\Local\Temp\update.xml` (simulated)
- Created: `2026-04-14 02:43:49 UTC` (simulated)
- Modified: `2026-04-14 02:43:49 UTC` (simulated)
- Accessed: Pending verification.
- Size: `1,032` bytes (simulated)
- SHA-256: Not established.
- Evidence ID: ART-001-L02
- Forensic significance: In this simulated scenario, the shortcut references the XML file reported in the acquisition notes. A real LNK record could help establish that the file was referenced by the shell, but would not independently prove that MSBuild opened or executed the XML. Correlate the actual shortcut metadata with the recovered XML and process execution evidence.

## Correlation and assessment

The acquisition notes report that `update.xml` was present on the live filesystem at the path identified by the alert. They also document a read-write mount before disk imaging and the absence of acquisition-time hashes. These limitations must remain visible in the evidentiary record.

The simulated persistence and execution entries above illustrate how Run keys, RunOnce, scheduled tasks, UserAssist, AppCompatCache, Amcache, and LNK artifacts could be documented. They are not findings recovered from the actual image.

The following steps are required to establish real findings:

1. Verify ART-001 against the baseline in `hashes.txt` and append the access event to `chain_of_custody.md`.
2. Access the image through a verified read-only workflow and record the actual partition offset.
3. Extract `NTUSER.DAT`, `SYSTEM`, and `Amcache.hve` using the actual file locations and inode numbers.
4. Parse registry hives with a suitable registry forensic tool. Preserve hive hashes and record parser names and versions.
5. Decode UserAssist entries and document the actual run counts and available timestamps.
6. Parse the scheduled task XML files and correlate their contents with TaskCache registry records.
7. Parse AppCompatCache using a parser compatible with the operating system version; distinguish observed paths from confirmed execution.
8. Examine Amcache records using their actual schemas and distinguish inventory timestamps from demonstrated execution times.
9. Extract and parse LNK files from the `dmarsh` profile.
10. Correlate confirmed findings with `siem_alert_export.json` and independent execution telemetry. Treat the SIEM export as original detection context, not as proof of the indicators it reports.

**Conclusion:** This report contains simulated examples for documentation purposes. The listed registry values, task definitions, execution counts, hashes, timestamps, and LNK targets have not been verified against ART-001 and must not be represented as actual forensic evidence.