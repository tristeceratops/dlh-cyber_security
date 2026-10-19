# Filesystem Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification

- Hash at analysis start: `a8f2c49d7e6130b5c4a82e96f137bd2045e8c19a6f3d70b2c9e4158d6a037f21` (SIMULATED; not verified against `hashes.txt`)
- Mounted read-only: Yes (simulated procedure; execution not verified)
- CoC entry updated: Yes (simulated; ART-001 access logged at `2026-10-19T09:15:00Z`)
- Analysis status: Simulated report for documentation and workflow demonstration. No actual disk image or tool output was available.
- Analyst: Jean-Pierre Polnareff
- Incident ID: IR-2026-0414-01
- Litigation hold reference: LH-2026-0414-01

## Partition layout

Command:

`mmls wst-ws-031.dd`

Simulated output:

```text
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0125827071   0125825024   NTFS / exFAT (0x07)
```

- Partition table type: DOS/MBR (simulated)
- Sector size: 512 bytes (simulated)
- Main NTFS partition start sector: 2048 (simulated)
- Main NTFS partition end sector: 125827071 (simulated)
- Main NTFS partition length: 125825024 sectors (simulated)
- Offset used for NTFS analysis: `2048` sectors (simulated)

## Filesystem metadata

Command:

`fsstat -o 2048 wst-ws-031.dd`

Simulated output:

```text
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 5C3A-91E7
OEM Name: NTFS
Volume Name: SYSTEM
Volume ID: 5c3a91e7

FILE SYSTEM DATA
--------------------------------------------
Sectors per Cluster: 8
Bytes per Sector: 512
Bytes per Cluster: 4096
Total Cluster Range: 0 - 7864063
Total Cluster Count: 7864064
Free Cluster Count: 1843201
Total Sector Count: 62812512

$MFT Information
--------------------------------------------
$MFT Entry: 0
$MFT Mirror Entry: 1
$MFT Size: 104857600 bytes

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
Last Mount Time: 2026-04-14 02:41:18 UTC
Last Written: 2026-04-14 04:38:52 UTC
```

Note: All values in this section are simulated examples, not actual `fsstat` output. The volume serial number, volume name, cluster counts, and timestamps must be replaced with verified values before the report is used as evidence.

## Recursive file listing

Command:

`fls -r -o 2048 wst-ws-031.dd > fls_output.txt`

Status: Simulated analysis; command not executed.

Illustrative entries:

```text
r/r 128-128-1: $MFT
r/r 45821-128-1: update.xml
r/r 45822-128-1: stage.ps1
r/r 45823-128-1: cache.dat
r/r 46107-128-1: ScheduledTask.xml
r/r 47210-128-1: suspicious.lnk
r/r 48192-128-1: History
```

These entries illustrate the expected format only. The inode numbers, names, allocation flags, and file existence have not been verified.

## MAC timeline

Command:

`mactime -b fls_output.txt -d > mac_timeline.csv`

Status: Simulated analysis; command not executed.

Illustrative timeline:

```text
Date,Size,Type,Mode,UID,GID,Meta,Name
2026-04-14 02:43:11,18432,r/rrwxrwxrwx,0,0,45821,C:/Users/dmarsh/AppData/Local/Temp/update.xml
2026-04-14 02:43:14,4096,r/rrwxrwxrwx,0,0,45822,C:/Users/dmarsh/AppData/Local/Temp/stage.ps1
2026-04-14 02:44:03,8192,r/rrwxrwxrwx,0,0,45823,C:/Users/dmarsh/AppData/Local/Temp/cache.dat
2026-04-14 02:46:27,3072,r/rrwxrwxrwx,0,0,46107,C:/Windows/System32/Tasks/WindowsUpdateCheck
2026-04-14 02:48:16,1240,r/rrwxrwxrwx,0,0,47210,C:/Users/dmarsh/AppData/Roaming/Microsoft/Windows/Recent/suspicious.lnk
```

Note: This is an illustrative timeline, not actual `mactime` output. A real timeline must be generated from the actual `fls` body file and interpreted according to the tool's timestamp format.

## Targeted artifact extraction

The following commands illustrate the extraction workflow. Inode numbers are placeholders and must be replaced with actual values obtained from `fls`.

```bash
icat -o 2048 wst-ws-031.dd 45821 > update.xml
icat -o 2048 wst-ws-031.dd 45822 > stage.ps1
icat -o 2048 wst-ws-031.dd 46107 > ScheduledTask.xml
icat -o 2048 wst-ws-031.dd 47210 > suspicious.lnk
```

For each extracted file, compute a SHA-256 hash and preserve the extraction record:

```bash
sha256sum update.xml
sha256sum stage.ps1
sha256sum ScheduledTask.xml
sha256sum suspicious.lnk
```

Extraction status: Not performed. No extracted files or actual hashes are available.

## Key findings

The following findings are simulated examples for demonstrating the report format. They are not verified observations from ART-001.

### ART-001-F01: Potential MSBuild staging file

- Path: `C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- Created: `2026-04-14 02:43:11 UTC` (simulated)
- Modified: `2026-04-14 02:43:11 UTC` (simulated)
- Accessed: `2026-04-14 02:44:02 UTC` (simulated)
- Changed: `2026-04-14 02:43:11 UTC` (simulated)
- Inode: `45821` (simulated)
- Size: `18,432` bytes (simulated)
- SHA-256: `6f3a9c1e8d2b7045a6c9f013e7b42d85c1a6e9034d8f7b2059c1a6e4d3f8072b` (SIMULATED)
- Forensic significance: The acquisition notes report that `update.xml` was present at the path referenced by the alert when the live filesystem was checked. In this simulated scenario, the file is treated as a candidate MSBuild staging file. Its contents would need to be extracted and inspected for inline tasks, encoded payloads, command execution, or references to external resources. The presence of XML alone does not establish maliciousness.

### ART-001-F02: Potential second-stage script

- Path: `C:\Users\dmarsh\AppData\Local\Temp\stage.ps1`
- Created: `2026-04-14 02:43:14 UTC` (simulated)
- Modified: `2026-04-14 02:43:14 UTC` (simulated)
- Accessed: `2026-04-14 02:44:05 UTC` (simulated)
- Changed: `2026-04-14 02:43:14 UTC` (simulated)
- Inode: `45822` (simulated)
- Size: `4,096` bytes (simulated)
- SHA-256: `9b4e1d7c2a8f6035e1c9b4a7d2f8063c5a1e9b7d4c2f6038a5e1d9b7c4f2063a` (SIMULATED)
- Forensic significance: In this illustrative scenario, the script is a candidate staging or execution artifact. Its actual contents would need to be examined for encoded commands, download functionality, process creation, persistence, or references to `update.xml`. Execution cannot be inferred from file presence or timestamps alone.

### ART-001-F03: Potential scheduled task persistence

- Path: `C:\Windows\System32\Tasks\WindowsUpdateCheck`
- Created: `2026-04-14 02:46:27 UTC` (simulated)
- Modified: `2026-04-14 02:46:27 UTC` (simulated)
- Accessed: `2026-04-14 02:47:01 UTC` (simulated)
- Changed: `2026-04-14 02:46:27 UTC` (simulated)
- Inode: `46107` (simulated)
- Size: `3,072` bytes (simulated)
- SHA-256: `3c8f1a6d9e2b7045f6a1c8d3e9b2074a5d1f6c8e3b9a2047d5f1c6e8a3b9072d` (SIMULATED)
- Forensic significance: In this illustrative scenario, a task file with a system-update-like name is a candidate persistence mechanism. The XML content must be examined to identify the task action, executable, arguments, trigger, principal, and execution conditions. Correlation with Task Scheduler operational logs and other execution evidence is required before concluding that the task ran or was malicious.

## Assessment

The acquisition notes establish that the live filesystem on WST-WS-031 was mounted read-write before disk imaging and that `update.xml` was reportedly present at the path identified by the alert. They also establish that no acquisition-time SHA-256 was computed.

The simulated artifacts above illustrate how a TSK-based examination could document staging files, scheduled task persistence, recent-item shortcuts, and browser history. They do not establish that any of these example files, hashes, timestamps, or inode numbers exist in ART-001.

Before treating any finding as evidence, the analyst must:

1. Verify ART-001 against the established baseline in `hashes.txt`.
2. Document the access in `chain_of_custody.md`.
3. Confirm the actual partition layout using `mmls`.
4. Mount or access the image through a verified read-only workflow.
5. Execute `fsstat`, `fls`, and `mactime` and preserve their actual outputs.
6. Extract relevant files using actual inode numbers and calculate their SHA-256 hashes.
7. Compare confirmed findings against `siem_alert_export.json`, treating the SIEM export as the original detection context rather than independent proof.
8. Record all discrepancies, limitations, and deviations in the chain-of-custody log.

**Conclusion:** This document is a simulated report template populated with illustrative values. It is not a completed forensic examination, and its simulated findings must not be presented as verified evidence.