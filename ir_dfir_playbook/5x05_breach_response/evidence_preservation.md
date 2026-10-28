# Evidence Preservation: IR-2026-0420-01

## Priority order rationale

WS-101 is the initial compromise host; memory was already captured at 19:38Z by Mike Torres (ART-001). Disk image must be captured before any containment action. WS-104 and WS-107 show active beaconing in Sysmon; memory must be captured before network isolation removes C2 telemetry. FILE-SVR-01 has no active beacon in the supplied evidence but holds the PHI access record; disk image priority is high but second to active-beacon hosts. WS-112 shows lateral logon events but no current beacon activity in the supplied evidence; captured last.

## ART-001: cs-ws-101.mem (Torres acquisition)

- acquired_by: Mike Torres
- acquired_at: 2026-04-20T19:38:00Z
- tool: WinPmem
- evidence_path: `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem`
- sha256_at_acquisition: Not recorded by Torres
- sha256_verified_by_analyst: Compute at 20:10Z; record the actual digest. An acquisition-time match cannot be confirmed because the original hash was not recorded.
- gap_note: Three-minute gap between acquisition (19:38Z) and Torres's call (19:43:18Z); fourteen-minute gap between acquisition and declaration (19:52Z). State at acquisition reflects pre-call conditions; relevant for timeline correlation.
- verification_command:
  ```powershell
  Get-FileHash "\\evidence\share\IR-2026-0420-01\cs-ws-101.mem" -Algorithm SHA256
  ```
- handling: Preserve the original unchanged, record the digest and verification timestamp, and use a verified working copy for analysis.

## ART-002: cs-ws-101.dd

- priority: 1
- acquired_before: Network isolation of WS-101, unless immediate containment is required to prevent harm
- tool: FTK Imager over IR jumpbox
- rationale: Initial compromise host with suspicious Word macro execution, PowerShell download, credential-access activity, active beaconing, and ransomware staging.
- volatile_evidence: Existing ART-001 memory dump; verify before analysis. Capture fresh memory only if authorized and safe.
- nonvolatile_evidence: Bit-for-bit system disk image; Sysmon, Security, System, PowerShell, and EDR logs; service configuration; suspicious executable and ransomware-staging script.
- sha256: Compute and record at acquisition; independently verify the stored image.
- verification_command:
  ``` powershell
  Get-FileHash "<actual_disk_image_path>" -Algorithm SHA256
  ```
- chain_of_custody: Record collector, acquisition start/end times in UTC, source disk identifiers, tool version, actual SHA-256 digest, destination path, and verification result.

## ART-003: cs-ws-104

- priority: 2
- acquired_before: Network isolation, provided acquisition does not delay urgent containment
- tool: WinPmem for memory; FTK Imager for disk
- rationale: Sysmon confirms service installation and beacon activity. Ransomware staging is present.
- volatile_evidence: Memory image, running processes, network connections, and active session details.
- nonvolatile_evidence: Disk image; Sysmon, Security, System, PowerShell, and EDR logs; `WinHealthSvc` configuration; `C:\ProgramData\Microsoft\svchost32.exe`; `C:\Windows\System32\encryption_staging.ps1`.
- memory_command:
  ``` powershell
  winpmem_mini_x64.exe "<evidence_directory>\cs-ws-104.mem"
  ```
- sha256: Compute and record at acquisition for memory and disk images; verify evidence-store copies.
- verification_commands:
  ``` powershell
  Get-FileHash "<actual_memory_dump_path>" -Algorithm SHA256
  Get-FileHash "<actual_disk_image_path>" -Algorithm SHA256
  ```
- chain_of_custody: Record collector, UTC timestamps, tool versions, source identifiers, destination paths, actual hashes, and transfer history.

## ART-004: cs-ws-107

- priority: 3
- acquired_before: Network isolation, provided acquisition does not delay urgent containment
- tool: WinPmem for memory; FTK Imager for disk
- rationale: Sysmon and proxy evidence confirm beaconing to `45.152.66.114`; ransomware staging is present.
- volatile_evidence: Memory image, running processes, network connections, and active session details.
- nonvolatile_evidence: Disk image; Sysmon, Security, System, PowerShell, and EDR logs; suspicious executable, service configuration, and encryption-staging script.
- memory_command:
  ``` powershell
  winpmem_mini_x64.exe "<evidence_directory>\cs-ws-107.mem"
  ```
- sha256: Compute and record at acquisition for memory and disk images; verify evidence-store copies.
- verification_commands:
  ``` powershell
  Get-FileHash "<actual_memory_dump_path>" -Algorithm SHA256
  Get-FileHash "<actual_disk_image_path>" -Algorithm SHA256
  ```
- chain_of_custody: Record collector, UTC timestamps, tool versions, source identifiers, destination paths, actual hashes, and transfer history.

## ART-005: FILE-SVR-01

- priority: 4
- acquired_before: Disk imaging and log export before remediation or rebuild
- tool: WinPmem for memory; FTK Imager for disk
- rationale: The file server contains clinical documentation. Logs show 1,847 Event ID 4663 read-access events between 2026-04-19T02:14:01Z and 02:41:12Z under `MEDDEFENSE\jdoe`. The supplied evidence does not show current beacon activity on this host, but its PHI exposure significance is high.
- volatile_evidence: Memory image and current process/network state, if safely obtainable.
- nonvolatile_evidence: Bit-for-bit disk image; full Windows Security EVTX logs; relevant Sysmon, System, and EDR logs; all 1,847 access records; supporting 4624 and 4634 events; ACLs and relevant proxy logs.
- memory_command:
  powershell
  ```
  winpmem_mini_x64.exe "<evidence_directory>\file-svr-01.mem"
  ```
- sha256: Hash the memory image, disk image, and each exported log file at acquisition; independently verify evidence-store copies.
- verification_commands:
  powershell
  ```
  Get-FileHash "<actual_memory_dump_path>" -Algorithm SHA256
  Get-FileHash "<actual_disk_image_path>" -Algorithm SHA256
  Get-FileHash "<actual_evtx_path>" -Algorithm SHA256
  ```
- chain_of_custody: Record collector, UTC timestamps, source identifiers, tool versions, actual hashes, destination paths, and every transfer.

## ART-006: cs-ws-112

- priority: 5
- acquired_before: Network isolation, provided acquisition does not delay urgent containment
- tool: WinPmem for memory; FTK Imager for disk
- rationale: Sysmon and proxy records show beacon activity and ransomware staging. It is acquired last because the initial host, other actively beaconing hosts, and the PHI-bearing file server have higher immediate evidence priorities.
- volatile_evidence: Memory image, running processes, network connections, and active session details.
- nonvolatile_evidence: Disk image; Sysmon, Security, System, PowerShell, and EDR logs; service configuration; suspicious executable and encryption-staging script.
- memory_command:
  ``` powershell
  winpmem_mini_x64.exe "<evidence_directory>\cs-ws-112.mem"
  ```
- sha256: Compute and record at acquisition for memory and disk images; verify evidence-store copies.
- verification_commands:
  ``` powershell
  Get-FileHash "<actual_memory_dump_path>" -Algorithm SHA256
  Get-FileHash "<actual_disk_image_path>" -Algorithm SHA256
  ```
- chain_of_custody: Record collector, UTC timestamps, tool versions, source identifiers, destination paths, actual hashes, and transfer history.

## Chain of custody table

| Artifact ID | Host / artifact | Acquired by | Acquired at (UTC) | SHA-256 at acquisition | Verification status |
| --- | --- | --- | --- | --- | --- |
| ART-001 | WS-101 memory: `cs-ws-101.mem` | Mike Torres | 2026-04-20T19:38:00Z | Not recorded | Pending; compute at 20:10Z. No acquisition-time baseline exists. |
| ART-002 | WS-101 disk: `cs-ws-101.dd` | Pending | Pending | Pending | Not acquired |
| ART-003 | WS-104 memory and disk | Pending | Pending | Pending | Not acquired |
| ART-004 | WS-107 memory and disk | Pending | Pending | Pending | Not acquired |
| ART-005 | FILE-SVR-01 memory, disk, and logs | Pending | Pending | Pending | Not acquired |
| ART-006 | WS-112 memory and disk | Pending | Pending | Pending | Not acquired |