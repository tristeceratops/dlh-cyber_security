# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: `/evidence/IR-2026-0414-01/`  
Hash algorithm: SHA-256

## 1. Volatile memory — WST-WS-031

- **What:** Full physical memory dump of `WST-WS-031`.
- **How:** `winpmem_3.3.rc3.exe -o \\evidence\IR-2026-0414-01\wst-ws-031.mem`
- **Where:** `/evidence/IR-2026-0414-01/wst-ws-031.mem`
- **Hash:** `sha256sum /evidence/IR-2026-0414-01/wst-ws-031.mem` — append the result to `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`.
- **Ordering:** Must precede process termination, reboot, or host isolation when safely feasible because volatile memory may contain credentials, injected code, and socket state that will be lost.

## 2. Process list and active network connections

- **What:** Process IDs, parent PIDs, command lines, executable paths, and active TCP connections.
- **How:** Run elevated PowerShell:
  ```powershell
  Get-CimInstance Win32_Process |
    Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate |
    Export-Csv -NoTypeInformation C:\Temp\processes.csv

  Get-NetTCPConnection |
    Export-Csv -NoTypeInformation C:\Temp\network.csv
  ```
  Transfer both files to the evidence store.
- **Where:** `/evidence/IR-2026-0414-01/wst-ws-031-processes.csv` and `/evidence/IR-2026-0414-01/wst-ws-031-network.csv`
- **Hash:** `sha256sum /evidence/IR-2026-0414-01/wst-ws-031-processes.csv /evidence/IR-2026-0414-01/wst-ws-031-network.csv` — append both hashes to `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`.
- **Ordering:** Capture immediately after memory and before terminating suspicious processes or isolating the network, if safe, because termination and isolation may destroy live-state evidence.

## 3. Full endpoint telemetry — previous 24 hours

- **What:** Unfiltered EDR/Wazuh JSONL telemetry for `WST-WS-031` from `2026-04-13T02:47:11Z` to `2026-04-14T02:47:11Z`.
- **How:** `cp /lab/materials/edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/edr_wst_ws_031_24h.jsonl`
- **Where:** `/evidence/IR-2026-0414-01/edr_wst_ws_031_24h.jsonl`
- **Hash:** `sha256sum /evidence/IR-2026-0414-01/edr_wst_ws_031_24h.jsonl` — append the result to `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`.
- **Ordering:** Export after volatile evidence capture and before retention or cleanup removes relevant endpoint events.

## 4. SIEM alert record

- **What:** Original JSON alert `A-20260414-9841`, including process tree, network connection, enrichment, and detection context.
- **How:** `cp /lab/materials/alert_A-20260414-9841.json /evidence/IR-2026-0414-01/alert_A-20260414-9841.json`
- **Where:** `/evidence/IR-2026-0414-01/alert_A-20260414-9841.json`
- **Hash:** `sha256sum /evidence/IR-2026-0414-9841/alert_A-20260414-9841.json` — append the result to `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`.
- **Ordering:** Preserve early to prevent loss through SIEM retention or modification; do not delay volatile memory capture to do so.

## 5. Proxy and DNS logs

- **What:** Proxy records for `dmarsh` and DNS records associated with `WST-WS-031` (`10.42.118.31`) covering the same 24-hour UTC window.
- **How:** `cp /lab/materials/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_24h_dmarsh.log`; export DNS records from the approved resolver or SIEM for the same time window and source IP.
- **Where:** `/evidence/IR-2026-0414-01/proxy_24h_dmarsh.log` and `/evidence/IR-2026-0414-01/dns_24h_wst-ws-031.jsonl`
- **Hash:** `sha256sum /evidence/IR-2026-0414-01/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/dns_24h_wst-ws-031.jsonl` — append both hashes to `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`.
- **Ordering:** Preserve before log retention expires or containment changes the surrounding network evidence. Urgent containment takes priority if harm is ongoing.

## 6. Authentication events — Active Directory and Azure AD

- **What:** Successful and failed authentication, sign-in, and relevant audit events for `MEDDEFENSE\dmarsh` and `dmarsh@meddefense.local` covering the previous 24 hours.
- **How:** `cp /lab/materials/auth_24h_dmarsh.json /evidence/IR-2026-0414-01/auth_24h_dmarsh.json`; verify that the file includes both on-premises Active Directory and Azure AD/Microsoft Entra ID. Export missing sources separately using approved administrative tools.
- **Where:** `/evidence/IR-2026-0414-01/auth_24h_dmarsh.json`, plus separate raw AD or Entra ID exports if required.
- **Hash:** `sha256sum /evidence/IR-2026-0414-01/auth_24h_dmarsh.json` — append the result to `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`; hash each additional export separately.
- **Ordering:** Preserve before retention expires and, where feasible, before account disablement, password reset, or token revocation. Immediately contain active credential abuse if necessary.

## 7. Hash manifest and verification

- **What:** SHA-256 integrity records for every acquired artifact.
- **How:** Append each actual hash, relative path, UTC capture time, and operator to `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`. Maintain `SHA256SUMS` with the original hash and relative filename for each artifact.
- **Where:** `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt` and `/evidence/IR-2026-0414-01/SHA256SUMS`
- **Hash:** `cd /evidence/IR-2026-0414-01 && sha256sum -c SHA256SUMS`
- **Ordering:** Verify after acquisition and again before handoff. Compare against original capture hashes, not newly generated replacement values. Investigate mismatches, preserve affected files, and append an `OBSERVATION` to the incident timeline. Hash the finalized manifest separately.