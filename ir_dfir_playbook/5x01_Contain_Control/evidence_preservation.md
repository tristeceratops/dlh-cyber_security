# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: `/evidence/IR-2026-0414-01/`  
Hash algorithm: SHA-256

**Host:** `WST-WS-031`  
**User:** `MEDDEFENSE\dmarsh`  
**Alert:** `A-20260414-9841`  
**UTC collection window:** `2026-04-13T02:47:11Z` to `2026-04-14T02:47:11Z`

**Prerequisite:** Review `evidence_store_init.sh` and verify the evidence store is initialized and access-controlled. The commands below assume approved collection tools and permissions. Confirm paths and tool syntax before execution. The initialization script and all referenced lab files must be available to the collecting analyst.

## 1. Volatile memory — WST-WS-031

- **What:** Full physical memory image.
- **How:**
  ```powershell
  .\winpmem_3.3.rc3.exe -o \\evidence\IR-2026-0414-01\wst-ws-031.mem
  ```
- **Where:** `/evidence/IR-2026-0414-01/wst-ws-031.mem`
- **Hash:**
  ```bash
  sha256sum /evidence/IR-2026-0414-01/wst-ws-031.mem
  ```
- **Ordering:** Acquire before killing processes, rebooting, or isolating the host when safely feasible. Memory contains volatile evidence that may be lost.

## 2. Process list and network connections

- **What:** Process IDs, parent PIDs, command lines, executable paths, and active TCP connections.
- **How:** Run elevated PowerShell on the endpoint:
  ```powershell
  Get-CimInstance Win32_Process |
    Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate |
    Export-Csv -NoTypeInformation C:\Temp\processes.csv

  Get-NetTCPConnection |
    Export-Csv -NoTypeInformation C:\Temp\network.csv
  ```
  Transfer both files to the approved evidence store.
- **Where:** `wst-ws-031-processes.csv`, `wst-ws-031-network.csv`
- **Hash:**
  ```bash
  sha256sum /evidence/IR-2026-0414-01/wst-ws-031-processes.csv /evidence/IR-2026-0414-01/wst-ws-031-network.csv
  ```
- **Ordering:** Capture immediately after memory and before terminating suspicious processes or isolating the network, if safe. These actions can destroy live-state evidence.

## 3. Endpoint telemetry — previous 24 hours

- **What:** Full EDR/Wazuh JSONL export for the host covering the specified UTC window.
- **How:**
  ```bash
  cp /lab/materials/edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/
  ```
  Verify the host and time range; preserve raw records without filtering.
- **Where:** `edr_wst_ws_031_24h.jsonl`
- **Hash:**
  ```bash
  sha256sum /evidence/IR-2026-0414-01/edr_wst_ws_031_24h.jsonl
  ```
- **Ordering:** Export before retention or cleanup removes relevant telemetry.

## 4. SIEM alert record

- **What:** Original JSON record for alert `A-20260414-9841`.
- **How:**
  ```bash
  cp /lab/materials/alert_A-20260414-9841.json /evidence/IR-2026-0414-01/
  ```
- **Where:** `alert_A-20260414-9841.json`
- **Hash:**
  ```bash
  sha256sum /evidence/IR-2026-0414-01/alert_A-20260414-9841.json
  ```
- **Ordering:** Preserve early to protect the original alert and enrichment from retention or modification.

## 5. Proxy and DNS logs

- **What:** Proxy logs for `dmarsh` and DNS records associated with `WST-WS-031` during the previous 24 hours.
- **How:**
  ```bash
  cp /lab/materials/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/
  ```
  Export DNS logs from the approved resolver/SIEM for the same UTC window and source host/IP.
- **Where:** `proxy_24h_dmarsh.log`, `dns_24h_wst-ws-031.jsonl`
- **Hash:**
  ```bash
  sha256sum /evidence/IR-2026-0414-01/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/dns_24h_wst-ws-031.jsonl
  ```
- **Ordering:** Preserve before log retention expires or blocking and cleanup alter available context.

## 6. Authentication events — AD and Azure AD

- **What:** Successful and failed authentication, sign-in, and relevant audit events for `MEDDEFENSE\dmarsh` and `dmarsh@meddefense.local`.
- **How:**
  ```bash
  cp /lab/materials/auth_24h_dmarsh.json /evidence/IR-2026-0414-01/
  ```
  Verify that the export includes both on-premises Active Directory and Azure AD/Microsoft Entra ID. Export missing sources separately using approved administrative tools.
- **Where:** `auth_24h_dmarsh.json` and any additional raw AD/Entra exports.
- **Hash:**
  ```bash
  sha256sum /evidence/IR-2026-0414-01/auth_24h_dmarsh.json
  ```
  Hash every additional export separately.
- **Ordering:** Preserve before log retention expires and, where feasible, before account resets or token revocation. Contain active credential abuse immediately if necessary.

## 7. Hash manifest and verification

- **What:** SHA-256 hash for every captured artifact.
- **How:** Append each actual hash, relative path, UTC time, and operator to:
  `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`

  Example:
  ```bash
  cd /evidence/IR-2026-0414-01
  sha256sum wst-ws-031.mem
  ```
  Record the actual output in the manifest. Repeat for every captured file. Never invent hashes or overwrite earlier evidence.

## 8. Final verification

- Re-hash every artifact and compare it against the original recorded SHA-256 value.
- Use a checksum file containing the original hashes:
  ```bash
  sha256sum -c SHA256SUMS
  ```
- Confirm all expected files exist and investigate every mismatch.
- Record the verification time, operator, results, and any mismatch.
- Append any integrity failure to the incident timeline as an `OBSERVATION`. Preserve mismatched evidence; never silently replace it.
- Hash the finalized manifest separately and retain that hash with the incident handoff records.

**Important:** Do not delay urgent containment to preserve volatile evidence if doing so would allow ongoing harm. Document any change in acquisition order and the reason.