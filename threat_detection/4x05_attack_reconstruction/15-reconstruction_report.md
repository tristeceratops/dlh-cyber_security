# HEALTHBANE / MedDefense Health Systems
## Module 4 Attack Reconstruction Report

**Scope:** T0, T5–T12 reconstruction evidence, with remediation synthesized from demonstrated findings.

## 1. Executive Summary

### What happened
HEALTHBANE began with a phishing campaign on 14 April 2026. A user on `WS-RECV-03` opened a malicious MedDefense password-reset message and submitted credentials to an attacker-controlled portal. On 15 April the host downloaded `svchost_update.exe` from `185.220.101.45`, established encrypted C2 beaconing at roughly five-minute intervals, and later maintained persistence through HealthSync artifacts. The attacker obtained access to service-account credentials, used PsExec, WMI and PowerShell remoting to move into production systems, accessed the `health_records` database, staged query results, cleared Windows event logs, and transmitted staged data to the primary C2. Reconstruction also identified a secondary C2, scheduled-task persistence, a Defender exclusion, LSASS access, and additional anti-forensic activity.

### How far the attacker got
`WS-RECV-03` was the confirmed pivot host. Confirmed lateral activity reached `SRV-HEALTH-DB`, `SRV-INS-DB`, and `SRV-DC-01`. The strongest data-access evidence is for `SRV-HEALTH-DB`: the malicious PowerShell workflow queried `health_records`, wrote results to CSV, compressed them, and moved archives to `C:\Users\Public\Tmp`. The database contains about 47,000 active patient records. Recovered staging files total approximately 34.4 MB, and firewall bursts to `185.220.101.45:443` total exactly 34,441,660 bytes, matching the reported staging volume. This confirms transmission of staged data, but does not prove that every database record was included.

### How it was stopped
Initial phishing and PCAP investigations established entry and C2. The 4x04 proactive hunt then correlated anomalous PsExec, WMI, PowerShell remoting, LSASS access and service-account authentication from `WS-RECV-03`. Memory, disk and firewall analysis in 4x05 connected persistence, data collection, staging, secondary C2, log clearing and exfiltration. `WS-RECV-03` was isolated and forensic acquisition followed.

### What happens next
Immediately rotate and restrict `svc_healthsync` and other potentially exposed credentials; eradicate persistence and malware; block all known C2 infrastructure; validate affected servers; review PHI/database access; restore trustworthy centralized logging; and hunt for the same tradecraft across the environment. Privacy/legal teams should perform the formal HIPAA breach assessment.

### Key metrics

| Metric | Result |
|---|---:|
| Credential submission | 2026-04-14 13:18:42Z |
| First C2 beacon | 2026-04-15 08:51:38Z |
| First confirmed lateral movement | 2026-05-06 02:12 CDT |
| Breakout time | ~21d 12h 54m |
| Containment used for metric | 2026-05-15 13:42 CDT |
| Approx. dwell time | ~31d 5h 24m |
| Recovered staging volume | 34,441,660 bytes (~34.4 MB) |
| Final confirmed ATT&CK coverage | 28/29 = 96% |

> **Date caveat:** supplied sources conflict on containment chronology: some material uses 18 May, while 4x04 and the asset inventory place isolation on 15 May. This report uses the 15 May response timestamp and preserves the conflict as a limitation.

## 2. Methodology

### Evidence sources

- T0 evidence inventory and investigation chronology.
- 4x00 phishing summary.
- 4x01 48-hour PCAP/network timeline.
- 4x02 ATT&CK baseline: `reference/attck_navigator_80pct.json`.
- 4x04 proactive hunt findings.
- 4x05 memory artifacts and IOC master data.
- 4x05 disk artifacts, Prefetch, scheduled-task, registry and NTFS evidence.
- 4x05 firewall sessions and transfer-volume evidence.
- `reference/meddefense_asset_inventory.txt`.
- T5–T12 reconstruction outputs.

### Analytical approach

The reconstruction used cross-evidence correlation by host, account, timestamp, process, destination, artifact and ATT&CK technique. Events were placed on a unified chronology and assessed as **confirmed**, **probable**, or **possible** according to the strength and independence of supporting evidence. Direct forensic evidence was preferred over inference from a single telemetry source.

### Limitations and assumptions

- April PCAP coverage ended on 16 April; later network visibility depends heavily on firewall evidence.
- Endpoint telemetry was incomplete before the proactive hunt.
- Full memory/disk acquisition was available for `WS-RECV-03`, not every destination server.
- Exact records inside transmitted archives cannot be reconstructed from size alone.
- Insurance database access is confirmed at the host/lateral level, but direct query evidence was not recovered.
- DC access included `Get-ADUser`; no supplied evidence proves `NTDS.dit` acquisition.
- Disk artifacts contain February timestamps that conflict with the broader May chronology.
- The ATT&CK JSON metadata says 23 observed / 3 inferred / 3 not covered, while its actual 29-entry array contains 22 score-3, 3 score-2 and 4 score-0 entries. The underlying technique list is used for final counting.

## 3. Attack Reconstruction

### Stage 1 — Initial Access: Phishing

**Evidence:** E1 impersonated MedDefense IT; SPF/DMARC failed and DKIM was absent. Diane Marsh on `WS-RECV-03` opened the link at `2026-04-14 13:18:05Z` and submitted credentials at `13:18:42Z`. PCAP independently recorded DNS, TLS and the `/collect.php` credential POST.

**ATT&CK:** T1566.001, T1566.002, T1204.002, T1078.

**Confidence:** **CONFIRMED**.

### Stage 2 — C2 Establishment

**Evidence:** `update.healthbane-c2.net` resolved to `185.220.101.45`; `svchost_update.exe` was downloaded at 08:51:11Z; first C2 beacon occurred at 08:51:38Z; subsequent beacons repeated about every 300 ±10 seconds. C2 used TLS 1.2, SNI `sync.healthbane-c2.net`, POST `/api/v1/checkin`, and RC4-wrapped JSON. Firewall evidence recorded 3,958 primary-C2 sessions and 80,967,579 outbound bytes. Secondary C2 `203.0.113.47:8443` first appeared in firewall evidence on 7 May.

**ATT&CK:** T1071.001, T1573.001, T1105, T1071.004, T1571.

**Confidence:** **CONFIRMED** for primary and secondary C2. DNS exfiltration beyond test traffic was not confirmed.

### Stage 3 — Malware Deployment

**Evidence:** Memory found `svchost_update.exe` under the HealthSync path, with an in-memory Stage 2 RAT matching the known sample, an RWX region and the `HealthSyncSingleton-h$lthb4n3` mutex. Hidden encoded PowerShell referenced `sync_healthdata.ps1`. A scheduled task named `HealthSync Update Service` executed encoded PowerShell daily at 02:00. A Defender exclusion covered `C:\Windows\Temp`. The PowerShell workflow queried the health database, generated CSV results, compressed them and moved archives to `C:\Users\Public\Tmp`.

**ATT&CK:** T1059.001, T1547.001, T1053.005, T1055, T1027, T1027.010, T1140, T1562.001, T1070.001.

**Confidence:** **CONFIRMED** for malware execution, process injection, scheduled-task persistence, defense impairment and log clearing. Memory and disk evidence conflict over whether the HKCU Run key was present; both findings are retained.

### Stage 4 — Lateral Movement and Data Staging

**Evidence:** 4x04 identified six PsExec, five WMI, four PSRemoting, two LSASS and six unauthorized `svc_healthsync` authentication events from `WS-RECV-03`. Targets included `SRV-HEALTH-DB`, `SRV-INS-DB` and `SRV-DC-01`. Recovered files were `query_results.csv` (8.4 MB), `staging_export_001.zip` (14.2 MB), and `staging_export_002.zip` (11.8 MB). Firewall bursts of 14,219,484 + 11,802,944 + 8,419,232 bytes equal 34,441,660 bytes, matching the reported staging volume.

**ATT&CK:** T1003.001, T1021.002, T1021.006, T1047, T1550.002, T1005, T1074.001, T1560.001, T1041, T1078.002.

**Confidence:** **CONFIRMED** for lateral movement, credential access, health-record collection, staging, archive creation and transmission. Insurance data exposure is **PROBABLE** at content level.

## 4. Unified Timeline

| Time | Event | Source | Confidence |
|---|---|---|---|
| Apr 14 13:14:22Z | Malicious phishing email arrives | 4x01 | Confirmed |
| Apr 14 13:18:05Z | User opens link | 4x00/4x01 | Confirmed |
| Apr 14 13:18:42Z | Credentials submitted | 4x00/4x01 | Confirmed |
| Apr 15 08:51:09Z | C2 DNS resolution | 4x01 | Confirmed |
| Apr 15 08:51:11Z | Payload download | 4x01 | Confirmed |
| Apr 15 08:51:38Z | First C2 beacon | 4x01 | Confirmed |
| May 5 03:22 CDT | LSASS access #1 | 4x04 | Confirmed |
| May 6 02:12 CDT | First lateral movement to health DB | 4x04 | Confirmed |
| May 7 06:48:11Z | Secondary C2 first observed | Firewall | Confirmed |
| May 8 | Exfil burst #1 | Firewall | Confirmed |
| May 9 03:40 CDT | Lateral movement to insurance DB | 4x04 | Confirmed |
| May 11 | Exfil burst #2 | Firewall | Confirmed |
| May 12 02:45 CDT | LSASS access #2 | 4x04 | Confirmed |
| May 13 01:56 CDT | Lateral movement to DC | 4x04 | Confirmed |
| May 13 | Exfil burst #3 | Firewall | Confirmed |
| May 15 13:42 CDT | WS-RECV-03 isolated | 4x04/inventory | Confirmed; date conflict noted |
| May 15 14:18 CDT | Memory capture | 4x04 | Confirmed |
| May 15 19:45 CDT | Disk imaging | 4x04 | Confirmed |

### Temporal metrics

- Initial access to first C2: ~19h 33m.
- Initial access to first confirmed lateral movement: ~21d 12h 54m.
- Initial access to containment: ~31d 5h 24m using 15 May.
- Primary C2 persisted into the May observation period.
- Secondary C2 appeared on 7 May.

### Identified gaps

1. No continuous PCAP after 16 April.
2. Limited endpoint telemetry before proactive hunting.
3. No complete forensic acquisition from destination servers.
4. Exact contents of staged archives are not fully known.
5. Secondary-C2 protocol/content remains incompletely characterized.
6. Persistence mechanism conflict remains unresolved.
7. February disk timestamps do not align with the May chronology.

## 5. ATT&CK Analysis

### Final technique inventory

The original ATT&CK baseline contains **29 techniques**. Four previously uncovered techniques became confirmed in 4x05: T1053.005, T1074.001, T1560.001 and T1070.001. Three additional techniques were identified outside the original baseline: T1571, T1055 and T1562.001.

| Technique | Final assessment |
|---|---|
| T1566.001 | Confirmed |
| T1566.002 | Confirmed |
| T1204.002 | Confirmed |
| T1059.001 | Confirmed |
| T1059.005 | Confirmed |
| T1547.001 | Confirmed |
| T1071.001 | Confirmed |
| T1071.004 | Confirmed capability/test traffic |
| T1573.001 | Confirmed |
| T1027 | Confirmed |
| T1027.010 | Confirmed |
| T1140 | Confirmed |
| T1105 | Confirmed |
| T1041 | Confirmed |
| T1048.003 | **Probable** |
| T1005 | Confirmed |
| T1583.001 | Confirmed |
| T1003.001 | Confirmed |
| T1021.002 | Confirmed |
| T1021.006 | Confirmed |
| T1047 | Confirmed |
| T1078 | Confirmed |
| T1078.002 | Confirmed |
| T1550.002 | Confirmed |
| T1112 | Confirmed |
| T1053.005 | Confirmed — new in 4x05 |
| T1074.001 | Confirmed — new in 4x05 |
| T1560.001 | Confirmed — new in 4x05 |
| T1070.001 | Confirmed — new in 4x05 |

### Coverage evolution

**40% → 55% → 80% → 96%**.

The final conservative metric is **28/29 confirmed (96%)**, with T1048.003 remaining probable. If probable evidence is counted as mapped/evidence-supported, all 29 baseline techniques are addressed.

### Gap and blind-spot assessment

The principal remaining ATT&CK gap is T1048.003. The more important operational blind spots were incomplete endpoint telemetry, limited destination-server forensics, lack of continuous network capture, weak database-level attribution, local log clearing, and investigations that did not initially connect identity, endpoint, network and data-access evidence.

## 6. Impact Assessment

| Asset/data | Assessment | Basis |
|---|---|---|
| WS-RECV-03 | Confirmed compromised | Malware, persistence, C2, credential access |
| SRV-HEALTH-DB | **Confirmed access/data collection** | `health_records` query + staged results |
| SRV-INS-DB | **Probable exposure** | Confirmed lateral movement; no recovered query result |
| SRV-DC-01 | **Possible directory-data exposure** | Remote access + `Get-ADUser`; no NTDS evidence |
| SRV-FILE-01 | No direct access established | No supporting lateral chain |
| Patient PHI | **Confirmed unauthorized access; transmission of staged data confirmed** | DB query + staging + firewall transfer |
| HR/employee records | Not established | No evidence of HR access |
| Backup repository | Not established | No evidence of access |

### Exfiltration determination

Exfiltration is **confirmed** for the recovered staging volume. Firewall bursts to `185.220.101.45:443` total 34,441,660 bytes, exactly matching the reported recovered staging volume. The evidence does not establish the exact patient records in those archives.

### Regulatory implications

The evidence establishes unauthorized access to PHI and supports transmission of staged data. The incident should therefore be treated as a **likely HIPAA breach-notification event pending formal legal/privacy risk assessment**. The approximately 47,000 active patient records define the population of the primary affected database, not proof that all 47,000 were exfiltrated.

## 7. Defensive Posture Evaluation

### What worked

- Phishing analysis identified the compromised user and malicious infrastructure.
- PCAP preserved initial C2 details.
- Credential reset/revocation reduced continued use of the phished identity.
- Proactive hunting exposed lateral movement and credential theft.
- Memory/disk acquisition preserved persistence, staging and anti-forensic evidence.
- Firewall records bridged the network-visibility gap and established exfiltration.
- Cross-evidence correlation ultimately produced the full attack chain.

### What failed

- Endpoint visibility was insufficient to connect the compromise to later movement in real time.
- Investigations initially lacked a unified identity/endpoint/network/database view.
- `svc_healthsync` could be abused from an unauthorized workstation.
- Off-hours remote administration from a records workstation was not blocked early.
- Local event logs could be cleared.
- Defender exclusions could be modified on the compromised host.
- Database access lacked sufficient record/query-level attribution.
- Secondary C2 was absent from the original PCAP window.

### Structural lessons

The principal weakness was not one missing control; it was the absence of continuous correlation across control planes. The attacker moved through phishing, endpoint malware, stolen credentials, remote administration, database access, staging and exfiltration while individual controls saw only fragments.

## 8. Remediation Plan

### Immediate

1. Rotate `svc_healthsync` and all potentially exposed credentials; invalidate sessions/tokens.
2. Remove HealthSync scheduled-task/Run-key persistence and malicious binaries/scripts.
3. Remove the unauthorized Defender exclusion and verify endpoint protection integrity.
4. Block `185.220.101.45`, `203.0.113.47`, malicious domains and related indicators.
5. Validate `SRV-HEALTH-DB`, `SRV-INS-DB` and `SRV-DC-01` for persistence and unauthorized access.
6. Preserve and centralize logs before additional cleanup.

### Short term

- Enforce approved-source restrictions for service accounts.
- Reduce/disable NTLM where feasible for sensitive paths.
- Alert on PsExec/WMI/WinRM from workstation VLANs.
- Centralize Windows security logs so local clearing cannot erase the authoritative record.
- Protect Defender configuration against unauthorized exclusions.
- Enable database auditing for sensitive PHI queries.
- Retain firewall/proxy telemetry across the full investigation horizon.

### Medium term

- Build detections correlating phishing, process execution, credential access, remote administration, database access, staging and exfiltration.
- Establish a dedicated detection for the `svc_healthsync => SRV-HEALTH-DB` critical access path.
- Deploy comprehensive endpoint telemetry to records, billing and administrative VLANs.
- Detect large archive creation in temporary/public directories followed by outbound transfer.
- Establish recurring proactive hunts against high-impact ATT&CK techniques.
- Formalize forensic-readiness procedures for memory, disk, centralized logs, network telemetry, clock synchronization and evidence retention.

### Prioritization rationale

Priorities follow the demonstrated attack path: **identity compromise → persistence → credential theft → lateral movement → PHI access → staging → exfiltration**. Controls protecting `SRV-HEALTH-DB` and breaking this chain earliest receive highest priority.

## 9. Conclusions

Module 4 demonstrated the gap between **detection and understanding**. Phishing analysis found the entry point, PCAP found C2, threat hunting found lateral movement and credential access, memory found malware behavior, disk found staging and anti-forensics, and firewall evidence established exfiltration. Reconstruction was required to show that these were phases of one intrusion.

Investigating in pieces creates blind spots because each evidence source answers a different question while the attacker crosses all of those boundaries. A service-account login can resemble administration; C2 can resemble routine TLS; staging can look like temporary files; and database access can be invisible without application-level auditing. Reconstruction exposes the causal chain.

Proactive hunting and forensic readiness are therefore operational necessities, not optional enhancements. They shorten the time between suspicion, understanding, containment and defensible impact assessment.

Remaining unknowns include the exact records transmitted, whether insurance tables were queried, whether T1048.003 was actually used, the full protocol/content of the secondary C2, the exact relationship between scheduled-task and Run-key persistence, whether additional credentials were obtained, and the cause of the February/May timestamp discrepancy. Resolving these questions requires destination-server forensics, database audit logs, complete network history, additional endpoint telemetry and recovery of the original staged content where possible.

## 10. Appendices

### Appendix A — IOC Summary

| IOC | Type | Source | Status |
|---|---|---|---|
| `185.220.101.45:443` | Primary C2 | 4x01/4x05 | Known / confirmed |
| `203.0.113.47:8443` | Secondary C2 | 4x05 | **New / confirmed** |
| `sync.healthbane-c2.net` | C2 domain | 4x01/memory | Known / confirmed |
| `update.healthbane-c2.net` | Update domain | 4x01 | Known / confirmed |
| `data-sync.healthbane-c2.net` | DNS test domain | 4x01 | Known / test |
| `91.219.236.117` | Phishing IP | 4x00/4x01 | Known |
| `45.142.214.108` | Phishing origin | 4x00/4x01 | Known |
| `no-reply@meddefense-portal.com` | Sender | 4x00 | Known |
| `benefits@meddefense-benefits.com` | Sender | 4x00 | Known |
| `no-reply@outlook-protection.com` | Sender | 4x00 | Known |
| `...\HealthSync\svchost_update.exe` | Malware | Memory | Known / confirmed |
| `HealthSyncSingleton-h$lthb4n3` | Mutex | Memory | Known / confirmed |
| `C:\Windows\Temp\debug_tool.exe` | Credential tool | Memory/disk/hunt | **New / confirmed** |
| `C:\Users\Public\Tmp\PsExec64.exe` | Lateral tool | Memory/disk/hunt | **New / confirmed** |
| `C:\Windows\Temp\out.dat` | LSASS output | 4x04/memory | Confirmed |
| `sync_healthdata.ps1` | Collection script | Memory | Confirmed |
| `HealthSync Update Service` | Scheduled task | Memory/disk | **New / confirmed** |
| `C:\Windows\Temp` | Defender exclusion | Memory | **New / confirmed** |
| `staging_export_001.zip` | Staged archive | Disk | **New / confirmed** |
| `staging_export_002.zip` | Staged archive | Disk | **New / confirmed** |
| `query_results.csv` | Query results | Disk | **New / confirmed** |
| `health_records` | Database | Memory/inventory | Confirmed target |
| `svc_healthsync` | Service account | 4x04/memory | Confirmed abused |

### Appendix B — Evidence Citation Index

| Citation | Evidence |
|---|---|
| T0 | Evidence inventory, chronology, reliability and gaps |
| 4x00 | Phishing investigation |
| 4x01 | PCAP, initial C2, payload transfer and beaconing |
| 4x02 | ATT&CK baseline Navigator layer |
| 4x03 | Malware/Stage 2 reference evidence |
| 4x04 | Proactive hunt: lateral movement, LSASS and service-account abuse |
| 4x05-memory | Processes, sockets, persistence, PowerShell and injection |
| 4x05-disk | Deleted staging, Prefetch, scheduled task, registry and log gap |
| 4x05-firewall | C2, secondary C2, cross-VLAN traffic and exfiltration |
| Asset inventory | `reference/meddefense_asset_inventory.txt` |
| T5 | Stage 1–2 reconstruction |
| T7 | Stage 4 reconstruction |
| T8 | Unified timeline |
| T9–T11 | ATT&CK reconstruction and coverage |
| T12 | Data exposure and regulatory assessment |
| T13/T14 | Not directly supplied in the provided corpus; remediation synthesized from demonstrated gaps |

### Appendix C — ATT&CK Navigator Layer Reference

**Source:** `reference/attck_navigator_80pct.json`

- Original baseline: 29 techniques.
- Actual underlying array: 22 score-3, 3 score-2, 4 score-0.
- 4x05 upgrades: T1053.005, T1074.001, T1560.001, T1070.001.
- Additional 4x05 techniques: T1571, T1055, T1562.001.
- Final: 28 confirmed / 1 probable within the original 29 = **96% confirmed coverage**.

> **Navigator metadata caveat:** the JSON metadata says 23 observed / 3 inferred / 3 not covered, which conflicts with the actual 29-entry technique array. The array is used for final counting.
