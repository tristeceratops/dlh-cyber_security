#!/bin/bash

set -u

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PREVIOUS="$BASE_DIR/4x05/previous_findings"
MEMORY="$BASE_DIR/1-memory_analysis_report.txt"
DISK="$BASE_DIR/2-disk_analysis.sh"
FIREWALL="$BASE_DIR/3-firewall_analysis.sh"
HUNT="$PREVIOUS/4x04_proactive_hunt.txt"

echo "================================================================"
echo "   ATTACK RECONSTRUCTION: Stage 4"
echo "   Lateral Movement, Data Staging, and Containment"
echo "================================================================"
echo

# ------------------------------------------------------------------
# LATERAL MOVEMENT
# ------------------------------------------------------------------

echo "LATERAL MOVEMENT CHAIN:"
echo

echo "  [2026-05-05 03:22 CDT] Credential access on WS-RECV-03"
echo "    Tool: debug_tool.exe"
echo "    Target: LSASS (PID 648)"
echo "    Access: 0x1010"
echo "    Output: C:\\Windows\\Temp\\out.dat"
echo "    Evidence: 4x04 H4 + IR memory"
echo "    Technique: T1003.001 LSASS Memory"
echo "    Confidence: CONVERGED"
echo

echo "  [2026-05-06 02:12 CDT] WS-RECV-03 -> SRV-HEALTH-DB"
echo "    Tool: PsExec64.exe"
echo "    Credential: svc_healthsync"
echo "    Additional activity: WMI + PowerShell Remoting"
echo "    Evidence: 4x04 H1/H2/H3 + IR evidence"
echo "    Technique: T1021.002 / T1047 / T1021.006"
echo "    Confidence: CONVERGED"
echo

echo "  [2026-05-09 03:40 CDT] WS-RECV-03 -> SRV-INS-DB"
echo "    Tool: PsExec64.exe"
echo "    Credential: svc_healthsync"
echo "    Additional activity: WMI + PowerShell Remoting"
echo "    Evidence: 4x04 H1/H2/H3"
echo "    Technique: T1021.002 / T1047 / T1021.006"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-05-13 01:56 CDT] WS-RECV-03 -> SRV-DC-01"
echo "    Tool: PsExec64.exe"
echo "    Credential: svc_healthsync"
echo "    Additional activity: PowerShell Remoting + Get-ADUser"
echo "    Evidence: 4x04 H1/H3"
echo "    Technique: T1021.002 / T1021.006"
echo "    Confidence: CONFIRMED"
echo

echo "  IR CORRELATION:"
echo "    Firewall evidence confirms cross-VLAN communication involving:"
echo "      10.10.20.30  SRV-HEALTH-DB"
echo "      10.10.20.31  SRV-INS-DB"
echo "      10.10.20.10  SRV-DC-01"
echo "    Source: WS-RECV-03 (10.10.3.21)"
echo "    Technique: T1021.002"
echo "    Confidence: CONVERGED"
echo

echo "  HUNT-MISSED ACTIVITY:"
echo "    IR evidence adds direct process-level evidence for:"
echo "      - scheduled-task persistence"
echo "      - secondary C2"
echo "      - data collection and staging"
echo "      - event-log clearing"
echo "    These were outside the original 4x04 lateral-movement hunt."
echo

# ------------------------------------------------------------------
# CREDENTIAL ACCESS
# ------------------------------------------------------------------

echo "CREDENTIAL ASSESSMENT:"
echo

echo "  [2026-05-05 03:22 CDT] LSASS access"
echo "    Process: debug_tool.exe"
echo "    Target: LSASS PID 648"
echo "    Access mask: 0x1010"
echo "    Result: credential-dumping activity"
echo "    Evidence: 4x04 H4 + IR memory"
echo "    Technique: T1003.001"
echo "    Confidence: CONVERGED"
echo

echo "  [2026-05-12 02:45 CDT] Second LSASS access"
echo "    Process: debug_tool.exe"
echo "    Target: LSASS PID 648"
echo "    Output: C:\\Windows\\Temp\\out.dat"
echo "    Evidence: 4x04 H4 + IR memory"
echo "    Technique: T1003.001"
echo "    Confidence: CONVERGED"
echo

echo "  Confirmed compromised account:"
echo "    svc_healthsync"
echo "      Type: service account"
echo "      Authentication: NTLM"
echo "      Source host: WS-RECV-03"
echo "      Targets: SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01"
echo

echo "  Additional credentials:"
echo "    IR evidence does not independently identify another"
echo "    confirmed compromised credential."
echo "    dmarsh was compromised during Stage 1, but the later"
echo "    Stage 4 pivot uses svc_healthsync."
echo

# ------------------------------------------------------------------
# DATA ACCESS / STAGING
# ------------------------------------------------------------------

echo "DATA ACCESS AND STAGING:"
echo

echo "  [Stage 4] Database access"
echo "    Source: WS-RECV-03"
echo "    Target: SRV-HEALTH-DB / health_records"
echo "    Evidence: IR memory recovered sync_healthdata.ps1"
echo "    Activity: query health_records and write CSV"
echo "    Technique: T1005"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-02-10 14:22] Query results created"
echo "    File: query_results.csv"
echo "    Size: 8.4 MB"
echo "    Location: C:\\Users\\Public\\Tmp\\"
echo "    Evidence: IR disk"
echo "    Technique: T1074.001 Local Data Staging"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-02-10 15:07] First staging archive"
echo "    File: staging_export_001.zip"
echo "    Size: 14.2 MB"
echo "    Location: C:\\Users\\Public\\Tmp\\"
echo "    Technique: T1560.001 Archive Collected Data"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-02-11 01:08] Second staging archive"
echo "    File: staging_export_002.zip"
echo "    Size: 11.8 MB"
echo "    Location: C:\\Users\\Public\\Tmp\\"
echo "    Technique: T1560.001 / T1074.001"
echo "    Confidence: CONFIRMED"
echo

echo "  STAGING FLOW:"
echo "    Database servers"
echo "        -> WS-RECV-03"
echo "        -> query_results.csv"
echo "        -> staging_export_001.zip"
echo "        -> staging_export_002.zip"
echo

echo "  Assessment:"
echo "    The recovered files are on WS-RECV-03, demonstrating"
echo "    local staging on the pivot host. The evidence supports"
echo "    database data being collected onto WS-RECV-03 before"
echo "    compression."
echo

echo "  EXFILTRATION:"
echo "    Firewall analysis identifies three outbound bursts:"
echo "      14,219,484 bytes"
echo "      11,802,944 bytes"
echo "       8,419,232 bytes"
echo "      ----------------"
echo "      34,441,660 bytes total"
echo
echo "    Recovered staging files total approximately 34.4 MB."
echo "    Assessment: network-correlated exfiltration."
echo "    Technique: T1041"
echo "    Confidence: CONVERGED"
echo

# ------------------------------------------------------------------
# PERSISTENCE / ANTI-FORENSICS
# ------------------------------------------------------------------

echo "PERSISTENCE AND OPERATIONAL SECURITY:"
echo

echo "  Scheduled Task:"
echo "    Name: HealthSync Update Service"
echo "    Trigger: 02:00 daily"
echo "    Action: powershell.exe -ExecutionPolicy Bypass -enc ..."
echo "    Evidence: IR memory + IR disk"
echo "    Technique: T1053.005"
echo "    Confidence: CONVERGED"
echo

echo "  Defense evasion:"
echo "    Defender exclusion: C:\\Windows\\Temp"
echo "    Evidence: IR memory"
echo "    Technique: T1562.001"
echo
echo "    Event-log clearing:"
echo "      wevtutil cl Security"
echo "      wevtutil cl Application"
echo "      wevtutil cl System"
echo "    Evidence: IR memory + disk log gap"
echo "    Technique: T1070.001"
echo
echo "  Operational security:"
echo "    - Off-hours execution"
echo "    - Service-account abuse"
echo "    - Non-standard PsExec copy"
echo "    - PowerShell encoded commands"
echo "    - Defender exclusion"
echo "    - Event-log clearing"
echo "    - Deleted staging files"
echo
echo "  Exposure point:"
echo "    The anomalous WS-RECV-03 PsExec/WMI/PSRemoting pattern"
echo "    violated the service-account baseline and triggered"
echo "    the 4x04 proactive hunt."
echo

# ------------------------------------------------------------------
# CONTAINMENT
# ------------------------------------------------------------------

echo "CONTAINMENT TIMELINE:"
echo

echo "  [2026-05-12 02:45 CDT] Second LSASS credential-dump event"
echo "    Evidence: 4x04 H4"
echo

echo "  [2026-05-13 01:56 CDT] PsExec pivot to SRV-DC-01"
echo "    Evidence: 4x04 H1/H3"
echo

echo "  [2026-05-18 09:00 CDT] 4x04 threat hunt initiated"
echo "    Trigger: HC3-004"
echo

echo "  [2026-05-18 17:30 CDT] Hunt escalation"
echo "    Evidence: 4x04"
echo

echo "  [2026-05-18 13:42 CDT] WS-RECV-03 isolated"
echo "    Evidence: IR collection timeline"
echo

echo "  [2026-05-18 14:18 CDT] Memory captured"
echo "    Evidence: IR collection timeline"
echo

echo "  [2026-05-18 19:45 CDT] Disk imaging completed"
echo "    Evidence: IR collection timeline"
echo

echo "  CONTAINMENT POINT:"
echo "    Isolation of WS-RECV-03 removed the attacker's primary"
echo "    pivot, credential-access, staging, and C2 host."
echo

echo "  IF NOT CONTAINED:"
echo "    The most likely next operation was continued transfer of"
echo "    staged archives through the established C2 channel."
echo "    Firewall evidence later correlates 34,441,660 bytes with"
echo "    the recovered staging archives."
echo "    Exact number of remaining sessions/time-to-exfiltration"
echo "    cannot be established from the supplied evidence."
echo

# ------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------

echo "STAGE 4 SUMMARY:"
echo "  Pivot host: WS-RECV-03"
echo "  Compromised service account: svc_healthsync"
echo "  Database targets: SRV-HEALTH-DB, SRV-INS-DB"
echo "  Domain controller: SRV-DC-01"
echo "  Credential access: T1003.001"
echo "  Lateral movement: T1021.002, T1021.006, T1047"
echo "  Data access: T1005"
echo "  Data staging: T1074.001"
echo "  Archive: T1560.001"
echo "  Exfiltration: T1041"
echo "  Persistence: T1053.005"
echo "  Defense evasion: T1562.001, T1070.001"
echo
echo "  Key finding:"
echo "    WS-RECV-03 was the central pivot. The attacker obtained"
echo "    svc_healthsync through LSASS access, moved to the health,"
echo "    insurance, and domain-controller systems, collected data"
echo "    back onto WS-RECV-03, compressed it, and subsequently"
echo "    generated firewall-correlated outbound transfer."
echo

echo "================================================================"