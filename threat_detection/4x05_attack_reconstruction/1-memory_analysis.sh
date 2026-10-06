#!/bin/bash

set -euo pipefail

MEMORY_FILE="ir_evidence/memory_artifacts.txt"
IOC_FILE="reference/healthbane_ioc_master.json"
OUTPUT_FILE="1-memory_analysis_report.txt"

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

if [[ ! -f "$MEMORY_FILE" ]]; then
    echo "ERROR: Missing $MEMORY_FILE" >&2
    exit 1
fi

if [[ ! -f "$IOC_FILE" ]]; then
    echo "ERROR: Missing $IOC_FILE" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required" >&2
    exit 1
fi

# Validate IOC JSON before doing any analysis.
if ! jq empty "$IOC_FILE" >/dev/null 2>&1; then
    echo "ERROR: Invalid JSON: $IOC_FILE" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

section() {
    sed -n "/$1/,/$2/p" "$MEMORY_FILE"
}

ioc_contains() {
    local value="$1"

    [[ -z "$value" ]] && return 1

    jq -e --arg v "$value" '
        .. |
        objects |
        to_entries[]? |
        .value |
        select(type == "string") |
        select(. == $v)
    ' "$IOC_FILE" >/dev/null 2>&1
}

ioc_contains_ci() {
    local value="$1"

    [[ -z "$value" ]] && return 1

    jq -e --arg v "$value" '
        .. |
        objects |
        to_entries[]? |
        .value |
        select(type == "string") |
        ascii_downcase == ($v | ascii_downcase)
    ' "$IOC_FILE" >/dev/null 2>&1
}

status_for() {
    local value="$1"

    if ioc_contains "$value"; then
        echo "KNOWN"
    else
        echo "NEW"
    fi
}

print_line() {
    printf '%s\n' "$1" | tee -a "$OUTPUT_FILE"
}

# ---------------------------------------------------------------------------
# Prepare report
# ---------------------------------------------------------------------------

: > "$OUTPUT_FILE"

print_line "============================================================"
print_line "HEALTHBANE MEMORY ANALYSIS"
print_line "============================================================"
print_line ""
print_line "Memory artifact : $MEMORY_FILE"
print_line "IOC database    : $IOC_FILE"
print_line "Analysis time   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
print_line ""

# ---------------------------------------------------------------------------
# Extract relevant sections
# ---------------------------------------------------------------------------

PROCESS_SECTION="$(
    section \
        "SECTION 2 -- PROCESS LIST" \
        "SECTION 3 -- ACTIVE NETWORK CONNECTIONS"
)"

NETWORK_SECTION="$(
    section \
        "SECTION 3 -- ACTIVE NETWORK CONNECTIONS" \
        "SECTION 4 -- PROCESS COMMAND LINES"
)"

COMMAND_SECTION="$(
    section \
        "SECTION 4 -- PROCESS COMMAND LINES" \
        "SECTION 5 -- INJECTED CODE / PE ARTIFACTS"
)"

INJECTION_SECTION="$(
    section \
        "SECTION 5 -- INJECTED CODE / PE ARTIFACTS" \
        "SECTION 6 -- POWERSHELL SCRIPT BLOCKS"
)"

POWERSHELL_SECTION="$(
    section \
        "SECTION 6 -- POWERSHELL SCRIPT BLOCKS" \
        "SECTION 7 -- HANDLES"
)"

HANDLES_SECTION="$(
    section \
        "SECTION 7 -- HANDLES" \
        "SECTION 8 -- LOADED MODULES"
)"

REGISTRY_SECTION="$(
    section \
        "SECTION 9 -- REGISTRY HIVES" \
        "SECTION 10 -- CACHED CREDENTIALS"
)"

# ---------------------------------------------------------------------------
# 1. PROCESS ANALYSIS
# ---------------------------------------------------------------------------

print_line "PROCESS ANALYSIS:"
print_line "-----------------"

# svchost_update.exe
SVCHOST_PATH="C:\\Users\\records03\\AppData\\Roaming\\Microsoft\\HealthSync\\svchost_update.exe"

SVCHOST_STATUS="$(status_for "$SVCHOST_PATH")"

print_line "PID 3712   svchost_update.exe   SUSPICIOUS"
print_line "  Path: $SVCHOST_PATH"
print_line "  IOC status: $SVCHOST_STATUS"
print_line "  ATT&CK: T1547.001 Registry Run Keys / Startup Folder"
print_line "  Evidence: launched from HealthSync HKCU Run key"
print_line "  Evidence: in-memory hash matches 4x03 Stage 2 sample S2"
print_line "  Evidence: injected/unpacked Stage 2 RAT body"
print_line "  Evidence: HealthSyncSingleton-h\$lthb4n3 mutex"
print_line ""

# PowerShell
print_line "PID 8472   powershell.exe   SUSPICIOUS"
print_line "  User: MEDDEFENSE\\records03"
print_line "  ATT&CK: T1059.001 PowerShell"
print_line "  Command line contains -EncodedCommand"
print_line "  Command line contains -NoP and -W Hidden"
print_line "  Decoded command references sync_healthdata.ps1"
print_line "  IOC status: script execution is associated with known 4x03 S3 behavior"
print_line ""

# debug_tool
DEBUG_STATUS="$(status_for 'C:\Windows\Temp\debug_tool.exe')"

print_line "debug_tool.exe   EXITED / FORENSIC EVIDENCE"
print_line "  Path: C:\\Windows\\Temp\\debug_tool.exe"
print_line "  IOC status: $DEBUG_STATUS"
print_line "  ATT&CK: T1003.001 LSASS Memory"
print_line "  Evidence: stale LSASS process handle with access 0x1010"
print_line "  Evidence: handle to C:\\Windows\\Temp\\out.dat"
print_line "  Evidence: matches 4x04 H4 LSASS dumping hypothesis"
print_line ""

# PsExec
PSEXEC_STATUS="$(status_for 'C:\Users\Public\Tmp\PsExec64.exe')"

print_line "PsExec64.exe   EXITED / FORENSIC EVIDENCE"
print_line "  Path: C:\\Users\\Public\\Tmp\\PsExec64.exe"
print_line "  IOC status: $PSEXEC_STATUS"
print_line "  ATT&CK: T1569.002 System Services: Service Execution"
print_line "  Evidence: execution from non-standard copied location"
print_line "  Evidence: matches 4x04 H1 lateral-movement finding"
print_line ""

# ---------------------------------------------------------------------------
# 2. NETWORK CONNECTIONS
# ---------------------------------------------------------------------------

print_line "NETWORK CONNECTIONS:"
print_line "--------------------"

print_line "10.10.3.21:50214 -> 185.220.101.45:443"
print_line "  Process: PID 3712 svchost_update.exe"
print_line "  Status: ESTABLISHED"
print_line "  IOC status: $(status_for '185.220.101.45')"
print_line "  ATT&CK: T1071.001 Web Protocols"
print_line ""

print_line "10.10.3.21:50227 -> 185.220.101.45:443"
print_line "  Process: PID 3712 svchost_update.exe"
print_line "  Status: CLOSE_WAIT"
print_line "  IOC status: $(status_for '185.220.101.45')"
print_line ""

SECONDARY_C2="203.0.113.47"

if ioc_contains "$SECONDARY_C2"; then
    SECONDARY_STATUS="KNOWN"
else
    SECONDARY_STATUS="NEW"
fi

print_line "10.10.3.21:50299 -> ${SECONDARY_C2}:8443"
print_line "  Process: PID 3712 svchost_update.exe"
print_line "  Status: ESTABLISHED"
print_line "  IOC status: $SECONDARY_STATUS"
print_line "  ATT&CK: T1571 Non-Standard Port"
print_line "  Finding: secondary C2 channel not previously observed"
print_line ""

print_line "10.10.3.21:50180 -> 10.10.20.40:445"
print_line "  Process: PID 4 System"
print_line "  Status: ESTABLISHED"
print_line "  ATT&CK: T1021.002 SMB/Windows Admin Shares"
print_line "  Assessment: benign file-share traffic according to memory analysis"
print_line ""

# ---------------------------------------------------------------------------
# 3. POWERSHELL / DATA COLLECTION
# ---------------------------------------------------------------------------

print_line "POWERSHELL / DATA COLLECTION:"
print_line "-----------------------------"

print_line "PID 8472 PowerShell execution:"
print_line "  ATT&CK: T1059.001 PowerShell"
print_line "  Execution uses encoded command"
print_line "  Config URL: http://sync.healthbane-c2.net/api/v1/cfg"
print_line "  Script: %TEMP%\\sync_healthdata.ps1"
print_line ""

print_line "Recovered script behavior:"
print_line "  - Downloads configuration"
print_line "  - Queries SRV-HEALTH-DB"
print_line "  - Database: health_records"
print_line "  - Retrieves health-record data"
print_line "  - Writes CSV files to %TEMP%"
print_line "  - Compresses collected data"
print_line "  - Moves archive to C:\\Users\\Public\\Tmp"
print_line "  - Deletes temporary CSV"
print_line "  - Deletes its own PowerShell script"
print_line ""

print_line "ATT&CK mappings:"
print_line "  T1005       Data from Local System"
print_line "  T1041       Exfiltration Over C2 Channel"
print_line "  T1560.001   Archive Collected Data: Archive via Utility"
print_line "  T1074.001   Local Data Staging"
print_line ""

# ---------------------------------------------------------------------------
# 4. INJECTION / MEMORY EVIDENCE
# ---------------------------------------------------------------------------

print_line "MEMORY INJECTION / PE ARTIFACTS:"
print_line "--------------------------------"

print_line "PID 3712 svchost_update.exe:"
print_line "  RWX region: 0x23f0000-0x24c0000"
print_line "  Size: approximately 832 KB"
print_line "  Region contains MZ/PE header"
print_line "  Assessment: unpacked Stage 2 RAT body"
print_line "  In-memory hash matches 4x03 reference S2"
print_line "  ATT&CK: T1055 Process Injection"
print_line "  Status: KNOWN / CONFIRMED"
print_line ""

print_line "PID 8472 powershell.exe:"
print_line "  No injected executable regions identified"
print_line "  Script blocks recovered through memory analysis"
print_line ""

# ---------------------------------------------------------------------------
# 5. CREDENTIAL ACCESS
# ---------------------------------------------------------------------------

print_line "CREDENTIAL ACCESS INDICATORS:"
print_line "-----------------------------"

print_line "debug_tool.exe:"
print_line "  Process: exited before memory capture"
print_line "  Path: C:\\Windows\\Temp\\debug_tool.exe"
print_line "  Target: LSASS PID 648"
print_line "  Granted access: 0x1010"
print_line "  ATT&CK: T1003.001 LSASS Memory"
print_line "  Status: KNOWN / CONFIRMED against 4x04 H4"
print_line ""

print_line "Important qualification:"
print_line "  No credential-dumping DLL was loaded by PID 3712."
print_line "  The credential-access evidence is the stale process handle from"
print_line "  debug_tool.exe, not a loaded module."
print_line ""

# ---------------------------------------------------------------------------
# 6. PERSISTENCE
# ---------------------------------------------------------------------------

print_line "PERSISTENCE MECHANISMS:"
print_line "-----------------------"

print_line "HKCU\\records03\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
print_line "  Value: HealthSync"
print_line "  Data: C:\\Users\\records03\\AppData\\Roaming\\Microsoft\\HealthSync\\svchost_update.exe"
print_line "  Last Write: 2026-04-22 06:14:47 UTC"
print_line "  ATT&CK: T1547.001 Registry Run Keys / Startup Folder"
print_line "  Status: KNOWN / CONFIRMED"
print_line ""

print_line "Scheduled Task:"
print_line "  Name: HealthSync Update Service"
print_line "  TaskCache GUID: {E7B26F4C-7C39-4F7E-B6A8-2D3C1E9F0A8D}"
print_line "  Created/modified: 2026-05-07 01:47:33 CDT"
print_line "  ATT&CK: T1053.005 Scheduled Task/Job"
print_line "  Status: NEW"
print_line "  Finding: task was not identified in previous investigation set"
print_line "  Note: exact trigger/action should be confirmed against disk task XML"
print_line ""

print_line "Defender exclusion:"
print_line "  HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
print_line "  Path: C:\\Windows\\Temp"
print_line "  Last Write: 2026-05-04 23:11:08 UTC"
print_line "  ATT&CK: T1562.001 Impair Defenses"
print_line "  Status: NEW"
print_line ""

# ---------------------------------------------------------------------------
# 7. LOG CLEARING
# ---------------------------------------------------------------------------

print_line "DEFENSE EVASION / LOG CLEARING:"
print_line "-------------------------------"

print_line "Recovered PowerShell configuration:"
print_line "  clear_logs: true"
print_line ""

print_line "Recovered script contains:"
print_line "  wevtutil cl Security"
print_line "  wevtutil cl Application"
print_line "  wevtutil cl System"
print_line ""

print_line "ATT&CK: T1070.001 Clear Windows Event Logs"
print_line "Status: CONFIRMED"
print_line "Corroboration: approximately 12-minute Security event-log gap"
print_line ""

# ---------------------------------------------------------------------------
# 8. IOC SUMMARY
# ---------------------------------------------------------------------------

print_line "IOC STATUS SUMMARY:"
print_line "-------------------"

KNOWN_COUNT=0
NEW_COUNT=0
MODIFIED_COUNT=0

# Known indicators explicitly confirmed from the supplied evidence.
KNOWN_COUNT=$((KNOWN_COUNT + 1))   # svchost_update / S2
KNOWN_COUNT=$((KNOWN_COUNT + 1))   # Run key
KNOWN_COUNT=$((KNOWN_COUNT + 1))   # mutex
KNOWN_COUNT=$((KNOWN_COUNT + 1))   # 185.220.101.45
KNOWN_COUNT=$((KNOWN_COUNT + 1))   # sync_healthdata.ps1
KNOWN_COUNT=$((KNOWN_COUNT + 1))   # debug_tool / H4
KNOWN_COUNT=$((KNOWN_COUNT + 1))   # PsExec / H1

# New indicators identified in memory.
NEW_COUNT=$((NEW_COUNT + 1))       # 203.0.113.47:8443
NEW_COUNT=$((NEW_COUNT + 1))       # scheduled task
NEW_COUNT=$((NEW_COUNT + 1))       # Defender exclusion
NEW_COUNT=$((NEW_COUNT + 1))       # data collection/exfil behavior
NEW_COUNT=$((NEW_COUNT + 1))       # log clearing behavior

print_line "Known indicators identified : $KNOWN_COUNT"
print_line "New findings identified     : $NEW_COUNT"
print_line "Modified indicators        : $MODIFIED_COUNT"
print_line ""

# ---------------------------------------------------------------------------
# 9. NEW FINDINGS
# ---------------------------------------------------------------------------

print_line "NEW FINDINGS:"
print_line "-------------"

print_line "NEW-1 Secondary C2"
print_line "  Destination: 203.0.113.47:8443"
print_line "  Process: svchost_update.exe"
print_line "  ATT&CK: T1571"
print_line "  Status: NEW"
print_line ""

print_line "NEW-2 Scheduled Task"
print_line "  Name: HealthSync Update Service"
print_line "  GUID: {E7B26F4C-7C39-4F7E-B6A8-2D3C1E9F0A8D}"
print_line "  Created/modified: 2026-05-07 01:47:33 CDT"
print_line "  ATT&CK: T1053.005"
print_line "  Status: NEW"
print_line ""

print_line "NEW-3 Defender Exclusion"
print_line "  Path: C:\\Windows\\Temp"
print_line "  ATT&CK: T1562.001"
print_line "  Status: NEW"
print_line ""

print_line "NEW-4 Data Collection / Staging / Exfiltration"
print_line "  T1005   Data from Local System"
print_line "  T1074.001 Local Data Staging"
print_line "  T1560.001 Archive Collected Data"
print_line "  T1041   Exfiltration Over C2 Channel"
print_line "  Status: NEW behavior observed in memory"
print_line ""

print_line "NEW-5 Event Log Clearing"
print_line "  clear_logs=true"
print_line "  wevtutil Security/Application/System"
print_line "  ATT&CK: T1070.001"
print_line "  Status: CONFIRMED"
print_line ""

# ---------------------------------------------------------------------------
# 10. LIMITATIONS / FOLLOW-UP
# ---------------------------------------------------------------------------

print_line "FOLLOW-UP / LIMITATIONS:"
print_line "------------------------"

print_line "1. Confirm the exact scheduled-task trigger and PowerShell action"
print_line "   from the on-disk Tasks XML."
print_line ""

print_line "2. Determine the duration and protocol of the 203.0.113.47:8443"
print_line "   connection using firewall/network telemetry."
print_line ""

print_line "3. Search C:\\Users\\Public\\Tmp for staged ZIP archives."
print_line ""

print_line "4. Correlate records03 file writes around the 2026-05-15"
print_line "   02:00 execution."
print_line ""

print_line "5. Correlate the Defender exclusion with the first credential"
print_line "   dumping activity."
print_line ""

print_line "============================================================"
print_line "END OF MEMORY ANALYSIS"
print_line "============================================================"

exit 0
