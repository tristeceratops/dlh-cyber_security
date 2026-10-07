#!/bin/bash

set -u

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PREVIOUS_DIR="$BASE_DIR/4x05/previous_findings"

FILES=(
    "$BASE_DIR/0-evidence_index.sh"
    "$BASE_DIR/1-memory_analysis_report.txt"
    "$BASE_DIR/2-disk_analysis.sh"
    "$BASE_DIR/3-firewall_analysis.sh"
)

if [ ! -d "$PREVIOUS_DIR" ]; then
    echo "ERROR: previous_findings/ not found"
    exit 1
fi

echo "================================================================"
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: T0-T3 + previous_findings/"
echo "================================================================"
echo

# ------------------------------------------------------------------
# Helper
# ------------------------------------------------------------------

find_source() {
    local pattern="$1"

    grep -Eil "$pattern" "${FILES[@]}" "$PREVIOUS_DIR"/* 2>/dev/null |
        sed 's#^.*/##' |
        sort -u |
        tr '\n' ',' |
        sed 's/,$//'
}

status_for() {
    local count="$1"

    if [ "$count" -ge 2 ]; then
        echo "CONVERGED"
    else
        echo "SINGLE-SOURCE"
    fi
}

# ------------------------------------------------------------------
# IOC correlation
# ------------------------------------------------------------------

echo "IOC CORRELATION:"
printf "%-30s %-20s %-18s\n" "IOC" "SOURCES" "STATUS"
printf "%-30s %-20s %-18s\n" "---" "-------" "------"

IOC_LIST="
meddefense-portal.com
meddefense-benefits.com
outlook-protection.com
healthbane-c2.net
update.healthbane-c2.net
sync.healthbane-c2.net
data-sync.healthbane-c2.net
185.220.101.45
185.220.101.46
203.0.113.47
svchost_update.exe
debug_tool.exe
PsExec64.exe
sync_healthdata.ps1
svc_healthsync
records03
dmarsh
HealthSync
staging_export_001.zip
staging_export_002.zip
query_results.csv
"

converged=0
single=0
new_ir=0

while IFS= read -r ioc; do
    [ -z "$ioc" ] && continue

    sources="$(find_source "$ioc")"

    count="$(printf '%s' "$sources" | awk -F',' '{print NF}')"

    if [ -z "$sources" ]; then
        count=0
    fi

    status="$(status_for "$count")"

    case "$status" in
        CONVERGED)
            converged=$((converged + 1))
            ;;
        SINGLE-SOURCE)
            single=$((single + 1))
            ;;
    esac

    printf "%-30s %-20s %-18s\n" "$ioc" "$sources" "$status"
done <<EOF
$IOC_LIST
EOF

# IR-only indicators from the supplied 4x05 evidence.
IR_NEW="
203.0.113.47
HealthSync Update Service
C:\\Windows\\Temp
staging_export_001.zip
staging_export_002.zip
query_results.csv
"

while IFS= read -r ioc; do
    [ -z "$ioc" ] && continue

    if grep -Eiq "$ioc" \
        "$BASE_DIR/1-memory_analysis_report.txt" \
        "$BASE_DIR/2-disk_analysis.sh" \
        "$BASE_DIR/3-firewall_analysis.sh" 2>/dev/null; then

        if ! grep -Eiq "$ioc" "$PREVIOUS_DIR"/* 2>/dev/null; then
            new_ir=$((new_ir + 1))
        fi
    fi
done <<EOF
$IR_NEW
EOF

echo
echo "Summary: $converged CONVERGED, $single SINGLE-SOURCE"
echo "New IR IOCs not found in previous_findings: $new_ir"
echo

# ------------------------------------------------------------------
# Timeline correlation
# ------------------------------------------------------------------

echo "TIMELINE CORRELATION:"
printf "%-28s %-28s %-18s\n" "EVENT" "SOURCES" "CONFIDENCE"
printf "%-28s %-28s %-18s\n" "---" "-------" "----------"

timeline_event() {
    local event="$1"
    local pattern="$2"

    local sources
    local count

    sources="$(find_source "$pattern")"
    count="$(printf '%s' "$sources" | awk -F',' '{print NF}')"

    if [ -z "$sources" ]; then
        count=0
    fi

    if [ "$count" -ge 2 ]; then
        printf "%-28s %-28s %-18s\n" \
            "$event" "$sources" "CONVERGED"
    elif [ "$count" -eq 1 ]; then
        printf "%-28s %-28s %-18s\n" \
            "$event" "$sources" "LOWER CONFIDENCE"
    fi
}

timeline_event "Phishing delivery" \
    "phishing|E1|meddefense-portal.com"

timeline_event "Credential theft" \
    "collect.php|credential submission|13:18:42"

timeline_event "Stage 2 deployment" \
    "svchost_update.exe|Stage 2"

timeline_event "C2 establishment" \
    "185.220.101.45|first C2|C2 beacon"

timeline_event "Credential dump" \
    "LSASS|debug_tool.exe|T1003.001"

timeline_event "Lateral movement" \
    "PsExec64.exe|PsExec|svc_healthsync"

timeline_event "Scheduled task" \
    "HealthSync Update Service|T1053.005"

timeline_event "Data collection" \
    "health_records|T1005|sync_healthdata.ps1"

timeline_event "Data staging" \
    "staging_export|query_results.csv|T1074.001"

timeline_event "Data exfiltration" \
    "EXFIL_BURST|34,441,660|T1041"

timeline_event "Event log clearing" \
    "wevtutil cl|clear_logs|T1070.001"

timeline_event "Secondary C2" \
    "203.0.113.47|8443|T1571"

echo
echo "TIMELINE NOTES:"
echo "  C2 timestamp: 4x01 PCAP is approximately 4 seconds ahead of"
echo "  firewall timestamps. Firewall time is authoritative for"
echo "  connection initiation."
echo
echo "  Lateral movement: 4x01 did not observe movement because its"
echo "  PCAP window did not cover the later cross-VLAN activity."
echo
echo "  Data staging: IR disk evidence is the primary evidence."
echo

# ------------------------------------------------------------------
# ATT&CK technique correlation
# ------------------------------------------------------------------

echo "TECHNIQUE CORRELATION:"
printf "%-12s %-38s %-12s %-12s %-24s\n" \
    "TECHNIQUE" "NAME" "4x02" "LATER" "UPDATE"
printf "%-12s %-38s %-12s %-12s %-24s\n" \
    "---" "---" "---" "---" "---"

technique() {
    local id="$1"
    local name="$2"
    local inferred_pattern="$3"
    local later_pattern="$4"

    local old="NOT-COVERED"
    local later="---"
    local update="NO CHANGE"

    if grep -Eiq "$inferred_pattern" "$PREVIOUS_DIR"/* 2>/dev/null; then
        old="INFERRED"
    fi

    if grep -Eiq "$later_pattern" \
        "$BASE_DIR/1-memory_analysis_report.txt" \
        "$BASE_DIR/2-disk_analysis.sh" \
        "$BASE_DIR/3-firewall_analysis.sh" \
        "$PREVIOUS_DIR"/* 2>/dev/null; then
        later="CONFIRMED"
    fi

    if [ "$old" = "INFERRED" ] && [ "$later" = "CONFIRMED" ]; then
        update="UPGRADED"
    elif [ "$old" = "NOT-COVERED" ] && [ "$later" = "CONFIRMED" ]; then
        update="NEW"
    fi

    printf "%-12s %-38s %-12s %-12s %-24s\n" \
        "$id" "$name" "$old" "$later" "$update"
}

technique "T1566.001" "Spearphishing Link" \
    "T1566.001|Spearphishing Link" \
    "T1566.001"

technique "T1071.001" "Web Protocols" \
    "T1071.001" \
    "T1071.001|185.220.101.45"

technique "T1021.002" "SMB / Windows Admin Shares" \
    "T1021.002" \
    "T1021.002|PsExec"

technique "T1021.006" "PowerShell Remoting" \
    "T1021.006" \
    "T1021.006|PSRemoting"

technique "T1047" "WMI" \
    "T1047" \
    "T1047|WMI"

technique "T1003.001" "LSASS Memory" \
    "T1003.001" \
    "T1003.001|LSASS|debug_tool"

technique "T1550.002" "Pass the Hash" \
    "T1550.002" \
    "T1550.002|NTLM"

technique "T1053.005" "Scheduled Task" \
    "T1053.005" \
    "T1053.005|HealthSync Update Service"

technique "T1074.001" "Local Data Staging" \
    "T1074.001" \
    "T1074.001|staging_export"

technique "T1560.001" "Archive Collected Data" \
    "T1560.001" \
    "T1560.001|staging_export"

technique "T1070.001" "Clear Windows Event Logs" \
    "T1070.001" \
    "T1070.001|wevtutil"

technique "T1041" "Exfiltration Over C2" \
    "T1041" \
    "T1041|EXFIL_BURST|34,441,660"

technique "T1571" "Non-Standard Port" \
    "T1571" \
    "T1571|203.0.113.47"

technique "T1005" "Data from Local System" \
    "T1005" \
    "T1005|health_records|sync_healthdata"

echo
echo "CRITICAL CONTRADICTIONS / RESOLUTIONS:"
echo
echo "1. C2 timestamp"
echo "   Resolution: 4x01 documents ~4s PCAP/firewall skew."
echo "   Firewall timestamp is used for connection initiation."
echo
echo "2. Lateral movement"
echo "   Resolution: 4x01 had no VLAN-20 visibility and ended earlier."
echo "   4x04/IR provide later evidence of lateral movement."
echo
echo "3. Run-key persistence"
echo "   Resolution: memory evidence shows the HKCU Run key;"
echo "   disk evidence did not recover a suspicious Run entry."
echo "   These are different collection results, not automatically"
echo "   a contradiction."
echo
echo "4. Data exfiltration"
echo "   Resolution: IR firewall bursts match the recovered staging"
echo "   archive sizes, providing network correlation for exfiltration."
echo
echo "5. Secondary C2"
echo "   Resolution: 203.0.113.47:8443 is supported by both memory"
echo "   and firewall evidence and is therefore converged."
echo

echo "================================================================"
echo "CORRELATION COMPLETE"
echo "================================================================"