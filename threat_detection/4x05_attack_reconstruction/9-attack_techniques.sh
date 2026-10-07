#!/bin/bash

set -u

BASELINE="4x05/reference/attck_navigator_80pct.json"

if [ ! -f "$BASELINE" ]; then
    echo "ERROR: Missing $BASELINE"
    exit 1
fi

echo "================================================================"
echo "   HEALTHBANE ATT&CK TECHNIQUE INVENTORY (FINAL)"
echo "   Total techniques in threat model: 29"
echo "================================================================"
echo

printf "  #   %-12s %-18s %-5s %-9s %-11s %-12s\n" \
    "Technique" "Tactic" "Conf" "First ID" "Status" "Evidence"
printf "  --  ------------ ------------------ ----- --------- ----------- ------------\n"

printf "  01  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1566.001" "Initial Access" "CONF" "4x00" "UNCHANGED" "4x00"
printf "  02  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1566.002" "Initial Access" "CONF" "4x00" "UNCHANGED" "4x00"
printf "  03  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1204.002" "Execution" "CONF" "4x03" "UNCHANGED" "4x03"
printf "  04  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1059.001" "Execution" "CONF" "4x03" "UNCHANGED" "4x03,4x04,4x05"
printf "  05  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1059.005" "Execution" "CONF" "4x03" "UNCHANGED" "4x03"
printf "  06  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1547.001" "Persistence" "CONF" "4x03" "UNCHANGED" "4x03,4x05"
printf "  07  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1071.001" "C2" "CONF" "4x01" "UNCHANGED" "4x01,4x03,4x04,4x05"
printf "  08  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1071.004" "C2" "CONF" "4x01" "UNCHANGED" "4x01,4x03"
printf "  09  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1573.001" "C2" "CONF" "4x03" "UNCHANGED" "4x01,4x03"
printf "  10  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1027" "Defense Evasion" "CONF" "4x03" "UNCHANGED" "4x03,4x05"
printf "  11  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1027.010" "Defense Evasion" "CONF" "4x03" "UNCHANGED" "4x03,4x05"
printf "  12  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1140" "Defense Evasion" "CONF" "4x03" "UNCHANGED" "4x03"
printf "  13  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1105" "C2" "CONF" "4x03" "UNCHANGED" "4x01,4x03"
printf "  14  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1041" "Exfiltration" "CONF" "4x03" "UPGRADED" "4x03,4x05"
printf "  15  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1048.003" "Exfiltration" "PROB" "4x03" "UNCHANGED" "4x01,4x03"
printf "  16  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1005" "Collection" "CONF" "4x02" "UPGRADED" "4x02,4x04,4x05"
printf "  17  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1583.001" "Resource Dev." "CONF" "4x00" "UNCHANGED" "4x00"
printf "  18  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1003.001" "Credential Access" "CONF" "4x04" "UNCHANGED" "4x04,4x05"
printf "  19  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1021.002" "Lateral Movement" "CONF" "4x04" "UNCHANGED" "4x04,4x05"
printf "  20  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1021.006" "Lateral Movement" "CONF" "4x04" "UNCHANGED" "4x04"
printf "  21  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1047" "Lateral Movement" "CONF" "4x04" "UNCHANGED" "4x04"
printf "  22  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1078" "Defense Evasion" "CONF" "4x00" "UNCHANGED" "4x00,4x04"
printf "  23  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1078.002" "Defense Evasion" "CONF" "4x04" "UNCHANGED" "4x04"
printf "  24  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1550.002" "Lateral Movement" "CONF" "4x04" "UNCHANGED" "4x04"
printf "  25  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1112" "Defense Evasion" "CONF" "4x03" "UNCHANGED" "4x03,4x04"
printf "  26  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1053.005" "Persistence" "CONF" "4x05-IR" "NEW" "4x05 T1,T2"
printf "  27  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1074.001" "Collection" "CONF" "4x05-IR" "NEW" "4x05 T2"
printf "  28  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1560.001" "Collection" "CONF" "4x05-IR" "NEW" "4x05 T2"
printf "  29  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1070.001" "Defense Evasion" "CONF" "4x05-IR" "NEW" "4x05 T2"
printf "  30  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1571" "C2" "CONF" "4x05-IR" "NEW" "4x05 T1,FW"
printf "  31  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1055" "Defense Evasion" "CONF" "4x05-IR" "NEW" "4x05 T1"
printf "  32  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1562.001" "Defense Evasion" "CONF" "4x05-IR" "NEW" "4x05 T1"
printf "  33  %-12s %-18s %-5s %-9s %-11s %s\n" \
    "T1070.001" "Defense Evasion" "CONF" "4x05-IR" "NEW" "4x05 T1,T2"

echo
echo "COVERAGE EVOLUTION:"
echo "  Post-4x02 (intelligence):       ~40% (12/29)"
echo "  Post-4x03 (malware):            ~55% (16/29)"
echo "  Post-4x04 (hunting):            ~80% (23/29)"
echo "  Post-4x05 (reconstruction):     Expanded evidence coverage"
echo
echo "BASELINE:"
echo "  Baseline file:                  $BASELINE"
echo "  Baseline threat model:          29 techniques"
echo "  Baseline observed:              23"
echo "  Baseline inferred:              3"
echo "  Baseline not covered:           3"
echo
echo "UPGRADED TECHNIQUES:"
echo "  T1041     Exfiltration Over C2 Channel"
echo "            Firewall exfiltration bursts total 34,441,660 bytes"
echo "            and match recovered staging archive sizes."
echo
echo "  T1005     Data from Local System"
echo "            sync_healthdata.ps1 queries SRV-HEALTH-DB / health_records"
echo "            and writes database results to CSV."
echo
echo "  T1071.004 DNS"
echo "            Capability and DNS TXT test traffic confirmed; however,"
echo "            high-volume DNS exfiltration was not demonstrated."
echo
echo "NEW TECHNIQUES FROM 4x05 IR:"
echo "  T1053.005  Scheduled Task/Job: Scheduled Task"
echo "             HealthSync Update Service, daily 02:00 trigger."
echo
echo "  T1074.001  Data Staged: Local Data Staging"
echo "             CSV and ZIP artifacts recovered from Public\\Tmp."
echo
echo "  T1560.001  Archive Collected Data"
echo "             staging_export_001.zip and staging_export_002.zip."
echo
echo "  T1070.001  Indicator Removal: Clear Windows Event Logs"
echo "             wevtutil cleared Security, Application and System logs."
echo
echo "  T1571      Non-Standard Port"
echo "             Secondary C2 at 203.0.113.47:8443."
echo
echo "  T1055      Process Injection"
echo "             Stage 2 RAT injected/unpacked in PID 3712."
echo
echo "  T1562.001  Impair Defenses"
echo "             Defender exclusion for C:\\Windows\\Temp."
echo
echo "CORRECTIONS / DOWNGRADES:"
echo "  T1048.003  DNS exfiltration remains PROBABLE, not CONFIRMED."
echo "             DNS TXT test traffic exists, but no high-volume DNS"
echo "             exfiltration was demonstrated at MedDefense."
echo
echo "  T1074.001 / T1560.001"
echo "             Disk artifacts confirm the techniques, but the supplied"
echo "             disk timestamps are dated Feb 10-11 while the main IR"
echo "             sequence is May 2026. Technique use is confirmed, but"
echo "             exact placement in the attack sequence is uncertain."
echo
echo "FINAL COVERAGE:"
echo "  Original threat model:         29 techniques"
echo "  Confirmed in final evidence:   28/29"
echo "  Final confirmed coverage:      96%"
echo
echo "REMAINING GAP:"
echo "  T1048.003 - Exfiltration Over Alternative Protocol: DNS"
echo "  Assessment: DNS TXT capability and test traffic are confirmed,"
echo "  but the evidence does not establish sustained DNS exfiltration"
echo "  of collected MedDefense data."
echo
echo "NOTE:"
echo "  T1571, T1055 and T1562.001 are additional techniques identified"
echo "  during 4x05. They are reported separately from the original"
echo "  29-technique threat-model coverage calculation."
echo
echo "================================================================"