#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIEM_DIR="$SCRIPT_DIR/4x04/siem_export"
ALERTS_FILE="$SIEM_DIR/wazuh_alerts_14d.json"
SYSMON_FILE="$SIEM_DIR/wazuh_raw_sysmon_14d.json"

for input_file in "$ALERTS_FILE" "$SYSMON_FILE"; do
    [[ -f "$input_file" ]] || {
        printf 'ERROR: SIEM export not found: %s\n' "$input_file" >&2
        exit 1
    }
done
command -v jq >/dev/null 2>&1 || {
    printf 'ERROR: jq is required.\n' >&2
    exit 1
}

# Match the working PsExec hunt ingestion: JSON Lines, then one jq array.
events=$(sed '/^[[:space:]]*$/d' "$ALERTS_FILE" "$SYSMON_FILE" | jq -s 'unique_by(.id)')

lsass_events=$(jq '
    [.[]
     | select((.data.win.eventdata.targetImage // "") | test("lsass\\.exe"; "i"))
     | . as $event
     | ($event.data.win.eventdata.sourceImage // "unknown") as $source
     | ($event.data.win.eventdata.sourceUser // "") as $user
     | ($source | test("(csrss|services|svchost|wininit|MsMpEng|WmiPrvSE)\\.exe$"; "i")) as $system_source
     | {
         timestamp: $event.timestamp,
         host: ($event.agent.name // $event.data.win.system.computer // "unknown"),
         source_process: $source,
         source_user: $user,
         target: ($event.data.win.eventdata.targetImage // "lsass.exe"),
         access_mask: ($event.data.win.eventdata.grantedAccess // "unknown"),
         memory_read: (($event.data.win.eventdata.grantedAccess // "") | test("0x.*(0010|1010)"; "i")),
         anomalous: ($system_source | not)
       }
    ]
' <<<"$events")

lsass_total=$(jq 'length' <<<"$lsass_events")
lsass_system=$(jq '[.[] | select(.anomalous == false)] | length' <<<"$lsass_events")
lsass_anomalous=$(jq '[.[] | select(.anomalous == true)] | length' <<<"$lsass_events")

svc_healthsync=$(jq '
    [.[]
     | select((.data.win.eventdata.targetUserName // "") | test("^svc_healthsync$"; "i"))
     | select((.data.win.eventdata.workstationName // "") | test("^WS-"; "i"))
     | {
         timestamp: .timestamp,
         source: (.data.win.eventdata.workstationName // .hunt_meta.source_host // "unknown"),
         target: (.data.win.system.computer // .hunt_meta.target_host // "unknown"),
         logon_type: (.data.win.eventdata.logonType // "unknown"),
         authentication: (.data.win.eventdata.authenticationPackageName // "unknown")
       }
    ]
' <<<"$events")

svc_count=$(jq 'length' <<<"$svc_healthsync")
psexec_count=$(jq '[.[] | select((.hunt_meta.tool // "") == "PsExec")] | length' <<<"$events")
wmi_count=$(jq '[.[] | select((.hunt_meta.tool // "") == "WMI")] | length' <<<"$events")
psremoting_count=$(jq '[.[] | select((.hunt_meta.tool // "") == "PSRemoting")] | length' <<<"$events")

printf '\n================================================================\n'
printf '   HUNT EXECUTION - H2: Credential Access (LSASS)\n'
printf '   Technique: T1003.001 LSASS Memory\n'
printf '================================================================\n\n'

printf 'LSASS ACCESS EVENTS:\n'
printf '  Total LSASS access events: %s\n' "$lsass_total"
printf '  System/legitimate: %s\n' "$lsass_system"
printf '  ANOMALOUS: %s\n\n' "$lsass_anomalous"

if [[ "$lsass_anomalous" -gt 0 ]]; then
    index=0
    while IFS= read -r event; do
        index=$((index + 1))
        printf '  [A%d] %s\n' "$index" "$(jq -r '.timestamp' <<<"$event")"
        printf '\tHost: %s\n' "$(jq -r '.host' <<<"$event")"
        printf '\tSource Process: %s\n' "$(jq -r '.source_process' <<<"$event")"
        printf '\tTarget: %s\n' "$(jq -r '.target' <<<"$event")"
        printf '\tAccess Mask: %s\n' "$(jq -r '.access_mask' <<<"$event")"
        if [[ "$(jq -r '.memory_read' <<<"$event")" == true ]]; then
            printf '\t-> Consistent with memory dumping\n'
        fi
        printf '\n'
    done < <(jq -c '.[] | select(.anomalous == true)' <<<"$lsass_events")
else
    printf '  None\n\n'
fi

printf 'CREDENTIAL USAGE CORRELATION:\n'
if [[ "$svc_count" -gt 0 ]]; then
    jq -r '.[] | "\t\(.timestamp) \(.source) -> \(.target) (Logon Type \(.logon_type), \(.authentication))"' <<<"$svc_healthsync"
else
    printf '\tNo svc_healthsync workstation authentication events found\n'
fi
printf '\n'

printf 'RELATED LATERAL-MOVEMENT ACTIVITY:\n'
printf '  PsExec events: %s\n' "$psexec_count"
printf '  WMI events: %s\n' "$wmi_count"
printf '  PSRemoting events: %s\n\n' "$psremoting_count"

printf 'CREDENTIAL THEFT TIMELINE:\n'
if [[ "$lsass_anomalous" -gt 0 ]]; then
    printf '  1. Anomalous LSASS access was observed from a non-standard process.\n'
else
    printf '  1. No anomalous LSASS access was observed.\n'
fi
if [[ "$svc_count" -gt 0 ]]; then
    printf '  2. svc_healthsync was later authenticated from a workstation.\n'
else
    printf '  2. No workstation-originated svc_healthsync authentication was observed.\n'
fi
printf '  3. Review related PsExec, WMI, and PSRemoting activity for lateral movement.\n\n'

printf 'FINDING:\n'
if [[ "$lsass_anomalous" -gt 0 && "$svc_count" -gt 0 ]]; then
    printf '  Status: POSITIVE - HIGH CONFIDENCE\n'
    printf '  The attacker likely dumped credentials and later used svc_healthsync for lateral movement.\n'
    printf '  Recommendation: ESCALATE\n'
elif [[ "$lsass_anomalous" -gt 0 || "$svc_count" -gt 0 ]]; then
    printf '  Status: POSITIVE - MEDIUM CONFIDENCE\n'
    printf '  Credential access or service-account misuse evidence requires correlation and escalation.\n'
    printf '  Recommendation: INVESTIGATE\n'
else
    printf '  Status: NEGATIVE - No correlated credential-theft evidence observed\n'
    printf '  Recommendation: Continue monitoring\n'
fi

printf '\n================================================================\n'
