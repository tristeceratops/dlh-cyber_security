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

# Both exports are JSON Lines; blank lines are ignored before slurping.
events=$(sed '/^[[:space:]]*$/d' "$ALERTS_FILE" "$SYSMON_FILE" | jq -s '.')

query() {
    jq "$1" <<<"$events"
}

first_event=$(query 'map(.timestamp) | min')
last_event=$(query 'map(.timestamp) | max')
total_events=$(query 'length')

hypothesis_count() {
    query "$1"
}

h1=$(hypothesis_count '[.[] | select((.hunt_meta.tool // "") == "PsExec" or ((.data.win.eventdata.commandLine // "") | test("psexec"; "i")))] | length')
h2=$(hypothesis_count '[.[] | select((.hunt_meta.tool // "") == "lsass_dump" or ((.data.win.eventdata.targetImage // "") | test("lsass\\.exe"; "i")) or ((.data.win.eventdata.commandLine // "") | test("lsass"; "i")))] | length')
h3=$(hypothesis_count '[.[] | select((.hunt_meta.tool // "") == "WMI" or ((.data.win.eventdata.image // "") | test("wmic"; "i")) or ((.data.win.eventdata.commandLine // "") | test("wmic|invoke-wmi"; "i")))] | length')
h4=$(hypothesis_count '[.[] | select((.hunt_meta.tool // "") == "PSRemoting" or ((.data.win.eventdata.commandLine // "") | test("Enter-PSSession|Invoke-Command|New-PSSession"; "i")) or ((.data.win.eventdata.destinationPort // "") == "5985"))] | length')
h5=$(hypothesis_count '[.[] | select(((.data.win.eventdata.targetUserName // "") | test("^svc_"; "i")) or ((.hunt_meta.tool // "") | test("^svc_"; "i")))] | length')

status() {
    [[ "$1" -gt 0 ]] && printf 'OK' || printf 'NO DATA'
}

printf '\n================================================================\n'
printf '   DATA RECONNAISSANCE - MedDefense SIEM Export\n'
printf '================================================================\n\n'

printf 'DATASET METADATA:\n'
printf '  Total events:   %s\n' "$total_events"
printf '  Time range:     %s to %s\n' "$first_event" "$last_event"
printf '  Duration:        14 days\n'
printf '  Format:          JSON / JSON Lines\n\n'

printf 'TOP 10 EVENT TYPES:\n'
query '
    group_by([.rule.id, .rule.description])
    | map({id: .[0].rule.id, description: .[0].rule.description, count: length})
    | sort_by(-.count)
    | .[:10][]
    | "  \(.id)  \(.description) (\(.count))"
'
printf '\n'

printf 'SOURCE HOST DISTRIBUTION:\n'
query '
    [.[] | (.agent.name // "unknown")]
    | group_by(.)[]
    | "  \(.[0]): \(length)"
' | sort
printf '\n'

printf 'SEVERITY DISTRIBUTION:\n'
query '
    [.[] | (.rule.level | tostring)]
    | group_by(.)[]
    | "  Level \(.[0]): \(length)"
' | sort -V
printf '\n'

printf 'HOURLY DISTRIBUTION (UTC):\n'
query '
        [range(0; 24) as $hour
            | {hour: $hour, count: ([.[] | select((.timestamp[11:2] | tonumber) == $hour)] | length)}]
    | .[]
    | "  \(.hour | tostring | if length == 1 then "0" + . else . end):00  \(.count)"
'
printf '\n'

printf 'HYPOTHESIS COVERAGE MATRIX:\n'
printf '  H1 (PsExec):       %s\n' "$(status "$h1")"
printf '  H2 (LSASS):        %s\n' "$(status "$h2")"
printf '  H3 (WMI):          %s\n' "$(status "$h3")"
printf '  H4 (PSRemoting):   %s\n' "$(status "$h4")"
printf '  H5 (Svc Accounts): %s\n' "$(status "$h5")"

printf '\n================================================================\n'
