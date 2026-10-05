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

# Combine the two JSONL exports and remove duplicate event IDs.
events=$(sed '/^[[:space:]]*$/d' "$ALERTS_FILE" "$SYSMON_FILE" | jq -s 'unique_by(.id)')

psexec_events=$(jq '
    def local_hour: (((.timestamp[11:2] | tonumber) + 19) % 24);
    def is_weekday:
        (.timestamp[0:19] | strptime("%Y-%m-%dT%H:%M:%S") | mktime | strftime("%u") | tonumber) <= 5;
    [.[]
     | select(
         ((.data.win.eventdata.image // "") | test("psexec"; "i"))
         or ((.data.win.eventdata.commandLine // "") | test("psexec"; "i"))
       )
     | . as $event
     | ($event.data.win.eventdata.user // "") as $user
     | ($event.agent.name // $event.hunt_meta.source_host // "unknown") as $source
     | ($event.hunt_meta.target_host // "unknown") as $target
     | ($event.data.win.eventdata.commandLine // "") as $command
     | ([
         (if $source != "WS-ADMIN-01" then "Source host is NOT WS-ADMIN-01" else empty end),
         (if ($event | local_hour) < 8 or ($event | local_hour) >= 18 then "Time is outside business hours" else empty end),
         (if (($event | is_weekday) | not) then "Activity is on a weekend" else empty end),
         (if ($user | test("^MEDDEFENSE\\\\svc_"; "i")) then "User is a service account" else empty end),
         (if ($target | test("DB$"; "i")) then "Target is a database server" else empty end)
       ]) as $flags
     | {
         timestamp: $event.timestamp,
         source: $source,
         user: $user,
         command: $command,
         target: $target,
         pid: ($event.data.win.eventdata.processId // "unknown"),
         flags: $flags,
         classification: (if ($flags | length) == 0 then "BASELINE" else "ANOMALOUS" end)
       }
    ]
' <<<"$events")

total=$(jq 'length' <<<"$psexec_events")
baseline=$(jq '[.[] | select(.classification == "BASELINE")] | length' <<<"$psexec_events")
anomalous=$(jq '[.[] | select(.classification == "ANOMALOUS")] | length' <<<"$psexec_events")

printf '\n================================================================\n'
printf '   HUNT EXECUTION - H1: Lateral Movement via PsExec\n'
printf '   Technique: T1021.002 SMB/Windows Admin Shares\n'
printf '================================================================\n\n'
printf 'QUERY RESULTS:\n'
printf '  Total PsExec events in 14 days: %s\n' "$total"
printf '  Baseline: %s\n' "$baseline"
printf '  ANOMALOUS: %s\n\n' "$anomalous"

printf 'ANOMALOUS EVENTS:\n'
if [[ "$anomalous" -eq 0 ]]; then
    printf '  None\n'
else
    index=0
    while IFS= read -r event; do
        index=$((index + 1))
        printf '  [A%d] %s\n' "$index" "$(jq -r '.timestamp' <<<"$event")"
        printf '\tSource: %s\n' "$(jq -r '.source' <<<"$event")"
        printf '\tUser: %s\n' "$(jq -r '.user' <<<"$event")"
        printf '\tCommand: %s\n' "$(jq -r '.command' <<<"$event")"
        printf '\tTarget: %s\n' "$(jq -r '.target' <<<"$event")"
        printf '\tPID: %s\n' "$(jq -r '.pid' <<<"$event")"
        printf '\tANOMALY FLAGS:\n'
        jq -r '.flags[] | "\t  [!] " + .' <<<"$event"
        printf '\n'
    done < <(jq -c '.[] | select(.classification == "ANOMALOUS")' <<<"$psexec_events")
fi

printf 'FINDING:\n'
if [[ "$anomalous" -gt 0 ]]; then
    printf '  Status: POSITIVE - HIGH CONFIDENCE\n'
    printf '  Evidence: PsExec executions outside Robert Kim administrative baseline\n'
    printf '  Recommendation: ESCALATE\n'
else
    printf '  Status: NEGATIVE - No baseline deviation observed\n'
    printf '  Evidence: All PsExec executions match the documented baseline\n'
    printf '  Recommendation: Continue monitoring\n'
fi

printf '\n================================================================\n'
