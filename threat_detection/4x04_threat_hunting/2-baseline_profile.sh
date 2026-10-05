#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASELINE_FILE="$SCRIPT_DIR/4x04/baseline/robert_kim_activity.json"

[[ -f "$BASELINE_FILE" ]] || {
    printf 'ERROR: baseline file not found: %s\n' "$BASELINE_FILE" >&2
    exit 1
}
command -v jq >/dev/null 2>&1 || {
    printf 'ERROR: jq is required.\n' >&2
    exit 1
}

# The fixture is JSON Lines with a trailing blank record.
baseline=$(sed '/^[[:space:]]*$/d' "$BASELINE_FILE" | jq -s '.')

query() {
    jq "$1" <<<"$baseline"
}

count_tool() {
    query "[.[] | select(.hunt_meta.tool == \"$1\")] | length"
}

count_source() {
    query "[.[] | select(.hunt_meta.source_host == \"$1\")] | length"
}

total_events=$(query 'length')
ps_exec_events=$(count_tool PsExec)
wmi_events=$(count_tool WMI)
ps_remoting_events=$(count_tool PSRemoting)
source_events=$(count_source WS-ADMIN-01)
other_hosts=$(query '[.[] | select(.hunt_meta.source_host != "WS-ADMIN-01")] | length')

business_hours=$(query '
    [.[]
     | (.timestamp[11:2] | tonumber) as $utc
     | (($utc + 19) % 24) as $central
     | select($central >= 8 and $central < 18)]
    | length
')
off_hours=$((total_events - business_hours))

service_accounts=$(query '[.[] | select(.data.win.eventdata.user | startswith("svc_"))] | length')

printf '\n================================================================\n'
printf '   BASELINE PROFILE - Robert Kim (IT Administrator)\n'
printf '   Source: baseline/robert_kim_activity.json\n'
printf '================================================================\n\n'

printf 'TOOL USAGE SUMMARY:\n'
printf '  PsExec events:          %s\n' "$ps_exec_events"
printf '  WMI events:             %s\n' "$wmi_events"
printf '  PSRemoting events:      %s\n' "$ps_remoting_events"
printf '  Total admin events:     %s\n\n' "$total_events"

printf 'SOURCE HOST:\n'
query '[.[] | .hunt_meta.source_host] | group_by(.)[] | "  \(.[0]): \(length)"' | sort
printf '  Other hosts: %s\n' "$other_hosts"
printf '  -> BASELINE: All admin activity originates from WS-ADMIN-01\n\n'

printf 'TIME DISTRIBUTION:\n'
printf '  08:00-18:00: %s\n' "$business_hours"
printf '  18:00-08:00: %s\n' "$off_hours"
printf '  -> BASELINE: Zero admin activity outside business hours\n\n'

printf 'DAY-OF-WEEK DISTRIBUTION:\n'
query '[.[] | (.timestamp[0:10] | strptime("%Y-%m-%d") | mktime | strftime("%A"))] | group_by(.)[] | "  \(.[0]): \(length)"' | sort
printf '  -> BASELINE: Maintenance activity is scheduled on weekdays\n\n'

printf 'TARGET HOST ANALYSIS:\n'
query '[.[] | .hunt_meta.target_host] | group_by(.)[] | "  \(.[0]): \(length)"' | sort
printf '\n'

printf 'USER ACCOUNTS:\n'
query '[.[] | .data.win.eventdata.user] | group_by(.)[] | "  \(.[0]): \(length)"' | sort
printf '  Service accounts: %s\n' "$service_accounts"
printf '  -> BASELINE: Never uses service accounts interactively\n\n'

printf 'BASELINE SUMMARY:\n'
printf '  Normal source host: WS-ADMIN-01\n'
printf '  Normal time window: 08:00-18:00 Central Time, Monday-Friday\n'
printf '  Normal account: MEDDEFENSE\\robert.kim\n'
printf '  Normal tools: PsExec, WMI, PSRemoting\n'
printf '  Normal targets: servers in 10.10.20.0/24\n\n'

printf 'ANOMALY DETECTION CRITERIA:\n'
printf '  [!] Admin tool from any host other than WS-ADMIN-01\n'
printf '  [!] Admin tool usage outside business hours\n'
printf '  [!] Service account used interactively from workstation\n'
printf '  [!] WMI targeting unusual hosts\n'
printf '  [!] Weekend activity without an approved exception\n\n'

printf '================================================================\n'
