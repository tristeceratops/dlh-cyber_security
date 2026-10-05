#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR="$SCRIPT_DIR/4x04"
BASELINE_FILE="$DATA_DIR/baseline/robert_kim_activity.json"

if [[ ! -f "$BASELINE_FILE" ]]; then
	printf 'ERROR: baseline file not found: %s\n' "$BASELINE_FILE" >&2
	exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
	printf 'ERROR: jq is required to parse %s\n' "$BASELINE_FILE" >&2
	exit 1
fi

jq_baseline() {
	local query="${!#}"
	local jq_args=("${@:1:$#-1}")
	local parse_filter='split("\n") | map(gsub("\r$"; "") | select((gsub("[[:space:]]"; "") | length) > 0) | fromjson)'
	jq -R -s "${jq_args[@]}" "${parse_filter} | ${query}" "$BASELINE_FILE"
}

total_events=$(jq_baseline 'length')

count_tool() {
	jq_baseline '[.[] | select(.hunt_meta.tool == $tool)] | length' --arg tool "$1"
}

count_source() {
	jq_baseline '[.[] | select(.hunt_meta.source_host == $source)] | length' --arg source "$1"
}

count_user() {
	jq_baseline '[.[] | select(.data.win.eventdata.user == $user)] | length' --arg user "$1"
}

business_hours=$(jq_baseline '
	[ .[]
	  | (.timestamp[11:2] | tonumber) as $utc_hour
	  | (($utc_hour + 19) % 24) as $central_hour
	  | select($central_hour >= 8 and $central_hour < 18)
	] | length
')
off_hours=$((total_events - business_hours))

service_account_events=$(jq_baseline '
	[ .[] | select(.data.win.eventdata.user | startswith("svc_")) ] | length
')

print_counts() {
	local query=$1
	jq_baseline "$query" -r
}

printf '\n================================================================\n'
printf '   BASELINE PROFILE - Robert Kim (IT Administrator)\n'
printf '   Source: baseline/robert_kim_activity.json\n'
printf '================================================================\n\n'

printf 'TOOL USAGE SUMMARY:\n'
printf '  PsExec events:          %s\n' "$(count_tool PsExec)"
printf '  WMI events:             %s\n' "$(count_tool WMI)"
printf '  PSRemoting events:      %s\n' "$(count_tool PSRemoting)"
printf '  Total admin events:     %s\n\n' "$total_events"

printf 'SOURCE HOST:\n'
print_counts '
	group_by(.hunt_meta.source_host)
	| .[]
	| "  \(.[0].hunt_meta.source_host): \(length)"
' | sort
printf '  Other hosts: %s\n' "$(jq_baseline '[.[] | select(.hunt_meta.source_host != "WS-ADMIN-01")] | length')"
printf '  -> BASELINE: All admin activity originates from WS-ADMIN-01\n\n'

printf 'TIME DISTRIBUTION:\n'
printf '  08:00-18:00: %s\n' "$business_hours"
printf '  18:00-08:00: %s\n' "$off_hours"
printf '  -> BASELINE: Zero admin activity outside business hours\n\n'

printf 'DAY-OF-WEEK DISTRIBUTION:\n'
print_counts '
	group_by(.timestamp[0:10] | strptime("%Y-%m-%d") | mktime | strftime("%A"))
	| .[]
	| "  \(.[0].timestamp[0:10] | strptime("%Y-%m-%d") | mktime | strftime("%A")): \(length)"
' | sort
printf '  -> BASELINE: Maintenance activity is scheduled on weekdays; weekends require an approved exception\n\n'

printf 'TARGET HOST ANALYSIS:\n'
print_counts '
	group_by(.hunt_meta.target_host)
	| .[]
	| "  \(.[0].hunt_meta.target_host): \(length)"
' | sort
printf '\n'

printf 'USER ACCOUNTS:\n'
print_counts '
	group_by(.data.win.eventdata.user)
	| .[]
	| "  \(.[0].data.win.eventdata.user): \(length)"
' | sort
printf '  Service accounts: %s\n' "$service_account_events"
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
printf '  [!] Administrative activity on Saturday or Sunday without an approved exception\n'
printf '  [!] Tool or account not present in this baseline\n\n'

printf '================================================================\n'
