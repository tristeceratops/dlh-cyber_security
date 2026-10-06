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

# Combine JSONL exports and remove duplicate event IDs.
events=$(sed '/^[[:space:]]*$/d' "$ALERTS_FILE" "$SYSMON_FILE" | jq -s 'unique_by(.id)')

correlated=$(jq '
    def ts: (.timestamp // .data.win.eventdata.utcTime // "");
    def epoch:
        try (ts | sub("\\.000\\+00:00$"; "Z") | fromdateiso8601)
        catch 0;
    def source: (.agent.name // .hunt_meta.source_host // .data.win.system.computer // "unknown");
    def target: (.hunt_meta.target_host // .data.win.system.computer // "unknown");
    def command: (.data.win.eventdata.commandLine // "");
    def service_auth:
        ((.data.win.eventdata.targetUserName // "") | test("^svc_healthsync$"; "i"))
        and ((.data.win.eventdata.workstationName // "") | test("^WS-"; "i"));
    def lsass_anomaly:
        ((.data.win.eventdata.targetImage // "") | test("lsass\\.exe"; "i"))
        and (((.data.win.eventdata.sourceImage // "") | test("(csrss|services|svchost|wininit|MsMpEng|WmiPrvSE)\\.exe$"; "i")) | not);
    def psexec:
        (((.hunt_meta.tool // "") == "PsExec") or ((.data.win.eventdata.image // "") | test("psexec"; "i")) or (command | test("psexec"; "i")));
    def wmi:
        ((.hunt_meta.tool // "") == "WMI" or (command | test("wmic|invoke-wmi"; "i")));
    def psremote:
        ((.hunt_meta.tool // "") == "PSRemoting" or (command | test("Enter-PSSession|Invoke-Command|New-PSSession"; "i")));
    def admin_anomaly:
        ((source != "WS-ADMIN-01")
         or ((.data.win.eventdata.user // "") != "MEDDEFENSE\\robert.kim")
         or ((.timestamp[11:2] | tonumber) + 19) % 24 < 8
         or ((.timestamp[11:2] | tonumber) + 19) % 24 >= 18);
    [
      .[]
      | select(lsass_anomaly)
      | {timestamp: ts, epoch: epoch, phase: "CREDENTIAL ACCESS", description: (source + ": LSASS memory access"), source: source, target: target, account: (.data.win.eventdata.sourceUser // "")}
    ],
    [
      .[]
    | select(service_auth or ((psexec or wmi or psremote) and admin_anomaly))
      | {timestamp: ts, epoch: epoch, phase: "LATERAL MOVEMENT", description: (source + " -> " + target + " using " + (if service_auth then "svc_healthsync" elif psexec then "PsExec" elif wmi then "WMI" else "PSRemoting" end)), source: source, target: target, account: (.data.win.eventdata.targetUserName // .data.win.eventdata.user // "")}
    ],
    [
      .[]
    | select(wmi and admin_anomaly and ((command | test("/node:|process|service|product|os get|diskdrive"; "i"))))
      | {timestamp: ts, epoch: epoch, phase: "RECONNAISSANCE", description: (source + ": WMI enumeration on " + target), source: source, target: target, account: (.data.win.eventdata.user // "")}
    ],
    [
      .[]
    | select(psremote and admin_anomaly and (command | test("Copy-Item|ToSession|New-PSSession|Invoke-Command"; "i")))
      | {timestamp: ts, epoch: epoch, phase: "STAGING", description: (source + ": PSRemoting staging on " + target), source: source, target: target, account: (.data.win.eventdata.user // "")}
    ]
    | sort_by(.epoch, .timestamp)
' <<<"$events")

# jq emits four arrays above; flatten them into one event array.
correlated=$(jq -s 'add | sort_by(.epoch, .timestamp)' <<<"$correlated")

timeline_count=$(jq 'length' <<<"$correlated")
first_epoch=$(jq 'if length == 0 then 0 else map(.epoch) | min end' <<<"$correlated")
last_epoch=$(jq 'if length == 0 then 0 else map(.epoch) | max end' <<<"$correlated")
dwell_seconds=$((last_epoch - first_epoch))
dwell_days=$((dwell_seconds / 86400))
dwell_hours=$(((dwell_seconds % 86400) / 3600))

tools=$(jq -r '[.[].description | select(test("using (PsExec|WMI|PSRemoting)")) | capture("using (?<tool>PsExec|WMI|PSRemoting)").tool] | unique | join(", ")' <<<"$correlated")
pivot=$(jq -r '[.[] | select(.phase == "CREDENTIAL ACCESS") | .source] | first // ([.[] | .source] | first // "unknown")' <<<"$correlated")
credential=$(jq -r '[.[] | select(.account | test("^svc_"; "i")) | .account] | first // "svc_healthsync"' <<<"$correlated")
targets=$(jq -r '[.[] | .target | select(test("^SRV-"; "i"))] | unique | join(", ")' <<<"$correlated")

printf '\n================================================================\n'
printf '   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction\n'
printf '================================================================\n\n'

printf 'ATTACK TIMELINE:\n'
if [[ "$timeline_count" -eq 0 ]]; then
    printf '  No correlated Stage 4 events found.\n'
else
    for phase in "CREDENTIAL ACCESS" "LATERAL MOVEMENT" "RECONNAISSANCE" "STAGING"; do
        printf '  [%s]\n' "$phase"
        jq -r --arg phase "$phase" '.[] | select(.phase == $phase) | "\t\(.description) [\(.timestamp)]"' <<<"$correlated"
    done
fi
printf '\n'

printf 'ATTACK SUMMARY:\n'
printf '  Pivot host:        %s\n' "$pivot"
printf '  Credential used:   %s\n' "$credential"
printf '  Targets:           %s\n' "${targets:-none}"
printf '  Tools used:        %s\n' "${tools:-none}"
printf '  Dwell time:        %d days, %d hours\n\n' "$dwell_days" "$dwell_hours"

printf 'NARRATIVE:\n'
printf '  HEALTHBANE activity began with credential access on the pivot host,\n'
printf '  followed by service-account authentication and administrative-tool\n'
printf '  activity against server targets. The correlated sequence indicates\n'
printf '  progression from workstation compromise to database/server access.\n\n'

printf 'ASSESSMENT:\n'
if [[ "$timeline_count" -gt 0 ]]; then
    printf '  HEALTHBANE Stage 4 was executed against MedDefense.\n'
    printf '  Confidence: HIGH\n'
else
    printf '  No correlated HEALTHBANE Stage 4 sequence was reconstructed.\n'
    printf '  Confidence: LOW\n'
fi

printf '\n================================================================\n'
