#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REFERENCE_DIR="$SCRIPT_DIR/4x04/reference"
SIEM_DIR="$SCRIPT_DIR/4x04/siem_export"
MATRIX_FILE="$REFERENCE_DIR/service_accounts.txt"
ALERTS_FILE="$SIEM_DIR/wazuh_alerts_14d.json"
SYSMON_FILE="$SIEM_DIR/wazuh_raw_sysmon_14d.json"

for input_file in "$MATRIX_FILE" "$ALERTS_FILE" "$SYSMON_FILE"; do
    [[ -f "$input_file" ]] || {
        printf 'ERROR: required input not found: %s\n' "$input_file" >&2
        exit 1
    }
done
command -v jq >/dev/null 2>&1 || {
    printf 'ERROR: jq is required.\n' >&2
    exit 1
}

# Match the working hunts: combine JSONL exports and remove duplicate IDs.
events=$(sed '/^[[:space:]]*$/d' "$ALERTS_FILE" "$SYSMON_FILE" | jq -s 'unique_by(.id)')

matrix_lines=$(awk '
    /^--- svc_/ {account=$2}
    /^  Authorized host:/ {print account "\t" $3}
' "$MATRIX_FILE")

printf '\n================================================================\n'
printf '   HUNT EXECUTION - H5: Service Account Abuse\n'
printf '   Technique: T1078.002 Domain Accounts\n'
printf '================================================================\n\n'

printf 'SERVICE ACCOUNT AUTHORIZATION MATRIX:\n'
while IFS=$'\t' read -r account host; do
    [[ -z "$account" ]] && continue
    printf '  %-16s Authorized on %s only\n' "$account:" "$host"
done <<<"$matrix_lines"
printf '\n'

auth_events=$(jq --rawfile matrix "$MATRIX_FILE" '
    def authorization_map:
        reduce ($matrix | split("\\n")[]) as $line
          ({current: null, accounts: {}};
           if ($line | test("^--- svc_")) then
             .current = ($line | capture("^--- (?<account>svc_[^ ]+)").account)
           elif ($line | test("^  Authorized host:")) and .current != null then
             .accounts[.current] = ($line | capture("^  Authorized host: +(?<host>[A-Z0-9-]+)").host)
           else .
           end)
        | .accounts;
    authorization_map as $authorized_hosts
    | [.[ ]
       | (.data.win.eventdata // {}) as $data
       | ($data.targetUserName // "") as $account
       | select($account | test("^svc_"; "i"))
       | ($data.workstationName // "unknown") as $source
       | ($data.logonType // "unknown") as $logon_type
       | ($data.authenticationPackageName // "unknown") as $authentication
       | (.data.win.system.computer // .hunt_meta.target_host // "unknown") as $target
       | ($authorized_hosts[$account] // "") as $authorized_host
       | ([
           (if $authorized_host == "" then "Account is not in authorization matrix" else empty end),
           (if ($source | startswith("WS-")) then "Source is a workstation" else empty end),
           (if $source != "unknown" and $source != $authorized_host then "Wrong source host" else empty end),
           (if ($logon_type | tostring) as $type | ["2", "10", "11"] | index($type) then "Interactive logon type" else empty end),
           (if ($authentication | test("NTLM"; "i")) then "NTLM authentication" else empty end)
         ]) as $flags
       | {
           timestamp: .timestamp,
           account: $account,
           source: $source,
           target: $target,
           logon_type: ($logon_type | tostring),
           authentication: $authentication,
           authorized_host: $authorized_host,
           flags: $flags,
           classification: (if $flags == [] then "AUTHORIZED" else "UNAUTHORIZED" end)
         }
    ]
' <<<"$events")

for account in $(printf '%s\n' "$matrix_lines" | cut -f1); do
    total=$(jq --arg account "$account" '[.[] | select(.account == $account)] | length' <<<"$auth_events")
    authorized=$(jq --arg account "$account" '[.[] | select(.account == $account and .classification == "AUTHORIZED")] | length' <<<"$auth_events")
    unauthorized=$(jq --arg account "$account" '[.[] | select(.account == $account and .classification == "UNAUTHORIZED")] | length' <<<"$auth_events")

    printf 'AUTHENTICATION AUDIT - %s:\n' "$account"
    printf '\tTotal auth events: %s\n' "$total"
    printf '\tAuthorized: %s\n' "$authorized"
    printf '\tUNAUTHORIZED: %s\n' "$unauthorized"
    jq -r --arg account "$account" '
        .[]
        | select(.account == $account and .classification == "UNAUTHORIZED")
        | "\t  [!] \(.timestamp) \(.source) -> \(.target) [\(.flags | join("; "))]"
    ' <<<"$auth_events"
    printf '\n'
done

unauthorized_total=$(jq '[.[] | select(.classification == "UNAUTHORIZED")] | length' <<<"$auth_events")
svc_healthsync_workstation=$(jq '[.[] | select(.account == "svc_healthsync" and (.source | startswith("WS-")))] | length' <<<"$auth_events")
psexec_count=$(jq '[.[] | select((.hunt_meta.tool // "") == "PsExec")] | length' <<<"$events")
wmi_count=$(jq '[.[] | select((.hunt_meta.tool // "") == "WMI")] | length' <<<"$events")
psremoting_count=$(jq '[.[] | select((.hunt_meta.tool // "") == "PSRemoting")] | length' <<<"$events")

printf 'CORRELATION WITH OTHER HUNT FINDINGS:\n'
printf '  svc_healthsync workstation-originated events: %s\n' "$svc_healthsync_workstation"
printf '  PsExec events: %s\n' "$psexec_count"
printf '  WMI events: %s\n' "$wmi_count"
printf '  PSRemoting events: %s\n\n' "$psremoting_count"

printf 'FINDING:\n'
if [[ "$svc_healthsync_workstation" -gt 0 && "$unauthorized_total" -gt 0 ]]; then
    printf '  Status: POSITIVE - CRITICAL CONFIDENCE\n'
    printf '  svc_healthsync was used from a workstation and correlated with lateral movement activity.\n'
    printf '  Recommendation: ESCALATE TO CISO / INCIDENT RESPONSE\n'
elif [[ "$unauthorized_total" -gt 0 ]]; then
    printf '  Status: POSITIVE - HIGH CONFIDENCE\n'
    printf '  Unauthorized service-account authentication requires investigation.\n'
    printf '  Recommendation: ESCALATE\n'
else
    printf '  Status: NEGATIVE - No unauthorized service-account use observed\n'
    printf '  Recommendation: Continue monitoring\n'
fi

printf '\n================================================================\n'
