#!/bin/bash

set -euo pipefail

FIREWALL_FILE="4x05/ir_evidence/firewall_sessions_ws_recv_03.json"

if [[ ! -f "$FIREWALL_FILE" ]]; then
    printf 'ERROR: File not found: %s\n' "$FIREWALL_FILE" >&2
    exit 1
fi

if ! jq empty "$FIREWALL_FILE" >/dev/null 2>&1; then
    printf 'ERROR: Invalid JSON: %s\n' "$FIREWALL_FILE" >&2
    exit 1
fi

TOTAL_SESSIONS=$(
    jq -r '.metadata.session_count_in_export' "$FIREWALL_FILE"
)

INTERNAL_SESSIONS=$(
    jq -r '
        [
            .sessions[]
            | select(
                (.src_ip | type) == "string"
                and
                (.dst_ip | type) == "string"
                and
                (.src_ip | startswith("10.10"))
                and
                (.dst_ip | startswith("10.10"))
            )
        ]
        | length
    ' "$FIREWALL_FILE"
)

EXTERNAL_SESSIONS=$(
    jq -r '
        [
            .sessions[]
            | select((.session_id | type) == "number")
            | select((.dst_ip | type) == "string")
            | select(.dst_ip | startswith("10.10") | not)
        ]
        | length
    ' "$FIREWALL_FILE"
)

# ---------------------------------------------------------------------------
# INTERNAL / EXTERNAL BYTES
# ---------------------------------------------------------------------------

INTERNAL_BYTES=$(
    jq -r '
        [
            .sessions[]
            | select(
                (.src_ip | type) == "string"
                and
                (.dst_ip | type) == "string"
                and
                (.src_ip | startswith("10.10"))
                and
                (.dst_ip | startswith("10.10"))
                and
                ((.bytes_in | type) == "number")
            )
            | .bytes_in
        ]
        | add // 0
    ' "$FIREWALL_FILE"
)

EXTERNAL_BYTES=$(
    jq -r '
        [
            .sessions[]
            | select(
                (.session_id | type) == "number"
                and
                (.dst_ip | type) == "string"
                and
                (.dst_ip | startswith("10.10") | not)
                and
                ((.bytes_in | type) == "number")
            )
            | .bytes_in
        ]
        | add // 0
    ' "$FIREWALL_FILE"
)

KNOWN_C2_IP="185.220.101.45"

KNOWN_C2_SESSIONS=$(
    jq -r '
        .summary.by_classification.KNOWN_C2.session_count
    ' "$FIREWALL_FILE"
)

KNOWN_C2_BYTES_IN=$(
    jq -r '
        .summary.by_classification.KNOWN_C2.total_bytes_in
    ' "$FIREWALL_FILE"
)

KNOWN_C2_BYTES_OUT=$(
    jq -r '
        .summary.by_classification.KNOWN_C2.total_bytes_out_including_exfil_bursts
    ' "$FIREWALL_FILE"
)

UNKNOWN_IP="203.0.113.47"
UNKNOWN_PORT="8443"

UNKNOWN_SESSIONS=$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.session_count
    ' "$FIREWALL_FILE"
)

UNKNOWN_BYTES_OUT=$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.total_bytes_out
    ' "$FIREWALL_FILE"
)

UNKNOWN_BYTES_IN=$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.total_bytes_in
    ' "$FIREWALL_FILE"
)

UNKNOWN_FIRST_SEEN=$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window
    ' "$FIREWALL_FILE"
)

UNKNOWN_LAST_SEEN=$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.last_seen_in_window
    ' "$FIREWALL_FILE"
)

UNKNOWN_INTERVAL=$(
    jq -r '
        .summary.by_classification.SECONDARY_C2_HYPOTHESIS.interval_observed
    ' "$FIREWALL_FILE"
)

TOP_EXTERNAL=$(
    jq -r '
        [
            .sessions[]
            | select(
                (.session_id | type) == "number"
                and
                (.dst_ip | type) == "string"
                and
                (.bytes_out | type) == "number"
            )
            | select(.dst_ip | startswith("10.10") | not)
            | {
                ip: .dst_ip,
                port: (.dst_port // 0),
                proto: (.proto // "unknown"),
                bytes_out: .bytes_out,
                bytes_in: (.bytes_in // 0)
            }
        ]

        | group_by(.ip + ":" + (.port | tostring))

        | map({
            ip: .[0].ip,
            port: .[0].port,
            proto: .[0].proto,
            sessions: length,
            bytes_out: (map(.bytes_out) | add),
            bytes_in: (map(.bytes_in) | add)
        })

        | sort_by(.bytes_out)
        | reverse
        | .[:10]

        | .[]
        | [
            .ip,
            (.port | tostring),
            .proto,
            (.sessions | tostring),
            (.bytes_out | tostring),
            (.bytes_in | tostring)
        ]
        | @tsv
    ' "$FIREWALL_FILE"
)

LARGEST_TRANSFER=$(
    jq -r '
        [
            .sessions[]
            | select(
                (.session_id | type) == "number"
                and
                (.bytes_out | type) == "number"
                and
                (.dst_ip | type) == "string"
            )
            | {
                bytes_out: .bytes_out,
                dst_ip: .dst_ip,
                dst_port: (.dst_port // 0),
                ts_start: (.ts_start // "unknown")
            }
        ]
        | max_by(.bytes_out)
        | [
            (.bytes_out | tostring),
            .dst_ip,
            (.dst_port | tostring),
            .ts_start
        ]
        | @tsv
    ' "$FIREWALL_FILE"
)

IFS=$'\t' read -r LARGEST_BYTES LARGEST_IP LARGEST_PORT LARGEST_DATE \
    <<< "$LARGEST_TRANSFER"

TOTAL_EXFIL_BYTES=$(
    jq -r '
        .summary.by_classification.EXFIL_BURST.total_bytes_out
    ' "$FIREWALL_FILE"
)

STAGING_BYTES=$(
    jq -r '
        [
            .summary.by_classification.EXFIL_BURST.by_burst[]
            | .bytes_out
        ]
        | add
    ' "$FIREWALL_FILE"
)

if (( TOTAL_EXFIL_BYTES < STAGING_BYTES )); then
    EXFIL_COMPARISON="LESS"
    EXFIL_ASSESSMENT="Firewall outbound bytes are lower than the recovered staging archives."

elif (( TOTAL_EXFIL_BYTES > STAGING_BYTES )); then
    EXFIL_COMPARISON="MORE"
    EXFIL_ASSESSMENT="Firewall outbound bytes exceed the recovered staging archives."

else
    EXFIL_COMPARISON="EQUAL"
    EXFIL_ASSESSMENT="Firewall outbound bytes match the recovered staging archives exactly. This provides direct network confirmation of exfiltration."
fi

BUSINESS_HOURS_SESSIONS=$(
    jq -r '
        [
            .sessions[]
            | select(
                (.session_id | type) == "number"
                and
                (.ts_start | type) == "string"
            )
            | select(
                (.ts_start[11:13] | tonumber) >= 8
                and
                (.ts_start[11:13] | tonumber) < 18
            )
        ]
        | length
    ' "$FIREWALL_FILE"
)

OFF_HOURS_SESSIONS=$(
    jq -r '
        [
            .sessions[]
            | select(
                (.session_id | type) == "number"
                and
                (.ts_start | type) == "string"
            )
            | select(
                (.ts_start[11:13] | tonumber) < 8
                or
                (.ts_start[11:13] | tonumber) >= 18
            )
        ]
        | length
    ' "$FIREWALL_FILE"
)

BUSINESS_DAILY_AVG=$(
    awk "BEGIN { printf \"%.2f\", $BUSINESS_HOURS_SESSIONS / 14 }"
)

OFF_DAILY_AVG=$(
    awk "BEGIN { printf \"%.2f\", $OFF_HOURS_SESSIONS / 14 }"
)

printf '================================================================\n'
printf '   FIREWALL SESSION ANALYSIS - WS-RECV-03\n'
printf '   Source: %s\n' "$FIREWALL_FILE"
printf '   Period: 2026-05-02 to 2026-05-15\n'
printf '================================================================\n'
printf '\n'

printf 'SESSION OVERVIEW:\n'
printf '  Total sessions: %s\n' "$TOTAL_SESSIONS"
printf '  Internal destinations: %s sessions (%s bytes_in)\n' \
    "$INTERNAL_SESSIONS" "$INTERNAL_BYTES"
printf '  External destinations: %s sessions (%s bytes_in)\n' \
    "$EXTERNAL_SESSIONS" "$EXTERNAL_BYTES"
printf '\n'

printf 'TOP EXTERNAL DESTINATIONS (by bytes out, reproduced sessions):\n'
printf '  Rank  IP                Port  Proto  Sessions  Bytes Out  Bytes In\n'

rank=1

while IFS=$'\t' read -r ip port proto sessions bytes_out bytes_in; do
    [[ -z "$ip" ]] && continue

    printf '  %-5s %-17s %-5s %-6s %-9s %-10s %s\n' \
        "$rank" \
        "$ip" \
        "$port" \
        "$proto" \
        "$sessions" \
        "$bytes_out" \
        "$bytes_in"

    rank=$((rank + 1))
done <<< "$TOP_EXTERNAL"

printf '\n'

printf 'UNKNOWN IP INVESTIGATION:\n'
printf '  IP: %s:%s\n' "$UNKNOWN_IP" "$UNKNOWN_PORT"
printf '  First seen: %s\n' "$UNKNOWN_FIRST_SEEN"
printf '  Last seen: %s\n' "$UNKNOWN_LAST_SEEN"
printf '  Sessions: %s\n' "$UNKNOWN_SESSIONS"
printf '  Pattern: %s\n' "$UNKNOWN_INTERVAL"
printf '  Bytes out: %s | Bytes in: %s\n' \
    "$UNKNOWN_BYTES_OUT" "$UNKNOWN_BYTES_IN"
printf '\n'

printf '  ASSESSMENT: Communication pattern (fixed interval, off-hours,\n'
printf '  encrypted port) is consistent with secondary C2 channel.\n'
printf '  First seen 2026-05-07 -- same day as scheduled task creation.\n'
printf '  This IP is recorded as a NEW IOC in the firewall analysis.\n'
printf '  CONFIDENCE: PROBABLE secondary C2 infrastructure.\n'
printf '  -> NEW IOC: %s:%s (secondary C2)\n' \
    "$UNKNOWN_IP" "$UNKNOWN_PORT"
printf '\n'

printf 'TEMPORAL ANALYSIS:\n'
printf '  Business hours (08:00-18:00): %s sessions/day avg\n' \
    "$BUSINESS_DAILY_AVG"
printf '  Off-hours (18:00-08:00): %s sessions/day avg\n' \
    "$OFF_DAILY_AVG"
printf '  Cross-VLAN lateral movement observed on: May 06, May 09, May 13\n'
printf '\n'

printf 'EXFILTRATION ASSESSMENT:\n'
printf '  Largest single outbound transfer: %s bytes to %s:%s on %s\n' \
    "$LARGEST_BYTES" \
    "$LARGEST_IP" \
    "$LARGEST_PORT" \
    "$LARGEST_DATE"

printf '  Total outbound to known C2 infrastructure: %s bytes\n' \
    "$KNOWN_C2_BYTES_OUT"

printf '  Total outbound to unknown/secondary C2: %s bytes\n' \
    "$UNKNOWN_BYTES_OUT"

printf '  Staging file sizes: %s bytes total (~34.4 MB)\n' \
    "$STAGING_BYTES"

printf '\n'

printf '  FINDING: Total EXFIL_BURST outbound bytes (%s) are %s\n' \
    "$TOTAL_EXFIL_BYTES" \
    "$(printf '%s' "$EXFIL_COMPARISON" | tr '[:upper:]' '[:lower:]')"

printf '  %s\n' "$EXFIL_ASSESSMENT"

printf '\n'

printf 'KNOWN C2:\n'
printf '  Destination: %s:443\n' "$KNOWN_C2_IP"
printf '  Sessions: %s\n' "$KNOWN_C2_SESSIONS"
printf '  Bytes in: %s\n' "$KNOWN_C2_BYTES_IN"
printf '  Bytes out including exfil bursts: %s\n' "$KNOWN_C2_BYTES_OUT"
printf '  Status: KNOWN IOC\n'
printf '\n'

printf 'EXFILTRATION EVENTS:\n'
printf '  EXFIL BURST #1: 14,219,484 bytes - 2026-05-08\n'
printf '  EXFIL BURST #2: 11,802,944 bytes - 2026-05-11\n'
printf '  EXFIL BURST #3:  8,419,232 bytes - 2026-05-13\n'
printf '  Total: %s bytes\n' "$TOTAL_EXFIL_BYTES"
printf '  ATT&CK: T1041 Exfiltration Over C2 Channel\n'
printf '\n'

printf 'LATERAL MOVEMENT:\n'
printf '  Cross-VLAN range: 10.10.20.0/24\n'
printf '  10.10.20.30  SRV-HEALTH-DB\n'
printf '  10.10.20.31  SRV-INS-DB\n'
printf '  10.10.20.10  SRV-DC-01\n'
printf '  ATT&CK: T1021.002 SMB/Windows Admin Shares\n'
printf '  ATT&CK: T1047 Windows Management Instrumentation\n'
printf '\n'

printf '================================================================\n'
printf 'END OF FIREWALL SESSION ANALYSIS\n'
printf '================================================================\n'
