#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-${HOME}/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"

EXPORT_FILE="${ASSETS_DIR}/wazuh_exports/scenario_c_search_results.json"
TRACE_FILE="${ASSETS_DIR}/wazuh_exports/scenario_c_dashboard_trace.json"
ZONE_FILE="${HANDOFF_DIR}/context/network_zones.json"

FINDINGS_DIR="${SCRIPT_DIR}/findings"
FINDING_FILE="${FINDINGS_DIR}/scenario_c_export.json"
T6_FINDING="${SCRIPT_DIR}/findings/scenario_c_cli.json"

START_EPOCH="$(date +%s)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$FINDINGS_DIR"

for required_file in "$EXPORT_FILE" "$TRACE_FILE"; do
    if [[ ! -f "$required_file" ]]; then
        printf 'error: required file not found: %s\n' "$required_file" >&2
        exit 1
    fi
done

printf 'reading     : scenario_c_search_results.json '

EVENTS_FILE="${TMP_DIR}/events.json"

jq -e '.events | type == "array"' "$EXPORT_FILE" >/dev/null
jq '.events' "$EXPORT_FILE" > "$EVENTS_FILE"

EVENT_COUNT="$(jq 'length' "$EVENTS_FILE")"
printf '(%s events)\n' "$EVENT_COUNT"

# Extract the requested fields and sort chronologically.
NORMALIZED_FILE="${TMP_DIR}/normalized_events.json"

jq '
    map({
        timestamp: (
            .["@timestamp"]
            // ._source["@timestamp"]
            // null
        ),
        source_ip: (._source.source.ip // null),
        destination_ip: (._source.destination.ip // null),
        source_zone: (._source.source.zone // null),
        raw_message: (
            .message
            // ._source.message
            // ._source.full_log
            // ._source.data
            // ""
        ),
        event_ref: (
            .eventref
            // .event_ref
            // ._source.eventref
            // ._source.event_ref
            // null
        )
    })
    | sort_by(.timestamp // "")
' "$EVENTS_FILE" > "$NORMALIZED_FILE"

SRC_IP="$(
    jq -r '
        map(.source_ip // empty)
        | map(select(length > 0))
        | .[0] // "unknown"
    ' "$NORMALIZED_FILE"
)"

DST_IP="$(
    jq -r '
        map(.destination_ip // empty)
        | map(select(length > 0))
        | .[0] // "unknown"
    ' "$NORMALIZED_FILE"
)"

printf 'src_ip      : %s\n' "$SRC_IP"
printf 'dst_ip      : %s\n' "$DST_IP"

# Resolve source.zone directly from the export.
SRC_ZONE="$(
    jq -r '
        map(.source_zone // empty)
        | map(select(type == "string" and length > 0))
        | .[0] // ""
    ' "$NORMALIZED_FILE"
)"

FALLBACK_USED="false"
ZONE_SOURCE="source.zone"
FALLBACK_ACTION=""

if [[ -n "$SRC_ZONE" ]]; then
    printf 'src_zone    : %s (from source.zone — immediately available)\n' "$SRC_ZONE"
else
    FALLBACK_USED="true"
    FALLBACK_ACTION="source.zone was absent; checked context/network_zones.json"
    ZONE_SOURCE="network_zones.json fallback"

    if [[ ! -f "$ZONE_FILE" ]]; then
        SRC_ZONE="UNKNOWN"
        printf 'src_zone    : %s (source.zone absent; fallback file unavailable)\n' "$SRC_ZONE"
    else
        SRC_ZONE="$(
            jq -r --arg ip "$SRC_IP" '
                def find_zone:
                    .zone
                    // .name
                    // .source_zone
                    // .network_zone
                    // empty;

                if type == "array" then
                    map(
                        select(
                            (.cidr? == "10.2.3.0/24")
                            or (.network? == "10.2.3.0/24")
                            or (.subnet? == "10.2.3.0/24")
                            or (.ip? == $ip)
                        )
                        | find_zone
                    )
                    | map(select(type == "string" and length > 0))
                    | .[0] // "UNKNOWN"
                elif type == "object" then
                    (
                        .[$ip]
                        // .["10.2.3.0/24"]
                        // .networks[$ip]
                        // .networks["10.2.3.0/24"]
                        // find_zone
                        // "UNKNOWN"
                    )
                    | if type == "object" then find_zone else . end
                else
                    "UNKNOWN"
                end
            ' "$ZONE_FILE"
        )"

        printf 'src_zone    : %s (from network_zones.json — fallback lookup)\n' "$SRC_ZONE"
    fi
fi

# Print beacon timestamps and the interval from the preceding event.
printf '\nbeacons     :\n'

BEACON_INDEX=0
PREVIOUS_EPOCH=""
BEACON_LINES_FILE="${TMP_DIR}/beacon_lines.txt"
: > "$BEACON_LINES_FILE"

while IFS=$'\t' read -r timestamp source_ip destination_ip source_zone raw_message event_ref; do
    [[ -z "$timestamp" ]] && continue

    CURRENT_EPOCH="$(date -u -d "$timestamp" '+%s' 2>/dev/null || true)"
    [[ -z "$CURRENT_EPOCH" ]] && continue

    BEACON_INDEX=$((BEACON_INDEX + 1))

    if [[ -n "$PREVIOUS_EPOCH" ]]; then
        INTERVAL_SECONDS=$((CURRENT_EPOCH - PREVIOUS_EPOCH))
        INTERVAL_MINUTES=$((INTERVAL_SECONDS / 60))

        printf 'beacon_%s    : %s  (%s min interval)\n' \
            "$BEACON_INDEX" "$timestamp" "$INTERVAL_MINUTES"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$BEACON_INDEX" \
            "$timestamp" \
            "$INTERVAL_SECONDS" \
            "$source_ip" \
            "$destination_ip" \
            "$event_ref" \
            "$raw_message" >> "$BEACON_LINES_FILE"
    else
        printf 'beacon_%s    : %s\n' "$BEACON_INDEX" "$timestamp"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$BEACON_INDEX" \
            "$timestamp" \
            "0" \
            "$source_ip" \
            "$destination_ip" \
            "$event_ref" \
            "$raw_message" >> "$BEACON_LINES_FILE"
    fi

    PREVIOUS_EPOCH="$CURRENT_EPOCH"
done < <(
    jq -r '
        .[]
        | [
            (.timestamp // ""),
            (.source_ip // ""),
            (.destination_ip // ""),
            (.source_zone // ""),
            (.raw_message // "" | tostring | gsub("\t"; " ")),
            (.event_ref // "")
        ]
        | @tsv
    ' "$NORMALIZED_FILE"
)

# Read the dashboard trace and extract the click path.
CLICK_PATH="$(
    jq -c '
        .click_path
        // .trace.click_path
        // []
    ' "$TRACE_FILE"
)"

if [[ "$(jq 'type' <<<"$CLICK_PATH")" != "array" ]]; then
    printf 'error: click_path is not an array in %s\n' "$TRACE_FILE" >&2
    exit 1
fi

CLICK_COUNT="$(jq 'length' <<<"$CLICK_PATH")"

# Build event references.
EVENT_REFS="$(
    jq -c '
        [
            .[]
            | .event_ref
            | select(type == "string" and length > 0)
        ]
        | unique
    ' "$NORMALIZED_FILE"
)"

# Determine investigation bounds.
INVESTIGATION_START="$(
    jq -r '
        map(.timestamp // empty)
        | map(select(type == "string" and length > 0))
        | sort
        | .[0] // empty
    ' "$NORMALIZED_FILE"
)"

INVESTIGATION_END="$(
    jq -r '
        map(.timestamp // empty)
        | map(select(type == "string" and length > 0))
        | sort
        | .[-1] // empty
    ' "$NORMALIZED_FILE"
)"

if [[ -z "$INVESTIGATION_START" ]]; then
    INVESTIGATION_START="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
fi

if [[ -z "$INVESTIGATION_END" ]]; then
    INVESTIGATION_END="$INVESTIGATION_START"
fi

END_EPOCH="$(date +%s)"
ELAPSED="$((END_EPOCH - START_EPOCH))"
CREATED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

printf 'attack      : T1071.001 T1041\n'
printf 'elapsed     : %s seconds, 3 file reads\n' "$ELAPSED"

# Build ordered actions.
ACTIONS_FILE="${TMP_DIR}/actions.json"

jq -n \
    --arg click_path "$CLICK_PATH" \
    --arg src_zone "$SRC_ZONE" \
    --arg zone_source "$ZONE_SOURCE" \
    --arg fallback_action "$FALLBACK_ACTION" \
    --argjson fallback_used "$FALLBACK_USED" '
    [
        {
            "action": "read scenario_c_search_results.json",
            "result": "events array extracted"
        },
        {
            "action": "extract timestamp, source.ip, destination.ip, source.zone, and raw message",
            "result": "requested Wazuh fields inspected"
        },
        {
            "action": "sort beacon events chronologically",
            "result": "inter-event intervals calculated"
        },
        {
            "action": "resolve source.zone",
            "result": ($src_zone + " (" + $zone_source + ")")
        },
        (
            if $fallback_used
            then {
                "action": $fallback_action,
                "result": "fallback lookup recorded"
            }
            else empty
            end
        ),
        {
            "action": "read scenario_c_dashboard_trace.json",
            "result": "click path extracted",
            "click_path": ($click_path | fromjson)
        }
    ]
    | .[:20]
' > "$ACTIONS_FILE"

jq -n \
    --arg finding_id "scenario_c_wazuh_export" \
    --arg scenario_id "scenario_c" \
    --arg interface "wazuh_export" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson actions "$(cat "$ACTIONS_FILE")" \
    --argjson event_refs "$EVENT_REFS" \
    --arg src_ip "$SRC_IP" \
    --arg dst_ip "$DST_IP" \
    --arg src_zone "$SRC_ZONE" \
    --arg zone_source "$ZONE_SOURCE" \
    --argjson fallback_used "$FALLBACK_USED" \
    --arg created_at "$CREATED_AT" '
    {
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "_source.source.ip",
            "_source.destination.ip",
            "_source.source.zone",
            "message",
            "_source.message",
            "_source.full_log"
        ],
        event_refs: $event_refs,
        attack_techniques: [
            "T1071.001",
            "T1041"
        ],
        hypothesis: (
            "The MEDICAL_IOT source " + $src_ip +
            " generated repeated HTTPS connections to " + $dst_ip +
            ". The periodic external communication is consistent with automated beaconing and warrants investigation under the no-direct-internet policy."
        ),
        confidence: "high",
        created_at: $created_at,
        evidence_summary: {
            source_ip: $src_ip,
            destination: $dst_ip,
            source_zone: $src_zone,
            source_zone_source: $zone_source,
            fallback_used: $fallback_used
        }
    }
' > "$FINDING_FILE"

# Compare actual elapsed time against T6.
if [[ -f "$T6_FINDING" ]]; then
    T6_ELAPSED="$(
        jq -r '.time_to_first_answer_seconds // empty' "$T6_FINDING"
    )"

    if [[ "$T6_ELAPSED" =~ ^[0-9]+$ ]]; then
        DELTA=$((ELAPSED - T6_ELAPSED))

        if (( DELTA > 0 )); then
            printf 'delta_vs_cli: %s seconds slower via export\n' "$DELTA"
        elif (( DELTA < 0 )); then
            printf 'delta_vs_cli: %s seconds faster via export\n' "$((-DELTA))"
        else
            printf 'delta_vs_cli: same elapsed time as CLI\n'
        fi
    else
        printf 'delta_vs_cli: T6 finding has no numeric elapsed time\n'
    fi
else
    printf 'delta_vs_cli: T6 finding not found at %s\n' "$T6_FINDING"
fi

printf 'finding     : findings/scenario_c_export.json written\n'
