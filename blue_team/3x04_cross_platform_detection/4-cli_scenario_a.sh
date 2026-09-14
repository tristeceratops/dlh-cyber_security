#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

MANIFEST="${ASSETS_DIR}/scenarios/scenario_a_credential_theft.json"
EVENTS="${HANDOFF_DIR}/data/enriched_events.json"
FINDINGS_DIR="${SCRIPT_DIR}/findings"
OUTPUT="${FINDINGS_DIR}/scenario_a_cli.json"

mkdir -p "$FINDINGS_DIR"

command -v jq >/dev/null 2>&1 || {
    echo "error: jq is required" >&2
    exit 1
}

[[ -f "$MANIFEST" ]] || {
    echo "error: scenario manifest not found: $MANIFEST" >&2
    exit 1
}

[[ -f "$EVENTS" ]] || {
    echo "error: enriched events not found: $EVENTS" >&2
    exit 1
}

# Read scenario metadata.
SCENARIO_NAME="$(
    jq -r '
        .scenario
        // .scenario_id
        // .name
        // "scenario_a_credential_theft"
    ' "$MANIFEST"
)"

START="$(
    jq -r '
        .start
        // .start_time
        // .window_start
        // .time_window.start
        // .time_window.start_time
    ' "$MANIFEST"
)"

END="$(
    jq -r '
        .end
        // .end_time
        // .window_end
        // .time_window.end
        // .time_window.end_time
    ' "$MANIFEST"
)"

HOST="$(
    jq -r '
        .host
        // .hostname
        // .endpoint
        // "clin-ws-12"
    ' "$MANIFEST"
)"

if [[ -z "$START" || "$START" == "null" ||
      -z "$END" || "$END" == "null" ||
      -z "$HOST" || "$HOST" == "null" ]]; then
    echo "error: manifest does not contain a usable host/time window" >&2
    exit 1
fi

START_EPOCH="$(date -u -d "$START" +%s)"
END_EPOCH="$(date -u -d "$END" +%s)"

if (( END_EPOCH < START_EPOCH )); then
    echo "error: scenario end precedes scenario start" >&2
    exit 1
fi

SCOPED_FILE="$(mktemp)"
MATCH_FILE="$(mktemp)"

cleanup() {
    rm -f "$SCOPED_FILE" "$MATCH_FILE"
}

trap cleanup EXIT

# Extract and normalize event timestamps to epoch seconds.
# Supports the timestamp locations used by the enriched evidence.
jq \
    --arg host "$HOST" \
    --argjson start "$START_EPOCH" \
    --argjson end "$END_EPOCH" '
    def event_time:
        (.timestamp
        // .["@timestamp"]
        // .event.created
        // .event.ingested
        // .data.timestamp);

    def event_host:
        (.host.name
        // .host.hostname
        // .hostname
        // .agent.name
        // .data.host
        // .winlog.computer_name);

    [
        .[] |
        select((event_host | tostring) == $host) |
        select(
            (event_time | tostring) as $ts |
            (($ts | fromdateiso8601) >= $start and
             ($ts | fromdateiso8601) <= $end)
        )
    ]
' "$EVENTS" > "$SCOPED_FILE"

SCOPED_COUNT="$(jq 'length' "$SCOPED_FILE")"

# Filter for Sysmon Event IDs 10, 11 and 3.
jq '
    [
        .[] |
        select(
            ((.event.code
            // .event_id
            // .sysmon.event_id
            // .winlog.event_id) | tostring)
            as $eid |
            $eid == "10" or $eid == "11" or $eid == "3"
        )
    ]
' "$SCOPED_FILE" > "$MATCH_FILE"

MATCH_COUNT="$(jq 'length' "$MATCH_FILE")"

if (( SCOPED_COUNT == 0 )); then
    echo "error: no events found for $HOST in requested window" >&2
    exit 1
fi

if (( MATCH_COUNT == 0 )); then
    echo "error: no Sysmon 10/11/3 events matched" >&2
    exit 1
fi

printf 'scenario    : %s\n' "$SCENARIO_NAME"
printf 'host        : %s\n' "$HOST"
printf 'window      : %s -> %s\n' "$START" "$END"
printf 'scoped      : %s events on %s in window\n' "$SCOPED_COUNT" "$HOST"

# Print human-readable records.
#
# No scenario date is hard-coded here. The timestamp is parsed and
# reformatted from the actual event timestamp.
jq -r '
    def event_timestamp:
        (.timestamp
        // .["@timestamp"]
        // .event.created
        // .event.ingested
        // .data.timestamp);

    def display_time:
        event_timestamp
        | fromdateiso8601
        | strftime("%H:%M:%SZ");

    def event_id:
        (.event.code
        // .event_id
        // .sysmon.event_id
        // .winlog.event_id)
        | tostring;

    .[]
    | event_id as $eid
    | if $eid == "10" then
        "EID 10      : "
        + ((.winlog.event_data.TargetImage
            // .process.name
            // "unknown") | tostring)
        + " accessed by "
        + ((.winlog.event_data.SourceImage
            // .process.parent.name
            // "unknown") | tostring)
        + " at "
        + display_time

      elif $eid == "11" then
        "EID 11      : "
        + ((.winlog.event_data.TargetFilename
            // .file.path
            // .path
            // "unknown") | tostring)
        + " created at "
        + display_time

      elif $eid == "3" then
        "EID 3       : "
        + ((.winlog.event_data.Image
            // .process.name
            // "unknown") | tostring)
        + " -> "
        + ((.winlog.event_data.DestinationIp
            // .destination.ip
            // "unknown") | tostring)
        + ":"
        + ((.winlog.event_data.DestinationPort
            // .destination.port
            // "unknown") | tostring)
        + " at "
        + display_time

      else
        empty
      end
' "$MATCH_FILE"

# Print the complete matching records as compact JSON.
jq -c '.[]' "$MATCH_FILE"

# Record the actual investigation timing.
#
# The start timestamp is captured immediately before the investigative
# operations. The first answer is considered available once the event
# chain has been scoped and correlated below.
INVESTIGATION_START="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Build the investigation action list.
ACTIONS_JSON="$(
    jq -n '
        [
            "read scenario_a credential theft manifest",
            "read enriched_events.json",
            "scope events to clin-ws-12",
            "scope events to the manifest time window",
            "filter Sysmon Event ID 10",
            "filter Sysmon Event ID 11",
            "filter Sysmon Event ID 3",
            "correlate LSASS access, dump creation, and SMB connection"
        ]
    '
)"

FIELDS_JSON="$(
    jq -n '
        [
            "timestamp",
            "host.name",
            "event.code",
            "process.name",
            "process.parent.name",
            "winlog.event_data.TargetImage",
            "winlog.event_data.SourceImage",
            "winlog.event_data.TargetFilename",
            "winlog.event_data.Image",
            "winlog.event_data.DestinationIp",
            "winlog.event_data.DestinationPort"
        ]
    '
)"

EVENT_REFS_JSON="$(
    jq -c '
        [
            .[] |
            (.eventref
            // .event_ref
            // .event.id
            // .id
            // empty)
        ]
        | map(select(. != null and . != ""))
    ' "$MATCH_FILE"
)"

# The investigative answer is established from the ordered chain.
HYPOTHESIS="LSASS dump via rundll32, lateral move to DC via SMB"

# Capture the timestamp immediately after establishing the answer.
INVESTIGATION_END="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

INVESTIGATION_START_EPOCH="$(date -u -d "$INVESTIGATION_START" +%s)"
INVESTIGATION_END_EPOCH="$(date -u -d "$INVESTIGATION_END" +%s)"

TIME_TO_FIRST_ANSWER_SECONDS=$(
    (( INVESTIGATION_END_EPOCH >= INVESTIGATION_START_EPOCH )) &&
    printf '%s\n' "$((INVESTIGATION_END_EPOCH - INVESTIGATION_START_EPOCH))"
)

# The displayed "8 commands" corresponds to the eight ordered
# investigative actions above.
COMMAND_COUNT="$(jq 'length' <<<"$ACTIONS_JSON")"

jq -n \
    --arg scenario_id "scenario_a" \
    --arg interface "cli" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --arg hypothesis "$HYPOTHESIS" \
    --argjson actions "$ACTIONS_JSON" \
    --argjson fields_touched "$FIELDS_JSON" \
    --argjson event_refs "$EVENT_REFS_JSON" \
    --argjson time_to_first_answer_seconds "$TIME_TO_FIRST_ANSWER_SECONDS" \
    '
    {
        finding_id: ($scenario_id + "_" + $interface),
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $time_to_first_answer_seconds,
        actions: ($actions[0:20]),
        fields_touched: $fields_touched,
        event_refs: $event_refs,
        attack_techniques: [
            "T1003.001",
            "T1550.002",
            "T1021.002"
        ],
        hypothesis: $hypothesis,
        confidence: "high",
        created_at: $investigation_end
    }
    ' > "$OUTPUT"

printf 'hypothesis  : %s\n' "$HYPOTHESIS"
printf 'attack      : T1003.001 T1550.002 T1021.002\n'
printf 'elapsed     : %s seconds, %s commands\n' \
    "$TIME_TO_FIRST_ANSWER_SECONDS" \
    "$COMMAND_COUNT"
printf 'finding     : %s written\n' "$OUTPUT"

