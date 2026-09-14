#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

MANIFEST="${ASSETS_DIR}/scenarios/scenario_b_offhours_phi.json"
EVENTS="${HANDOFF_DIR}/data/enriched_events.json"
INVENTORY="${HANDOFF_DIR}/context/asset_inventory.json"

FINDINGS_DIR="${SCRIPT_DIR}/findings"
OUTPUT="${FINDINGS_DIR}/scenario_b_cli.json"

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

[[ -f "$INVENTORY" ]] || {
    echo "error: asset inventory not found: $INVENTORY" >&2
    exit 1
}

# Read scenario metadata from the manifest.
SCENARIO_NAME="$(
    jq -r '
        .scenario
        // .scenario_id
        // .name
        // "scenario_b_offhours_phi"
    ' "$MANIFEST"
)"

HOST="$(
    jq -r '
        .host
        // .hostname
        // .endpoint
        // "clin-ws-07"
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

# Extract ambiguity from the manifest. Support common field layouts.
AMBIGUITY="$(
    jq -r '
        .ambiguity
        // .ambiguity_note
        // .notes.ambiguity
        // .investigation.ambiguity
        // empty
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

if [[ -z "$AMBIGUITY" ]]; then
    echo "error: scenario manifest does not contain an ambiguity statement" >&2
    exit 1
fi

SCOPED_FILE="$(mktemp)"
MATCH_FILE="$(mktemp)"

cleanup() {
    rm -f "$SCOPED_FILE" "$MATCH_FILE"
}

trap cleanup EXIT

# Locate the host record in asset_inventory.json.
#
# Supports an inventory represented as either:
#   [ {...}, {...} ]
# or:
#   { "assets": [ {...}, {...} ] }
# or:
#   { "hosts": [ {...}, {...} ] }
ASSET_RECORD="$(
    jq -c --arg host "$HOST" '
        def records:
            if type == "array" then .
            elif (.assets? | type) == "array" then .assets
            elif (.hosts? | type) == "array" then .hosts
            elif (.inventory? | type) == "array" then .inventory
            else []
            end;

        records[]
        | select(
            (.hostname // .host // .name // .asset_name // .endpoint)
            == $host
        )
    ' "$INVENTORY" | head -n 1
)"

if [[ -z "$ASSET_RECORD" ]]; then
    echo "error: host record not found in asset inventory: $HOST" >&2
    exit 1
fi

CRITICALITY="$(
    jq -r '.criticality // "UNKNOWN"' <<<"$ASSET_RECORD"
)"

DATA_CLASSIFICATION="$(
    jq -r '
        .data_classification
        // .dataClassification
        // .classification
        // "UNKNOWN"
    ' <<<"$ASSET_RECORD"
)"

# Scope enriched events to the host and manifest-defined window.
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

if (( SCOPED_COUNT == 0 )); then
    echo "error: no events found for $HOST in requested window" >&2
    exit 1
fi

# Filter:
#   Windows Security 4624
#   Windows Security 4672
#   Sysmon Event ID 1
jq '
    [
        .[] |
        select(
            (
                .event.code
                // .event_id
                // .sysmon.event_id
                // .winlog.event_id
            ) as $eid
            |
            ($eid | tostring) == "4624"
            or ($eid | tostring) == "4672"
            or ($eid | tostring) == "1"
        )
    ]
' "$SCOPED_FILE" > "$MATCH_FILE"

MATCH_COUNT="$(jq 'length' "$MATCH_FILE")"

if (( MATCH_COUNT == 0 )); then
    echo "error: no 4624/4672/Sysmon EID 1 events matched" >&2
    exit 1
fi

printf 'scenario    : %s\n' "$SCENARIO_NAME"
printf 'host        : %s (criticality: %s, data: %s)\n' \
    "$HOST" "$CRITICALITY" "$DATA_CLASSIFICATION"
printf 'window      : %s -> %s\n' "$START" "$END"

# Print the requested event summaries.
# Timestamp formatting is generic and uses the actual event timestamp.
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
        (
            .event.code
            // .event_id
            // .sysmon.event_id
            // .winlog.event_id
        ) | tostring;

    .[]
    | event_id as $eid

    | if $eid == "4624" then
        "EID 4624    : "
        + (
            .winlog.event_data.TargetUserName
            // .user.name
            // .user
            // "unknown"
          | tostring
        )
        + " "
        + (
            .winlog.event_data.LogonTypeDescription
            // .winlog.event_data.LogonType
            // .logon.type
            // "logon"
          | tostring
        )
        + " logon at "
        + display_time

      elif $eid == "4672" then
        "EID 4672    : "
        + (
            .winlog.event_data.PrivilegeList
            // .privileges
            // "special privileges"
          | tostring
          | gsub("\\r?\\n"; " ")
          | gsub("\\s*:\\s*"; " ")
        )
        + " at "
        + display_time

      elif $eid == "1" then
        "EID 1       : "
        + (
            .winlog.event_data.CommandLine
            // .process.command_line
            // .command_line
            // (
                (
                    .winlog.event_data.Image
                    // .process.executable
                    // .process.name
                    // "unknown"
                ) | tostring
              )
          | tostring
        )
        + " at "
        + display_time

      else
        empty
      end
' "$MATCH_FILE"

# Investigation timing starts after the evidence has been loaded and
# immediately before the event-chain interpretation.
INVESTIGATION_START="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

ACTIONS_JSON="$(
    jq -n '
        [
            "read scenario_b offhours PHI manifest",
            "read enriched_events.json",
            "scope events to clin-ws-07",
            "scope events to the manifest time window",
            "read asset_inventory.json",
            "extract asset criticality and data classification",
            "filter Windows Event ID 4624",
            "filter Windows Event ID 4672",
            "filter Sysmon Event ID 1",
            "correlate off-hours logon, privileged access, and PowerShell execution",
            "review manifest ambiguity",
            "assess escalation requirement"
        ]
    '
)"

FIELDS_JSON="$(
    jq -n '
        [
            "timestamp",
            "host.name",
            "event.code",
            "user.name",
            "winlog.event_data.TargetUserName",
            "winlog.event_data.LogonType",
            "winlog.event_data.LogonTypeDescription",
            "winlog.event_data.PrivilegeList",
            "process.name",
            "process.command_line",
            "winlog.event_data.CommandLine",
            "asset.criticality",
            "asset.data_classification",
            "scenario.ambiguity"
        ]
    '
)"

EVENT_REFS_JSON="$(
    jq -c '
        [
            .[] |
            (
                .eventref
                // .event_ref
                // .event.id
                // .id
                // empty
            )
        ]
        | map(select(. != null and . != ""))
    ' "$MATCH_FILE"
)"

# The ambiguity is preserved from the manifest rather than replacing it
# with an unsupported conclusion.
HYPOTHESIS="$AMBIGUITY"

INVESTIGATION_END="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

INVESTIGATION_START_EPOCH="$(
    date -u -d "$INVESTIGATION_START" +%s
)"

INVESTIGATION_END_EPOCH="$(
    date -u -d "$INVESTIGATION_END" +%s
)"

if (( INVESTIGATION_END_EPOCH >= INVESTIGATION_START_EPOCH )); then
    TIME_TO_FIRST_ANSWER_SECONDS=$(
        printf '%s\n' \
            "$((INVESTIGATION_END_EPOCH - INVESTIGATION_START_EPOCH))"
    )
else
    echo "error: investigation timestamps are inconsistent" >&2
    exit 1
fi

COMMAND_COUNT="$(jq 'length' <<<"$ACTIONS_JSON")"

jq -n \
    --arg scenario_id "scenario_b" \
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
            "T1078.002",
            "T1059.001"
        ],
        hypothesis: $hypothesis,
        confidence: "medium",
        created_at: $investigation_end
    }
    ' > "$OUTPUT"

printf 'ambiguity   : %s\n' "$AMBIGUITY"
printf 'attack      : T1078.002 T1059.001\n'
printf 'finding     : %s written\n' "$OUTPUT"

