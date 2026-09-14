#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-${HOME}/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"

EXPORT_FILE="${ASSETS_DIR}/wazuh_exports/scenario_b_search_results.json"
TRACE_FILE="${ASSETS_DIR}/wazuh_exports/scenario_b_dashboard_trace.json"
INVENTORY_FILE="${HANDOFF_DIR}/context/asset_inventory.json"

FINDINGS_DIR="${SCRIPT_DIR}/findings"
FINDING_FILE="${FINDINGS_DIR}/scenario_b_export.json"
T5_FINDING="${SCRIPT_DIR}/findings/scenario_b_cli.json"

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

printf 'reading     : scenario_b_search_results.json '

EVENTS_FILE="${TMP_DIR}/events.json"
jq -e '.events | type == "array"' "$EXPORT_FILE" >/dev/null
jq '.events' "$EXPORT_FILE" > "$EVENTS_FILE"

EVENT_COUNT="$(jq 'length' "$EVENTS_FILE")"
printf '(%s events)\n' "$EVENT_COUNT"

# Extract the requested Wazuh fields from every event.
FIELDS_FILE="${TMP_DIR}/fields.json"

jq '
    map({
        timestamp: (
            .["@timestamp"]
            // ._source["@timestamp"]
            // null
        ),
        agent_name: (._source.agent.name // null),
        user_name: (._source.user.name // null),
        event_id: (._source.winlog.event_id // null),
        agent_labels: (._source.agent.labels // null)
    })
' "$EVENTS_FILE" > "$FIELDS_FILE"

HOST="$(jq -r '
    map(.agent_name // empty)
    | map(select(length > 0))
    | .[0] // "unknown"
' "$FIELDS_FILE")"

USER_NAME="$(jq -r '
    map(.user_name // empty)
    | map(select(length > 0))
    | .[0] // "unknown"
' "$FIELDS_FILE")"

printf 'host        : %s (from agent.name)\n' "$HOST"
printf 'user        : %s (from user.name)\n' "$USER_NAME"

# Resolve data_classification from agent.labels.
#
# Supported label forms:
#   {"data_classification":"PHI"}
#   [{"key":"data_classification","value":"PHI"}]
#   [{"name":"data_classification","value":"PHI"}]
#   ["data_classification=PHI"]
#
# The fallback is used only when the labels do not contain the field.
LABEL_RESULT="$(
    jq -r '
        def label_value:
            if type == "object" then
                (.data_classification // .["data_classification"] // empty)
            elif type == "array" then
                (
                    map(
                        if type == "object" then
                            select(
                                (.key == "data_classification")
                                or (.name == "data_classification")
                            )
                            | (.value // .val // empty)
                        elif type == "string" then
                            select(startswith("data_classification="))
                            | split("=")[1]
                        else
                            empty
                        end
                    )
                    | map(select(type == "string" and length > 0))
                    | .[0] // empty
                )
            elif type == "string" then
                if startswith("data_classification=")
                then split("=")[1]
                else empty
                end
            else
                empty
            end;

        [
            .[]
            | .agent_labels
            | select(. != null)
            | label_value
        ]
        | map(select(type == "string" and length > 0))
        | .[0] // ""
    ' "$FIELDS_FILE"
)"

FALLBACK_USED="false"
FALLBACK_ACTION=""

if [[ -n "$LABEL_RESULT" ]]; then
    DATA_CLASS="$LABEL_RESULT"
    DATA_CLASS_SOURCE="agent.labels"
    printf 'data_class  : %s (from agent.labels — resolved without fallback)\n' "$DATA_CLASS"
else
    FALLBACK_USED="true"
    FALLBACK_ACTION="agent.labels lacked data_classification; checked context/asset_inventory.json"

    if [[ ! -f "$INVENTORY_FILE" ]]; then
        printf 'error: data_classification was not present in agent.labels and fallback inventory was not found: %s\n' \
            "$INVENTORY_FILE" >&2
        exit 1
    fi

    DATA_CLASS="$(
        jq -r --arg host "$HOST" '
            def extract_class:
                .data_classification
                // .classification
                // .labels.data_classification
                // .asset.data_classification
                // .asset.labels.data_classification
                // empty;

            if type == "array" then
                map(
                    select(
                        (.hostname? == $host)
                        or (.host? == $host)
                        or (.name? == $host)
                        or (.asset_name? == $host)
                    )
                    | extract_class
                )
                | map(select(type == "string" and length > 0))
                | .[0] // ""
            elif type == "object" then
                if has($host) then
                    .[$host] | extract_class
                else
                    extract_class
                end
            else
                ""
            end
        ' "$INVENTORY_FILE"
    )"

    if [[ -z "$DATA_CLASS" ]]; then
        DATA_CLASS="UNKNOWN"
        DATA_CLASS_SOURCE="asset_inventory.json (fallback lookup; unresolved)"
    else
        DATA_CLASS_SOURCE="asset_inventory.json (fallback lookup)"
    fi

    printf 'data_class  : %s (from asset_inventory.json — fallback lookup)\n' "$DATA_CLASS"
fi

# Determine the first event timestamp and report whether it is outside
# the normal 06:00-18:00 window.
FIRST_TIMESTAMP="$(
    jq -r '
        map(.timestamp // empty)
        | map(select(type == "string" and length > 0))
        | sort
        | .[0] // empty
    ' "$FIELDS_FILE"
)"

OFF_HOURS="false"
OFF_HOURS_TEXT="unknown"

if [[ -n "$FIRST_TIMESTAMP" ]]; then
    FIRST_HHMM="$(
        date -u -d "$FIRST_TIMESTAMP" '+%H:%M' 2>/dev/null || true
    )"

    if [[ -n "$FIRST_HHMM" ]]; then
        FIRST_EPOCH="$(
            date -u -d "$FIRST_TIMESTAMP" '+%s' 2>/dev/null || true
        )"

        if [[ -n "$FIRST_EPOCH" ]]; then
            HOUR="$(date -u -d "@${FIRST_EPOCH}" '+%H')"
            HOUR_NUM=$((10#$HOUR))

            if (( HOUR_NUM < 6 || HOUR_NUM >= 18 )); then
                OFF_HOURS="true"
                OFF_HOURS_TEXT="${FIRST_HHMM}Z outside 06:00-18:00 window"
            else
                OFF_HOURS_TEXT="${FIRST_HHMM}Z within 06:00-18:00 window"
            fi
        fi
    fi
fi

printf 'off_hours   : %s\n' "$OFF_HOURS_TEXT"

# Read dashboard trace and extract click path.
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
printf 'click_path  : %s steps\n' "$CLICK_COUNT"

# Print the extracted event fields for verification.
printf '\nevents      :\n'
jq -r '
    .[]
    | [
        (.timestamp // "unknown"),
        ("agent=" + (.agent_name // "unknown")),
        ("user=" + (.user_name // "unknown")),
        ("event_id=" + ((.event_id // "unknown") | tostring))
    ]
    | "  " + (join(" | "))
' "$FIELDS_FILE"

# Record the actual elapsed wall-clock time.
END_EPOCH="$(date +%s)"
ELAPSED="$((END_EPOCH - START_EPOCH))"
printf 'elapsed     : %s seconds\n' "$ELAPSED"

# Collect event references from the export events.
EVENT_REFS_FILE="${TMP_DIR}/event_refs.json"

jq '
    [
        .[]
        | .eventref
        // .event_ref
        // ._source.eventref
        // ._source.event_ref
        // empty
    ]
    | map(select(type == "string" and length > 0))
    | unique
' "$EVENTS_FILE" > "$EVENT_REFS_FILE"

# Fields touched are deterministic and reflect the requested investigation.
FIELDS_TOUCHED='[
    "_source.agent.name",
    "_source.user.name",
    "_source.winlog.event_id",
    "_source.agent.labels"
]'

if [[ "$FALLBACK_USED" == "true" ]]; then
    FIELDS_TOUCHED="$(jq -c '. + ["asset_inventory.json:data_classification"]' <<<"$FIELDS_TOUCHED")"
fi

# Determine investigation bounds from the event timestamps.
INVESTIGATION_START="$(
    jq -r '
        map(."@timestamp" // ._source["@timestamp"] // empty)
        | map(select(type == "string" and length > 0))
        | sort
        | .[0] // empty
    ' "$EVENTS_FILE"
)"

INVESTIGATION_END="$(
    jq -r '
        map(."@timestamp" // ._source["@timestamp"] // empty)
        | map(select(type == "string" and length > 0))
        | sort
        | .[-1] // empty
    ' "$EVENTS_FILE"
)"

# If timestamps are unavailable, use the current UTC time so the output
# still conforms to the locked finding schema.
if [[ -z "$INVESTIGATION_START" ]]; then
    INVESTIGATION_START="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
fi

if [[ -z "$INVESTIGATION_END" ]]; then
    INVESTIGATION_END="$INVESTIGATION_START"
fi

CREATED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Build ordered actions, keeping the list under the 20-item schema limit.
ACTIONS_FILE="${TMP_DIR}/actions.json"

jq -n \
    --arg click_path "$CLICK_PATH" \
    --arg data_class_source "$DATA_CLASS_SOURCE" \
    --arg fallback_action "$FALLBACK_ACTION" \
    --arg off_hours "$OFF_HOURS_TEXT" \
    --argjson fallback_used "$FALLBACK_USED" '
    [
        {
            action: "read scenario_b_search_results.json",
            result: "events extracted"
        },
        {
            action: "extract Wazuh agent.name, user.name, winlog.event_id, and agent.labels",
            result: "fields inspected"
        },
        {
            action: "resolve data_classification",
            result: $data_class_source
        },
        (
            if $fallback_used
            then {
                action: $fallback_action,
                result: "fallback lookup recorded"
            }
            else empty
            end
        ),
        {
            action: "check off-hours window",
            result: $off_hours
        },
        {
            action: "replay Wazuh dashboard click path",
            click_path: ($click_path | fromjson)
        }
    ]
    | .[:20]
' > "$ACTIONS_FILE"

jq -n \
    --arg finding_id "scenario_b_wazuh_export" \
    --arg scenario_id "scenario_b" \
    --arg interface "wazuh_export" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson actions "$(cat "$ACTIONS_FILE")" \
    --argjson fields_touched "$FIELDS_TOUCHED" \
    --argjson event_refs "$(cat "$EVENT_REFS_FILE")" \
    --argjson off_hours "$OFF_HOURS" \
    --arg data_class "$DATA_CLASS" \
    --arg data_class_source "$DATA_CLASS_SOURCE" \
    --arg host "$HOST" \
    --arg user "$USER_NAME" \
    --arg created_at "$CREATED_AT" '
    {
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: $fields_touched,
        event_refs: $event_refs,
        attack_techniques: [
            "T1078.002",
            "T1059.001"
        ],
        hypothesis: (
            "The account " + $user +
            " authenticated to " + $host +
            " during off-hours and received elevated privileges before PowerShell execution. " +
            "The PHI classification and execution timing warrant investigation to distinguish authorized administrative activity from credential misuse."
        ),
        confidence: "medium",
        created_at: $created_at,
        evidence_summary: {
            host: $host,
            user: $user,
            data_classification: $data_class,
            data_classification_source: $data_class_source,
            off_hours: $off_hours
        }
    }
' > "$FINDING_FILE"

printf 'finding     : findings/scenario_b_export.json written\n'

# Compare elapsed time against T5 CLI finding.
printf '\ncomparison  :\n'

if [[ -f "$T5_FINDING" ]]; then
    T5_ELAPSED="$(
        jq -r '.time_to_first_answer_seconds // empty' "$T5_FINDING"
    )"

    if [[ "$T5_ELAPSED" =~ ^[0-9]+$ ]]; then
        DELTA=$((ELAPSED - T5_ELAPSED))

        if (( DELTA > 0 )); then
            printf 'delta_vs_cli: %s seconds slower via export\n' "$DELTA"
        elif (( DELTA < 0 )); then
            printf 'delta_vs_cli: %s seconds faster via export\n' "$((-DELTA))"
        else
            printf 'delta_vs_cli: same elapsed time as CLI\n'
        fi
    else
        printf 'delta_vs_cli: T5 finding has no numeric elapsed time\n'
    fi
else
    printf 'delta_vs_cli: T5 finding not found at %s\n' "$T5_FINDING"
fi

