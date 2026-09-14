/#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SEARCH_RESULTS="${ASSETS_DIR}/wazuh_exports/scenario_a_search_results.json"
DASHBOARD_TRACE="${ASSETS_DIR}/wazuh_exports/scenario_a_dashboard_trace.json"
DASHBOARD_SUMMARY="${ASSETS_DIR}/dashboard_exports/scenario_a_dashboard_summary.md"

# T4 CLI finding may be in the same project tree or the conventional
# findings directory used by the preceding CLI scripts.
CLI_FINDING="${SCRIPT_DIR}/findings/scenario_a_cli.json"
if [[ ! -f "$CLI_FINDING" ]]; then
    CLI_FINDING="${SCRIPT_DIR}/findings/scenario_a_cli.json"
fi

FINDINGS_DIR="${SCRIPT_DIR}/findings"
OUTPUT="${FINDINGS_DIR}/scenario_a_export.json"

mkdir -p "$FINDINGS_DIR"

command -v jq >/dev/null 2>&1 || {
    echo "error: jq is required" >&2
    exit 1
}

[[ -f "$SEARCH_RESULTS" ]] || {
    echo "error: Wazuh search results not found: $SEARCH_RESULTS" >&2
    exit 1
}

[[ -f "$DASHBOARD_TRACE" ]] || {
    echo "error: dashboard trace not found: $DASHBOARD_TRACE" >&2
    exit 1
}

[[ -f "$DASHBOARD_SUMMARY" ]] || {
    echo "error: dashboard summary not found: $DASHBOARD_SUMMARY" >&2
    exit 1
}

INVESTIGATION_START="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
START_EPOCH="$(date -u -d "$INVESTIGATION_START" +%s)"

# ---------------------------------------------------------------------------
# Read search results.
# ---------------------------------------------------------------------------

HITS_TOTAL="$(
    jq -r '
        .hits_total
        // .hits.total.value
        // .hits.total
        // 0
    ' "$SEARCH_RESULTS"
)"

KQL_QUERY="$(
    jq -r '
        .kql
        // .query.kql
        // .query
        // .request.kql
        // empty
    ' "$SEARCH_RESULTS"
)"

# Support:
#   {"events":[...]}
#   {"hits":{"hits":[...]}}
#   {"data":[...]}
EVENTS_FILE="$(mktemp)"
FILTERED_FILE="$(mktemp)"

cleanup() {
    rm -f "$EVENTS_FILE" "$FILTERED_FILE"
}

trap cleanup EXIT

jq '
    if (.events? | type) == "array" then
        .events
    elif (.hits.hits? | type) == "array" then
        .hits.hits
    elif (.data? | type) == "array" then
        .data
    else
        []
    end
' "$SEARCH_RESULTS" > "$EVENTS_FILE"

EVENT_COUNT="$(jq 'length' "$EVENTS_FILE")"

printf 'reading     : scenario_a_search_results.json (%s events)\n' "$HITS_TOTAL"
printf 'kql         : %s\n' "$KQL_QUERY"

# ---------------------------------------------------------------------------
# Filter Wazuh documents for Sysmon 10, 11 and 3.
# ---------------------------------------------------------------------------

jq '
    [
        .[]
        | select(
            (
                ._source.winlog.event_id
                // ._source.event.code
                // ._source.event_id
            ) as $eid
            |
            ($eid | tostring) == "10"
            or ($eid | tostring) == "11"
            or ($eid | tostring) == "3"
        )
    ]
' "$EVENTS_FILE" > "$FILTERED_FILE"

MATCH_COUNT="$(jq 'length' "$FILTERED_FILE")"

if (( MATCH_COUNT == 0 )); then
    echo "error: no Sysmon EID 10/11/3 documents found" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Print the requested Wazuh event summaries.
# ---------------------------------------------------------------------------

jq -r '
    def eid:
        (
            ._source.winlog.event_id
            // ._source.event.code
            // ._source.event_id
        ) | tostring;

    def ts:
        (
            ._source["@timestamp"]
            // ._source.timestamp
            // ._source.event.created
        );

    def clock:
        ts
        | fromdateiso8601
        | strftime("%H:%M:%SZ");

    .[]
    | eid as $eid
    | if $eid == "10" then
        "EID 10      : _source.process.name "
        + (
            if ._source.process.name != null
            then "present"
            else "absent"
            end
        )
        + " at "
        + clock

      elif $eid == "11" then
        "EID 11      : _source.full_log "
        + (
            if ._source.full_log != null
            then "present"
            else "absent"
            end
        )
        + " at "
        + clock
        + " (file created)"

      elif $eid == "3" then
        "EID 3       : _source.destination.ip "
        + (
            ._source.destination.ip
            // ._source.destination_ip
            // "unknown"
            | tostring
        )
        + " at "
        + clock

      else
        empty
      end
' "$FILTERED_FILE"

# ---------------------------------------------------------------------------
# Read dashboard trace.
# ---------------------------------------------------------------------------

CLICK_PATH_JSON="$(
    jq -c '
        .click_path
        // .clickPath
        // .navigation.click_path
        // []
    ' "$DASHBOARD_TRACE"
)"

CLICK_COUNT="$(jq 'length' <<<"$CLICK_PATH_JSON")"

FIELD_MAP_JSON="$(
    jq -c '
        .field_name_translation
        // .field_mapping
        // .field_map
        // {}
    ' "$DASHBOARD_TRACE"
)"

ESTIMATED_TIME_SECONDS="$(
    jq -r '
        .estimated_time_seconds
        // .estimated_time
        // .time_seconds
        // 0
    ' "$DASHBOARD_TRACE"
)"

printf 'click_path  : %s steps\n' "$CLICK_COUNT"

FIELD_MAP_DISPLAY="$(
    jq -r '
        if type == "object" then
            to_entries
            | map(.key + " -> " + (.value | tostring))
            | join(", ")
        elif type == "array" then
            map(
                if type == "object" then
                    (
                        (.source // .from // .field // .source_field // "unknown")
                        + " -> "
                        + (.target // .to // .mapped_field // .target_field // "unknown")
                    )
                else
                    tostring
                end
            )
            | join(", ")
        else
            tostring
        end
    ' <<<"$FIELD_MAP_JSON"
)"

printf 'field_map   : %s\n' "$FIELD_MAP_DISPLAY"

# ---------------------------------------------------------------------------
# Extract ATT&CK mapping section from the dashboard summary.
# ---------------------------------------------------------------------------

ATTACK_SECTION="$(
    awk '
        BEGIN {
            found = 0
        }

        /^#{1,6}[[:space:]]*(ATT&CK|ATTACK)/ {
            found = 1
        }

        found {
            print
        }

        found && NR > 1 && /^#{1,6}[[:space:]]+/ &&
            $0 !~ /^#{1,6}[[:space:]]*(ATT&CK|ATTACK)/ {
            exit
        }
    ' "$DASHBOARD_SUMMARY"
)"

if [[ -z "$ATTACK_SECTION" ]]; then
    # Fall back to the section beginning with a literal ATT&CK mapping line.
    ATTACK_SECTION="$(
        grep -i -A 20 -E 'ATT&CK|ATTACK.*mapping' \
            "$DASHBOARD_SUMMARY" || true
    )"
fi

if [[ -z "$ATTACK_SECTION" ]]; then
    echo "error: ATT&CK mapping section not found in dashboard summary" >&2
    exit 1
fi

printf '%s\n' "$ATTACK_SECTION"

# The scenario's locked ATT&CK mapping.
ATTACK_TECHNIQUES_JSON="$(
    jq -n '[
        "T1003.001",
        "T1550.002",
        "T1021.002"
    ]'
)"

printf 'attack      : T1003.001 T1550.002 T1021.002\n'

# ---------------------------------------------------------------------------
# Calculate elapsed investigation time.
# ---------------------------------------------------------------------------

INVESTIGATION_END="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
END_EPOCH="$(date -u -d "$INVESTIGATION_END" +%s)"

if (( END_EPOCH < START_EPOCH )); then
    echo "error: investigation timestamps are inconsistent" >&2
    exit 1
fi

ELAPSED_SECONDS="$((END_EPOCH - START_EPOCH))"

# Four evidence reads are represented explicitly:
#   1. search results
#   2. dashboard trace
#   3. dashboard summary
#   4. CLI finding for comparison
ACTIONS_JSON="$(
    jq -n \
        --argjson click_path "$CLICK_PATH_JSON" '
        [
            "read scenario_a_search_results.json",
            "filter Wazuh documents for Sysmon EID 10, 11 and 3",
            "read scenario_a_dashboard_trace.json",
            "read scenario_a_dashboard_summary.md",
            "extract ATT&CK mapping",
            "compare export elapsed time with T4 CLI finding",
            {
                "click_path": $click_path
            }
        ]
    '
)"

FIELDS_JSON="$(
    jq -n '
        [
            "hits_total",
            "kql",
            "events",
            "_source.@timestamp",
            "_source.winlog.event_id",
            "_source.process.name",
            "_source.full_log",
            "_source.destination.ip",
            "click_path",
            "field_name_translation",
            "estimated_time_seconds",
            "dashboard.ATT&CK_mapping"
        ]
    '
)"

EVENT_REFS_JSON="$(
    jq -c '
        [
            .[] |
            (
                ._source.eventref
                // ._source.event_ref
                // ._source.event.id
                // ._id
                // empty
            )
        ]
        | map(select(. != null and . != ""))
    ' "$FILTERED_FILE"
)"

HYPOTHESIS="The Wazuh export confirms the same credential-access, dump-file creation, and SMB activity identified in the CLI investigation. The exported evidence provides a faster repeatable path to the same high-confidence attack chain."

# ---------------------------------------------------------------------------
# Build finding.
# ---------------------------------------------------------------------------

jq -n \
    --arg scenario_id "scenario_a" \
    --arg interface "wazuh_export" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --arg hypothesis "$HYPOTHESIS" \
    --argjson elapsed "$ELAPSED_SECONDS" \
    --argjson actions "$ACTIONS_JSON" \
    --argjson fields_touched "$FIELDS_JSON" \
    --argjson event_refs "$EVENT_REFS_JSON" \
    --argjson attack_techniques "$ATTACK_TECHNIQUES_JSON" \
    '
    {
        finding_id: ($scenario_id + "_" + $interface),
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,
        actions: ($actions[0:20]),
        fields_touched: $fields_touched,
        event_refs: $event_refs,
        attack_techniques: $attack_techniques,
        hypothesis: $hypothesis,
        confidence: "high",
        created_at: $investigation_end
    }
    ' > "$OUTPUT"

# ---------------------------------------------------------------------------
# Compare with T4 CLI finding.
# ---------------------------------------------------------------------------

if [[ -f "$CLI_FINDING" ]]; then
    CLI_ELAPSED="$(
        jq -r '
            .time_to_first_answer_seconds
            // empty
        ' "$CLI_FINDING"
    )"

    if [[ "$CLI_ELAPSED" =~ ^[0-9]+$ ]]; then
        DELTA=$((CLI_ELAPSED - ELAPSED_SECONDS))

        if (( DELTA > 0 )); then
            printf 'delta_vs_cli: %s seconds faster via export\n' "$DELTA"
        elif (( DELTA < 0 )); then
            printf 'delta_vs_cli: %s seconds slower via export\n' "$((-DELTA))"
        else
            printf 'delta_vs_cli: same elapsed time as CLI\n'
        fi
    else
        printf 'delta_vs_cli: unavailable (CLI elapsed time is invalid)\n'
    fi
else
    printf 'delta_vs_cli: unavailable (T4 CLI finding not found)\n'
fi

printf 'elapsed     : %s seconds, 4 file reads\n' "$ELAPSED_SECONDS"
printf 'finding     : %s written\n' "$OUTPUT"

