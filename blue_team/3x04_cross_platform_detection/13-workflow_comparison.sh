#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FINDINGS_DIR="${SCRIPT_DIR}/findings"
COMPARISON_DIR="${SCRIPT_DIR}/comparison"
OUTPUT_FILE="${COMPARISON_DIR}/workflow_comparison.json"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$COMPARISON_DIR"

if ! command -v jq >/dev/null 2>&1; then
    printf 'error: jq is required\n' >&2
    exit 1
fi

if [[ ! -d "$FINDINGS_DIR" ]]; then
    printf 'error: findings directory not found: %s\n' "$FINDINGS_DIR" >&2
    exit 1
fi

shopt -s nullglob
FINDING_FILES=("${FINDINGS_DIR}"/*.json)
shopt -u nullglob

if (( ${#FINDING_FILES[@]} == 0 )); then
    printf 'error: no JSON findings found in %s\n' "$FINDINGS_DIR" >&2
    exit 1
fi

ALL_FINDINGS="${TMP_DIR}/all_findings.json"

jq -s '
    map(
        select(
            (.scenario_id? | type == "string")
            and (.interface? | type == "string")
            and (.time_to_first_answer_seconds? | type == "number")
            and (.actions? | type == "array")
            and (.fields_touched? | type == "array")
            and (.event_refs? | type == "array")
            and (.confidence? | type == "string")
        )
    )
' "${FINDING_FILES[@]}" > "$ALL_FINDINGS"

LOADED_COUNT="$(jq 'length' "$ALL_FINDINGS")"

if (( LOADED_COUNT == 0 )); then
    printf 'error: no findings matched the required schema\n' >&2
    exit 1
fi

CLI_COUNT="$(
    jq '[.[] | select(.interface == "cli")] | length' "$ALL_FINDINGS"
)"

EXPORT_COUNT="$(
    jq '[.[] | select(.interface == "wazuh_export")] | length' "$ALL_FINDINGS"
)"

if (( CLI_COUNT == 0 || EXPORT_COUNT == 0 )); then
    printf 'error: both cli and wazuh_export findings are required\n' >&2
    exit 1
fi

# Build normalized records with all computed counts.
NORMALIZED_FILE="${TMP_DIR}/normalized.json"

jq '
    map({
        scenario_id: .scenario_id,
        interface: .interface,
        time_to_first_answer_seconds: .time_to_first_answer_seconds,
        action_count: (.actions | length),
        fields_touched_count: (.fields_touched | length),
        event_refs_count: (.event_refs | length),
        confidence: .confidence
    })
' "$ALL_FINDINGS" > "$NORMALIZED_FILE"

# Generate the complete JSON artifact.
jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --argjson records "$(cat "$NORMALIZED_FILE")" '
    def median:
        sort
        | if length == 0 then
            null
          elif (length % 2) == 1 then
            .[(length / 2) | floor]
          else
            (
                .[(length / 2) - 1]
                + .[(length / 2)]
            ) / 2
          end;

    def interface_summary($interface):
        ($records | map(select(.interface == $interface))) as $items
        | {
            finding_count: ($items | length),
            totals: {
                time_to_first_answer_seconds:
                    ([$items[].time_to_first_answer_seconds] | add // 0),
                action_count:
                    ([$items[].action_count] | add // 0),
                fields_touched_count:
                    ([$items[].fields_touched_count] | add // 0),
                event_refs_count:
                    ([$items[].event_refs_count] | add // 0)
            },
            averages: {
                time_to_first_answer_seconds:
                    (if ($items | length) > 0
                     then ([$items[].time_to_first_answer_seconds] | add) / ($items | length)
                     else 0
                     end),
                action_count:
                    (if ($items | length) > 0
                     then ([$items[].action_count] | add) / ($items | length)
                     else 0
                     end),
                fields_touched_count:
                    (if ($items | length) > 0
                     then ([$items[].fields_touched_count] | add) / ($items | length)
                     else 0
                     end),
                event_refs_count:
                    (if ($items | length) > 0
                     then ([$items[].event_refs_count] | add) / ($items | length)
                     else 0
                     end)
            },
            medians: {
                time_to_first_answer_seconds:
                    ([$items[].time_to_first_answer_seconds] | median),
                action_count:
                    ([$items[].action_count] | median),
                fields_touched_count:
                    ([$items[].fields_touched_count] | median),
                event_refs_count:
                    ([$items[].event_refs_count] | median)
            }
        };

    def confidence_summary($interface):
        ($records | map(select(.interface == $interface))) as $items
        | {
            low: ([$items[] | select(.confidence == "low")] | length),
            medium: ([$items[] | select(.confidence == "medium")] | length),
            high: ([$items[] | select(.confidence == "high")] | length)
        };

    ($records | group_by(.scenario_id)) as $scenario_groups
    | {
        per_interface: {
            cli: interface_summary("cli"),
            wazuh_export: interface_summary("wazuh_export")
        },

        per_scenario: [
            $scenario_groups[]
            | {
                scenario_id: .[0].scenario_id,
                cli: (
                    map(select(.interface == "cli")) | .[0] // null
                ),
                wazuh_export: (
                    map(select(.interface == "wazuh_export")) | .[0] // null
                )
            }
            | . as $pair
            | {
                scenario_id: $pair.scenario_id,
                cli: $pair.cli,
                wazuh_export: $pair.wazuh_export,
                deltas: (
                    if ($pair.cli != null and $pair.wazuh_export != null) then
                        {
                            time_to_first_answer_seconds:
                                (
                                    $pair.wazuh_export.time_to_first_answer_seconds
                                    - $pair.cli.time_to_first_answer_seconds
                                ),
                            action_count:
                                (
                                    $pair.wazuh_export.action_count
                                    - $pair.cli.action_count
                                ),
                            fields_touched_count:
                                (
                                    $pair.wazuh_export.fields_touched_count
                                    - $pair.cli.fields_touched_count
                                ),
                            event_refs_count:
                                (
                                    $pair.wazuh_export.event_refs_count
                                    - $pair.cli.event_refs_count
                                )
                        }
                    else
                        null
                    end
                )
            }
            | . + {
                faster_interface: (
                    if .deltas == null then
                        "incomplete"
                    elif .deltas.time_to_first_answer_seconds < 0 then
                        "wazuh_export"
                    elif .deltas.time_to_first_answer_seconds > 0 then
                        "cli"
                    else
                        "tie"
                    end
                )
            }
        ],

        confidence_distribution: {
            cli: confidence_summary("cli"),
            wazuh_export: confidence_summary("wazuh_export")
        },

        generated_at: $generated_at
    }
' > "$OUTPUT_FILE"

# Print a vendor-brief-safe summary using generated values.
printf 'findings loaded       : %s (%s cli + %s wazuh_export)\n' \
    "$LOADED_COUNT" "$CLI_COUNT" "$EXPORT_COUNT"

printf 'per interface totals:\n'

jq -r '
    def fmt:
        if . == null then "n/a"
        elif (floor == .) then tostring
        else tostring
        end;

    .per_interface
    | to_entries[]
    | "  \(.key | if . == "wazuh_export" then "wazuh_export" else . end): "
      + (.value.totals.time_to_first_answer_seconds | fmt)
      + "s total, avg "
      + (.value.averages.time_to_first_answer_seconds | fmt)
      + "s, median "
      + (.value.medians.time_to_first_answer_seconds | fmt)
      + "s, "
      + (.value.totals.action_count | tostring)
      + " actions"
' "$OUTPUT_FILE"

printf 'per interface confidence:\n'

jq -r '
    .confidence_distribution
    | to_entries[]
    | "  \(.key): high=\(.value.high) medium=\(.value.medium) low=\(.value.low)"
' "$OUTPUT_FILE"

printf 'per scenario deltas (wazuh_export - cli):\n'

jq -r '
    .per_scenario[]
    | if .deltas == null then
        "  \(.scenario_id | .): incomplete pair"
      else
        (
            "  "
            + .scenario_id
            + "      : "
            + (
                if .deltas.time_to_first_answer_seconds > 0 then
                    "+" + (.deltas.time_to_first_answer_seconds | tostring)
                else
                    (.deltas.time_to_first_answer_seconds | tostring)
                end
            )
            + "s ("
            + (
                if .faster_interface == "wazuh_export" then
                    "wazuh_export faster"
                elif .faster_interface == "cli" then
                    "cli faster"
                else
                    "tie"
                end
            )
            + ")"
        )
      end
' "$OUTPUT_FILE"

printf 'comparison/workflow_comparison.json written\n'
