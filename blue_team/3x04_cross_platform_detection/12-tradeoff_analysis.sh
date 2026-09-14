#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FINDINGS_DIR="${SCRIPT_DIR}/findings"
COMPARISON_DIR="${SCRIPT_DIR}/comparison"

OUTPUT_JSON="${COMPARISON_DIR}/tradeoff_table.json"
OUTPUT_MD="${COMPARISON_DIR}/tradeoff_table.md"

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

ALL_FINDINGS="${TMP_DIR}/all_findings.json"

# Load every JSON finding from findings/. Invalid or unrelated JSON files
# are rejected rather than silently included in the comparison.
shopt -s nullglob
FINDING_FILES=("${FINDINGS_DIR}"/*.json)
shopt -u nullglob

if (( ${#FINDING_FILES[@]} == 0 )); then
    printf 'error: no JSON findings found in %s\n' "$FINDINGS_DIR" >&2
    exit 1
fi

jq -s '
    map(
        select(
            (.scenario_id? | type == "string")
            and (.interface? | type == "string")
            and (.time_to_first_answer_seconds? | type == "number")
            and (.actions? | type == "array")
        )
    )
' "${FINDING_FILES[@]}" > "$ALL_FINDINGS"

VALID_COUNT="$(jq 'length' "$ALL_FINDINGS")"

if (( VALID_COUNT == 0 )); then
    printf 'error: no findings matched the required schema\n' >&2
    exit 1
fi

# Pair CLI and wazuh_export findings by scenario_id.
PAIRS_FILE="${TMP_DIR}/pairs.json"

jq '
    group_by(.scenario_id)
    | map({
        scenario_id: .[0].scenario_id,
        cli: (map(select(.interface == "cli")) | .[0] // null),
        wazuh_export: (map(select(.interface == "wazuh_export")) | .[0] // null)
    })
    | map(select(.cli != null and .wazuh_export != null))
    | sort_by(.scenario_id)
' "$ALL_FINDINGS" > "$PAIRS_FILE"

SCENARIO_COUNT="$(jq 'length' "$PAIRS_FILE")"

if (( SCENARIO_COUNT == 0 )); then
    printf 'error: no scenarios contained both CLI and wazuh_export findings\n' >&2
    exit 1
fi

# Attribute the interface advantage to one operational cause.
#
# The attribution is deliberately rule-based and uses observable finding
# properties rather than subjective interface preference.
jq '
    def action_text:
        (.actions // [])
        | tostring
        | ascii_downcase;

    def cause_for_cli:
        if (
            (action_text | contains("reproduc"))
            or ((.fields_touched // []) | any(. == "eventref"))
        ) then
            "reproducibility"
        elif (
            (action_text | contains("query"))
            or (action_text | contains("jq"))
            or (action_text | contains("pipeline"))
        ) then
            "pipeline_expressiveness"
        else
            "text_speed_iteration"
        end;

    def cause_for_export:
        if (
            ((.fields_touched // []) | any(
                . == "_source.source.zone"
                or . == "_source.agent.labels"
                or . == "_source.agent.name"
                or . == "_source.user.name"
            ))
        ) then
            "native_field_surface"
        elif (
            (action_text | contains("dashboard"))
            or (action_text | contains("click_path"))
            or (action_text | contains("timeline"))
        ) then
            "timeline_visualization"
        elif (
            (action_text | contains("filter"))
            or (action_text | contains("discover"))
        ) then
            "filter_bar_efficiency"
        elif (
            (action_text | contains("fallback"))
            or (action_text | contains("inventory"))
            or (action_text | contains("context"))
        ) then
            "context_join_ergonomics"
        else
            "native_field_surface"
        end;

    map(
        . as $pair
        | ($pair.cli.time_to_first_answer_seconds
           - $pair.wazuh_export.time_to_first_answer_seconds) as $time_delta_cli_minus_export
        | (($pair.cli.actions | length)
           - ($pair.wazuh_export.actions | length)) as $action_delta_cli_minus_export
        | (
            if $time_delta_cli_minus_export < 0 then
                "cli"
            elif $time_delta_cli_minus_export > 0 then
                "wazuh_export"
            else
                "tie"
            end
        ) as $faster_interface
        | {
            scenario_id: $pair.scenario_id,

            cli: {
                time_to_first_answer_seconds:
                    $pair.cli.time_to_first_answer_seconds,
                action_count:
                    ($pair.cli.actions | length)
            },

            wazuh_export: {
                time_to_first_answer_seconds:
                    $pair.wazuh_export.time_to_first_answer_seconds,
                action_count:
                    ($pair.wazuh_export.actions | length)
            },

            deltas: {
                time_seconds_cli_minus_export:
                    $time_delta_cli_minus_export,
                action_count_cli_minus_export:
                    $action_delta_cli_minus_export
            },

            faster_interface: $faster_interface,

            advantage_cause: (
                if $faster_interface == "cli" then
                    $pair.cli | cause_for_cli
                elif $faster_interface == "wazuh_export" then
                    $pair.wazuh_export | cause_for_export
                else
                    "none"
                end
            ),

            advantage_explanation: (
                if $faster_interface == "cli" then
                    "CLI was faster because its command-driven workflow reduced interaction overhead and supported direct text-based iteration."
                elif $faster_interface == "wazuh_export" then
                    "Wazuh export was faster because the relevant structured fields or dashboard workflow reduced the effort required to isolate the signal."
                else
                    "Neither interface was faster; both produced the same time to first answer."
                end
            )
        )
    )
' "$PAIRS_FILE" > "${TMP_DIR}/comparisons.json"

# Emit the JSON artifact.
jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --argjson scenarios "$(cat "${TMP_DIR}/comparisons.json")" \
    '
    {
        generated_at: $generated_at,
        scenarios_analyzed: ($scenarios | length),
        methodology: {
            pairing_key: "scenario_id",
            interfaces: ["cli", "wazuh_export"],
            time_delta_definition: "CLI time minus Wazuh export time",
            action_delta_definition: "CLI action count minus Wazuh export action count",
            advantage_attribution: "deterministic rule based on observed fields and actions"
        },
        scenarios: $scenarios,
        totals: {
            cli_advantages: (
                [$scenarios[] | select(.faster_interface == "cli")] | length
            ),
            export_advantages: (
                [$scenarios[] | select(.faster_interface == "wazuh_export")] | length
            ),
            ties: (
                [$scenarios[] | select(.faster_interface == "tie")] | length
            )
        }
    }
    ' > "$OUTPUT_JSON"

# Emit the Markdown artifact.
{
    printf '# Cross-Platform Trade-off Analysis\n\n'
    printf 'Generated: `%s`\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '## Method\n\n'
    printf '%s\n\n' \
        'Findings are paired by `scenario_id`. Time delta is calculated as **CLI time minus Wazuh export time**. A positive time delta means the export was faster.'
    printf '## Trade-off table\n\n'
    printf '| Scenario | CLI time (s) | Export time (s) | Δ time (CLI − export) | CLI actions | Export actions | Δ actions | Faster interface | Cause |'
    printf '\n'
    printf '|---|---:|---:|---:|---:|---:|---:|---|---|\n'

    jq -r '
        .[]
        | [
            .scenario_id,
            (.cli.time_to_first_answer_seconds | tostring),
            (.wazuh_export.time_to_first_answer_seconds | tostring),
            (.deltas.time_seconds_cli_minus_export | tostring),
            (.cli.action_count | tostring),
            (.wazuh_export.action_count | tostring),
            (.deltas.action_count_cli_minus_export | tostring),
            .faster_interface,
            .advantage_cause
        ]
        | "| " + (join(" | ")) + " |"
    ' "${TMP_DIR}/comparisons.json"

    printf '\n## Attribution details\n\n'

    jq -r '
        .[]
        | "### " + .scenario_id + "\n\n"
        + "- **Faster interface:** " + .faster_interface + "\n"
        + "- **Operational cause:** `" + .advantage_cause + "`\n"
        + "- **Explanation:** " + .advantage_explanation + "\n"
        + "- **Time delta:** " + (.deltas.time_seconds_cli_minus_export | tostring) + " seconds, CLI minus export\n"
        + "- **Action-count delta:** " + (.deltas.action_count_cli_minus_export | tostring) + ", CLI minus export\n"
    ' "${TMP_DIR}/comparisons.json"

    printf '## Summary\n\n'
    jq -r '
        "- Export advantages: " + (.totals.export_advantages | tostring) + "\n"
        + "- CLI advantages: " + (.totals.cli_advantages | tostring) + "\n"
        + "- Ties: " + (.totals.ties | tostring) + "\n"
    ' "$OUTPUT_JSON"
} > "$OUTPUT_MD"

printf 'scenarios analyzed   : %s\n' "$SCENARIO_COUNT"

EXPORT_ADVANTAGES="$(
    jq -r '
        [.[] | select(.faster_interface == "wazuh_export") | .scenario_id]
        | if length == 0 then "(none)" else join(", ") end
    ' "${TMP_DIR}/comparisons.json"
)"

CLI_ADVANTAGES="$(
    jq -r '
        [.[] | select(.faster_interface == "cli") | .scenario_id]
        | if length == 0 then "(none)" else join(", ") end
    ' "${TMP_DIR}/comparisons.json"
)"

printf 'export advantages    : %s\n' "$EXPORT_ADVANTAGES"
printf 'cli advantages       : %s\n' "$CLI_ADVANTAGES"
printf 'comparison/tradeoff_table.json written\n'
printf 'comparison/tradeoff_table.md written\n'
