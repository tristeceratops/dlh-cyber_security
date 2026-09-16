#!/bin/bash
set -euo pipefail

fail() {
    echo "[baseline] ERROR: $*" >&2
    exit 1
}

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || fail "$name is not set"
}

require_env SHIFT_WORKSPACE
require_env BASELINE_BIN

PIPELINE_RUN="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
BASELINE_OUT="$ENRICHED_DIR/baseline.json"
BASELINE_RUN="$SHIFT_WORKSPACE/runtime/baseline_run.json"
BASELINE_LOG="$SHIFT_WORKSPACE/runtime/baseline_run.log"

[[ -s "$PIPELINE_RUN" ]] || \
    fail "pipeline_run.json is absent or empty: $PIPELINE_RUN"

jq -e . "$PIPELINE_RUN" >/dev/null 2>&1 || \
    fail "pipeline_run.json is invalid JSON: $PIPELINE_RUN"

pipeline_status="$(jq -r '.exit_status // -1' "$PIPELINE_RUN")"
[[ "$pipeline_status" == "0" ]] || \
    fail "pipeline check failed: exit_status=$pipeline_status"

echo "[baseline] pipeline check: OK"

if [[ -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
    EVENTS_FILE="$ENRICHED_DIR/enriched_events.jsonl"
elif [[ -s "$ENRICHED_DIR/enriched_events.json" ]]; then
    EVENTS_FILE="$ENRICHED_DIR/enriched_events.json"
else
    fail "no enriched events file found"
fi

[[ -x "$BASELINE_BIN" ]] || \
    fail "BASELINE_BIN is not executable: $BASELINE_BIN"

echo "[baseline] invoking $BASELINE_BIN"
echo "[baseline] input: $EVENTS_FILE"
echo "[baseline] output: $BASELINE_OUT"

started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

baseline_version="unknown"
if "$BASELINE_BIN" --version >/tmp/baseline_version.$$ 2>&1; then
    baseline_version="$(head -n 1 /tmp/baseline_version.$$ || true)"
    [[ -n "$baseline_version" ]] || baseline_version="unknown"
fi
rm -f /tmp/baseline_version.$$

: > "$BASELINE_LOG"

set +e
"$BASELINE_BIN" "$EVENTS_FILE" "$BASELINE_OUT" >"$BASELINE_LOG" 2>&1
baseline_status=$?
set -e

ended_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if (( baseline_status != 0 )); then
    fail "baseline script failed with exit status $baseline_status; see $BASELINE_LOG"
fi

[[ -s "$BASELINE_OUT" ]] || \
    fail "baseline.json is absent or empty: $BASELINE_OUT"

jq -e . "$BASELINE_OUT" >/dev/null 2>&1 || \
    fail "baseline.json is invalid JSON: $BASELINE_OUT"

echo "[baseline] baseline output: OK"

# Support common baseline layouts:
#   {"hosts": {...}}
#   {"hosts": [...]}
#   {"deviation_markers": [...]}
#
# The normalization below produces the locked runtime schema without
# changing the source baseline.json.

hosts_total="$(
    jq -r '
        if (.hosts? | type) == "object" then
            (.hosts | length)
        elif (.hosts? | type) == "array" then
            ([.hosts[]?.host // .hosts[]?.hostname] | unique | length)
        elif (.host_profiles? | type) == "object" then
            (.host_profiles | length)
        else
            (
                [
                    .deviation_markers[]?.host,
                    .deviations[]?.host,
                    .markers[]?.host
                ]
                | map(select(type == "string"))
                | unique
                | length
            )
        end
    ' "$BASELINE_OUT"
)"

[[ "$hosts_total" =~ ^[0-9]+$ ]] || \
    fail "could not determine hosts_total from baseline.json"

(( hosts_total > 0 )) || \
    fail "baseline completed but hosts_total is zero"

# Extract all supported deviation markers into the locked marker schema.
jq -c '
    def marker_name:
        if .marker then .marker
        elif .type == "unseen_src_ip" then "unseen_src_ip"
        elif .type == "off_hours_login" then "off_hours_login"
        elif .type == "unusual_parent_process" then "unusual_parent_process"
        elif .type == "unknown_destination" then "unknown_destination"
        elif .type == "new_service" then "new_service"
        elif .type == "encoding_anomaly" then "encoding_anomaly"
        else (.type // "unknown")
        end;

    def marker_array:
        if (.deviation_markers? | type) == "array" then
            .deviation_markers
        elif (.deviations? | type) == "array" then
            .deviations
        elif (.markers? | type) == "array" then
            .markers
        else
            []
        end;

    marker_array[]
    | {
        host: (.host // .hostname // "unknown"),
        marker: marker_name,
        field: (.field // .trigger_field // .source_field // "unknown"),
        observed_value: (
            .observed_value
            // .observed
            // .value
            // ""
            | tostring
        ),
        baseline_reference: (
            .baseline_reference
            // .expected
            // .baseline
            // ""
            | tostring
        ),
        deviation_score: (
            .deviation_score
            // .score
            // 0
            | tonumber
        )
    }
    | select(
        .marker == "unseen_src_ip"
        or .marker == "off_hours_login"
        or .marker == "unusual_parent_process"
        or .marker == "unknown_destination"
        or .marker == "new_service"
        or .marker == "encoding_anomaly"
    )
' "$BASELINE_OUT" > "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"

markers_total="$(wc -l < "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp" | tr -d ' ')"

hosts_with_deviations="$(
    jq -s '
        map(.host)
        | unique
        | length
    ' "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"
)"

[[ "$hosts_with_deviations" =~ ^[0-9]+$ ]] || \
    fail "invalid hosts_with_deviations value"

# Calculate total deviation score per host and select five highest.
hot_hosts_json="$(
    jq -s '
        group_by(.host)
        | map({
            host: .[0].host,
            score: (map(.deviation_score) | add)
          })
        | sort_by(-.score, .host)
        | .[:5]
    ' "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"
)"

hot_hosts="$(
    jq -r 'map(.host) | .[]?' <<< "$hot_hosts_json"
)"

# Print one-line summary for every hot host.
while IFS= read -r host; do
    [[ -n "$host" ]] || continue

    score="$(
        jq -r --arg host "$host" '
            map(select(.host == $host) | .deviation_score)
            | add // 0
        ' "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"
    )"

    marker_count="$(
        jq -r --arg host "$host" '
            map(select(.host == $host))
            | length
        ' "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"
    )"

    echo "[baseline] hot host: $host score=$score markers=$marker_count"
done <<< "$hot_hosts"


declare -A marker_counts=()

# Marker-type summary.
for marker in unseen_src_ip off_hours_login unusual_parent_process unknown_destination new_service encoding_anomaly; do
    count="$(
        jq -s --arg marker "$marker" '
            map(select(.marker == $marker))
            | length
        ' "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"
    )"

    case "$marker" in
        off_hours_login)
            marker_label="off_hours"
            ;;
        *)
            marker_label="$marker"
            ;;
    esac

    marker_counts["$marker_label"]="$count"
done

echo "[baseline] hosts processed: $hosts_total"
echo "[baseline] hosts with deviations: $hosts_with_deviations"
echo "[baseline] hot hosts: $(echo "$hot_hosts" | paste -sd' ' -)"
echo "[baseline] markers: $markers_total total (unseen_src_ip: ${marker_counts[unseen_src_ip]}  off_hours: ${marker_counts[off_hours]}  new_service: ${marker_counts[new_service]})"

jq -n \
    --arg baseline_version "$baseline_version" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    --argjson hosts_total "$hosts_total" \
    --argjson hosts_with_deviations "$hosts_with_deviations" \
    --argjson deviation_markers "$(
        jq -s '.' "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"
    )" \
    --argjson hot_hosts "$(
        jq -c 'map(.host)' <<< "$hot_hosts_json"
    )" \
    --argjson exit_status "$baseline_status" \
    '{
      baseline_version: $baseline_version,
      hosts_total: $hosts_total,
      hosts_with_deviations: $hosts_with_deviations,
      deviation_markers: $deviation_markers,
      hot_hosts: $hot_hosts,
      started_at: $started_at,
      ended_at: $ended_at,
      exit_status: $exit_status
    }' > "$BASELINE_RUN"

rm -f "$SHIFT_WORKSPACE/runtime/.baseline_markers.tmp"

echo "[baseline] baseline_run.json written"
