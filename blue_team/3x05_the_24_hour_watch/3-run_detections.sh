#!/bin/bash
set -euo pipefail

fail() {
    echo "[detect] ERROR: $*" >&2
    exit 1
}

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || fail "$name is not set"
}

require_env SHIFT_WORKSPACE
require_env CATALOG_DIR

PIPELINE_RUN="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
ALERT_QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
CATALOG_RUN="$SHIFT_WORKSPACE/runtime/catalog_run.json"
DETECT_LOG="$SHIFT_WORKSPACE/runtime/detection_run.log"

[[ -s "$PIPELINE_RUN" ]] || \
    fail "pipeline_run.json is absent or empty: $PIPELINE_RUN"

jq -e . "$PIPELINE_RUN" >/dev/null 2>&1 || \
    fail "pipeline_run.json is invalid JSON"

pipeline_status="$(jq -r '.exit_status // -1' "$PIPELINE_RUN")"
[[ "$pipeline_status" == "0" ]] || \
    fail "pipeline check failed: exit_status=$pipeline_status"

echo "[detect] pipeline check: OK"

if [[ -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
    EVENTS_FILE="$ENRICHED_DIR/enriched_events.jsonl"
elif [[ -s "$ENRICHED_DIR/enriched_events.json" ]]; then
    EVENTS_FILE="$ENRICHED_DIR/enriched_events.json"
else
    fail "no enriched events file found"
fi

# Support the standard 3x02 layout as well as a catalog whose rules
# are stored directly under CATALOG_DIR.
if [[ -d "$CATALOG_DIR/rules/sigma" ]]; then
    SIGMA_RULE_DIR="$CATALOG_DIR/rules/sigma"
else
    SIGMA_RULE_DIR="$CATALOG_DIR"
fi

[[ -d "$SIGMA_RULE_DIR" && -r "$SIGMA_RULE_DIR" ]] || \
    fail "Sigma rule directory is not readable: $SIGMA_RULE_DIR"

catalog_rules_total="$(
    find "$SIGMA_RULE_DIR" -type f -name '*.yml' -print | wc -l | tr -d ' '
)"

[[ "$catalog_rules_total" =~ ^[0-9]+$ ]] || \
    fail "could not count catalog rules"

(( catalog_rules_total > 0 )) || \
    fail "no .yml Sigma rules found in $SIGMA_RULE_DIR"

echo "[detect] catalog loaded: $catalog_rules_total rules"

[[ -x "${TRIAGE_BIN:-/nonexistent}" || -x "${CATALOG_DIR}/run_detections.sh" || -x "${CATALOG_DIR}/detect.sh" || -x "${CATALOG_DIR}/run_sigma.sh" || command -v sigma-cli >/dev/null 2>&1 ]] || \
    fail "no detection runner found"

echo "[detect] invoking detection runner"

started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
: > "$DETECT_LOG"

# Prefer a dedicated 3x02 wrapper if present. Otherwise invoke sigma-cli.
RUNNER=""
if [[ -x "$CATALOG_DIR/run_detections.sh" ]]; then
    RUNNER="$CATALOG_DIR/run_detections.sh"
elif [[ -x "$CATALOG_DIR/detect.sh" ]]; then
    RUNNER="$CATALOG_DIR/detect.sh"
elif [[ -x "$CATALOG_DIR/run_sigma.sh" ]]; then
    RUNNER="$CATALOG_DIR/run_sigma.sh"
fi

set +e

if [[ -n "$RUNNER" ]]; then
    "$RUNNER" "$EVENTS_FILE" "$SIGMA_RULE_DIR" "$ALERT_QUEUE" \
        >"$DETECT_LOG" 2>&1
    detection_status=$?
else
    # The catalog is passed explicitly through --path and the output
    # queue is supplied through the JSON output option expected by the
    # local runner. If the installed sigma-cli exposes a different
    # invocation, replace this block with the exact 3x02 wrapper.
    sigma-cli --help >/dev/null 2>&1
    detection_status=$?

    if (( detection_status == 0 )); then
        sigma-cli \
            -t "$EVENTS_FILE" \
            -r "$SIGMA_RULE_DIR" \
            -o "$ALERT_QUEUE" \
            >"$DETECT_LOG" 2>&1
        detection_status=$?
    fi
fi

set -e

ended_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if (( detection_status != 0 )); then
    fail "detection runner failed with exit status $detection_status; see $DETECT_LOG"
fi

[[ -s "$ALERT_QUEUE" ]] || \
    fail "alert_queue.json is absent or empty: $ALERT_QUEUE"

jq -e . "$ALERT_QUEUE" >/dev/null 2>&1 || \
    fail "alert_queue.json is invalid JSON"

echo "[detect] alert queue: OK"

# Normalize supported queue layouts to an array.
alerts_json="$(
    jq -c '
        if type == "array" then .
        elif (.alerts? | type) == "array" then .alerts
        elif (.results? | type) == "array" then .results
        elif (.matches? | type) == "array" then .matches
        else []
        end
    ' "$ALERT_QUEUE"
)"

alerts_total="$(jq 'length' <<< "$alerts_json")"

[[ "$alerts_total" =~ ^[0-9]+$ ]] || \
    fail "invalid alert count"

(( alerts_total > 0 )) || \
    fail "detection completed but alerts_total is zero"

critical="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "critical")] | length' <<< "$alerts_json")"
high="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "high")] | length' <<< "$alerts_json")"
medium="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "medium")] | length' <<< "$alerts_json")"
low="$(jq '[.[] | select((.severity // "" | ascii_downcase) == "low")] | length' <<< "$alerts_json")"

# Rule ID can be represented by rule_id, rule.id, id, or rule.
rule_counts="$(
    jq -c '
        map(
            .rule_id
            // .rule?.id
            // .rule?.rule_id
            // .id
            // .rule
            // "unknown"
            | tostring
        )
        | group_by(.)
        | map({
            rule_id: .[0],
            count: length
        })
        | sort_by(-.count, .rule_id)
    ' <<< "$alerts_json"
)"

catalog_rules_fired="$(jq 'length' <<< "$rule_counts")"

echo "[detect] matched: $catalog_rules_fired rules / $alerts_total alerts"
echo "[detect] severity critical=$critical high=$high medium=$medium low=$low"
echo "[detect] top rules:"

jq -r '.[] | "  \(.rule_id)   : \(.count) alerts"' <<< "$rule_counts"

# Build the locked alerts_by_rule object.
alerts_by_rule="$(
    jq -c '
        reduce .[] as $item
            ({}; .[$item.rule_id] = $item.count)
    ' <<< "$rule_counts"
)"

jq -n \
    --argjson catalog_rules_total "$catalog_rules_total" \
    --argjson catalog_rules_fired "$catalog_rules_fired" \
    --argjson alerts_total "$alerts_total" \
    --argjson critical "$critical" \
    --argjson high "$high" \
    --argjson medium "$medium" \
    --argjson low "$low" \
    --argjson alerts_by_rule "$alerts_by_rule" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    --argjson exit_status "$detection_status" \
    '{
      catalog_rules_total: $catalog_rules_total,
      catalog_rules_fired: $catalog_rules_fired,
      alerts_total: $alerts_total,
      alerts_by_severity: {
        critical: $critical,
        high: $high,
        medium: $medium,
        low: $low
      },
      alerts_by_rule: $alerts_by_rule,
      started_at: $started_at,
      ended_at: $ended_at,
      exit_status: $exit_status
    }' > "$CATALOG_RUN"

echo "[detect] alert_queue.json written"
echo "[detect] catalog_run.json written"
