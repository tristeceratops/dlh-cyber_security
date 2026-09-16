#!/bin/bash
set -euo pipefail

fail() {
    echo "[triage] ERROR: $*" >&2
    exit 1
}

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || fail "$name is not set"
}

require_file() {
    local file="$1"
    [[ -s "$file" ]] || fail "required file missing or empty: $file"
}

require_env SHIFT_WORKSPACE
require_env TRIAGE_BIN
require_env ASSETS_DIR

ALERT_QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
BRIEFING="$SHIFT_WORKSPACE/alerts/shift_briefing.json"
BASELINE="$SHIFT_WORKSPACE/enriched/baseline.json"
ASSETS="$ASSETS_DIR/assets.json"
TRIAGE_LOG="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
TRIAGE_OUTPUT="$SHIFT_WORKSPACE/runtime/triage_runner_output.json"
TRIAGE_RUN_LOG="$SHIFT_WORKSPACE/runtime/triage_run.log"

require_file "$ALERT_QUEUE"
require_file "$BRIEFING"
require_file "$BASELINE"
require_file "$ASSETS"

jq -e . "$ALERT_QUEUE" >/dev/null 2>&1 || fail "alert_queue.json is invalid JSON"
jq -e . "$BRIEFING" >/dev/null 2>&1 || fail "shift_briefing.json is invalid JSON"
jq -e . "$BASELINE" >/dev/null 2>&1 || fail "baseline.json is invalid JSON"
jq -e . "$ASSETS" >/dev/null 2>&1 || fail "assets.json is invalid JSON"

alert_count="$(
    jq '
        if type == "array" then length
        elif (.alerts? | type) == "array" then (.alerts | length)
        elif (.results? | type) == "array" then (.results | length)
        elif (.matches? | type) == "array" then (.matches | length)
        else 0
        end
    ' "$ALERT_QUEUE"
)"

[[ "$alert_count" =~ ^[0-9]+$ ]] || fail "unable to determine alert count"
(( alert_count > 0 )) || fail "alert queue contains zero alerts"

ioc_count="$(jq -r '.ioc_count // 0' "$BRIEFING")"
ticket_count="$(jq '.active_change_tickets // [] | length' "$BRIEFING")"

echo "[triage] alert_queue: $alert_count alerts"
echo "[triage] briefing loaded ($ioc_count IOCs, $ticket_count change tickets)"
echo "[triage] invoking $TRIAGE_BIN"
echo "[triage] classifying $alert_count alerts"

[[ -x "$TRIAGE_BIN" ]] || fail "TRIAGE_BIN is not executable: $TRIAGE_BIN"

: > "$TRIAGE_RUN_LOG"

# The 3x03 triage runner receives:
#   1. alert queue
#   2. shift briefing
#   3. baseline
#   4. asset inventory
#   5. output path
set +e
"$TRIAGE_BIN" \
    "$ALERT_QUEUE" \
    "$BRIEFING" \
    "$BASELINE" \
    "$ASSETS" \
    "$TRIAGE_OUTPUT" \
    >"$TRIAGE_RUN_LOG" 2>&1
triage_status=$?
set -e

(( triage_status == 0 )) || \
    fail "TRIAGE_BIN failed with exit status $triage_status; see $TRIAGE_RUN_LOG"

[[ -s "$TRIAGE_OUTPUT" ]] || \
    fail "triage runner produced no output: $TRIAGE_OUTPUT"

jq -e . "$TRIAGE_OUTPUT" >/dev/null 2>&1 || \
    fail "triage runner output is invalid JSON: $TRIAGE_OUTPUT"

# Locate the runner's classification array.
jq -e '
    if type == "array" then true
    elif (.classifications? | type) == "array" then true
    elif (.triage? | type) == "array" then true
    elif (.results? | type) == "array" then true
    else false
    end
' "$TRIAGE_OUTPUT" >/dev/null || \
    fail "triage output contains no classification records"

# Convert runner records into the locked triage_log schema.
jq -c '
    def records:
        if type == "array" then .
        elif (.classifications? | type) == "array" then .classifications
        elif (.triage? | type) == "array" then .triage
        elif (.results? | type) == "array" then .results
        else []
        end;

    def classification:
        (.classification // .verdict // .disposition // "")
        | ascii_upcase;

    def severity:
        (.severity // "medium")
        | ascii_downcase;

    records[]
    | {
        alert_id: (.alert_id // .id // .alert?.id // ""),
        rule_id: (.rule_id // .rule?.id // .rule // ""),
        host: (
            .host
            // .hostname
            // .asset
            // ""
            | ascii_downcase
        ),
        user: (
            if (.user? // .username? // .account?) == null
            then null
            else (.user // .username // .account)
        ),
        classification: classification,
        severity: severity,
        matches_ioc: (
            .matches_ioc
            // .ioc_matches
            // .matched_iocs
            // []
        ),
        baseline_deviation: (
            .baseline_deviation
            // .deviation
            // false
        ),
        change_ticket_match: (
            .change_ticket_match
            // .change_ticket
            // null
        ),
        analyst_note: (
            .analyst_note
            // .reason
            // .note
            // ""
            | tostring
            | .[0:200]
        ),
        classified_at: (
            .classified_at
            // .timestamp
            // ""
        )
    }
' "$TRIAGE_OUTPUT" > "$TRIAGE_LOG"

[[ -s "$TRIAGE_LOG" ]] || \
    fail "triage runner produced an empty classification log"

# Validate every JSONL record against the locked schema.
line_number=0

while IFS= read -r record; do
    line_number=$((line_number + 1))

    jq -e '
        (.alert_id | type == "string" and length > 0)
        and (.rule_id | type == "string" and length > 0)
        and (.host | type == "string" and length > 0)
        and (.host == ascii_downcase)
        and (
            .user == null
            or (.user | type == "string")
        )
        and (
            .classification == "TP"
            or .classification == "FP"
            or .classification == "NOISE"
        )
        and (
            .severity == "critical"
            or .severity == "high"
            or .severity == "medium"
            or .severity == "low"
        )
        and (.matches_ioc | type == "array")
        and all(.matches_ioc[]; type == "string")
        and (.baseline_deviation | type == "boolean")
        and (
            .change_ticket_match == null
            or (.change_ticket_match | type == "string")
        )
        and (.analyst_note | type == "string" and length <= 200)
        and (.classified_at | type == "string" and length > 0)
    ' <<< "$record" >/dev/null || \
        fail "invalid triage record at line $line_number"
done < "$TRIAGE_LOG"

logged_count="$(wc -l < "$TRIAGE_LOG" | tr -d ' ')"

(( logged_count == alert_count )) || \
    fail "alert coverage mismatch: queue=$alert_count logged=$logged_count"

# Confirm every alert ID appears in the triage log.
missing_count="$(
    comm -23 \
        <(
            jq -r '
                if type == "array" then .
                elif (.alerts? | type) == "array" then .alerts
                elif (.results? | type) == "array" then .results
                elif (.matches? | type) == "array" then .matches
                else []
                end
                | .[]
                | (.alert_id // .id // .alert?.id // "")
            ' "$ALERT_QUEUE" |
            sort -u
        ) \
        <(
            jq -r '.alert_id' "$TRIAGE_LOG" |
            sort -u
        ) |
        wc -l |
        tr -d ' '
)"

(( missing_count == 0 )) || \
    fail "$missing_count alerts are missing from triage_log.jsonl"

tp_count="$(
    jq -s '[.[] | select(.classification == "TP")] | length' "$TRIAGE_LOG"
)"

fp_count="$(
    jq -s '[.[] | select(.classification == "FP")] | length' "$TRIAGE_LOG"
)"

noise_count="$(
    jq -s '[.[] | select(.classification == "NOISE")] | length' "$TRIAGE_LOG"
)"

unclassified_count="$(
    jq -s '
        [
            .[]
            | select(
                .classification != "TP"
                and .classification != "FP"
                and .classification != "NOISE"
            )
        ]
        | length
    ' "$TRIAGE_LOG"
)"

(( unclassified_count == 0 )) || \
    fail "$unclassified_count alerts remain unclassified"

echo "[triage] TP=$tp_count FP=$fp_count NOISE=$noise_count unclassified=$unclassified_count"
echo "[triage] triage_log.jsonl written"
