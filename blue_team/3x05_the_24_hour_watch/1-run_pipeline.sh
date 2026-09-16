#!/bin/bash
set -euo pipefail

fail() {
    echo "[pipeline] ERROR: $*" >&2
    exit 1
}

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || fail "$name is not set"
}

require_env SHIFT_WORKSPACE
require_env PIPELINE_BIN
require_env CAPSTONE_PACK

SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"
OUTPUT_DIR="$SHIFT_WORKSPACE/enriched"
RUN_LOG="$SHIFT_WORKSPACE/runtime/pipeline_run.log"
RUN_JSON="$SHIFT_WORKSPACE/runtime/pipeline_run.json"

[[ -s "$SHIFT_START" ]] || \
    fail "shift_start.json is absent or empty: $SHIFT_START"

jq -e . "$SHIFT_START" >/dev/null 2>&1 || \
    fail "shift_start.json is not valid JSON: $SHIFT_START"

mkdir -p "$OUTPUT_DIR" "$SHIFT_WORKSPACE/runtime"

echo "[pipeline] intake check: OK"
echo "[pipeline] invoking $PIPELINE_BIN"
echo "[pipeline] input: $CAPSTONE_PACK"
echo "[pipeline] output: $OUTPUT_DIR/"

pipeline_version="unknown"
if "$PIPELINE_BIN" --version >/tmp/pipeline_version.$$ 2>&1; then
    version_line="$(head -n 1 /tmp/pipeline_version.$$ || true)"
    [[ -n "$version_line" ]] && pipeline_version="$version_line"
fi
rm -f /tmp/pipeline_version.$$

started_epoch="$(date +%s)"
started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

: > "$RUN_LOG"

set +e
"$PIPELINE_BIN" "$CAPSTONE_PACK" "$OUTPUT_DIR" 2>&1 | while IFS= read -r line; do
    printf '%s\n' "$line" >> "$RUN_LOG"

    if [[ "$line" =~ stage[[:space:]]+([0-9]+)[[:space:]]+([^.]*)\.*[[:space:]]*ok ]]; then
        stage_num="${BASH_REMATCH[1]}"
        stage_name="${BASH_REMATCH[2]}"
        stage_name="$(echo "$stage_name" | sed 's/[[:space:]]*$//')"
        echo "[pipeline] stage $stage_num $stage_name ... ok"
    fi
done
pipeline_status="${PIPESTATUS[0]}"
set -e

ended_epoch="$(date +%s)"
ended_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
duration_seconds=$((ended_epoch - started_epoch))

if (( pipeline_status != 0 )); then
    fail "pipeline failed with exit status $pipeline_status; see $RUN_LOG"
fi

echo "[pipeline] pipeline process exited successfully"

# Accept either of the two names allowed by the contract.
if [[ -s "$OUTPUT_DIR/enriched_events.jsonl" ]]; then
    events_file="$OUTPUT_DIR/enriched_events.jsonl"
elif [[ -s "$OUTPUT_DIR/enriched_events.json" ]]; then
    events_file="$OUTPUT_DIR/enriched_events.json"
else
    fail "missing or empty enriched events output: expected enriched_events.jsonl or enriched_events.json"
fi

if [[ -s "$OUTPUT_DIR/timeline.jsonl" ]]; then
    timeline_file="$OUTPUT_DIR/timeline.jsonl"
elif [[ -s "$OUTPUT_DIR/timeline_index.json" ]]; then
    timeline_file="$OUTPUT_DIR/timeline_index.json"
else
    fail "missing or empty timeline output: expected timeline.jsonl or timeline_index.json"
fi

[[ -s "$OUTPUT_DIR/source_stats.json" ]] || \
    fail "missing or empty source_stats.json: $OUTPUT_DIR/source_stats.json"

echo "[pipeline] required output files: OK"

# Extract source counts while allowing several common source_stats layouts.
declare -A source_counts=(
    [windows_json]=0
    [linux_text]=0
    [firewall]=0
    [suricata_alert]=0
    [pcap_flow]=0
)

extract_count() {
    local source="$1"

    jq -r --arg source "$source" '
        def numeric:
            if type == "number" then .
            elif type == "string" and test("^[0-9]+$") then tonumber
            else 0
            end;

        if type == "object" then
            if .source_counts? and (.source_counts | type == "object") then
                (.source_counts[$source] // 0) | numeric
            elif .sources? and (.sources | type == "object") then
                (.sources[$source] // 0) | numeric
            elif .source_types? and (.source_types | type == "object") then
                (.source_types[$source] // 0) | numeric
            else
                0
            end
        else
            0
        end
    ' "$OUTPUT_DIR/source_stats.json"
}

for source in "${!source_counts[@]}"; do
    count="$(extract_count "$source")"
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    source_counts["$source"]="$count"
    echo "[pipeline] source $source: $count events"
done

nonzero_sources=0
for source in "${!source_counts[@]}"; do
    if (( source_counts["$source"] > 0 )); then
        ((nonzero_sources+=1))
    fi
done

(( nonzero_sources >= 4 )) || \
    fail "source validation failed: only $nonzero_sources source types have non-zero event counts; at least 4 required"

# Count input/output events.
events_in="$(jq -r '
    if type == "array" then length
    elif type == "object" then
        (.events_in // .input_events // .event_count // .total_events // 0)
    else 0
    end
' "$OUTPUT_DIR/source_stats.json" 2>/dev/null || echo 0)"

events_out="$(wc -l < "$events_file" | tr -d ' ')"

if [[ "$events_file" == *.json ]]; then
    events_out="$(jq -r 'if type == "array" then length else (.events_out // .event_count // 0) end' "$events_file")"
fi

[[ "$events_in" =~ ^[0-9]+$ ]] || events_in="$events_out"
[[ "$events_out" =~ ^[0-9]+$ ]] || events_out=0

if (( events_in >= events_out )); then
    events_dropped=$((events_in - events_out))
else
    events_dropped=0
fi

echo "[pipeline] duration ${duration_seconds}s"
echo "[pipeline] events_in=$events_in events_out=$events_out dropped=$events_dropped"
echo "[pipeline] source windows_json=${source_counts[windows_json]} linux_text=${source_counts[linux_text]} firewall=${source_counts[firewall]} suricata_alert=${source_counts[suricata_alert]}"

jq -n \
    --arg pipeline_version "$pipeline_version" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    --arg input_pack "$CAPSTONE_PACK" \
    --argjson duration_seconds "$duration_seconds" \
    --argjson events_in "$events_in" \
    --argjson events_out "$events_out" \
    --argjson events_dropped "$events_dropped" \
    --argjson windows_json "${source_counts[windows_json]}" \
    --argjson linux_text "${source_counts[linux_text]}" \
    --argjson firewall "${source_counts[firewall]}" \
    --argjson suricata_alert "${source_counts[suricata_alert]}" \
    --argjson pcap_flow "${source_counts[pcap_flow]}" \
    --argjson exit_status "$pipeline_status" \
    '{
      pipeline_version: $pipeline_version,
      started_at: $started_at,
      ended_at: $ended_at,
      duration_seconds: $duration_seconds,
      input_pack: $input_pack,
      events_in: $events_in,
      events_out: $events_out,
      events_dropped: $events_dropped,
      source_counts: {
        windows_json: $windows_json,
        linux_text: $linux_text,
        firewall: $firewall,
        suricata_alert: $suricata_alert,
        pcap_flow: $pcap_flow
      },
      dirty_data_detected: [],
      exit_status: $exit_status
    }' > "$RUN_JSON"

echo "[pipeline] pipeline_run.json written"
