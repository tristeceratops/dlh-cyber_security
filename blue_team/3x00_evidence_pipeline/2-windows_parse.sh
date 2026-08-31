#!/bin/bash
set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-"$HOME/evidence_pack_primary"}"
WINDOWS_DIR="${WINDOWS_DIR:-"$EVIDENCE_PACK/windows"}"
TELEMETRY_FILE="${TELEMETRY_FILE:-"$EVIDENCE_PACK/student_telemetry/windows_events.json"}"
OUTPUT="${OUTPUT:-windows_events.json}"

files=("security.json" "sysmon.json" "powershell.json")

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required" >&2
    exit 1
fi

: > "$OUTPUT"

total=0

for file in "${files[@]}"; do
    path="$WINDOWS_DIR/$file"

    if [[ ! -f "$path" ]]; then
        echo "error: missing $path" >&2
        exit 1
    fi

    count=$(jq -s 'length' "$path")

    jq -c '
        .timestamp_raw |= (fromdateiso8601 | todate)
        | .source_origin = "evidence_pack"
        | .event_data = (
            if (.event_data | type) == "object"
            then .event_data
            else {}
            end
        )
        | {
            timestamp_raw,
            hostname,
            event_id,
            channel,
            provider,
            raw_message,
            event_data,
            source_origin
        }
    ' "$path" >> "$OUTPUT"

    printf 'reading %-20s ... %6d records\n' "$file" "$count"
    total=$((total + count))
done

if [[ ! -f "$TELEMETRY_FILE" ]]; then
    echo "error: missing $TELEMETRY_FILE" >&2
    exit 1
fi

telemetry_count=$(jq -s 'length' "$TELEMETRY_FILE")

jq -c '
    .timestamp_raw = (
        (.timestamp // .timestamp_raw)
        | fromdateiso8601
        | todate
    )
    | .source_origin = (.source_origin // "student_telemetry")
    | .hostname = (.hostname // null)
    | .event_id = (.event_id // null)
    | .channel = (.channel // .source_type // null)
    | .provider = (.provider // null)
    | .raw_message = (.raw_message // null)
    | .event_data = (.event_data // {})
' "$TELEMETRY_FILE" >> "$OUTPUT"

printf 'appending student telemetry ... %6d records\n' "$telemetry_count"
total=$((total + telemetry_count))

if ! jq empty "$OUTPUT" >/dev/null; then
    echo "error: output validation failed" >&2
    exit 1
fi

printf 'windows_events.json: %6d records\n' "$total"
