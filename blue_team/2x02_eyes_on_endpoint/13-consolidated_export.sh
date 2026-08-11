#!/bin/bash
set -euo pipefail

# name: 13-consolidated_export.sh
# purpose: Consolidate Windows and Linux telemetry into a handoff directory

WINDOWS="windows_events_export.json"
LINUX="linux_events_export.json"
WIN_GT="windows_attack_log.json"
LINUX_GT="linux_attack_log.json"
OUT="telemetry_handoff"

command -v jq >/dev/null 2>&1 || {
    echo "[-] jq is required"
    exit 1
}

for f in "$WINDOWS" "$LINUX" "$WIN_GT" "$LINUX_GT"; do
    [[ -f "$f" ]] || {
        echo "[-] Missing: $f"
        exit 1
    }
done

# Check that telemetry is an event array.
check_events() {
    local file="$1"
    jq -e 'type == "array"' "$file" >/dev/null || {
        echo "[-] $file must contain an event array"
        exit 1
    }
}

check_events "$WINDOWS"
check_events "$LINUX"

WIN_COUNT=$(jq 'length' "$WINDOWS")
LINUX_COUNT=$(jq 'length' "$LINUX")

echo "[*] Loading Windows events ($WIN_COUNT)..."
echo "[*] Loading Linux events ($LINUX_COUNT)..."

mkdir -p "$OUT"

echo "[*] Normalizing timestamps to UTC..."

# Windows timestamps are already UTC ISO 8601 in the expected format.
# For timestamps already ending in Z, keep them unchanged.
# For simple ISO timestamps without Z, append Z.
normalize() {
    local input="$1"
    local output="$2"

    jq '
      map(
        .timestamp =
          if (.timestamp | type) != "string" then .timestamp
          elif (.timestamp | endswith("Z")) then .timestamp
          elif (.timestamp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")) then
            .timestamp + "Z"
          else
            .timestamp
          end
      )
    ' "$input" > "$output"
}

normalize "$WINDOWS" "$OUT/windows_events.json"
normalize "$LINUX" "$OUT/linux_events.json"

echo "    Windows: $WIN_COUNT events normalized"
echo "    Linux: $LINUX_COUNT events normalized"

echo "[*] Verifying field consistency..."

REQUIRED='
  ["timestamp","hostname","source_type","event_category"]
'

if jq -e '
    all(.[];
      all(["timestamp","hostname","source_type","event_category"][];
        has(.)
      )
    )
  ' "$OUT/windows_events.json" >/dev/null &&
   jq -e '
    all(.[];
      all(["timestamp","hostname","source_type","event_category"][];
        has(.)
      )
    )
  ' "$OUT/linux_events.json" >/dev/null; then
    echo "    Required fields present in all events    [OK]"
else
    echo "    Required fields present in all events    [FAIL]"
    exit 1
fi

echo "[*] Combining ground truth..."

WIN_ACTIONS=$(jq '
    if type == "array" then length
    elif (.events | type) == "array" then .events | length
    else 0 end
' "$WIN_GT")

LINUX_ACTIONS=$(jq '
    if type == "array" then length
    elif (.events | type) == "array" then .events | length
    else 0 end
' "$LINUX_GT")

TOTAL_ACTIONS=$((WIN_ACTIONS + LINUX_ACTIONS))

jq -n \
  --argjson windows "$(jq 'if type == "array" then . else .events end' "$WIN_GT")" \
  --argjson linux "$(jq 'if type == "array" then . else .events end' "$LINUX_GT")" \
  '{
    windows: $windows,
    linux: $linux
  }' > "$OUT/attack_ground_truth.json"

echo "    Windows actions: $WIN_ACTIONS | Linux actions: $LINUX_ACTIONS | Total: $TOTAL_ACTIONS"

echo "[*] Building handoff directory..."

WIN_SIZE=$(du -h "$OUT/windows_events.json" | cut -f1)
LINUX_SIZE=$(du -h "$OUT/linux_events.json" | cut -f1)

echo "telemetry_handoff/"
echo "  windows_events.json     ($WIN_COUNT events, $WIN_SIZE)"
echo "  linux_events.json       ($LINUX_COUNT events, $LINUX_SIZE)"
echo "  attack_ground_truth.json ($TOTAL_ACTIONS actions)"
echo "Total: $((WIN_COUNT + LINUX_COUNT)) events across 2 platforms"

