#!/bin/bash

# name: 15-handoff_validation.sh
# purpose: Validate telemetry_handoff package and ground truth detection coverage
# author: Tristeceratops

set -euo pipefail

DIR="telemetry_handoff"
WIN="$DIR/windows_events.json"
LINUX="$DIR/linux_events.json"
GROUND="$DIR/attack_ground_truth.json"

WIN_MATRIX="windows_detection_matrix.json"
LINUX_MATRIX="linux_detection_matrix.json"
OUTPUT="handoff_validation.json"

command -v jq >/dev/null 2>&1 || {
    echo "[-] jq is required"
    exit 1
}

echo "[*] Validating telemetry_handoff/ ..."

checks=0
passed=0

check() {
    local name="$1"
    local result="$2"
    local detail="$3"

    checks=$((checks + 1))

    if [[ "$result" == "PASS" ]]; then
        passed=$((passed + 1))
        echo "[PASS] $name $detail"
    else
        echo "[FAIL] $name $detail"
    fi
}

# --------------------------------------------------
# File Existence
# --------------------------------------------------

echo "=== File Existence ==="

for file in "$WIN" "$LINUX" "$GROUND"; do
    name=$(basename "$file")

    if [[ -f "$file" ]]; then
        size=$(du -h "$file" | cut -f1)
        check "$name exists" PASS "($size)"
    else
        check "$name exists" FAIL ""
    fi
done

if [[ ! -f "$WIN" || ! -f "$LINUX" || ! -f "$GROUND" ]]; then
    echo "VERDICT: FAIL"
    exit 1
fi

# --------------------------------------------------
# JSON Validity
# --------------------------------------------------

echo "=== JSON Validity ==="

for file in "$WIN" "$LINUX" "$GROUND"; do
    name=$(basename "$file")

    if jq empty "$file" >/dev/null 2>&1; then
        count=$(jq '
            if type == "array" then length
            elif .events? then (.events | length)
            elif .windows? and .linux? then
                (.windows | length) + (.linux | length)
            else 0
            end
        ' "$file")

        check "$name: valid JSON" PASS "$count objects"
    else
        check "$name: valid JSON" FAIL ""
    fi
done

# --------------------------------------------------
# Required Fields
# --------------------------------------------------

echo "=== Required Fields ==="

FIELDS='["timestamp","hostname","source_type","event_category"]'

win_fields=$(jq -r --argjson fields "$FIELDS" '
    all(.[]; all($fields[]; has(.)))
' "$WIN")

linux_fields=$(jq -r --argjson fields "$FIELDS" '
    all(.[]; all($fields[]; has(.)))
' "$LINUX")

if [[ "$win_fields" == "true" && "$linux_fields" == "true" ]]; then
    check "Required fields" PASS \
        "All events have timestamp, hostname, source_type, event_category"
else
    check "Required fields" FAIL "Required field missing"
fi

# --------------------------------------------------
# Minimum Event Counts
# --------------------------------------------------

echo "=== Minimum Event Counts ==="

WIN_COUNT=$(jq 'length' "$WIN")
LINUX_COUNT=$(jq 'length' "$LINUX")

GROUND_COUNT=$(jq '
    if type == "array" then length
    elif .events? then (.events | length)
    elif .windows? and .linux? then
        (.windows | length) + (.linux | length)
    else 0
    end
' "$GROUND")

if (( WIN_COUNT >= 1000 )); then
    check "Windows" PASS "$WIN_COUNT >= 1000"
else
    check "Windows" FAIL "$WIN_COUNT < 1000"
fi

if (( LINUX_COUNT >= 500 )); then
    check "Linux" PASS "$LINUX_COUNT >= 500"
else
    check "Linux" FAIL "$LINUX_COUNT < 500"
fi

if (( GROUND_COUNT >= 10 )); then
    check "Ground truth" PASS "$GROUND_COUNT >= 10"
else
    check "Ground truth" FAIL "$GROUND_COUNT < 10"
fi

# --------------------------------------------------
# Timestamp Consistency
# --------------------------------------------------

echo "=== Timestamp Consistency ==="

NOW=$(date -u +%s)
START=$((NOW - 86400))

timestamp_check() {
    jq '
        all(.[];
            (.timestamp | type) == "string" and
            (.timestamp |
                test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
            )
        )
    ' "$1"
}

WIN_TS=$(timestamp_check "$WIN")
LINUX_TS=$(timestamp_check "$LINUX")

if [[ "$WIN_TS" == "true" && "$LINUX_TS" == "true" ]]; then
    check "ISO 8601" PASS "All timestamps valid ISO 8601"
else
    check "ISO 8601" FAIL "Invalid timestamp detected"
fi

timestamp_range() {
    jq -r '.[].timestamp' "$1" |
    while read -r timestamp; do
        date -u -d "$timestamp" +%s 2>/dev/null || true
    done |
    sort -n
}

WIN_TIMES=$(timestamp_range "$WIN")
LINUX_TIMES=$(timestamp_range "$LINUX")

WIN_MIN=$(printf '%s\n' "$WIN_TIMES" | head -1)
WIN_MAX=$(printf '%s\n' "$WIN_TIMES" | tail -1)

LINUX_MIN=$(printf '%s\n' "$LINUX_TIMES" | head -1)
LINUX_MAX=$(printf '%s\n' "$LINUX_TIMES" | tail -1)

FUTURE=$(printf '%s\n%s\n' "$WIN_MAX" "$LINUX_MAX" |
    awk -v now="$NOW" '$1 > now {n++} END {print n+0}')

if (( FUTURE == 0 )); then
    check "Future timestamps" PASS "No future timestamps"
else
    check "Future timestamps" FAIL "$FUTURE future timestamps"
fi

OLD=$(printf '%s\n%s\n' "$WIN_MIN" "$LINUX_MIN" |
    awk -v start="$START" '$1 < start {n++} END {print n+0}')

if (( OLD == 0 )); then
    check "Last 24 hours" PASS "All timestamps within last 24 hours"
else
    check "Last 24 hours" FAIL "$OLD timestamps outside last 24 hours"
fi

format_date() {
    date -u -d "@$1" +"%Y-%m-%dT%H:%M:%SZ"
}

RANGE_START=$(printf '%s\n%s\n' "$WIN_MIN" "$LINUX_MIN" | sort -n | head -1)
RANGE_END=$(printf '%s\n%s\n' "$WIN_MAX" "$LINUX_MAX" | sort -n | tail -1)

echo "    Range: $(format_date "$RANGE_START") to $(format_date "$RANGE_END")"

# --------------------------------------------------
# Cross-platform Alignment
# --------------------------------------------------

echo "=== Cross-Platform Alignment ==="

OVERLAP_START=$(printf '%s\n%s\n' "$WIN_MIN" "$LINUX_MIN" | sort -n | tail -1)
OVERLAP_END=$(printf '%s\n%s\n' "$WIN_MAX" "$LINUX_MAX" | sort -n | head -1)

if (( OVERLAP_START <= OVERLAP_END )); then
    SHARED=$((OVERLAP_END - OVERLAP_START))
    HOURS=$(awk -v seconds="$SHARED" \
        'BEGIN {printf "%.1f", seconds / 3600}')

    check "Time range overlap" PASS "$HOURS hours shared"
else
    check "Time range overlap" FAIL "No overlapping time range"
fi

# --------------------------------------------------
# Ground Truth Completeness
# Match by MITRE technique.
# --------------------------------------------------

echo "=== Ground Truth Completeness ==="

GROUND_TECHNIQUES=$(jq -r '
    if type == "array" then .[]
    elif .events? then .events[]
    elif .windows? and .linux? then .windows[], .linux[]
    else empty
    end
    | (.MITRE // .mitre // .technique // empty)
' "$GROUND" | sort -u)

MATRIX_TECHNIQUES=$(
    jq -r '
        .. |
        objects |
        (.MITRE // .mitre // .technique // empty)
    ' "$WIN_MATRIX" "$LINUX_MATRIX" 2>/dev/null |
    sort -u
)

MATCHED=0
TOTAL_TECHNIQUES=0

while read -r technique; do
    [[ -n "$technique" ]] || continue

    TOTAL_TECHNIQUES=$((TOTAL_TECHNIQUES + 1))

    if grep -Fxq "$technique" <<< "$MATRIX_TECHNIQUES"; then
        MATCHED=$((MATCHED + 1))
    fi
done <<< "$GROUND_TECHNIQUES"

if (( MATCHED == TOTAL_TECHNIQUES )); then
    check "Ground Truth Completeness" PASS \
        "$MATCHED/$TOTAL_TECHNIQUES techniques matched"
else
    check "Ground Truth Completeness" FAIL \
        "$MATCHED/$TOTAL_TECHNIQUES techniques matched"
fi

# --------------------------------------------------
# Final Verdict
# --------------------------------------------------

if (( passed == checks )); then
    VERDICT="PASS"
else
    VERDICT="FAIL"
fi

jq -n \
    --arg verdict "$VERDICT" \
    --argjson checks "$checks" \
    --argjson passed "$passed" \
    --argjson failed "$((checks - passed))" \
    --argjson windows "$WIN_COUNT" \
    --argjson linux "$LINUX_COUNT" \
    --argjson ground_truth "$GROUND_COUNT" \
    --argjson matched "$MATCHED" \
    --argjson techniques "$TOTAL_TECHNIQUES" \
    --arg range_start "$(format_date "$RANGE_START")" \
    --arg range_end "$(format_date "$RANGE_END")" \
    '{
        verdict: $verdict,
        checks: {
            total: $checks,
            passed: $passed,
            failed: $failed
        },
        minimum_event_counts: {
            windows: $windows,
            linux: $linux,
            ground_truth: $ground_truth
        },
        timestamp: {
            range_start: $range_start,
            range_end: $range_end,
            validation_range: "last 24 hours"
        },
        ground_truth_completeness: {
            matched: $matched,
            techniques: $techniques,
            method: "MITRE technique"
        }
    }' > "$OUTPUT"

echo "VERDICT: $VERDICT ($passed/$checks checks)"
echo "Report saved to: $OUTPUT"

if [[ "$VERDICT" != "PASS" ]]; then
    exit 1
fi
