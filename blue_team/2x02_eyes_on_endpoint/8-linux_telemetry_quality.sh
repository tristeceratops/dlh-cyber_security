#!/bin/bash

# name: 8-linux_telemetry_quality.sh
# purpose: Analyze Linux telemetry export quality
# author: Tristeceratops

set -euo pipefail

INPUT="linux_events_export.json"
OUTPUT="linux_telemetry_quality.json"

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required"
    exit 1
fi

if [[ ! -f "$INPUT" ]]; then
    echo "Missing: $INPUT"
    exit 1
fi

echo "[*] Analyzing $INPUT..."

TOTAL=$(jq -r '.total_events // 0' "$INPUT")

events_per_hour=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | .timestamp[0:13]]
        | group_by(.)
        | map({hour: .[0], count: length})
    else []
    end
' "$INPUT")

HOURS_WITH=$(printf '%s' "$events_per_hour" | jq 'length')
HOURS_TOTAL=24
HOURS_WITHOUT=$((HOURS_TOTAL - HOURS_WITH))

gap_count=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | .timestamp | fromdateiso8601] |
        sort |
        [range(1; length) as $i |
         .[$i] - .[$i-1] |
         select(. > 1800)] |
        length
    else 0
    end
' "$INPUT")

timestamp_total=$(jq -r '
    if (.events | type) == "array" then (.events | length) else 0 end
' "$INPUT")

timestamp_good=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.timestamp != null and .timestamp != "")] | length
    else 0
    end
' "$INPUT")

hostname_good=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.hostname != null and .hostname != "")] | length
    else 0
    end
' "$INPUT")

source_good=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.source_type != null and .source_type != "")] | length
    else 0
    end
' "$INPUT")

category_good=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.event_category != null and .event_category != "")] | length
    else 0
    end
' "$INPUT")

exec_total=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.event_category == "execve")] | length
    else 0
    end
' "$INPUT")

exec_good=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.event_category == "execve")
         | select(.command_line != null and .command_line != "")] | length
    else 0
    end
' "$INPUT")

ssh_total=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.event_category == "ssh")] | length
    else 0
    end
' "$INPUT")

ssh_good=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.event_category == "ssh")
         | select(.source_ip != null and .source_ip != "" and
                 .user != null and .user != "")] | length
    else 0
    end
' "$INPUT")

file_total=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.event_category == "file_access")] | length
    else 0
    end
' "$INPUT")

file_good=$(jq -r '
    if (.events | type) == "array" then
        [.events[] | select(.event_category == "file_access")
         | select(.path != null and .path != "")] | length
    else 0
    end
' "$INPUT")

percent() {
    if (( $2 == 0 )); then
        echo "0.0"
    else
        awk "BEGIN {printf \"%.1f\", ($1/$2)*100}"
    fi
}

timestamp_pct=$(percent "$timestamp_good" "$timestamp_total")
hostname_pct=$(percent "$hostname_good" "$timestamp_total")
source_pct=$(percent "$source_good" "$timestamp_total")
category_pct=$(percent "$category_good" "$timestamp_total")
exec_pct=$(percent "$exec_good" "$exec_total")
ssh_pct=$(percent "$ssh_good" "$ssh_total")
file_pct=$(percent "$file_good" "$file_total")

if (( timestamp_total > 0 )); then
    score=$(awk "BEGIN {
        print (\
            $timestamp_pct * 0.20 +
            $hostname_pct * 0.15 +
            $source_pct * 0.15 +
            $category_pct * 0.15 +
            $exec_pct * 0.15 +
            $ssh_pct * 0.10 +
            $file_pct * 0.10
        )
    }")
else
    score="0.0"
fi

assessment=$(awk -v s="$score" 'BEGIN {
    if (s >= 90) print "good";
    else if (s >= 70) print "acceptable";
    else print "poor";
}')

if (( gap_count == 0 )); then
    echo "No gaps detected"
else
    echo "Gaps > 30 minutes: $gap_count"
fi

echo "Total events: $TOTAL"
echo "Hours with events: $HOURS_WITH/$HOURS_TOTAL"
echo "execve command_line completeness: $exec_pct%"
echo "SSH source_ip completeness: $ssh_pct%"
echo "auditd file path completeness: $file_pct%"
echo "Quality score: $score% ($assessment)"

jq -n \
    --argjson total "$TOTAL" \
    --argjson hours_with "$HOURS_WITH" \
    --argjson hours_without "$HOURS_WITHOUT" \
    --argjson gaps "$gap_count" \
    --argjson events_per_hour "$events_per_hour" \
    --argjson event_distribution "$(jq '.counts // {}' "$INPUT")" \
    --argjson source_distribution "$(jq '.counts // {}' "$INPUT")" \
    --arg timestamp "$timestamp_pct" \
    --arg hostname "$hostname_pct" \
    --arg source "$source_pct" \
    --arg category "$category_pct" \
    --arg execve "$exec_pct" \
    --arg ssh "$ssh_pct" \
    --arg file "$file_pct" \
    --arg score "$score" \
    --arg assessment "$assessment" \
'{
    "event_distribution": $event_distribution,
    "source_distribution": $source_distribution,
    "total_events": $total,
    "time_coverage": {
        "events_per_hour": $events_per_hour,
        "hours_with_events": $hours_with,
        "hours_without_events": $hours_without
    },
    "gap_detection": {
        "threshold_minutes": 30,
        "gaps_over_30_minutes": $gaps
    },
    "field_completeness": {
        "timestamp": ($timestamp | tonumber),
        "hostname": ($hostname | tonumber),
        "source_type": ($source | tonumber),
        "event_category": ($category | tonumber),
        "execve_command_line": ($execve | tonumber),
        "ssh_source_ip_user": ($ssh | tonumber),
        "auditd_file_path": ($file | tonumber)
    },
    "quality_score": {
        "score": ($score | tonumber),
        "assessment": $assessment
    }
}' > "$OUTPUT"

echo "Report saved to: $OUTPUT"
