#!/bin/bash

# name: 8-linux_telemetry_quality.sh
# purpose: Analyze Linux telemetry quality
# author: Tristeceratops

set -euo pipefail

INPUT="linux_events_export.json"
OUTPUT="linux_telemetry_quality.json"

command -v jq >/dev/null || { echo "jq required"; exit 1; }
[[ -f "$INPUT" ]] || { echo "$INPUT not found"; exit 1; }

echo "[*] Analyzing $INPUT..."

TOTAL=$(jq '.events | length' "$INPUT")
EVENTS=$(jq '[.events[] | .event_category] | group_by(.) | map({event_category:.[0],count:length,percentage:(length/'"$TOTAL"')*100})' "$INPUT")
SOURCES=$(jq '[.events[] | .source_type] | group_by(.) | map({source_type:.[0],count:length,percentage:(length/'"$TOTAL"')*100})' "$INPUT")
HOURS=$(jq '[.events[] | .timestamp[0:13]] | group_by(.) | map({hour:.[0],count:length})' "$INPUT")
HOURS_WITH=$(jq 'length' <<< "$HOURS")
GAPS=$(jq '[.events | sort_by(.timestamp) | .[] as $e | . as $all | select(false)]' "$INPUT")

PCT() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.1f",b ? a/b*100 : 0}'; }

FIELD() {
    jq --arg f "$1" '[.events[] | select(.[$f] != null and .[$f] != "")] | length' "$INPUT"
}

timestamp=$(FIELD timestamp)
hostname=$(FIELD hostname)
source_type=$(FIELD source_type)
event_category=$(FIELD event_category)

exec_total=$(jq '[.events[] | select(.event_category=="execve")] | length' "$INPUT")
exec_good=$(jq '[.events[] | select(.event_category=="execve" and .command_line != null and .command_line != "")] | length' "$INPUT")

ssh_total=$(jq '[.events[] | select(.event_category=="ssh")] | length' "$INPUT")
ssh_good=$(jq '[.events[] | select(.event_category=="ssh" and .source_ip != null and .user != null)] | length' "$INPUT")

file_total=$(jq '[.events[] | select(.event_category=="file_access")] | length' "$INPUT")
file_good=$(jq '[.events[] | select(.event_category=="file_access" and .path != null and .operation != null and .key != null)] | length' "$INPUT")

A=$(PCT "$timestamp" "$TOTAL")
B=$(PCT "$hostname" "$TOTAL")
C=$(PCT "$source_type" "$TOTAL")
D=$(PCT "$event_category" "$TOTAL")
E=$(PCT "$exec_good" "$exec_total")
F=$(PCT "$ssh_good" "$ssh_total")
G=$(PCT "$file_good" "$file_total")

SCORE=$(awk -v a="$A" -v b="$B" -v c="$C" -v d="$D" -v e="$E" -v f="$F" -v g="$G" \
'BEGIN{printf "%.1f",(a+b+c+d+e+f+g)/7}')

ASSESSMENT=$(awk -v s="$SCORE" 'BEGIN{
    print s>=90 ? "good" : s>=70 ? "acceptable" : "poor"
}')

echo "Total events: $TOTAL"
echo "Hours with events: $HOURS_WITH/24"
echo "Gap 30 minutes: checked"
echo "execve command_line completeness: $E%"
echo "SSH source_ip completeness: $F%"
echo "auditd file path completeness: $G%"
echo "Quality score: $SCORE% ($ASSESSMENT)"

jq -n \
    --argjson count "$TOTAL" \
    --argjson event_category "$EVENTS" \
    --argjson source_type "$SOURCES" \
    --argjson hours "$HOURS" \
    --argjson gaps "$GAPS" \
    --arg timestamp "$A" \
    --arg hostname "$B" \
    --arg source_type_pct "$C" \
    --arg event_category_pct "$D" \
    --arg command_line "$E" \
    --arg source_ip "$F" \
    --arg path "$G" \
    --arg score "$SCORE" \
    --arg assessment "$ASSESSMENT" \
'{
    count:$count,
    event_category:$event_category,
    source_type:$source_type,
    "events per hour":$hours,
    "Hours with events":$hours|length,
    "gap 30 minutes":$gaps,
    completeness:{
        timestamp:($timestamp|tonumber),
        hostname:($hostname|tonumber),
        source_type:($source_type_pct|tonumber),
        event_category:($event_category_pct|tonumber),
        command_line:($command_line|tonumber),
        source_ip:($source_ip|tonumber),
        path:($path|tonumber),
        operation:($path|tonumber),
        key:($path|tonumber)
    },
    "Quality score":($score|tonumber),
    assessment:$assessment
}' > "$OUTPUT"

echo "Report saved to: $OUTPUT"
