#!/bin/bash
set -euo pipefail

# name: 14-coverage_assessment.sh
# purpose: Assess telemetry coverage, detection and quality

OUT="telemetry_coverage_assessment.json"

FILES=(
  "telemetry_handoff/windows_events.json"
  "telemetry_handoff/linux_events.json"
  "telemetry_handoff/attack_ground_truth.json"
  "windows_detection_matrix.json"
  "linux_detection_matrix.json"
  "windows_telemetry_quality.json"
  "linux_telemetry_quality.json"
  "sysmon_coverage_matrix.json"
)

command -v jq >/dev/null 2>&1 || {
  echo "[-] jq is required"
  exit 1
}

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || {
    echo "[-] Missing: $f"
    exit 1
  }
  jq empty "$f" >/dev/null || {
    echo "[-] Invalid JSON: $f"
    exit 1
  }
done

echo "[*] Loading telemetry handoff package..."

WIN=$(jq 'length' telemetry_handoff/windows_events.json)
LINUX=$(jq 'length' telemetry_handoff/linux_events.json)

ACTIONS=$(jq '
  if type == "array" then length
  elif (.windows? and .linux?) then
    (.windows | length) + (.linux | length)
  elif .events? then (.events | length)
  else 0 end
' telemetry_handoff/attack_ground_truth.json)

echo "Windows events: $WIN"
echo "Linux events: $LINUX"
echo "Ground truth actions: $ACTIONS"

# Detection matrix helpers.
matrix_total() {
  jq '
    if .actions? then
      (.actions | length)
    elif .events? then
      (.events | length)
    elif type == "array" then length
    else 0 end
  ' "$1"
}

matrix_captured() {
  jq '
    if .actions? then
      [.actions[] | select(
        (.status? // "" | ascii_upcase) == "CAPTURED" or
        (.captured? // false) == true
      )] | length
    elif .events? then
      [.events[] | select(
        (.status? // "" | ascii_upcase) == "CAPTURED" or
        (.captured? // false) == true
      )] | length
    elif type == "array" then
      [.[] | select(
        (.status? // "" | ascii_upcase) == "CAPTURED" or
        (.captured? // false) == true
      )] | length
    else 0 end
  ' "$1"
}

# for multi-source
matrix_multi() {
  jq '
    if .actions? then
      [.actions[] | select(
        (.multi_source? // false) == true or
        ((.sources? // []) | length) > 1
      )] | length
    elif .events? then
      [.events[] | select(
        (.multi_source? // false) == true or
        ((.sources? // []) | length) > 1
      )] | length
    elif type == "array" then
      [.[] | select(
        (.multi_source? // false) == true or
        ((.sources? // []) | length) > 1
      )] | length
    else 0 end
  ' "$1"
}

WIN_DT=$(matrix_total windows_detection_matrix.json)
LINUX_DT=$(matrix_total linux_detection_matrix.json)
WIN_CAP=$(matrix_captured windows_detection_matrix.json)
LINUX_CAP=$(matrix_captured linux_detection_matrix.json)
WIN_MULTI=$(matrix_multi windows_detection_matrix.json)
LINUX_MULTI=$(matrix_multi linux_detection_matrix.json)

DT_TOTAL=$((WIN_DT + LINUX_DT))
CAPTURED=$((WIN_CAP + LINUX_CAP))
MISSED=$((DT_TOTAL - CAPTURED))
MULTI=$((WIN_MULTI + LINUX_MULTI))

echo "Detection matrix: $CAPTURED/$DT_TOTAL captured"

# ATT&CK coverage.
jq -n \
  --argjson win "$(cat sysmon_coverage_matrix.json)" \
  --argjson wdt "$(cat windows_detection_matrix.json)" \
  --argjson ldt "$(cat linux_detection_matrix.json)" \
  '
  def techniques:
    [
      $win.techniques? // [],
      $win.covered_techniques? // [],
      $wdt.techniques? // [],
      $ldt.techniques? // []
    ] | add | map(
      if type == "string" then
        {technique: ., status: "covered"}
      else . end
    );

  (techniques) as $t |
  {
    covered: ([$t[] | select(
      (.status // "" | ascii_downcase) == "covered"
    ) | .technique] | unique),
    partial: ([$t[] | select(
      (.status // "" | ascii_downcase) == "partial"
    ) | .technique] | unique),
    blind: ([$t[] | select(
      (.status // "" | ascii_downcase) == "blind"
    ) | .technique] | unique)
  }
  ' > /tmp/attack_coverage.json

COVERED=$(jq '.covered | length' /tmp/attack_coverage.json)
PARTIAL=$(jq '.partial | length' /tmp/attack_coverage.json)
BLIND=$(jq '.blind | length' /tmp/attack_coverage.json)

echo "ATT&CK covered: $COVERED"
echo "ATT&CK partial: $PARTIAL"
echo "ATT&CK blind: $BLIND"

# Quality scores.
WIN_SCORE=$(jq -r '
  .quality_score // .score // .quality?.score // 0
' windows_telemetry_quality.json)

LINUX_SCORE=$(jq -r '
  .quality_score // .score // .quality?.score // 0
' linux_telemetry_quality.json)

if (( $(awk "BEGIN {print ($WIN_SCORE + $LINUX_SCORE) / 2 >= 90}") )); then
  CONFIDENCE="good"
elif (( $(awk "BEGIN {print ($WIN_SCORE + $LINUX_SCORE) / 2 >= 75}") )); then
  CONFIDENCE="acceptable"
else
  CONFIDENCE="poor"
fi

echo "Windows quality: $WIN_SCORE"
echo "Linux quality: $LINUX_SCORE"
echo "Confidence: $CONFIDENCE"

# Build event distributions.
jq -n \
  --argjson w "$(cat telemetry_handoff/windows_events.json)" \
  --argjson l "$(cat telemetry_handoff/linux_events.json)" \
  '
  ($w + $l) as $events |
  {
    total_events: ($events | length),
    platform: {
      Windows: ($w | length),
      Linux: ($l | length)
    },
    source_type: (
      $events
      | group_by(.source_type)
      | map({key: .[0].source_type, value: length})
      | from_entries
    ),
    event_category: (
      $events
      | group_by(.event_category)
      | map({key: .[0].event_category, value: length})
      | from_entries
    )
  }
  ' > /tmp/event_summary.json

# Known gaps from blind/partial ATT&CK techniques.
jq '
  [
    (.blind[] | {
      description: "No telemetry coverage detected",
      impacted_platform: "Windows/Linux",
      impacted_technique: .,
      reason: "No matching detection source",
      recommendation: "Add or enable endpoint instrumentation for the technique"
    }),
    (.partial[] | {
      description: "Partial telemetry coverage",
      impacted_platform: "Windows/Linux",
      impacted_technique: .,
      reason: "Detection exists but telemetry is incomplete",
      recommendation: "Increase audit/Sysmon coverage and validate event collection"
    })
  ]
' /tmp/attack_coverage.json > /tmp/known_gaps.json

# Final report with simulated actions from detection matrix, attack coverage, gaps and a resume of event distribution.
jq -n \
  --argjson summary "$(cat /tmp/event_summary.json)" \
  --argjson coverage "$(cat /tmp/attack_coverage.json)" \
  --argjson gaps "$(cat /tmp/known_gaps.json)" \
  --argjson actions "$ACTIONS" \
  --argjson captured "$CAPTURED" \
  --argjson missed "$MISSED" \
  --argjson multi "$MULTI" \
  --argjson win_score "$WIN_SCORE" \
  --argjson linux_score "$LINUX_SCORE" \
  --arg confidence "$CONFIDENCE" \
  '{
    total_events: $summary.total_events,
    event_distribution: {
      platform: $summary.platform,
      source_type: $summary.source_type,
      event_category: $summary.event_category
    },
    detection_matrix: {
      simulated_actions: $actions,
      captured: $captured,
      missed: $missed,
      multi_source: $multi
    },
    attack_coverage: {
      covered: $coverage.covered,
      partial: $coverage.partial,
      blind: $coverage.blind
    },
    known_gaps: $gaps,
    quality_summary: {
      windows_score: $win_score,
      linux_score: $linux_score,
      final_handoff_confidence: $confidence
    }
  }' > "$OUT"

rm -f /tmp/attack_coverage.json /tmp/event_summary.json /tmp/known_gaps.json

echo "Report saved to: $OUT"
