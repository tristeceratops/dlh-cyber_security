#!/bin/bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?SHIFT_WORKSPACE must be set}"

START_FILE="$SHIFT_WORKSPACE/runtime/shift_start.json"
INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
CAMPAIGN_FILE="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"
MANIFEST_FILE="$SHIFT_WORKSPACE/MANIFEST.json"
HANDOFF_FILE="$SHIFT_WORKSPACE/handoff/shift_handoff.md"

required_files=(
  "runtime/shift_start.json"
  "runtime/pipeline_run.json"
  "runtime/catalog_run.json"
  "runtime/baseline_run.json"
  "enriched/enriched_events.jsonl"
  "enriched/timeline.jsonl"
  "enriched/baseline.json"
  "enriched/source_stats.json"
  "alerts/alert_queue.json"
  "alerts/shift_briefing.json"
  "alerts/triage_log.jsonl"
  "alerts/incidents.json"
  "investigations/incident_A.json"
  "investigations/incident_B.json"
  "investigations/incident_C_cli.json"
  "investigations/incident_C_export.json"
  "campaign/campaign_assessment.json"
  "reports/incident_A.md"
  "reports/incident_B.md"
  "reports/incident_C.md"
  "response/tuning_recommendations.json"
  "response/containment.json"
  "response/ioc_package.json"
  "handoff/shift_handoff.md"
)

fail() {
  echo "[handoff] ERROR: $*" >&2
  exit 1
}

echo "[handoff] checking workspace layout..."

for rel in "${required_files[@]}"; do
  path="$SHIFT_WORKSPACE/$rel"

  if [[ ! -e "$path" ]]; then
    fail "missing file: $rel"
  fi

  if [[ ! -s "$path" ]]; then
    fail "empty file: $rel"
  fi

  echo "[handoff] OK $rel"
done

echo "[handoff] checking workspace layout... ${#required_files[@]} files OK"

[[ -s "$START_FILE" ]] || fail "shift_start.json missing or empty"
[[ -s "$INCIDENTS_FILE" ]] || fail "incidents.json missing or empty"
[[ -s "$CAMPAIGN_FILE" ]] || fail "campaign_assessment.json missing or empty"

shift_id="$(jq -er '.shift_id' "$START_FILE")"
analyst_host="$(jq -er '.analyst_host' "$START_FILE")"
started_at="$(jq -er '.started_at' "$START_FILE")"
ended_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

[[ -n "$shift_id" ]] || fail "shift_id is empty"
[[ -n "$analyst_host" ]] || fail "analyst_host is empty"
[[ -n "$started_at" ]] || fail "started_at is empty"

start_epoch="$(date -u -d "$started_at" '+%s')" \
  || fail "invalid started_at: $started_at"
end_epoch="$(date -u -d "$ended_at" '+%s')" \
  || fail "could not calculate ended_at"

if (( end_epoch < start_epoch )); then
  fail "ended_at precedes started_at"
fi

duration_hours="$(awk -v d="$((end_epoch - start_epoch))" 'BEGIN { printf "%.1f", d / 3600 }')"

echo "[handoff] shift_id: $shift_id"
echo "[handoff] duration: $duration_hours hours"

incident_ids_json="$(jq -c '.incidents | map(.incident_id)' "$INCIDENTS_FILE")"
incident_count="$(jq -r 'length' <<< "$incident_ids_json")"

(( incident_count > 0 )) || fail "incidents.json contains no incidents"

campaign_linked="$(jq -er '.campaign_linked' "$CAMPAIGN_FILE")"
cluster_id="$(jq -r '.cluster_id // "unknown"' "$CAMPAIGN_FILE")"
campaign_confidence="$(jq -r '.confidence // "unknown"' "$CAMPAIGN_FILE")"

ioc_count="$(jq -r '.ioc_count // 0' "$SHIFT_WORKSPACE/alerts/shift_briefing.json")"

pack_period="$(
  jq -r '
    [
      .first_seen?,
      .last_seen?
    ]
    | map(select(. != null and . != ""))
    | if length == 2 then "\(.[0]) to \(.[1])" else null end
  ' "$SHIFT_WORKSPACE/enriched/timeline.jsonl" 2>/dev/null || true
)"

if [[ -z "$pack_period" || "$pack_period" == "null" ]]; then
  pack_period="$(
    jq -r '
      [
        .started_at?,
        .ended_at?
      ]
      | map(select(. != null and . != ""))
      | if length == 2 then "\(.[0]) to \(.[1])" else "evidence-pack period recorded in enriched timeline" end
    ' "$SHIFT_WORKSPACE/runtime/pipeline_run.json"
  )"
fi

# Build a manifest snapshot containing all existing workspace files except:
# - MANIFEST.json itself
# - shift_handoff.md, because its contents depend on the manifest snapshot.
#
# This avoids an impossible cryptographic circular dependency.
snapshot_file="$(mktemp)"
final_manifest_file="$(mktemp)"
trap 'rm -f "$snapshot_file" "$final_manifest_file"' EXIT

mapfile -t workspace_files < <(
  find "$SHIFT_WORKSPACE" -type f \
    ! -path "$MANIFEST_FILE" \
    ! -path "$HANDOFF_FILE" \
    -printf '%P\n' \
    | sort
)

[[ "${#workspace_files[@]}" -gt 0 ]] || fail "no workspace files available for manifest"

files_json='[]'

for rel in "${workspace_files[@]}"; do
  full="$SHIFT_WORKSPACE/$rel"
  hash="$(sha256sum "$full" | awk '{print $1}')"
  size="$(stat -c '%s' "$full")"

  files_json="$(
    jq -c \
      --arg path "$rel" \
      --arg sha256 "$hash" \
      --argjson size "$size" \
      '. + [{path:$path,sha256:$sha256,size:$size}]' \
      <<< "$files_json"
  )"
done

artifact_counts="$(
  jq -n \
    --argjson files "$files_json" '
    reduce $files[] as $f
      ({
        runtime:0,
        enriched:0,
        alerts:0,
        investigations:0,
        campaign:0,
        reports:0,
        response:0,
        handoff:0
      };
      if ($f.path | startswith("runtime/")) then .runtime += 1
      elif ($f.path | startswith("enriched/")) then .enriched += 1
      elif ($f.path | startswith("alerts/")) then .alerts += 1
      elif ($f.path | startswith("investigations/")) then .investigations += 1
      elif ($f.path | startswith("campaign/")) then .campaign += 1
      elif ($f.path | startswith("reports/")) then .reports += 1
      elif ($f.path | startswith("response/")) then .response += 1
      elif ($f.path | startswith("handoff/")) then .handoff += 1
      else .
      end)
  '
)"

jq -n \
  --arg shift_id "$shift_id" \
  --arg analyst_host "$analyst_host" \
  --arg started_at "$started_at" \
  --arg ended_at "$ended_at" \
  --argjson duration_hours "$duration_hours" \
  --argjson files "$files_json" \
  --argjson artifact_counts "$artifact_counts" \
  --argjson incident_ids "$incident_ids_json" \
  --argjson campaign_linked "$campaign_linked" \
  --arg cluster_id "$cluster_id" '
  {
    shift_id:$shift_id,
    analyst_host:$analyst_host,
    started_at:$started_at,
    ended_at:$ended_at,
    duration_hours:$duration_hours,
    files:$files,
    artifact_counts:$artifact_counts,
    incident_ids:$incident_ids,
    campaign_linked:$campaign_linked,
    cluster_id:$cluster_id
  }
' > "$snapshot_file"

# Determine verdict/technique for each incident from the actual finding.
incident_paragraphs=""

while IFS= read -r incident_id; do
  suffix="${incident_id##*-}"
  case "$suffix" in
    A|B|C)
      finding="$SHIFT_WORKSPACE/investigations/incident_${suffix}.json"
      report="$SHIFT_WORKSPACE/reports/incident_${suffix}.md"
      ;;
    *)
      finding=""
      report=""
      ;;
  esac

  [[ -n "$finding" && -s "$finding" ]] \
    || fail "no investigation finding for $incident_id"

  [[ -n "$report" && -s "$report" ]] \
    || fail "no incident report for $incident_id"

  verdict="$(
    jq -r '
      if (.confidence // "unknown") == "high" then "TP"
      elif (.confidence // "unknown") == "medium" then "TP"
      else "ambiguous"
      end
    ' "$finding"
  )"

  technique="$(
    jq -r '
      (.attack_techniques // [])
      | if length > 0 then .[0] else "not recorded" end
    ' "$finding"
  )"

  incident_paragraphs+="The incident $incident_id is assessed as $verdict. The primary ATT&CK technique is $technique. The detailed incident report is at \`reports/incident_${suffix}.md\`. "

done < <(jq -r '.incidents[].incident_id' "$INCIDENTS_FILE")

open_items=()

# Prior-shift open items
while IFS= read -r item; do
  [[ -n "$item" ]] && open_items+=("$item")
done < <(
  jq -r '.prior_shift_open_items[]?' \
    "$SHIFT_WORKSPACE/alerts/shift_briefing.json"
)

# Add unresolved/ambiguous investigations.
while IFS= read -r incident_id; do
  suffix="${incident_id##*-}"
  finding="$SHIFT_WORKSPACE/investigations/incident_${suffix}.json"

  if [[ -s "$finding" ]]; then
    confidence="$(jq -r '.confidence // "unknown"' "$finding")"
    if [[ "$confidence" != "high" ]]; then
      open_items+=(
        "Revalidate $incident_id using the enriched event timeline and investigation finding before final closure."
      )
    fi
  fi
done < <(jq -r '.incidents[].incident_id' "$INCIDENTS_FILE")

# Add campaign follow-up when assessment is not high confidence.
if [[ "$campaign_confidence" != "high" ]]; then
  open_items+=(
    "Resolve campaign-linkage uncertainty using the remaining Wazuh export evidence and cross-incident IOC/tactic correlations."
  )
fi

# Ensure no more than eight open items.
open_items_json='[]'
for item in "${open_items[@]}"; do
  if (( $(jq 'length' <<< "$open_items_json") >= 8 )); then
    break
  fi

  open_items_json="$(
    jq -c --arg item "$item" '. + [$item]' <<< "$open_items_json"
  )"
done

{
  echo "# Shift Handoff"
  echo
  echo "## Shift Identifier"
  echo
  echo "**Shift ID:** $shift_id  "
  echo "**Analyst Host:** $analyst_host  "
  echo "**Started:** $started_at  "
  echo "**Ended:** $ended_at  "
  echo "**Duration:** $duration_hours hours"
  echo
  echo "## Situation"
  echo
  echo "This shift covered the secondary evidence pack and the HC-RED7 advisory context. The current IOC feed contains $ioc_count tracked indicators, which were used alongside detections, baselines, and investigation findings. The evidence-pack period is $pack_period. The handoff records the observed incidents, campaign assessment, outstanding investigation items, and response artifacts for the next analyst."
  echo
  echo "## Incidents"
  echo
  printf '%s\n' "$incident_paragraphs"
  echo
  echo "## Campaign Assessment"
  echo
  echo "The incidents are assessed as campaign-linked: **$campaign_linked**. The associated cluster is **$cluster_id**, with an assessment confidence of **$campaign_confidence**. The authoritative campaign assessment, including mechanical linkage counts and export-view comparison, is recorded in \`campaign/campaign_assessment.json\`."
  echo
  echo "## Open Items for Next Shift"
  echo

  jq -r '.[] | "- \(. )"' <<< "$open_items_json"

  echo
  echo "## Artifact Index"
  echo
  echo "| Artifact | SHA256 |"
  echo "|---|---|"

  jq -r '
    .files[]
    | "| `\(.path)` | `\(.sha256)` |"
  ' "$snapshot_file"

} > "$HANDOFF_FILE"

[[ -s "$HANDOFF_FILE" ]] || fail "shift_handoff.md was not created"

word_count="$(wc -w < "$HANDOFF_FILE" | tr -d ' ')"

if (( word_count > 900 )); then
  fail "shift_handoff.md is $word_count words; maximum is 900"
fi

required_sections=(
  "## Shift Identifier"
  "## Situation"
  "## Incidents"
  "## Campaign Assessment"
  "## Open Items for Next Shift"
  "## Artifact Index"
)

for section in "${required_sections[@]}"; do
  grep -Fqx "$section" "$HANDOFF_FILE" \
    || fail "missing required section: $section"
done

echo "[handoff] shift_handoff.md: $word_count words, 6 sections OK"

# Verify every incident ID mentioned in the handoff exists in incidents.json.
mapfile -t handoff_ids < <(
  grep -oE 'INC-[0-9]{8}-[A-Z]+' "$HANDOFF_FILE" | sort -u
)

for id in "${handoff_ids[@]}"; do
  jq -e --arg id "$id" '.incidents[] | select(.incident_id == $id)' \
    "$INCIDENTS_FILE" >/dev/null \
    || fail "incident ID in handoff not found in incidents.json: $id"
done

handoff_id_display="${handoff_ids[*]:-none}"
echo "[handoff] incident IDs in handoff: $handoff_id_display (all in incidents.json: OK)"

# Build the final manifest, now including the actual handoff hash.
final_files_json="$files_json"

handoff_hash="$(sha256sum "$HANDOFF_FILE" | awk '{print $1}')"
handoff_size="$(stat -c '%s' "$HANDOFF_FILE")"

final_files_json="$(
  jq -c \
    --arg path "handoff/shift_handoff.md" \
    --arg sha256 "$handoff_hash" \
    --argjson size "$handoff_size" \
    '. + [{path:$path,sha256:$sha256,size:$size}]' \
    <<< "$final_files_json"
)"

final_artifact_counts="$(
  jq '.handoff += 1' <<< "$artifact_counts"
)"

jq -n \
  --arg shift_id "$shift_id" \
  --arg analyst_host "$analyst_host" \
  --arg started_at "$started_at" \
  --arg ended_at "$ended_at" \
  --argjson duration_hours "$duration_hours" \
  --argjson files "$final_files_json" \
  --argjson artifact_counts "$final_artifact_counts" \
  --argjson incident_ids "$incident_ids_json" \
  --argjson campaign_linked "$campaign_linked" \
  --arg cluster_id "$cluster_id" '
  {
    shift_id:$shift_id,
    analyst_host:$analyst_host,
    started_at:$started_at,
    ended_at:$ended_at,
    duration_hours:$duration_hours,
    files:$files,
    artifact_counts:$artifact_counts,
    incident_ids:$incident_ids,
    campaign_linked:$campaign_linked,
    cluster_id:$cluster_id
  }
' > "$final_manifest_file"

mv "$final_manifest_file" "$MANIFEST_FILE"

manifest_files="$(jq '.files | length' "$MANIFEST_FILE")"
manifest_bytes="$(du -b "$MANIFEST_FILE" | awk '{print $1}')"
manifest_kb="$(awk -v b="$manifest_bytes" 'BEGIN { printf "%.1f", b / 1024 }')"

echo "[handoff] MANIFEST.json: $manifest_files files, $manifest_kb KB total"
echo "[handoff] campaign_linked=$campaign_linked cluster=$cluster_id"

# Final validation: all required files, including newly written manifest, exist.
for rel in "${required_files[@]}"; do
  [[ -s "$SHIFT_WORKSPACE/$rel" ]] \
    || fail "final validation failed: $rel"
done

[[ -s "$MANIFEST_FILE" ]] || fail "final MANIFEST.json missing or empty"

echo "[handoff] handoff package complete"
