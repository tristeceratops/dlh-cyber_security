#!/bin/bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?SHIFT_WORKSPACE is not set}"
: "${ASSETS_DIR:?ASSETS_DIR is not set}"
: "${WAZUH_EXPORTS:?WAZUH_EXPORTS is not set}"

CAMPAIGN_DIR="$SHIFT_WORKSPACE/campaign"
INC_DIR="$SHIFT_WORKSPACE/investigations"
ALERTS_DIR="$SHIFT_WORKSPACE/alerts"
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"

A_FILE="$INC_DIR/incident_A.json"
B_FILE="$INC_DIR/incident_B.json"
C_FILE="$INC_DIR/incident_C_cli.json"

INCIDENTS_FILE="$ALERTS_DIR/incidents.json"
IOC_FEED="$ASSETS_DIR/ioc_feed.json"
EVENTS_FILE="$ENRICHED_DIR/enriched_events.jsonl"
SUMMARY_FILE="$WAZUH_EXPORTS/campaign_dashboard_summary.md"
WORKFLOW_FILE="$WAZUH_EXPORTS/exported_dashboard_workflow.json"

OUT="$CAMPAIGN_DIR/campaign_assessment.json"

fail() {
    echo "[campaign] ERROR: $*" >&2
    exit 1
}

require_file() {
    local f="$1"
    [[ -s "$f" ]] || fail "required file missing or empty: $f"
}

echo "[campaign] loading 3 incident findings"

require_file "$A_FILE"
require_file "$B_FILE"
require_file "$C_FILE"
require_file "$INCIDENTS_FILE"
require_file "$IOC_FEED"
require_file "$EVENTS_FILE"
require_file "$SUMMARY_FILE"
require_file "$WORKFLOW_FILE"

mkdir -p "$CAMPAIGN_DIR"

jq empty "$A_FILE" >/dev/null || fail "invalid JSON: $A_FILE"
jq empty "$B_FILE" >/dev/null || fail "invalid JSON: $B_FILE"
jq empty "$C_FILE" >/dev/null || fail "invalid JSON: $C_FILE"
jq empty "$INCIDENTS_FILE" >/dev/null || fail "invalid JSON: $INCIDENTS_FILE"
jq empty "$IOC_FEED" >/dev/null || fail "invalid JSON: $IOC_FEED"
jq empty "$WORKFLOW_FILE" >/dev/null || fail "invalid JSON: $WORKFLOW_FILE"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# Normalize the three CLI findings.
# ---------------------------------------------------------------------------
jq -s '
  {
    A: .[0],
    B: .[1],
    C: .[2]
  }
' "$A_FILE" "$B_FILE" "$C_FILE" > "$TMPDIR/findings.json"

for key in A B C; do
    jq -e --arg k "$key" '.[$k].incident_id and (.[$k].event_refs | type == "array") and (.[$k].attack_techniques | type == "array")' \
        "$TMPDIR/findings.json" >/dev/null \
        || fail "finding $key does not contain required fields"
done

# ---------------------------------------------------------------------------
# Build normalized IOC feed:
# - all scalar IOC values become strings
# - preserve type/confidence/cluster where available
# ---------------------------------------------------------------------------
jq -c '
  def objects:
    .. | objects;

  [
    objects
    | (
        .value?
        // .ioc?
        // .indicator?
        // .ip?
        // .domain?
        // .hash?
        // .account?
        // .service_name?
        // .port?
      ) as $v
    | select($v != null)
    | {
        value: ($v | tostring),
        type: (.type? // "unknown" | tostring),
        confidence: (.confidence? // "unknown" | tostring),
        cluster: (.cluster? // "unknown" | tostring)
      }
  ]
  | unique_by(.value)
' "$IOC_FEED" > "$TMPDIR/ioc_objects.json"

IOC_COUNT="$(jq 'length' "$TMPDIR/ioc_objects.json")"
[[ "$IOC_COUNT" -gt 0 ]] || fail "no IOC values found in feed"

echo "[campaign] ioc feed: $IOC_COUNT IOCs loaded"

# Fast lookup set: normalized value -> true.
jq '
  map({
    key: (.value | ascii_downcase),
    value: true
  })
  | from_entries
' "$TMPDIR/ioc_objects.json" > "$TMPDIR/ioc_set.json"

# ---------------------------------------------------------------------------
# Normalize enriched events. This allows event_refs from findings to be
# resolved to the actual event records and checks both IPs and user accounts.
# ---------------------------------------------------------------------------
jq -s '
  if length == 1 and (.[0] | type) == "array" then .[0]
  elif length == 1 and (.[0] | type) == "object" then [.[0]]
  else .
  end
' "$EVENTS_FILE" > "$TMPDIR/events.json"

# ---------------------------------------------------------------------------
# Resolve every finding event_ref and calculate direct IOC-feed matches.
#
# A direct feed match is counted once per event_ref if at least one relevant
# event field (src_ip, dst_ip, user/account) occurs in the IOC set.
# ---------------------------------------------------------------------------
for key in A B C; do
    jq --arg key "$key" \
       --slurpfile events "$TMPDIR/events.json" \
       --slurpfile iocset "$TMPDIR/ioc_set.json" '
        def norm:
          if . == null then null
          else tostring | ascii_downcase
          end;

        ($events[0]) as $events_array |
        ($iocset[0]) as $ioc_values |
        .[$key].event_refs
        | map(. as $ref |
            ($events_array
             | map(select(
                 ((.event_id? // .id? // .eventId?) | tostring) == ($ref | tostring)
               ))
             | .[0]) as $event
            | {
                event_ref: ($ref | tostring),
                found: ($event != null),
                feed_match: (
                  if $event == null then false
                  else [
                    ($event.src_ip? // empty),
                    ($event.dst_ip? // empty),
                    ($event.source_ip? // empty),
                    ($event.destination_ip? // empty),
                    ($event.user? // empty),
                    ($event.username? // empty),
                    ($event.account? // empty)
                  ]
                  | map(norm)
                  | map(select(. != null))
                  | any(.[]; $ioc_values[.] == true)
                  end
                )
              }
          )
    ' "$TMPDIR/findings.json" > "$TMPDIR/${key}_event_matches.json"

    total_refs="$(jq 'length' "$TMPDIR/${key}_event_matches.json")"
    missing_refs="$(jq '[.[] | select(.found == false)] | length' "$TMPDIR/${key}_event_matches.json")"
    feed_matches="$(jq '[.[] | select(.feed_match == true)] | length' "$TMPDIR/${key}_event_matches.json")"

    [[ "$missing_refs" -eq 0 ]] || \
        fail "finding $key references $missing_refs event(s) not present in enriched_events.jsonl"

    printf '%s\n' "$feed_matches" > "$TMPDIR/${key}_feed_count"
done

A_FEED="$(cat "$TMPDIR/A_feed_count")"
B_FEED="$(cat "$TMPDIR/B_feed_count")"
C_FEED="$(cat "$TMPDIR/C_feed_count")"

# ---------------------------------------------------------------------------
# Load incident surface information from incidents.json.
# ---------------------------------------------------------------------------
jq '
  .incidents
  | map({
      key: (.incident_id | capture("INC-[0-9]{8}-(?<suffix>[ABC])").suffix),
      value: {
        incident_id,
        host_list: (.host_list // [] | map(tostring | ascii_downcase) | unique),
        user_list: (.user_list // [] | map(select(. != null) | tostring | ascii_downcase) | unique),
        ioc_list: (
          (.ioc_list // .matches_ioc // [])
          | map(select(. != null) | tostring)
          | unique
        ),
        first_seen,
        last_seen
      }
    })
  | from_entries
' "$INCIDENTS_FILE" > "$TMPDIR/incident_surface.json"

for key in A B C; do
    jq -e --arg k "$key" '.[$k] != null' "$TMPDIR/incident_surface.json" >/dev/null \
        || fail "incident surface missing $key"
done

# ---------------------------------------------------------------------------
# Pairwise mechanical correlation.
# ---------------------------------------------------------------------------
pair_calculation() {
    local left="$1"
    local right="$2"

    jq --arg l "$left" --arg r "$right" '
      def minutes_between($a; $b):
        (($b | fromdateiso8601) - ($a | fromdateiso8601)) / 60;

      . as $s
      | ($s[$l]) as $a
      | ($s[$r]) as $b

      | (
          [$a.ioc_list[] | tostring]
          | map(select(. as $v | ($b.ioc_list | index($v)) != null))
          | unique
          | length
        ) as $ioc

      | (
          [$a.host_list[]] as $ah
          | [$b.host_list[]] as $bh
          | (($ah + $bh) | unique | length)
        ) as $host_union

      | {
          ioc_overlap: $ioc,
          shared_host: (
            [$a.host_list[]]
            | any(.[]; . as $h | ($b.host_list | index($h)) != null)
          ),
          shared_user: (
            [$a.user_list[]]
            | any(.[]; . as $u | ($b.user_list | index($u)) != null)
          ),
          temporal_distance: (
            if ($a.last_seen | fromdateiso8601) <= ($b.first_seen | fromdateiso8601)
            then minutes_between($a.last_seen; $b.first_seen)
            elif ($b.last_seen | fromdateiso8601) <= ($a.first_seen | fromdateiso8601)
            then minutes_between($b.last_seen; $a.first_seen)
            else 0
            end
          )
        }
    ' "$TMPDIR/incident_surface.json"
}

pair_calculation A B > "$TMPDIR/AB.json"
pair_calculation A C > "$TMPDIR/AC.json"
pair_calculation B C > "$TMPDIR/BC.json"

# ---------------------------------------------------------------------------
# Tactic overlap comes from the three CLI finding files.
# ---------------------------------------------------------------------------
tactic_overlap() {
    local left="$1"
    local right="$2"

    jq --arg l "$left" --arg r "$right" '
      .[$l].attack_techniques as $a
      | .[$r].attack_techniques as $b
      | [$a[] | select(($b | index(.)) != null)]
      | unique
      | length
    ' "$TMPDIR/findings.json"
}

AB_TACTICS="$(tactic_overlap A B)"
AC_TACTICS="$(tactic_overlap A C)"
BC_TACTICS="$(tactic_overlap B C)"

AB_IOC="$(jq -r '.ioc_overlap' "$TMPDIR/AB.json")"
AC_IOC="$(jq -r '.ioc_overlap' "$TMPDIR/AC.json")"
BC_IOC="$(jq -r '.ioc_overlap' "$TMPDIR/BC.json")"

AB_TIME="$(jq -r '.temporal_distance' "$TMPDIR/AB.json")"
AC_TIME="$(jq -r '.temporal_distance' "$TMPDIR/AC.json")"
BC_TIME="$(jq -r '.temporal_distance' "$TMPDIR/BC.json")"

echo "[campaign] A-B: ioc_overlap=$AB_IOC tactic_overlap=$AB_TACTICS temporal_dist=${AB_TIME}min"
echo "[campaign] A-C: ioc_overlap=$AC_IOC tactic_overlap=$AC_TACTICS temporal_dist=${AC_TIME}min"
echo "[campaign] B-C: ioc_overlap=$BC_IOC tactic_overlap=$BC_TACTICS temporal_dist=${BC_TIME}min"

echo "[campaign] feed matches: A=$A_FEED B=$B_FEED C=$C_FEED"

# ---------------------------------------------------------------------------
# Apply the locked mechanical linkage rules.
#
# Rule 1: shared IOC >= 1 AND either incident has a direct feed match.
# Rule 2: shared tactic >= 2 AND temporal distance <= 360 minutes.
# Rule 3: shared user OR shared host.
# ---------------------------------------------------------------------------
link_pair() {
    local pair="$1"
    local left="$2"
    local right="$3"
    local json_file="$4"
    local tactic_count="$5"
    local left_feed="$6"
    local right_feed="$7"

    local ioc_count
    local temporal
    local shared_user
    local shared_host
    local linked

    ioc_count="$(jq -r '.ioc_overlap' "$json_file")"
    temporal="$(jq -r '.temporal_distance' "$json_file")"
    shared_user="$(jq -r '.shared_user' "$json_file")"
    shared_host="$(jq -r '.shared_host' "$json_file")"

    linked=false

    if [[ "$ioc_count" -ge 1 ]] && { [[ "$left_feed" -gt 0 ]] || [[ "$right_feed" -gt 0 ]]; }; then
        linked=true
    fi

    if [[ "$tactic_count" -ge 2 ]] && awk "BEGIN { exit !($temporal <= 360) }"; then
        linked=true
    fi

    if [[ "$shared_user" == "true" || "$shared_host" == "true" ]]; then
        linked=true
    fi

    if [[ "$linked" == "true" ]]; then
        printf '%s\n' "$pair" >> "$TMPDIR/linked_pairs.txt"
    fi
}

: > "$TMPDIR/linked_pairs.txt"

link_pair "A-B" A B "$TMPDIR/AB.json" "$AB_TACTICS" "$A_FEED" "$B_FEED"
link_pair "A-C" A C "$TMPDIR/AC.json" "$AC_TACTICS" "$A_FEED" "$C_FEED"
link_pair "B-C" B C "$TMPDIR/BC.json" "$B_TACTICS" "$B_FEED" "$C_FEED"

# ---------------------------------------------------------------------------
# Extract export-view campaign verdict.
# Prefer explicit workflow verdict fields, then dashboard summary text.
# ---------------------------------------------------------------------------
export_verdict="$(
    jq -r '
      def candidates:
        [
          .campaign_linked?,
          .campaign_verdict?,
          .verdict?,
          .campaign?.linked?,
          .campaign?.campaign_linked?,
          .campaign?.verdict?,
          .result?.campaign_linked?,
          .result?.verdict?
        ]
        | map(select(. != null))
        | .[0] // empty;

      candidates
      | if type == "boolean" then
          ("campaign_linked=" + tostring)
        else tostring
        end
    ' "$WORKFLOW_FILE" 2>/dev/null || true
)"

workflow_cluster="$(
    jq -r '
      [
        .cluster_id?,
        .cluster?,
        .campaign?.cluster_id?,
        .campaign?.cluster?,
        .result?.cluster_id?
      ]
      | map(select(. != null))
      | .[0] // empty
    ' "$WORKFLOW_FILE" 2>/dev/null || true
)"

summary_verdict="$(
    grep -Eio \
        'campaign[_ -]?linked[[:space:]]*[:=][[:space:]]*(true|false)|campaign[[:space:]]+verdict[[:space:]]*[:=][[:space:]]*[A-Za-z_-]+' \
        "$SUMMARY_FILE" \
        | head -n1 \
        || true
)"

summary_cluster="$(
    grep -Eio \
        'cluster[ _-]?id[[:space:]]*[:=][[:space:]]*[A-Za-z0-9._-]+' \
        "$SUMMARY_FILE" \
        | head -n1 \
        | sed -E 's/.*[:=][[:space:]]*//' \
        || true
)"

if [[ -n "$export_verdict" ]]; then
    export_view_verdict="$export_verdict"
elif [[ -n "$summary_verdict" ]]; then
    export_view_verdict="$summary_verdict"
else
    export_view_verdict="unknown"
fi

cluster_id="${workflow_cluster:-${summary_cluster:-unknown}}"

echo "[campaign] export view: ${export_view_verdict} cluster=${cluster_id}"

# ---------------------------------------------------------------------------
# Determine mechanical campaign linkage and confidence.
#
# Confidence is mechanical, based on linkage evidence count:
#   high   = 2+ linked pairs
#   medium = 1 linked pair
#   low    = no linked pairs
# ---------------------------------------------------------------------------
linked_pairs_json="$(
    jq -R -s '
      split("\n")
      | map(select(length > 0))
    ' "$TMPDIR/linked_pairs.txt"
)"

linked_count="$(jq 'length' <<< "$linked_pairs_json")"

if [[ "$linked_count" -ge 2 ]]; then
    confidence="high"
elif [[ "$linked_count" -eq 1 ]]; then
    confidence="medium"
else
    confidence="low"
fi

if [[ "$linked_count" -gt 0 ]]; then
    campaign_linked=true
else
    campaign_linked=false
fi

shared_iocs_total=$((AB_IOC + AC_IOC + BC_IOC))
shared_tactics_total=$((AB_TACTICS + AC_TACTICS + BC_TACTICS))

echo "[campaign] linked pairs: $(if [[ "$linked_count" -gt 0 ]]; then paste -sd ', ' "$TMPDIR/linked_pairs.txt"; else echo "none"; fi)"

# ---------------------------------------------------------------------------
# Final locked campaign assessment.
# ---------------------------------------------------------------------------
jq -n \
    --argjson incidents "$(
        jq '[.A.incident_id, .B.incident_id, .C.incident_id]' "$TMPDIR/findings.json"
    )" \
    --argjson ioc_matrix "$(
        jq -n \
            --argjson ab "$AB_IOC" \
            --argjson ac "$AC_IOC" \
            --argjson bc "$BC_IOC" \
            '{"A-B":$ab,"A-C":$ac,"B-C":$bc}'
    )" \
    --argjson tactic_matrix "$(
        jq -n \
            --argjson ab "$AB_TACTICS" \
            --argjson ac "$AC_TACTICS" \
            --argjson bc "$BC_TACTICS" \
            '{"A-B":$ab,"A-C":$ac,"B-C":$bc}'
    )" \
    --argjson temporal_matrix "$(
        jq -n \
            --argjson ab "$AB_TIME" \
            --argjson ac "$AC_TIME" \
            --argjson bc "$BC_TIME" \
            '{"A-B":$ab,"A-C":$ac,"B-C":$bc}'
    )" \
    --argjson ioc_feed_matches \
        "$(jq -n --argjson a "$A_FEED" --argjson b "$B_FEED" --argjson c "$C_FEED" '{"A":$a,"B":$b,"C":$c}')" \
    --argjson linked_pairs "$linked_pairs_json" \
    --arg campaign_linked "$campaign_linked" \
    --arg cluster_id "$cluster_id" \
    --arg confidence "$confidence" \
    --arg export_view_verdict "$export_view_verdict" \
    --argjson shared_iocs_total "$shared_iocs_total" \
    --argjson shared_tactics_total "$shared_tactics_total" \
    '{
      incidents: $incidents,
      ioc_overlap_matrix: $ioc_matrix,
      tactic_overlap_matrix: $tactic_matrix,
      temporal_distance_minutes: $temporal_matrix,
      ioc_feed_matches: $ioc_feed_matches,
      linked_pairs: $linked_pairs,
      campaign_linked: ($campaign_linked == "true"),
      cluster_id: $cluster_id,
      confidence: $confidence,
      export_view_verdict: $export_view_verdict,
      supporting_counts: {
        shared_iocs_total: $shared_iocs_total,
        shared_tactics_total: $shared_tactics_total
      }
    }' > "$OUT"

jq empty "$OUT" >/dev/null
[[ -s "$OUT" ]] || fail "campaign assessment was not written"

echo "[campaign] verdict: campaign_linked=$campaign_linked cluster=$cluster_id confidence=$confidence"
echo "[campaign] campaign_assessment.json written"

exit 0
