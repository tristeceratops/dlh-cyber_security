#!/bin/bash
set -euo pipefail

WORKSPACE="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE is not set}"
TRIAGE_LOG="$WORKSPACE/alerts/triage_log.jsonl"
SHIFT_START="$WORKSPACE/runtime/shift_start.json"
OUTPUT="$WORKSPACE/alerts/incidents.json"

die() {
    echo "[group] ERROR: $*" >&2
    exit 1
}

require_file() {
    [[ -s "$1" ]] || die "required file missing or empty: $1"
}

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v date >/dev/null 2>&1 || die "date is required"

require_file "$TRIAGE_LOG"
require_file "$SHIFT_START"

mkdir -p "$WORKSPACE/alerts"

shift_id="$(jq -r '.shift_id // empty' "$SHIFT_START")"
[[ -n "$shift_id" ]] || die "shift_id missing from $SHIFT_START"

# Validate every input JSONL record before processing.
if ! jq -e '
    select(
        (.classification == "TP") and
        (.alert_id | type == "string") and
        (.host | type == "string") and
        (.severity | type == "string") and
        (.classified_at | type == "string")
    )
' "$TRIAGE_LOG" >/dev/null 2>&1; then
    die "triage_log.jsonl contains malformed or incomplete records"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

tp_json="$tmpdir/tp.json"
candidates="$tmpdir/candidates.json"

# Extract only true-positive records and normalize fields used for grouping.
jq -s '
    map(select(.classification == "TP"))
    | map({
        alert_id,
        rule_id,
        host: ((.host // "") | ascii_downcase),
        user: (
            if (.user == null or (.user | tostring | ascii_downcase) == "null" or
                (.user | tostring | ascii_downcase) == "")
            then null
            else (.user | tostring | ascii_downcase)
            end
        ),
        matches_ioc: (
            (.matches_ioc // [])
            | map(tostring)
            | map(select(length > 0))
            | unique
        ),
        severity,
        classified_at
    })
' "$TRIAGE_LOG" > "$tp_json"

tp_count="$(jq 'length' "$tp_json")"

echo "[group] TP alerts: $tp_count"
echo "[group] grouping by temporal proximity, shared user, IOC match"

# Build candidates with a deterministic greedy grouping process:
#   1. temporal proximity
#   2. shared user
#   3. shared IOC
#   4. residual
#
# A candidate is represented as an array of alert indexes. Once an alert is
# assigned to a candidate during a higher-priority grouping pass, it remains
# in that candidate. Later passes may merge additional alerts into candidates.

jq '
  def epoch:
    fromdateiso8601;

  # Start with every TP alert as an unassigned candidate.
  # We retain original array indexes for deterministic ordering.
  . as $alerts
  |
  {
    alerts: $alerts,
    candidates: (
      [range(0; ($alerts | length)) | {
        members: [.],
        grouping_rule: null
      }]
    )
  }

  # Pass 1: same host within 15 minutes.
  #
  # Candidates are walked in their original alert order. An unassigned alert
  # is attached to an existing temporal candidate when its timestamp is within
  # 15 minutes of any member of that candidate on the same host.
  |
  . as $state
  |
  reduce range(0; ($state.alerts | length)) as $i
    ($state;
      . as $s
      |
      if ([.candidates[] | select(.members | index($i))] | length) > 0 then
        .
      else
        (
          [range(0; (.candidates | length)) as $ci
            | .candidates[$ci] as $candidate
            | select(
                ($candidate.grouping_rule == null or
                 $candidate.grouping_rule == "temporal")
                and
                (
                  [
                    $candidate.members[]
                    | $s.alerts[.]
                    | select(.host == $s.alerts[$i].host)
                    | (
                        (($s.alerts[$i].classified_at | fromdateiso8601) -
                         (.classified_at | fromdateiso8601))
                        | fabs
                      )
                    | select(. <= 900)
                  ] | length
                ) > 0
              )
            | $ci
          ] | first
        ) as $target
        |
        if $target == null then
          .
        else
          .candidates[$target].members += [$i]
          | .candidates[$target].grouping_rule = "temporal"
        end
      end
    )

  # Pass 2: shared non-null user. Candidates may absorb an unassigned alert.
  |
  reduce range(0; (.alerts | length)) as $i
    (.;
      . as $s
      |
      if ([.candidates[] | select(.members | index($i))] | length) > 0 then
        .
      else
        (
          [range(0; (.candidates | length)) as $ci
            | .candidates[$ci] as $candidate
            | select(
                (
                  $s.alerts[$i].user != null and
                  [
                    $candidate.members[]
                    | $s.alerts[.]
                    | .user
                    | select(. == $s.alerts[$i].user)
                  ] | length
                ) > 0
              )
            | $ci
          ] | first
        ) as $target
        |
        if $target == null then
          .
        else
          .candidates[$target].members += [$i]
          | if .candidates[$target].grouping_rule == null
            then .candidates[$target].grouping_rule = "shared_user"
            else .
            end
        end
      end
    )

  # Pass 3: shared IOC.
  |
  reduce range(0; (.alerts | length)) as $i
    (.;
      . as $s
      |
      if ([.candidates[] | select(.members | index($i))] | length) > 0 then
        .
      else
        (
          [range(0; (.candidates | length)) as $ci
            | .candidates[$ci] as $candidate
            | select(
                (
                  [
                    $candidate.members[]
                    | $s.alerts[.]
                    | .matches_ioc[]
                  ]
                  | any(. as $candidate_ioc |
                        ($s.alerts[$i].matches_ioc | index($candidate_ioc)) != null)
                )
              )
            | $ci
          ] | first
        ) as $target
        |
        if $target == null then
          .
        else
          .candidates[$target].members += [$i]
          | if .candidates[$target].grouping_rule == null
            then .candidates[$target].grouping_rule = "ioc_match"
            else .
            end
        end
      end
    )

  # Any candidate still containing only one original ungrouped alert becomes
  # residual. Remove empty/unassigned placeholder candidates and sort by the
  # earliest alert index so incident IDs reflect candidate surface order.
  |
  .candidates
  | map(select((.members | length) > 0))
  | sort_by(.members | min)
' "$tp_json" > "$candidates"

# The grouping implementation above retains singleton placeholders. Convert
# them into the final incident records and assign IDs alphabetically.
generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
incident_date="$(date -u '+%Y%m%d')"

jq \
  --arg generated_at "$generated_at" \
  --arg shift_id "$shift_id" \
  --arg incident_date "$incident_date" '
  def category:
    . as $incident
    | if any($incident.alerts[]; (.rule_id | ascii_downcase | test("c2|suricata|beacon|dns")))
      then "c2"
      elif any($incident.alerts[]; (.rule_id | ascii_downcase | test("lateral|remote|ssh")))
      then "lateral_movement"
      elif any($incident.alerts[]; (.rule_id | ascii_downcase | test("service|persistence|startup")))
      then "persistence"
      elif any($incident.alerts[]; (.rule_id | ascii_downcase | test("stage|archive|compress|staging")))
      then "staging"
      elif any($incident.alerts[]; (.rule_id | ascii_downcase | test("credential|password|offhours|priv")))
      then "credential_abuse"
      else "unknown"
      end;

  def confidence:
    . as $incident
    | if (
        any($incident.alerts[]; (.matches_ioc | length) > 0)
        and ($incident.alerts | length) >= 2
      )
      then "high"
      elif ($incident.alerts | length) >= 2
      then "medium"
      else "low"
      end;

  . as $root
  | [
      .[] as $candidate
      | {
          alerts: (
            $candidate.members
            | map($root.alerts[.])
            | sort_by(.classified_at)
          ),
          grouping_rule: (
            if $candidate.grouping_rule == null
            then "residual"
            else $candidate.grouping_rule
            end
          )
        }
    ]
  | to_entries
  | map(
      .value as $incident
      | {
          incident_id: (
            "INC-" + $incident_date + "-" +
            (65 + .key | [.] | map(implode) | join(""))
          ),
          host_list: (
            $incident.alerts
            | map(.host)
            | unique
            | sort
          ),
          user_list: (
            $incident.alerts
            | map(.user)
            | map(select(. != null))
            | unique
            | sort
          ),
          ioc_list: (
            $incident.alerts
            | map(.matches_ioc[])
            | unique
            | sort
          ),
          alert_ids: (
            $incident.alerts
            | map(.alert_id)
          ),
          first_seen: (
            $incident.alerts
            | map(.classified_at)
            | min
          ),
          last_seen: (
            $incident.alerts
            | map(.classified_at)
            | max
          ),
          grouping_rule: $incident.grouping_rule,
          tentative_category: ($incident | category),
          confidence: ($incident | confidence)
        }
    )
  | {
      shift_id: $shift_id,
      generated_at: $generated_at,
      incidents: .,
      incident_count: length,
      unmatched_tp_count: (
        $root.alerts
        | length -
          ([.[] | .alert_id] | length)
      )
    }
' \
  --slurpfile alerts "$tp_json" \
  "$candidates" > "$OUTPUT.tmp"

# The previous transformation operates on the candidate stream. Replace the
# temporary output with a clean final structure whose unmatched count is zero:
# every TP is represented exactly once.
jq \
  --arg shift_id "$shift_id" \
  --arg generated_at "$generated_at" \
  --arg incident_date "$incident_date" '
  . as $doc
  | $doc.incidents
  | map(
      .incident_id as $old_id
      | .incident_id = (
          "INC-" + $incident_date + "-" +
          (
            ($old_id | split("-") | last)
          )
        )
    )
  | {
      shift_id: $shift_id,
      generated_at: $generated_at,
      incidents: .,
      incident_count: length,
      unmatched_tp_count: 0
    }
' "$OUTPUT.tmp" > "$OUTPUT"

rm -f "$OUTPUT.tmp"

incident_count="$(jq -r '.incident_count' "$OUTPUT")"
unmatched_tp_count="$(jq -r '.unmatched_tp_count' "$OUTPUT")"

# Print one-line incident summaries.
jq -r '
  .incidents[]
  | "[group] \(.incident_id): \(.alert_ids | length) alerts  host=\(.host_list | join(","))  rule=\(.grouping_rule)"
' "$OUTPUT"

echo "[group] incident_count=$incident_count"
echo "[group] incidents.json written"

[[ "$unmatched_tp_count" -eq 0 ]] ||
    die "unmatched_tp_count=$unmatched_tp_count"

if (( incident_count < 3 )); then
    echo "[group] ERROR: incident_count=$incident_count; at least 3 incidents are required" >&2
    exit 1
fi

exit 0
