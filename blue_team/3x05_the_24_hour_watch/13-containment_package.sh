#!/bin/bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?SHIFT_WORKSPACE is not set}"
: "${ASSETS_DIR:?ASSETS_DIR is not set}"

RESPONSE_DIR="$SHIFT_WORKSPACE/response"
CAMPAIGN_FILE="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"
INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
IOC_FEED="$ASSETS_DIR/ioc_feed.json"

INVESTIGATION_DIR="$SHIFT_WORKSPACE/investigations"

CONTAINMENT_OUT="$RESPONSE_DIR/containment.json"
IOC_OUT="$RESPONSE_DIR/ioc_package.json"

mkdir -p "$RESPONSE_DIR"

fail() {
    echo "[resp] ERROR: $*" >&2
    exit 1
}

require_file() {
    local file="$1"
    [[ -s "$file" ]] || fail "required file missing or empty: $file"
}

require_file "$CAMPAIGN_FILE"
require_file "$INCIDENTS_FILE"
require_file "$EVENTS_FILE"
require_file "$IOC_FEED"

for suffix in A B C; do
    require_file "$INVESTIGATION_DIR/incident_${suffix}.json"
done

jq empty "$CAMPAIGN_FILE" >/dev/null || fail "invalid JSON: $CAMPAIGN_FILE"
jq empty "$INCIDENTS_FILE" >/dev/null || fail "invalid JSON: $INCIDENTS_FILE"
jq empty "$IOC_FEED" >/dev/null || fail "invalid JSON: $IOC_FEED"

for suffix in A B C; do
    jq empty "$INVESTIGATION_DIR/incident_${suffix}.json" >/dev/null \
        || fail "invalid investigation JSON for $suffix"
done

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[resp] loading campaign_assessment and incidents"

# ---------------------------------------------------------------------------
# Normalize incidents and enriched events.
# ---------------------------------------------------------------------------
jq '
    if type == "array" then .
    elif .incidents? then .incidents
    else []
    end
' "$INCIDENTS_FILE" > "$TMPDIR/incidents.json"

jq -s '
    if length == 1 and (.[0] | type) == "array" then .[0]
    elif length == 1 and (.[0] | type) == "object" then [.[0]]
    else .
    end
' "$EVENTS_FILE" > "$TMPDIR/events.json"

jq -e 'length >= 3' "$TMPDIR/incidents.json" >/dev/null \
    || fail "incidents.json does not contain the expected incidents"

# ---------------------------------------------------------------------------
# Validate that the three findings map to actual incident records.
# ---------------------------------------------------------------------------
for suffix in A B C; do
    jq -r '.incident_id // empty' \
        "$INVESTIGATION_DIR/incident_${suffix}.json" > "$TMPDIR/${suffix}_id"

    incident_id="$(cat "$TMPDIR/${suffix}_id")"
    [[ -n "$incident_id" ]] || fail "incident_${suffix}.json has no incident_id"

    jq -e --arg id "$incident_id" '
        any(.[]; .incident_id == $id)
    ' "$TMPDIR/incidents.json" >/dev/null \
        || fail "finding $suffix references non-existent incident $incident_id"
done

# ---------------------------------------------------------------------------
# Build normalized finding collection.
# ---------------------------------------------------------------------------
jq -s '
    map({
        incident_id: (.incident_id // ""),
        confidence: (.confidence // "medium"),
        event_refs: (.event_refs // [] | map(tostring)),
        actions: (.actions // [] | map(tostring)),
        matches_ioc: (
            .matches_ioc
            // .ioc_matches
            // []
        ),
        hypothesis: (.hypothesis // "")
    })
' \
    "$INVESTIGATION_DIR/incident_A.json" \
    "$INVESTIGATION_DIR/incident_B.json" \
    "$INVESTIGATION_DIR/incident_C_cli.json" \
    > "$TMPDIR/findings.json"

# ---------------------------------------------------------------------------
# IOC feed normalization.
# ---------------------------------------------------------------------------
jq '
    [
        .. | objects
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
            confidence: (.confidence? // "unknown" | tostring)
        }
    ]
    | unique_by(.value | ascii_downcase)
' "$IOC_FEED" > "$TMPDIR/feed_iocs.json"

jq '
    map({
        key: (.value | tostring | ascii_downcase),
        value: true
    })
    | from_entries
' "$TMPDIR/feed_iocs.json" > "$TMPDIR/feed_set.json"

FEED_COUNT="$(jq 'length' "$TMPDIR/feed_iocs.json")"

# ---------------------------------------------------------------------------
# Extract event-backed IOC candidates.
#
# Candidates are restricted to IPs, domains, hashes, accounts, service names,
# and ports. Finding matches_ioc values are also included, but only retained
# if they can be associated with one of the finding's event_refs.
# ---------------------------------------------------------------------------
jq '
    def eid:
        (.event_id? // .id? // .eventId?) | tostring;

    def host:
        (.host? // .hostname? // "") | tostring;

    def event_timestamp:
        (.timestamp? // .time? // .event_time? // .datetime? // "") | tostring;

    def candidate($type; $value):
        {
            type: $type,
            value: ($value | tostring)
        };

    [
        .[]
        | . as $finding
        | $finding.event_refs as $refs
        | ($finding.matches_ioc // []) as $finding_iocs
        | $finding_iocs[]
        | if type == "object" then
            {
                type: (
                    .type
                    // (
                        if ((.value? // .ioc? // .indicator? // "") | test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"))
                        then "ip"
                        else "unknown"
                        end
                    )
                ),
                value: (
                    .value
                    // .ioc
                    // .indicator
                    // .ip
                    // .domain
                    // .hash
                    // .account
                    // .service_name
                    // .port
                    // tostring
                )
            }
          else
            {
                type: "unknown",
                value: tostring
            }
          end
        | . as $candidate
        | select($candidate.value != null and ($candidate.value | tostring) != "")
        | {
            incident_id: $finding.incident_id,
            type: $candidate.type,
            value: ($candidate.value | tostring),
            event_refs: $refs
          }
    ]
' "$TMPDIR/findings.json" > "$TMPDIR/finding_ioc_candidates.json"

# ---------------------------------------------------------------------------
# Resolve event references and extract IOC-like fields directly from events.
# This is the authoritative event backing for every shareable IOC.
# ---------------------------------------------------------------------------
jq '
    def eid:
        (.event_id? // .id? // .eventId?) | tostring;

    [
        .[] as $event
        | ($event.event_id? // $event.id? // $event.eventId?) as $event_id
        | select($event_id != null)
        | [
            {
                type: "ip",
                value: ($event.src_ip? // $event.source_ip? // null)
            },
            {
                type: "ip",
                value: ($event.dst_ip? // $event.destination_ip? // null)
            },
            {
                type: "account",
                value: ($event.user? // $event.username? // $event.account? // null)
            },
            {
                type: "service_name",
                value: ($event.service_name? // $event.service? // null)
            },
            {
                type: "domain",
                value: ($event.domain? // $event.destination_domain? // null)
            },
            {
                type: "hash",
                value: (
                    $event.hash?
                    // $event.sha256?
                    // $event.sha1?
                    // $event.md5?
                    // null
                )
            },
            {
                type: "port",
                value: ($event.dst_port? // $event.destination_port? // null)
            }
        ]
        | .[]
        | select(.value != null and (.value | tostring) != "")
        | {
            event_id: ($event_id | tostring),
            type: .type,
            value: (.value | tostring)
          }
    ]
' "$TMPDIR/events.json" > "$TMPDIR/event_ioc_candidates.jsonl"

# ---------------------------------------------------------------------------
# Keep only event-backed values belonging to an investigation finding.
# ---------------------------------------------------------------------------
jq -s '
    . as $event_iocs
    | [
        $event_iocs[]
        | . as $candidate
        | select(
            any(
                input_filename;
                false
            ) == false
        )
    ]
' /dev/null >/dev/null 2>&1 || true

jq -n \
    --slurpfile findings "$TMPDIR/findings.json" \
    --slurpfile events "$TMPDIR/events.json" \
    --slurpfile event_iocs "$TMPDIR/event_ioc_candidates.jsonl" '
    ($findings[0]) as $findings_array
    | ($events[0]) as $events_array
    | ($event_iocs | map(.)) as $candidate_events

    | [
        $findings_array[]
        | . as $finding
        | .event_refs[]
        | tostring
        | . as $ref
        | ($candidate_events | map(select(.event_id == $ref)))
        | .[]
        | {
            incident_id: $finding.incident_id,
            event_ref: .event_id,
            type: .type,
            value: .value
          }
      ]
      | unique_by([.incident_id, .event_ref, .type, .value])
' > "$TMPDIR/event_backed_iocs.json"

# ---------------------------------------------------------------------------
# Add finding matches_ioc values when the value occurs in one of the finding's
# referenced events. This handles findings whose IOC value is stored in a
# dedicated matches_ioc field rather than an event's direct IOC field.
# ---------------------------------------------------------------------------
jq -n \
    --slurpfile findings "$TMPDIR/findings.json" \
    --slurpfile backed "$TMPDIR/event_backed_iocs.json" '
    ($findings[0]) as $findings_array
    | ($backed[0]) as $backed_array

    | [
        $findings_array[]
        | . as $finding
        | (.matches_ioc // [])[]
        | if type == "object" then
            {
                type: (
                    .type
                    // (
                        if ((.value? // .ioc? // .indicator? // "") | test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"))
                        then "ip"
                        else "indicator"
                        end
                    )
                ),
                value: (
                    .value
                    // .ioc
                    // .indicator
                    // .ip
                    // .domain
                    // .hash
                    // .account
                    // .service_name
                    // .port
                    // tostring
                )
            }
          else
            {
                type: "indicator",
                value: tostring
            }
          end
        | . as $ioc
        | select($ioc.value != null and ($ioc.value | tostring) != "")
        | (
            $backed_array
            | map(
                select(
                    .incident_id == $finding.incident_id
                    and (.value | ascii_downcase) == ($ioc.value | tostring | ascii_downcase)
                    and (.event_ref as $r | ($finding.event_refs | index($r)) != null)
                )
            )
            | .[]
          )
        | {
            incident_id: $finding.incident_id,
            event_ref,
            type: (
                if $ioc.type == "indicator" then .type else $ioc.type end
            ),
            value: $ioc.value
          }
      ]
      | unique_by([.incident_id, .event_ref, .type, .value])
' > "$TMPDIR/backed_finding_iocs.json"

# Combine all event-backed IOC records.
jq -s '
    add
    | unique_by([.incident_id, .event_ref, .type, .value])
' \
    "$TMPDIR/event_backed_iocs.json" \
    "$TMPDIR/backed_finding_iocs.json" \
    > "$TMPDIR/all_backed_iocs.json"

# ---------------------------------------------------------------------------
# Normalize IOC types.
# ---------------------------------------------------------------------------
jq '
    map(
        .type |= (
            ascii_downcase
            | if . == "ipv4" or . == "ip_address" then "ip"
              elif . == "username" or . == "user" or . == "account_name" then "account"
              elif . == "service" then "service_name"
              elif . == "sha256" or . == "sha1" or . == "md5" then "hash"
              elif . == "destination" then "domain"
              elif . == "tcp_port" or . == "udp_port" then "port"
              else .
              end
        )
    )
    | map(select(.type | IN("ip","domain","hash","account","service_name","port")))
' "$TMPDIR/all_backed_iocs.json" > "$TMPDIR/normalized_iocs.json"

# ---------------------------------------------------------------------------
# Calculate first/last seen and determine whether each IOC is feed-known or
# newly discovered.
# ---------------------------------------------------------------------------
jq -n \
    --slurpfile backed "$TMPDIR/normalized_iocs.json" \
    --slurpfile findings "$TMPDIR/findings.json" \
    --slurpfile events "$TMPDIR/events.json" \
    --slurpfile feed "$TMPDIR/feed_iocs.json" '
    def event_id:
        (.event_id? // .id? // .eventId?) | tostring;

    def timestamp:
        (.timestamp? // .time? // .event_time? // .datetime? // "") | tostring;

    ($backed[0]) as $records
    | ($findings[0]) as $findings_array
    | ($events[0]) as $events_array
    | ($feed[0]) as $feed_array

    | [
        $records[]
        | . as $record
        | (
            $events_array
            | map(
                select(
                    (event_id) == $record.event_ref
                    and (
                        [
                            (.src_ip? // empty),
                            (.source_ip? // empty),
                            (.dst_ip? // empty),
                            (.destination_ip? // empty),
                            (.user? // empty),
                            (.username? // empty),
                            (.account? // empty),
                            (.service_name? // empty),
                            (.service? // empty),
                            (.domain? // empty),
                            (.destination_domain? // empty),
                            (.hash? // empty),
                            (.sha256? // empty),
                            (.sha1? // empty),
                            (.md5? // empty),
                            (.dst_port? // empty),
                            (.destination_port? // empty)
                        ]
                        | map(tostring | ascii_downcase)
                        | index($record.value | tostring | ascii_downcase)
                    ) != null
                )
            )
        ) as $matching_events

        | (
            $findings_array
            | map(select(.incident_id == $record.incident_id))
            | .[0]
          ) as $finding

        | {
            type: $record.type,
            value: $record.value,
            first_seen: (
                [$matching_events[] | timestamp | select(length > 0)]
                | sort
                | .[0]
                // "unknown"
            ),
            last_seen: (
                [$matching_events[] | timestamp | select(length > 0)]
                | sort
                | .[-1]
                // "unknown"
            ),
            incident_id: $record.incident_id,
            event_ref: $record.event_ref,
            source: (
                if any(
                    $feed_array[];
                    ((.value | tostring | ascii_downcase)
                     == ($record.value | tostring | ascii_downcase))
                )
                then "ioc_feed"
                else "shift_discovered"
                end
            ),
            confidence: (
                if any(
                    $feed_array[];
                    ((.value | tostring | ascii_downcase)
                     == ($record.value | tostring | ascii_downcase))
                    and ((.confidence? // "") | tostring | ascii_downcase) == "high"
                )
                then "high"
                elif ($finding.confidence // "") == "high"
                then "high"
                elif any(
                    $feed_array[];
                    ((.value | tostring | ascii_downcase)
                     == ($record.value | tostring | ascii_downcase))
                )
                then "medium"
                else "medium"
                end
            )
        }
    ]
    | unique_by([
        .type,
        .value,
        .incident_id
    ])
' > "$TMPDIR/ioc_package_records.json"

# Reject any IOC whose event timestamp could not be resolved.
if jq -e 'any(.[]; .first_seen == "unknown" or .last_seen == "unknown")' \
    "$TMPDIR/ioc_package_records.json" >/dev/null; then
    fail "one or more IOC values lack event timestamp backing"
fi

# Every package IOC must have an event_ref.
if jq -e 'any(.[]; (.event_ref // "") == "")' \
    "$TMPDIR/ioc_package_records.json" >/dev/null; then
    fail "one or more IOCs have no event reference backing"
fi

# ---------------------------------------------------------------------------
# Build one representative IOC record per value/incident.
# ---------------------------------------------------------------------------
jq '
    group_by([.type, .value, .incident_id])
    | map(.[0])
' "$TMPDIR/ioc_package_records.json" > "$TMPDIR/iocs.json"

# ---------------------------------------------------------------------------
# Build containment actions.
#
# Each incident receives at most four actions:
#   1. Immediate IOC block
#   2. Immediate host isolation
#   3. Short-term credential/service-account review
#   4. Medium-term firewall/Sysmon hardening
#
# This keeps the total at <= 12 for three incidents while covering all
# required containment horizons.
# ---------------------------------------------------------------------------
jq -n \
    --slurpfile incidents "$TMPDIR/incidents.json" \
    --slurpfile iocs "$TMPDIR/iocs.json" \
    --slurpfile campaign "$CAMPAIGN_FILE" '
    def incident_hosts($incident):
        ($incident.host_list // [])
        | map(tostring)
        | unique;

    def incident_users($incident):
        ($incident.user_list // [])
        | map(select(. != null) | tostring)
        | unique;

    def incident_ips($incident):
        ($iocs[0]
         | map(select(.incident_id == $incident.incident_id and .type == "ip"))
         | map(.value)
         | unique);

    def incident_services($incident):
        ($iocs[0]
         | map(select(.incident_id == $incident.incident_id and .type == "service_name"))
         | map(.value)
         | unique);

    [
        $incidents[0][]
        | . as $incident
        | .incident_id as $id
        | (incident_hosts($incident)) as $hosts
        | (incident_users($incident)) as $users
        | (incident_ips($incident)) as $ips
        | (incident_services($incident)) as $services

        | [
            if ($ips | length) > 0 then
                {
                    priority: "immediate",
                    action: (
                        "Block confirmed IOC IPs at the perimeter firewall: "
                        + ($ips | join(", "))
                        + "."
                    ),
                    target_type: "ip",
                    target_value: ($ips | join(", ")),
                    incident_id: $id,
                    operational_impact: "May block legitimate traffic to confirmed IOC destinations; validate firewall logs after deployment.",
                    requires_approval_from: "Network Security"
                }
            else empty end,

            if ($hosts | length) > 0 then
                {
                    priority: "immediate",
                    action: (
                        "Isolate confirmed compromised host(s) from the network: "
                        + ($hosts | join(", "))
                        + "."
                    ),
                    target_type: "host",
                    target_value: ($hosts | join(", ")),
                    incident_id: $id,
                    operational_impact: "Network isolation may interrupt production services and active administrative sessions.",
                    requires_approval_from: "Incident Commander"
                }
            else empty end,

            if (($users | length) > 0 or ($services | length) > 0) then
                {
                    priority: "short_term",
                    action: (
                        "Reset identified account credentials and audit service accounts matching IOC service patterns: "
                        + (($users + $services) | unique | join(", "))
                        + "."
                    ),
                    target_type: (
                        if ($users | length) > 0 then "user"
                        else "service"
                        end
                    ),
                    target_value: (($users + $services) | unique | join(", ")),
                    incident_id: $id,
                    operational_impact: "Credential resets or service-account changes may interrupt dependent jobs and scheduled services.",
                    requires_approval_from: "Identity and Access Management"
                }
            else empty end,

            if ($hosts | length) > 0 then
                {
                    priority: "medium_term",
                    action: (
                        "Review and tighten firewall rules for affected zones and deploy additional Sysmon rules on: "
                        + ($hosts | join(", "))
                        + "."
                    ),
                    target_type: "rule",
                    target_value: "affected host zones and Sysmon policy",
                    incident_id: $id,
                    operational_impact: "Additional controls can increase logging volume and may require rule tuning to avoid operational noise.",
                    requires_approval_from: "Security Engineering"
                }
            else empty end
          ]
    ]
    | flatten
    | to_entries
    | map(
        .value
        + {
            action_id: ("ACT-" + ((.key + 1) | tostring | ("000" + .)[-3:]))
        }
        | del(.key)
      )
    | .[:12]
' > "$TMPDIR/actions.json"

# Validate action schema and incident references.
jq -e '
    all(.[];
        (.action_id | type == "string")
        and (.priority | IN("immediate","short_term","medium_term"))
        and (.action | type == "string" and length <= 160)
        and (.target_type | IN("host","user","ip","service","rule"))
        and (.target_value | type == "string")
        and (.incident_id | type == "string")
        and (.operational_impact | type == "string" and length <= 160)
        and (.requires_approval_from | type == "string")
    )
' "$TMPDIR/actions.json" >/dev/null \
    || fail "containment action schema validation failed"

jq -e \
    --slurpfile incidents "$TMPDIR/incidents.json" '
    all(.[];
        any(
            $incidents[0][];
            .incident_id == (.incident_id)
        )
    )
' "$TMPDIR/actions.json" >/dev/null \
    || fail "one or more containment actions reference a non-existent incident"

ACTION_TOTAL="$(jq 'length' "$TMPDIR/actions.json")"
IMMEDIATE_COUNT="$(jq '[.[] | select(.priority == "immediate")] | length' "$TMPDIR/actions.json")"
SHORT_COUNT="$(jq '[.[] | select(.priority == "short_term")] | length' "$TMPDIR/actions.json")"
MEDIUM_COUNT="$(jq '[.[] | select(.priority == "medium_term")] | length' "$TMPDIR/actions.json")"

[[ "$ACTION_TOTAL" -le 12 ]] || fail "containment action count exceeds maximum of 12"

echo "[resp] actions: immediate=$IMMEDIATE_COUNT short_term=$SHORT_COUNT medium_term=$MEDIUM_COUNT total=$ACTION_TOTAL"

# ---------------------------------------------------------------------------
# Cluster ID and shift ID.
# ---------------------------------------------------------------------------
SHIFT_ID="$(
    jq -r '
        .shift_id
        // empty
    ' "$SHIFT_WORKSPACE/runtime/shift_start.json" 2>/dev/null || true
)"

if [[ -z "$SHIFT_ID" ]]; then
    SHIFT_ID="SHIFT-UNKNOWN"
fi

CLUSTER_ID="$(
    jq -r '.cluster_id // "unknown"' "$CAMPAIGN_FILE"
)"

GENERATED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# Write containment.json.
# ---------------------------------------------------------------------------
jq -n \
    --arg shift_id "$SHIFT_ID" \
    --arg generated_at "$GENERATED_AT" \
    --slurpfile actions "$TMPDIR/actions.json" '
    {
        shift_id: $shift_id,
        generated_at: $generated_at,
        actions: $actions[0]
    }
' > "$CONTAINMENT_OUT"

jq empty "$CONTAINMENT_OUT" >/dev/null
[[ -s "$CONTAINMENT_OUT" ]] || fail "containment.json was not written"

# ---------------------------------------------------------------------------
# IOC counts and newly discovered count.
# ---------------------------------------------------------------------------
IOC_TOTAL="$(jq 'length' "$TMPDIR/iocs.json")"
IP_COUNT="$(jq '[.[] | select(.type == "ip")] | length' "$TMPDIR/iocs.json")"
DOMAIN_COUNT="$(jq '[.[] | select(.type == "domain")] | length' "$TMPDIR/iocs.json")"
HASH_COUNT="$(jq '[.[] | select(.type == "hash")] | length' "$TMPDIR/iocs.json")"
ACCOUNT_COUNT="$(jq '[.[] | select(.type == "account")] | length' "$TMPDIR/iocs.json")"
SERVICE_COUNT="$(jq '[.[] | select(.type == "service_name")] | length' "$TMPDIR/iocs.json")"
PORT_COUNT="$(jq '[.[] | select(.type == "port")] | length' "$TMPDIR/iocs.json")"

NEW_COUNT="$(
    jq '[.[] | select(.source == "shift_discovered")] | length' "$TMPDIR/iocs.json"
)"

echo "[resp] IOCs: ip=$IP_COUNT domain=$DOMAIN_COUNT hash=$HASH_COUNT account=$ACCOUNT_COUNT service=$SERVICE_COUNT total=$IOC_TOTAL"
echo "[resp] newly discovered (not in feed): $NEW_COUNT"

# ---------------------------------------------------------------------------
# Defang network indicators in shareable package.
# ---------------------------------------------------------------------------
jq '
    map(
        if .type == "ip" then
            .value |= gsub(
                "([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})";
                "\\1[.]\\2[.]\\3[.]\\4"
            )
        else .
        end
    )
' "$TMPDIR/iocs.json" > "$TMPDIR/iocs_defanged.json"

# ---------------------------------------------------------------------------
# Ensure every IOC has an event backing and that the event_ref belongs to
# the corresponding investigation finding.
# ---------------------------------------------------------------------------
jq -n \
    --slurpfile iocs "$TMPDIR/iocs.json" \
    --slurpfile findings "$TMPDIR/findings.json" '
    ($iocs[0]) as $records
    | ($findings[0]) as $findings_array
    | all(
        $records[];
        (.event_ref != null)
        and
        any(
            $findings_array[];
            .incident_id == .incident_id
            and (.event_refs | index(.event_ref)) != null
        )
    )
' >/dev/null 2>&1 || true

# Explicit per-record validation avoids ambiguous jq variable scoping.
while IFS=$'\t' read -r incident_id event_ref; do
    [[ -n "$incident_id" && -n "$event_ref" ]] || fail "IOC record missing incident/event reference"

    jq -e \
        --arg incident "$incident_id" \
        --arg event "$event_ref" '
        any(.[]; .incident_id == $incident and (.event_refs | index($event)) != null)
    ' "$TMPDIR/findings.json" >/dev/null \
        || fail "IOC $event_ref is not backed by an event_ref in finding $incident_id"

    jq -e \
        --arg event "$event_ref" '
        any(.[]; ((.event_id? // .id? // .eventId?) | tostring) == $event)
    ' "$TMPDIR/events.json" >/dev/null \
        || fail "IOC event reference $event_ref does not exist in enriched_events.jsonl"
done < <(
    jq -r '.[] | [.incident_id, .event_ref] | @tsv' "$TMPDIR/iocs.json"
)

echo "[resp] all IOCs traced to events: OK"

# ---------------------------------------------------------------------------
# Write ioc_package.json.
# ---------------------------------------------------------------------------
jq -n \
    --arg shift_id "$SHIFT_ID" \
    --arg cluster_id "$CLUSTER_ID" \
    --arg generated_at "$GENERATED_AT" \
    --slurpfile iocs "$TMPDIR/iocs_defanged.json" '
    {
        shift_id: $shift_id,
        tlp: "AMBER",
        cluster_id: $cluster_id,
        generated_at: $generated_at,
        iocs: (
            $iocs[0]
            | map(
                {
                    type,
                    value,
                    first_seen,
                    last_seen,
                    incident_id,
                    source,
                    confidence
                }
            )
            | sort_by([.type, .value, .incident_id])
        )
    }
' > "$IOC_OUT"

jq empty "$IOC_OUT" >/dev/null
[[ -s "$IOC_OUT" ]] || fail "ioc_package.json was not written"

echo "[resp] containment.json written"
echo "[resp] ioc_package.json written"

exit 0
