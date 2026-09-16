#!/bin/bash
set -euo pipefail

WORKSPACE="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE is not set}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR is not set}"

INCIDENTS="$WORKSPACE/alerts/incidents.json"
EVENTS_JSONL="$WORKSPACE/enriched/enriched_events.jsonl"
EVENTS_JSON="$WORKSPACE/enriched/enriched_events.json"
CHANGE_TICKETS="$ASSETS/change_tickets.json"
IOC_FEED="$ASSETS/ioc_feed.json"
ASSETS_FILE="$ASSETS/assets.json"
OUTPUT="$WORKSPACE/investigations/incident_B.json"

die() {
    echo "[inv-B] ERROR: $*" >&2
    exit 1
}

require_file() {
    [[ -s "$1" ]] || die "required file missing or empty: $1"
}

command -v jq >/dev/null 2>&1 || die "jq is required"

require_file "$INCIDENTS"
require_file "$CHANGE_TICKETS"
require_file "$IOC_FEED"
require_file "$ASSETS_FILE"

if [[ -s "$EVENTS_JSONL" ]]; then
    EVENTS_FILE="$EVENTS_JSONL"
elif [[ -s "$EVENTS_JSON" ]]; then
    EVENTS_FILE="$EVENTS_JSON"
else
    die "enriched events file not found"
fi

require_file "$EVENTS_FILE"

mkdir -p "$WORKSPACE/investigations"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ACTIONS_FILE="$TMPDIR/actions.txt"
: > "$ACTIONS_FILE"

#
# Record every jq command executed.
#
run_jq() {
    local description="$1"
    shift
    printf '%s\n' "$description" >> "$ACTIONS_FILE"
    jq "$@"
}

echo "[inv-B] loading INC-YYYYMMDD-B"

run_jq \
    "jq -c '.incidents[] | select(.incident_id | test(\"^INC-[0-9]{8}-B$\"))' \"$INCIDENTS\"" \
    -c '.incidents[] | select(.incident_id | test("^INC-[0-9]{8}-B$"))' \
    "$INCIDENTS" > "$TMPDIR/incident_B.json"

[[ -s "$TMPDIR/incident_B.json" ]] ||
    die "INC-YYYYMMDD-B not found"

incident_id="$(run_jq \
    "jq -r '.incident_id' \"$TMPDIR/incident_B.json\"" \
    -r '.incident_id' "$TMPDIR/incident_B.json")"

first_seen="$(run_jq \
    "jq -r '.first_seen' \"$TMPDIR/incident_B.json\"" \
    -r '.first_seen' "$TMPDIR/incident_B.json")"

last_seen="$(run_jq \
    "jq -r '.last_seen' \"$TMPDIR/incident_B.json\"" \
    -r '.last_seen' "$TMPDIR/incident_B.json")"

alert_count="$(run_jq \
    "jq '.alert_ids | length' \"$TMPDIR/incident_B.json\"" \
    '.alert_ids | length' "$TMPDIR/incident_B.json")"

tentative_category="$(run_jq \
    "jq -r '.tentative_category' \"$TMPDIR/incident_B.json\"" \
    -r '.tentative_category' "$TMPDIR/incident_B.json")"

run_jq \
    "jq -r '.host_list[]' \"$TMPDIR/incident_B.json\"" \
    -r '.host_list[]' \
    "$TMPDIR/incident_B.json" > "$TMPDIR/hosts.txt"

run_jq \
    "jq -r '.user_list[]?' \"$TMPDIR/incident_B.json\"" \
    -r '.user_list[]?' \
    "$TMPDIR/incident_B.json" > "$TMPDIR/users.txt"

[[ -s "$TMPDIR/hosts.txt" ]] ||
    die "incident B has no hosts"

echo "[inv-B] hosts: $(paste -sd ',' "$TMPDIR/hosts.txt")"
echo "[inv-B] alert count: $alert_count"
echo "[inv-B] tentative category: $tentative_category"

run_jq \
    "jq -c '.host_list | map(ascii_downcase) | unique' \"$TMPDIR/incident_B.json\"" \
    -c '.host_list | map(ascii_downcase) | unique' \
    "$TMPDIR/incident_B.json" > "$TMPDIR/hosts.json"

run_jq \
    "jq -c '.user_list // [] | map(select(. != null) | tostring | ascii_downcase) | unique' \"$TMPDIR/incident_B.json\"" \
    -c '.user_list // [] | map(select(. != null) | tostring | ascii_downcase) | unique' \
    "$TMPDIR/incident_B.json" > "$TMPDIR/users.json"

#
# Calculate ±15 minute event window.
#
window_start="$(run_jq \
    "jq -nr --arg ts \"$first_seen\" '(\$ts | fromdateiso8601) - 900 | todateiso8601'" \
    -nr \
    --arg ts "$first_seen" \
    '($ts | fromdateiso8601) - 900 | todateiso8601')"

window_end="$(run_jq \
    "jq -nr --arg ts \"$last_seen\" '(\$ts | fromdateiso8601) + 900 | todateiso8601'" \
    -nr \
    --arg ts "$last_seen" \
    '($ts | fromdateiso8601) + 900 | todateiso8601')"

#
# Normalize JSONL / JSON input.
#
run_jq \
    "jq -s 'if length == 1 and (.[0] | type) == \"array\" then .[0] elif length == 1 and (.[0] | type) == \"object\" then [.[0]] else . end' \"$EVENTS_FILE\"" \
    -s '
    if length == 1 and (.[0] | type) == "array"
    then .[0]
    elif length == 1 and (.[0] | type) == "object"
    then [.[0]]
    else .
    end
    ' \
    "$EVENTS_FILE" > "$TMPDIR/all_events.json"

#
# Pull every event for every incident host in the ±15 minute window.
#
run_jq \
    "jq --argjson hosts \"\$(cat \"$TMPDIR/hosts.json\")\" --arg start \"$window_start\" --arg end \"$window_end\" 'map(select(((.host // .hostname // .agent_name // \"\") | tostring | ascii_downcase) as \$h | (\$hosts | index(\$h)) != null and (.timestamp // .time // .[\"@timestamp\"] // \"\") != \"\" and ((.timestamp // .time // .[\"@timestamp\"]) | fromdateiso8601) >= (\$start | fromdateiso8601) and ((.timestamp // .time // .[\"@timestamp\"]) | fromdateiso8601) <= (\$end | fromdateiso8601)))' \"$TMPDIR/all_events.json\"" \
    --argjson hosts "$(cat "$TMPDIR/hosts.json")" \
    --arg start "$window_start" \
    --arg end "$window_end" \
    '
    map(
        select(
            ((.host // .hostname // .agent_name // "")
                | tostring
                | ascii_downcase) as $h
            | ($hosts | index($h)) != null
            and
            (.timestamp // .time // .["@timestamp"] // "") != ""
            and
            ((.timestamp // .time // .["@timestamp"]) | fromdateiso8601)
                >= ($start | fromdateiso8601)
            and
            ((.timestamp // .time // .["@timestamp"]) | fromdateiso8601)
                <= ($end | fromdateiso8601)
        )
    )
    ' \
    "$TMPDIR/all_events.json" > "$TMPDIR/matching_events.json"

event_count="$(run_jq \
    "jq 'length' \"$TMPDIR/matching_events.json\"" \
    'length' \
    "$TMPDIR/matching_events.json")"

echo "[inv-B] events in window: $event_count"

[[ "$event_count" -gt 0 ]] ||
    die "no events found in incident B window"

#
# Normalize event fields for ticket-scope and IOC analysis.
#
run_jq \
    "jq 'map({event_id:(.event_id // .id // .event_ref // .eventId // \"\"), timestamp:(.timestamp // .time // .[\"@timestamp\"] // \"\"), host:((.host // .hostname // .agent_name // \"\") | tostring | ascii_downcase), user:((.user // .username // .account // .actor // null) | if . == null then null else tostring | ascii_downcase end), src_ip:(.src_ip // .source_ip // null), dst_ip:(.dst_ip // .destination_ip // null), dst_port:(.dst_port // .destination_port // .dest_port // .port // null), source_type:(.source_type // .source // .log_type // \"unknown\"), event_category:(.event_category // .category // .event_type // .type // \"unknown\"), raw_message:(.raw_message // .message // .full_log // .log // \"\")}) | sort_by(.timestamp)' \"$TMPDIR/matching_events.json\"" \
    '
    map({
        event_id: (.event_id // .id // .event_ref // .eventId // ""),
        timestamp: (.timestamp // .time // .["@timestamp"] // ""),
        host: ((.host // .hostname // .agent_name // "")
            | tostring
            | ascii_downcase),
        user: (
            (.user // .username // .account // .actor // null)
            | if . == null then null
              else tostring | ascii_downcase
              end
        ),
        src_ip: (.src_ip // .source_ip // null),
        dst_ip: (.dst_ip // .destination_ip // null),
        dst_port: (.dst_port // .destination_port // .dest_port // .port // null),
        source_type: (.source_type // .source // .log_type // "unknown"),
        event_category: (.event_category // .category // .event_type // .type // "unknown"),
        raw_message: (.raw_message // .message // .full_log // .log // "")
    })
    | sort_by(.timestamp)
    ' \
    "$TMPDIR/matching_events.json" > "$TMPDIR/events_normalized.json"

#
# Load and normalize change tickets.
#
run_jq \
    "jq 'if type == \"array\" then . elif .tickets? then .tickets elif .change_tickets? then .change_tickets else [] end' \"$CHANGE_TICKETS\"" \
    '
    if type == "array"
    then .
    elif .tickets?
    then .tickets
    elif .change_tickets?
    then .change_tickets
    else []
    end
    ' \
    "$CHANGE_TICKETS" > "$TMPDIR/tickets.json"

#
# Match tickets by:
#   - host
#   - time overlap
#   - owner/account
#   - activity scope
#
# Scope is checked against the approved_activity text. An outbound destination
# not represented in the approved activity is treated as a scope mismatch.
#
run_jq \
    "jq --argjson hosts \"\$(cat \"$TMPDIR/hosts.json\")\" --argjson users \"\$(cat \"$TMPDIR/users.json\")\" --arg start \"$first_seen\" --arg end \"$last_seen\" --argjson events \"\$(cat \"$TMPDIR/events_normalized.json\")\" 'map({ticket_id:(.ticket_id // .id // .change_id // \"unknown\"), window_start:(.window_start // .start // .approved_window_start // \"\"), window_end:(.window_end // .end // .approved_window_end // \"\"), hosts:(.hosts // [] | map(tostring | ascii_downcase)), owner:(.owner // .requestor // .approved_by // null), approved_activity:(.approved_activity // .activity // .description // .scope // \"\")}) | map(. as \$t | {ticket:\$t, host_match:(any(\$t.hosts[]; . as \$h | (\$hosts | index(\$h)) != null)), window_match:(if (\$t.window_start != \"\" and \$t.window_end != \"\") then ((\$t.window_start | fromdateiso8601) <= (\$end | fromdateiso8601) and (\$t.window_end | fromdateiso8601) >= (\$start | fromdateiso8601)) else false end), owner_match:(if (\$t.owner == null or (\$users | length) == 0) then false else ((\$users | map(ascii_downcase)) | index((\$t.owner | tostring | ascii_downcase))) != null end), scope_match:(if (\$events | length) == 0 then false else ([\$events[] | .dst_ip, .dst_port] | map(select(. != null) | tostring) | any(.[]; (\$t.approved_activity | tostring | ascii_downcase) | contains((. | tostring | ascii_downcase)))) end)})' \"$TMPDIR/tickets.json\"" \
    --argjson hosts "$(cat "$TMPDIR/hosts.json")" \
    --argjson users "$(cat "$TMPDIR/users.json")" \
    --arg start "$first_seen" \
    --arg end "$last_seen" \
    --argjson events "$(cat "$TMPDIR/events_normalized.json")" \
    '
    map({
        ticket_id: (.ticket_id // .id // .change_id // "unknown"),
        window_start: (.window_start // .start // .approved_window_start // ""),
        window_end: (.window_end // .end // .approved_window_end // ""),
        hosts: (.hosts // [] | map(tostring | ascii_downcase)),
        owner: (.owner // .requestor // .approved_by // null),
        approved_activity: (.approved_activity // .activity // .description // .scope // "")
    })
    | map(
        . as $t
        | {
            ticket: $t,

            host_match: (
                any(
                    $t.hosts[];
                    . as $h
                    | ($hosts | index($h)) != null
                )
            ),

            window_match: (
                if ($t.window_start != "" and $t.window_end != "")
                then
                    (($t.window_start | fromdateiso8601)
                        <= ($end | fromdateiso8601))
                    and
                    (($t.window_end | fromdateiso8601)
                        >= ($start | fromdateiso8601))
                else false
                end
            ),

            owner_match: (
                if ($t.owner == null or ($users | length) == 0)
                then false
                else
                    (
                        ($users | map(ascii_downcase))
                        | index(($t.owner | tostring | ascii_downcase))
                    ) != null
                end
            ),

            scope_match: (
                if ($events | length) == 0
                then false
                else
                    true
                end
            )
        }
    )
    ' \
    "$TMPDIR/tickets.json" > "$TMPDIR/ticket_matches_base.json"

#
# Scope matching is evaluated separately and conservatively.
# If an outbound destination appears in the events, it must be explicitly
# represented in approved_activity to count as covered.
#
run_jq \
    "jq --argjson matches \"\$(cat \"$TMPDIR/ticket_matches_base.json\")\" --argjson events \"\$(cat \"$TMPDIR/events_normalized.json\")\" 'map(. as \$m | \$m + {scope_match: (if (([\$events[] | select(.dst_ip != null) | .dst_ip] | length) == 0) then true else all(\$events[] | select(.dst_ip != null); ((\$m.ticket.approved_activity | tostring | ascii_downcase) | contains((.dst_ip | tostring | ascii_downcase)))) end)})' \"$TMPDIR/ticket_matches_base.json\"" \
    --argjson events "$(cat "$TMPDIR/events_normalized.json")" \
    '
    map(
        . as $m
        | $m + {
            scope_match: (
                if (
                    [
                        $events[]
                        | select(.dst_ip != null)
                        | .dst_ip
                    ]
                    | length
                ) == 0
                then true
                else
                    all(
                        $events[]
                        | select(.dst_ip != null);
                        (
                            ($m.ticket.approved_activity
                                | tostring
                                | ascii_downcase)
                            | contains(
                                (.dst_ip
                                    | tostring
                                    | ascii_downcase)
                              )
                        )
                    )
                end
            )
        }
    )
    ' \
    "$TMPDIR/ticket_matches_base.json" > "$TMPDIR/ticket_matches.json"

#
# Pick the first ticket that at least matches a host. If none exists, document
# the absence of a ticket.
#
run_jq \
    "jq 'map(select(.host_match)) | .[0] // null' \"$TMPDIR/ticket_matches.json\"" \
    'map(select(.host_match)) | .[0] // null' \
    "$TMPDIR/ticket_matches.json" > "$TMPDIR/selected_ticket.json"

ticket_id="$(run_jq \
    "jq -r '.ticket.ticket_id // empty' \"$TMPDIR/selected_ticket.json\"" \
    -r '.ticket.ticket_id // empty' \
    "$TMPDIR/selected_ticket.json")"

if [[ -z "$ticket_id" ]]; then
    echo "[inv-B] ticket match: NONE FOUND"
    ticket_found="false"
else
    echo "[inv-B] ticket match: $ticket_id FOUND"
    ticket_found="true"
fi

#
# Individual ticket outcomes.
#
if [[ "$ticket_found" == "true" ]]; then
    host_match="$(run_jq \
        "jq -r 'if .host_match then \"match\" else \"mismatch\" end' \"$TMPDIR/selected_ticket.json\"" \
        -r 'if .host_match then "match" else "mismatch" end' \
        "$TMPDIR/selected_ticket.json")"

    window_match="$(run_jq \
        "jq -r 'if .window_match then \"match\" else \"mismatch\" end' \"$TMPDIR/selected_ticket.json\"" \
        -r 'if .window_match then "match" else "mismatch" end' \
        "$TMPDIR/selected_ticket.json")"

    owner_match="$(run_jq \
        "jq -r 'if .owner_match then \"match\" else \"mismatch\" end' \"$TMPDIR/selected_ticket.json\"" \
        -r 'if .owner_match then "match" else "mismatch" end' \
        "$TMPDIR/selected_ticket.json")"

    scope_match="$(run_jq \
        "jq -r 'if .scope_match then \"match\" else \"mismatch\" end' \"$TMPDIR/selected_ticket.json\"" \
        -r 'if .scope_match then "match" else "mismatch" end' \
        "$TMPDIR/selected_ticket.json")"

    ticket_owner="$(run_jq \
        "jq -r '.ticket.owner // \"unknown\"' \"$TMPDIR/selected_ticket.json\"" \
        -r '.ticket.owner // "unknown"' \
        "$TMPDIR/selected_ticket.json")"

    approved_activity="$(run_jq \
        "jq -r '.ticket.approved_activity // \"\"' \"$TMPDIR/selected_ticket.json\"" \
        -r '.ticket.approved_activity // ""' \
        "$TMPDIR/selected_ticket.json")"

    if [[ "$host_match" == "match" ]]; then
        echo "[inv-B]   host match:   OK (incident host appears in ticket)"
    else
        echo "[inv-B]   host match:   FAIL (incident host absent from ticket)"
    fi

    if [[ "$window_match" == "match" ]]; then
        echo "[inv-B]   window match: OK (incident window overlaps approved window)"
    else
        echo "[inv-B]   window match: FAIL (incident window does not overlap approved window)"
    fi

    incident_users="$(paste -sd ',' "$TMPDIR/users.txt" 2>/dev/null || true)"

    if [[ "$owner_match" == "match" ]]; then
        echo "[inv-B]   owner match:  OK ($ticket_owner matches incident account)"
    else
        echo "[inv-B]   owner match:  FAIL ($incident_users — ticket owner: $ticket_owner)"
    fi

    if [[ "$scope_match" == "match" ]]; then
        echo "[inv-B]   scope match:  OK (observed activity covered by approved activity)"
    else
        echo "[inv-B]   scope match:  FAIL (observed outbound activity not covered by approved activity)"
    fi
else
    host_match="mismatch"
    window_match="mismatch"
    owner_match="mismatch"
    scope_match="mismatch"

    ticket_owner=""
    approved_activity=""

    echo "[inv-B]   host match:   FAIL (no ticket found for incident host)"
    echo "[inv-B]   window match: FAIL (no applicable approved window)"
    echo "[inv-B]   owner match:  FAIL (no applicable ticket owner)"
    echo "[inv-B]   scope match:  FAIL (no approved activity scope)"
fi

#
# IOC feed normalization.
#
run_jq \
    "jq -r '.. | objects | (.value? // .ioc? // .indicator? // .ip? // .domain? // .hash? // .account? // .service_name? // .port?)? | select(. != null) | tostring' \"$IOC_FEED\"" \
    -r '
    .. | objects
    | (
        .value? //
        .ioc? //
        .indicator? //
        .ip? //
        .domain? //
        .hash? //
        .account? //
        .service_name? //
        .port?
      )?
    | select(. != null)
    | tostring
    ' \
    "$IOC_FEED" |
    sort -u > "$TMPDIR/ioc_values.txt"

#
# Extract richer IOC objects where available.
#
run_jq \
    "jq -c '.. | objects | select((.value? // .ioc? // .indicator?) != null) | {value:(.value // .ioc // .indicator), type:(.type // .ioc_type // .indicator_type // \"unknown\"), confidence:(.confidence // .score // \"unknown\"), cluster:(.cluster // .cluster_id // \"\")}' \"$IOC_FEED\"" \
    -c '
    .. | objects
    | select((.value? // .ioc? // .indicator?) != null)
    | {
        value: (.value // .ioc // .indicator),
        type: (.type // .ioc_type // .indicator_type // "unknown"),
        confidence: (.confidence // .score // "unknown"),
        cluster: (.cluster // .cluster_id // "")
      }
    ' \
    "$IOC_FEED" > "$TMPDIR/ioc_objects.jsonl"

#
# Check every outbound destination IP in incident events.
#
run_jq \
    "jq --slurpfile iocs <(jq -s '.' \"$TMPDIR/ioc_objects.jsonl\") 'map(select(.dst_ip != null)) | map(. as \$event | \$iocs[0][] | select((.value | tostring) == (\$event.dst_ip | tostring)) | {event_id:\$event.event_id, value:(.value | tostring), type:(.type | tostring), confidence:(.confidence | tostring), cluster:(.cluster | tostring)})' \"$TMPDIR/events_normalized.json\"" \
    --slurpfile iocs <(jq -s '.' "$TMPDIR/ioc_objects.jsonl") \
    '
    map(select(.dst_ip != null))
    | map(
        . as $event
        | $iocs[0][]
        | select(
            (.value | tostring)
            ==
            ($event.dst_ip | tostring)
          )
        | {
            event_id: $event.event_id,
            value: (.value | tostring),
            type: (.type | tostring),
            confidence: (.confidence | tostring),
            cluster: (.cluster | tostring)
          }
      )
    ' \
    "$TMPDIR/events_normalized.json" > "$TMPDIR/ioc_matches.json"

ioc_count="$(run_jq \
    "jq 'length' \"$TMPDIR/ioc_matches.json\"" \
    'length' \
    "$TMPDIR/ioc_matches.json")"

if [[ "$ioc_count" -gt 0 ]]; then
    run_jq \
        "jq -r '.[] | \"[inv-B] ioc_match: \\(.value) (type: \\(.type), confidence: \\(.confidence), cluster: \\(.cluster // \"unknown\"))\"' \"$TMPDIR/ioc_matches.json\"" \
        -r '
        .[]
        | "[inv-B] ioc_match: \(.value) " +
          "(type: \(.type), confidence: \(.confidence), " +
          "cluster: \(.cluster // "unknown"))"
        ' \
        "$TMPDIR/ioc_matches.json"
else
    echo "[inv-B] ioc_match: none"
fi

#
# Asset criticality and data classification.
#
run_jq \
    "jq -c 'if type == \"array\" then . elif .assets? then .assets else [] end' \"$ASSETS_FILE\"" \
    -c '
    if type == "array"
    then .
    elif .assets?
    then .assets
    else []
    end
    ' \
    "$ASSETS_FILE" > "$TMPDIR/assets_array.json"

run_jq \
    "jq --argjson hosts \"\$(cat \"$TMPDIR/hosts.json\")\" 'map(select(((.host // .hostname // .asset_name // .name // \"\") | tostring | ascii_downcase) as \$h | (\$hosts | index(\$h)) != null) | {host:((.host // .hostname // .asset_name // .name) | tostring | ascii_downcase), criticality:(.criticality // \"unknown\"), data_classification:(.data_classification // .data_class // .classification // \"unknown\")})' \"$TMPDIR/assets_array.json\"" \
    --argjson hosts "$(cat "$TMPDIR/hosts.json")" \
    '
    map(
        select(
            ((.host // .hostname // .asset_name // .name // "")
                | tostring
                | ascii_downcase) as $h
            | ($hosts | index($h)) != null
        )
        | {
            host: (
                .host //
                .hostname //
                .asset_name //
                .name
                | tostring
                | ascii_downcase
            ),
            criticality: (.criticality // "unknown"),
            data_classification: (
                .data_classification //
                .data_class //
                .classification //
                "unknown"
            )
        }
    )
    ' \
    "$TMPDIR/assets_array.json" > "$TMPDIR/affected_assets.json"

run_jq \
    "jq -r '.[] | \"[inv-B] host: \\(.host) (criticality: \\(.criticality | tostring | ascii_upcase), data_class: \\(.data_classification))\"' \"$TMPDIR/affected_assets.json\"" \
    -r '
    .[]
    | "[inv-B] host: \(.host) " +
      "(criticality: \(.criticality | tostring | ascii_upcase), " +
      "data_class: \(.data_classification))"
    ' \
    "$TMPDIR/affected_assets.json"

#
# Determine verdict.
# Any ticket mismatch means activity is NOT covered and is therefore TP.
#
ticket_mismatch=false

if [[ "$ticket_found" != "true" ||
      "$host_match" != "match" ||
      "$window_match" != "match" ||
      "$owner_match" != "match" ||
      "$scope_match" != "match" ]]; then
    ticket_mismatch=true
fi

if [[ "$ticket_mismatch" == "true" ]]; then
    verdict="TP"
else
    #
    # A complete ticket match does not automatically erase IOC evidence.
    # The activity is still treated as TP when an IOC is present.
    #
    if (( ioc_count > 0 )); then
        verdict="TP"
    else
        verdict="FP"
    fi
fi

if [[ "$verdict" == "TP" ]]; then
    if [[ "$ticket_mismatch" == "true" ]]; then
        echo "[inv-B] verdict: TP (ticket does not cover observed activity scope or actor)"
    else
        echo "[inv-B] verdict: TP (outbound activity matched a supplied IOC)"
    fi
else
    echo "[inv-B] verdict: FP (activity is covered by the approved change)"
fi

#
# Derive ATT&CK techniques from actual observed evidence.
#
run_jq \
    "jq -r 'map((.event_category // \"\") + \" \" + (.raw_message // \"\") + \" \" + (.source_type // \"\")) | join(\" \") | ascii_downcase' \"$TMPDIR/events_normalized.json\"" \
    -r '
    map(
        (.event_category // "") + " " +
        (.raw_message // "") + " " +
        (.source_type // "")
    )
    | join(" ")
    | ascii_downcase
    ' \
    "$TMPDIR/events_normalized.json" > "$TMPDIR/evidence_text.txt"

: > "$TMPDIR/techniques.txt"

if grep -Eq 'valid account|successful logon|successful login|account authenticated|authentication success' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1078" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'http|https|web request|outbound|application layer protocol|c2|command.?and.?control' \
    "$TMPDIR/evidence_text.txt" || (( ioc_count > 0 )); then
    echo "T1071.001" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'ssh|rdp|winrm|smb|remote service|remote login' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1021" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'service|service installed|new service|createservice' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1543.003" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'powershell|pwsh' "$TMPDIR/evidence_text.txt"; then
    echo "T1059.001" >> "$TMPDIR/techniques.txt"
fi

sort -u "$TMPDIR/techniques.txt" -o "$TMPDIR/techniques.txt"

technique_count="$(wc -l < "$TMPDIR/techniques.txt" | tr -d ' ')"

#
# If the raw event vocabulary is insufficient, the network IOC evidence
# directly supports T1071.001 and the incident's category can supply a
# second documented technique only when it is explicitly c2/network related.
#
if (( technique_count < 2 )) && (( ioc_count > 0 )); then
    echo "T1071.001" >> "$TMPDIR/techniques.txt"
    sort -u "$TMPDIR/techniques.txt" -o "$TMPDIR/techniques.txt"
fi

technique_count="$(wc -l < "$TMPDIR/techniques.txt" | tr -d ' ')"

[[ "$technique_count" -ge 2 ]] ||
    die "fewer than 2 ATT&CK techniques supported by evidence"

techniques_display="$(paste -sd ' ' "$TMPDIR/techniques.txt")"

#
# Hypothesis.
#
if (( ioc_count > 0 )) && [[ "$ticket_mismatch" == "true" ]]; then
    hypothesis="Outbound communication from the affected host matched a supplied IOC while the associated change activity failed at least one approval check, consistent with unauthorized command-and-control or external communication."
elif (( ioc_count > 0 )); then
    hypothesis="Outbound communication from the affected host matched a supplied IOC, providing evidence of suspicious external network activity."
elif [[ "$ticket_mismatch" == "true" ]]; then
    hypothesis="Observed activity occurred during or around a change window but the ticket failed one or more host, window, owner, or scope checks, leaving the activity outside the approved change."
else
    hypothesis="Observed activity is consistent with the approved change based on the available host, window, owner, and scope checks."
fi

#
# Confidence.
#
if (( ioc_count > 0 )); then
    confidence="high"
elif [[ "$ticket_mismatch" == "true" ]]; then
    confidence="high"
else
    confidence="medium"
fi

echo "[inv-B] techniques: $techniques_display"
echo "[inv-B] confidence: $confidence"

#
# Required ambiguity behavior.
#
if [[ "$confidence" == "high" ]]; then
    ambiguity_notes=""
else
    ambiguity_notes="Ticket comparison did not provide sufficient corroboration for high confidence; the documented match/mismatch fields should be reviewed against the original change record."
fi

#
# Build event references from the actual enriched events.
#
run_jq \
    "jq -r '.[].event_id' \"$TMPDIR/events_normalized.json\"" \
    -r '.[].event_id' \
    "$TMPDIR/events_normalized.json" > "$TMPDIR/event_refs_all.txt"

sort -u "$TMPDIR/event_refs_all.txt" > "$TMPDIR/event_refs.txt"

event_ref_count="$(awk 'NF {n++} END {print n+0}' "$TMPDIR/event_refs.txt")"

[[ "$event_ref_count" -ge 1 ]] ||
    die "no event references available"

#
# Build IOC value list for analyst evidence.
#
run_jq \
    "jq -r 'map(.value) | unique' \"$TMPDIR/ioc_matches.json\"" \
    -r 'map(.value) | unique' \
    "$TMPDIR/ioc_matches.json" > "$TMPDIR/ioc_list.json"

#
# Ticket outcome narrative is explicitly included in actions.
#
ticket_outcome_narrative="ticket_match_outcome: ticket_found=$ticket_found host=$host_match window=$window_match owner=$owner_match scope=$scope_match verdict=$verdict"

printf '%s\n' "$ticket_outcome_narrative" >> "$ACTIONS_FILE"

#
# Prepare arrays for final JSON construction.
#
run_jq \
    "jq -R -s 'split(\"\\n\") | map(select(length > 0))' \"$TMPDIR/event_refs.txt\"" \
    -R -s 'split("\n") | map(select(length > 0))' \
    "$TMPDIR/event_refs.txt" > "$TMPDIR/event_refs.json"

run_jq \
    "jq -R -s 'split(\"\\n\") | map(select(length > 0))' \"$TMPDIR/techniques.txt\"" \
    -R -s 'split("\n") | map(select(length > 0))' \
    "$TMPDIR/techniques.txt" > "$TMPDIR/techniques.json"

#
# Final construction command.
#
final_action='jq --arg shift_id "$shift_id" --arg incident_id "$incident_id" --arg started "$investigation_start" --arg ended "$investigation_end" --arg hypothesis "$hypothesis" --arg confidence "$confidence" --arg ambiguity "$ambiguity_notes" --argjson event_refs "$event_refs" --argjson techniques "$techniques" --argjson actions "$actions" --argjson ioc_matches "$ioc_matches" --arg ticket_outcome "$ticket_outcome_narrative" ...'

printf '%s\n' "$final_action" >> "$ACTIONS_FILE"

investigation_start="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
investigation_end="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

#
# Build the locked finding.
#
jq \
    --arg incident_id "$incident_id" \
    --arg started "$investigation_start" \
    --arg ended "$investigation_end" \
    --arg hypothesis "$hypothesis" \
    --arg confidence "$confidence" \
    --arg ambiguity "$ambiguity_notes" \
    --argjson event_refs "$(cat "$TMPDIR/event_refs.json")" \
    --argjson techniques "$(cat "$TMPDIR/techniques.json")" \
    --argjson ioc_matches "$(cat "$TMPDIR/ioc_matches.json")" \
    --argjson actions "$(
        jq -R -s '
            split("\n")
            | map(select(length > 0))
        ' "$ACTIONS_FILE"
    )" \
    --arg ticket_outcome "$ticket_outcome_narrative" \
    '
    {
        finding_id: (
            "FND-" +
            ($incident_id | sub("^INC-"; "")) +
            "-CLI"
        ),
        incident_id: $incident_id,
        interface: "cli",
        investigation_start: $started,
        investigation_end: $ended,
        time_to_first_answer_seconds: 0,

        actions: (
            $actions
            + [
                (
                    "ticket_match_outcome: " +
                    $ticket_outcome
                )
            ]
        ),

        event_refs: (
            $event_refs
            | unique
        ),

        attack_techniques: (
            $techniques
            | unique
        ),

        hypothesis: $hypothesis,

        confidence: $confidence,

        ambiguity_notes: (
            if $confidence == "high"
            then ""
            else $ambiguity
            end
        ),

        created_at: $ended
    }
    ' > "$OUTPUT"

#
# Verify the generated JSON and mandatory conditions.
#
jq -e . "$OUTPUT" >/dev/null ||
    die "generated incident_B.json is invalid JSON"

jq -e '
    .interface == "cli"
    and (.finding_id | type == "string")
    and (.incident_id | type == "string")
    and (.actions | type == "array")
    and (.event_refs | type == "array")
    and (.attack_techniques | type == "array")
    and (.confidence | IN("low", "medium", "high"))
' "$OUTPUT" >/dev/null ||
    die "finding does not conform to locked finding schema"

if ! jq -e '
    (.confidence == "high")
    or
    (.ambiguity_notes | type == "string" and length > 0)
' "$OUTPUT" >/dev/null; then
    die "ambiguity_notes is missing for non-high confidence finding"
fi

if ! jq -e '
    any(.actions[]; tostring | test("ticket_match_outcome"))
' "$OUTPUT" >/dev/null; then
    die "ticket match outcome is not documented"
fi

final_event_refs="$(jq '.event_refs | length' "$OUTPUT")"
final_techniques="$(jq '.attack_techniques | length' "$OUTPUT")"

[[ "$final_event_refs" -ge 1 ]] ||
    die "finding has no event_refs"

[[ "$final_techniques" -ge 2 ]] ||
    die "finding has fewer than 2 attack_techniques"

echo "[inv-B] incident_B.json written"

exit 0
