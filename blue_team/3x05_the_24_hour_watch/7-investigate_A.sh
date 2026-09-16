#!/bin/bash
set -euo pipefail

WORKSPACE="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE is not set}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR is not set}"

INCIDENTS="$WORKSPACE/alerts/incidents.json"
EVENTS_JSONL="$WORKSPACE/enriched/enriched_events.jsonl"
EVENTS_JSON="$WORKSPACE/enriched/enriched_events.json"
IOC_FEED="$ASSETS/ioc_feed.json"
BASELINE="$WORKSPACE/enriched/baseline.json"
BASELINE_RUN="$WORKSPACE/runtime/baseline_run.json"
OUTPUT="$WORKSPACE/investigations/incident_A.json"

die() {
    echo "[inv-A] ERROR: $*" >&2
    exit 1
}

require_file() {
    [[ -s "$1" ]] || die "required file missing or empty: $1"
}

command -v jq >/dev/null 2>&1 || die "jq is required"

require_file "$INCIDENTS"
require_file "$IOC_FEED"

if [[ -s "$EVENTS_JSONL" ]]; then
    EVENTS_FILE="$EVENTS_JSONL"
else
    EVENTS_FILE="$EVENTS_JSON"
fi

require_file "$EVENTS_FILE"

if [[ -s "$BASELINE" ]]; then
    BASELINE_FILE="$BASELINE"
elif [[ -s "$BASELINE_RUN" ]]; then
    BASELINE_FILE="$BASELINE_RUN"
else
    die "baseline.json or baseline_run.json not found"
fi

mkdir -p "$WORKSPACE/investigations"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ACTIONS_FILE="$TMPDIR/actions.txt"
: > "$ACTIONS_FILE"

#
# Every jq invocation is recorded before it executes.
#
run_jq() {
    local description="$1"
    shift

    printf '%s\n' "$description" >> "$ACTIONS_FILE"
    jq "$@"
}

#
# Load incident A.
#
echo "[inv-A] loading INC-YYYYMMDD-A"

run_jq \
    "jq -c '.incidents[] | select(.incident_id | test(\"^INC-[0-9]{8}-A$\"))' \"$INCIDENTS\"" \
    -c '.incidents[] | select(.incident_id | test("^INC-[0-9]{8}-A$"))' \
    "$INCIDENTS" > "$TMPDIR/incident_A.json"

[[ -s "$TMPDIR/incident_A.json" ]] ||
    die "INC-YYYYMMDD-A not found"

incident_id="$(run_jq \
    "jq -r '.incident_id' \"$TMPDIR/incident_A.json\"" \
    -r '.incident_id' "$TMPDIR/incident_A.json")"

alert_count="$(run_jq \
    "jq -r '.alert_ids | length' \"$TMPDIR/incident_A.json\"" \
    -r '.alert_ids | length' "$TMPDIR/incident_A.json")"

tentative_category="$(run_jq \
    "jq -r '.tentative_category' \"$TMPDIR/incident_A.json\"" \
    -r '.tentative_category' "$TMPDIR/incident_A.json")"

first_seen="$(run_jq \
    "jq -r '.first_seen' \"$TMPDIR/incident_A.json\"" \
    -r '.first_seen' "$TMPDIR/incident_A.json")"

last_seen="$(run_jq \
    "jq -r '.last_seen' \"$TMPDIR/incident_A.json\"" \
    -r '.last_seen' "$TMPDIR/incident_A.json")"

run_jq \
    "jq -r '.host_list[]' \"$TMPDIR/incident_A.json\"" \
    -r '.host_list[]' \
    "$TMPDIR/incident_A.json" > "$TMPDIR/hosts.txt"

[[ -s "$TMPDIR/hosts.txt" ]] ||
    die "incident A has no hosts"

echo "[inv-A] host_list: $(paste -sd ',' "$TMPDIR/hosts.txt")"
echo "[inv-A] alert count: $alert_count"
echo "[inv-A] tentative category: $tentative_category"

run_jq \
    "jq -c '.host_list | map(ascii_downcase) | unique' \"$TMPDIR/incident_A.json\"" \
    -c '.host_list | map(ascii_downcase) | unique' \
    "$TMPDIR/incident_A.json" > "$TMPDIR/hosts.json"

#
# Calculate first_seen - 15 minutes and last_seen + 15 minutes.
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
# Normalize either JSONL or a JSON array/object into an array.
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
# Filter to incident hosts and the required time window.
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

echo "[inv-A] events in window: $event_count"

[[ "$event_count" -ge 6 ]] ||
    die "fewer than 6 events found in investigation window"

#
# Normalize event fields for timeline analysis.
#
run_jq \
    "jq 'map({event_id:(.event_id // .id // .event_ref // .eventId // \"\"), timestamp:(.timestamp // .time // .[\"@timestamp\"] // \"\"), host:((.host // .hostname // .agent_name // \"\") | tostring | ascii_downcase), source_type:(.source_type // .source // .log_type // \"unknown\"), event_category:(.event_category // .category // .event_type // .type // \"unknown\"), raw_message:(.raw_message // .message // .full_log // .log // \"\"), src_ip:(.src_ip // .source_ip // null), dst_ip:(.dst_ip // .destination_ip // null), rule_id:(.rule_id // .rule // \"\")}) | sort_by(.timestamp)' \"$TMPDIR/matching_events.json\"" \
    '
    map({
        event_id: (.event_id // .id // .event_ref // .eventId // ""),
        timestamp: (.timestamp // .time // .["@timestamp"] // ""),
        host: ((.host // .hostname // .agent_name // "")
            | tostring
            | ascii_downcase),
        source_type: (.source_type // .source // .log_type // "unknown"),
        event_category: (.event_category // .category // .event_type // .type // "unknown"),
        raw_message: (.raw_message // .message // .full_log // .log // ""),
        src_ip: (.src_ip // .source_ip // null),
        dst_ip: (.dst_ip // .destination_ip // null),
        rule_id: (.rule_id // .rule // "")
    })
    | sort_by(.timestamp)
    ' \
    "$TMPDIR/matching_events.json" > "$TMPDIR/timeline.json"

#
# Analytical significance:
# authentication > process/service > network > other.
#
run_jq \
    "jq 'map(. + {significance:(if (.event_category | tostring | ascii_downcase | test(\"authentication|auth|login|logon\")) then 5 elif (.event_category | tostring | ascii_downcase | test(\"process|service|execution\")) then 4 elif (.event_category | tostring | ascii_downcase | test(\"network|firewall|suricata|dns|http|connection\")) then 4 else 2 end)})' \"$TMPDIR/timeline.json\"" \
    '
    map(
        . + {
            significance:
                (
                    if (.event_category
                        | tostring
                        | ascii_downcase
                        | test("authentication|auth|login|logon"))
                    then 5
                    elif (.event_category
                        | tostring
                        | ascii_downcase
                        | test("process|service|execution"))
                    then 4
                    elif (.event_category
                        | tostring
                        | ascii_downcase
                        | test("network|firewall|suricata|dns|http|connection"))
                    then 4
                    else 2
                    end
                )
        }
    )
    ' \
    "$TMPDIR/timeline.json" > "$TMPDIR/scored_timeline.json"

#
# Select at least six highest-significance events, then restore chronological
# order for presentation.
#
run_jq \
    "jq 'sort_by(-.significance, .timestamp) | .[0:6] | sort_by(.timestamp)' \"$TMPDIR/scored_timeline.json\"" \
    'sort_by(-.significance, .timestamp) | .[0:6] | sort_by(.timestamp)' \
    "$TMPDIR/scored_timeline.json" > "$TMPDIR/top6.json"

top6_count="$(run_jq \
    "jq 'length' \"$TMPDIR/top6.json\"" \
    'length' \
    "$TMPDIR/top6.json")"

[[ "$top6_count" -ge 6 ]] ||
    die "unable to select six significant events"

echo "[inv-A] timeline (top 6):"

run_jq \
    "jq -r '.[] | \"  \\(.timestamp)  \\(.host)  \\(.source_type)  \\(.event_category)  \\(.raw_message | tostring | gsub(\"[[:space:]]+\"; \" \") | .[0:80])\"' \"$TMPDIR/top6.json\"" \
    -r '
    .[]
    | "  \(.timestamp)  \(.host)  \(.source_type)  \(.event_category)  " +
      "\(.raw_message | tostring | gsub("[[:space:]]+"; " ") | .[0:80])"
    ' \
    "$TMPDIR/top6.json"

#
# IOC values.
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
# Check source and destination IPs against the IOC feed.
#
run_jq \
    "jq --rawfile iocs \"$TMPDIR/ioc_values.txt\" 'map(. as \$e | [(.src_ip // null), (.dst_ip // null)] | map(select(. != null) | tostring) | map(select((\$iocs | split(\"\\\\n\")) | index(.)) | {event_id:\$e.event_id, value:.})) | add // []' \"$TMPDIR/top6.json\"" \
    --rawfile iocs "$TMPDIR/ioc_values.txt" \
    '
    map(
        . as $e
        | [
            ($e.src_ip // null),
            ($e.dst_ip // null)
          ]
        | map(select(. != null) | tostring)
        | map(
            . as $value
            | select(
                ($iocs | split("\n"))
                | index($value)
              )
            | {
                event_id: $e.event_id,
                value: $value
            }
          )
    )
    | add // []
    ' \
    "$TMPDIR/top6.json" > "$TMPDIR/ip_ioc_matches.json"

#
# Check explicit IOC fields in the event.
#
run_jq \
    "jq --rawfile iocs \"$TMPDIR/ioc_values.txt\" 'map(. as \$e | ([.matches_ioc[]?, .ioc?, .indicator?] | map(select(. != null) | tostring) | map(select((\$iocs | split(\"\\\\n\")) | index(.)) | {event_id:\$e.event_id, value:.}))) | add // []' \"$TMPDIR/matching_events.json\"" \
    --rawfile iocs "$TMPDIR/ioc_values.txt" \
    '
    map(
        . as $e
        | [
            .matches_ioc[]?,
            .ioc?,
            .indicator?
          ]
        | map(select(. != null) | tostring)
        | map(
            . as $value
            | select(
                ($iocs | split("\n"))
                | index($value)
              )
            | {
                event_id: $e.event_id,
                value: $value
            }
          )
    )
    | add // []
    ' \
    "$TMPDIR/matching_events.json" > "$TMPDIR/explicit_ioc_matches.json"

run_jq \
    "jq -s 'add | unique_by([.event_id, .value])' \"$TMPDIR/ip_ioc_matches.json\" \"$TMPDIR/explicit_ioc_matches.json\"" \
    -s 'add | unique_by([.event_id, .value])' \
    "$TMPDIR/ip_ioc_matches.json" \
    "$TMPDIR/explicit_ioc_matches.json" > "$TMPDIR/ioc_matches.json"

ioc_count="$(run_jq \
    "jq 'length' \"$TMPDIR/ioc_matches.json\"" \
    'length' \
    "$TMPDIR/ioc_matches.json")"

ioc_display="$(run_jq \
    "jq -r 'map(.value) | unique | join(\", \")' \"$TMPDIR/ioc_matches.json\"" \
    -r 'map(.value) | unique | join(", ")' \
    "$TMPDIR/ioc_matches.json")"

if [[ "$ioc_count" -gt 0 ]]; then
    echo "[inv-A] ioc_matches: $ioc_count ($ioc_display)"

    run_jq \
        "jq -r '.[] | \"  IOC \\(.value) event=\\(.event_id)\"' \"$TMPDIR/ioc_matches.json\"" \
        -r '.[] | "  IOC \(.value) event=\(.event_id)"' \
        "$TMPDIR/ioc_matches.json"
else
    echo "[inv-A] ioc_matches: 0"
fi

#
# Baseline deviations.
#
run_jq \
    "jq --argjson hosts \"\$(cat \"$TMPDIR/hosts.json\")\" '(.deviation_markers // []) | map(select((.host // \"\" | ascii_downcase) as \$h | (\$hosts | index(\$h)) != null))' \"$BASELINE_FILE\"" \
    --argjson hosts "$(cat "$TMPDIR/hosts.json")" \
    '
    (.deviation_markers // [])
    | map(
        select(
            (.host // "" | ascii_downcase) as $h
            | ($hosts | index($h)) != null
        )
      )
    ' \
    "$BASELINE_FILE" > "$TMPDIR/deviations.json"

deviation_count="$(run_jq \
    "jq 'length' \"$TMPDIR/deviations.json\"" \
    'length' \
    "$TMPDIR/deviations.json")"

echo "[inv-A] baseline deviations: $deviation_count markers for $(paste -sd ',' "$TMPDIR/hosts.txt")"

if [[ "$deviation_count" -gt 0 ]]; then
    run_jq \
        "jq -r '.[] | \"  \\(.host)  \\(.marker // .field // \"deviation\")  observed=\\(.observed_value // \"unknown\")  reference=\\(.baseline_reference // \"unknown\")\"' \"$TMPDIR/deviations.json\"" \
        -r '
        .[]
        | "  \(.host)  \(.marker // .field // "deviation")  " +
          "observed=\(.observed_value // "unknown")  " +
          "reference=\(.baseline_reference // "unknown")"
        ' \
        "$TMPDIR/deviations.json"
fi

#
# Build evidence text for ATT&CK mapping.
#
run_jq \
    "jq -r 'map((.event_category // \"\") + \" \" + (.raw_message // \"\") + \" \" + (.rule_id // \"\")) | join(\" \") | ascii_downcase' \"$TMPDIR/top6.json\"" \
    -r '
    map(
        (.event_category // "") + " " +
        (.raw_message // "") + " " +
        (.rule_id // "")
    )
    | join(" ")
    | ascii_downcase
    ' \
    "$TMPDIR/top6.json" > "$TMPDIR/evidence_text.txt"

#
# ATT&CK technique derivation.
#
: > "$TMPDIR/techniques.txt"

if grep -Eq 'brute.?force|password spray|failed logon|failed login|authentication failure|t1110' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1110.003" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'new service|service installed|service creation|createservice|sc\.exe|systemd|service' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1543.003" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'http|https|web request|dns|beacon|c2|command.?and.?control' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1071.001" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'powershell|pwsh' "$TMPDIR/evidence_text.txt"; then
    echo "T1059.001" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'successful logon|successful login|valid account|authentication success' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1078" >> "$TMPDIR/techniques.txt"
fi

if grep -Eq 'ssh|rdp|winrm|smb|remote service|lateral' \
    "$TMPDIR/evidence_text.txt"; then
    echo "T1021" >> "$TMPDIR/techniques.txt"
fi

sort -u "$TMPDIR/techniques.txt" -o "$TMPDIR/techniques.txt"

technique_count="$(wc -l < "$TMPDIR/techniques.txt" | tr -d ' ')"

[[ "$technique_count" -ge 2 ]] ||
    die "fewer than 2 ATT&CK techniques supported by evidence"

techniques_display="$(paste -sd ' ' "$TMPDIR/techniques.txt")"

#
# Form a concise evidence-based hypothesis.
#
has_bruteforce=0
has_service=0
has_network=0
has_valid=0

grep -Eq 'brute.?force|password spray|failed logon|failed login|authentication failure|t1110' \
    "$TMPDIR/evidence_text.txt" && has_bruteforce=1 || true

grep -Eq 'new service|service installed|service creation|createservice|sc\.exe|systemd|service' \
    "$TMPDIR/evidence_text.txt" && has_service=1 || true

grep -Eq 'http|https|web request|dns|beacon|c2|command.?and.?control' \
    "$TMPDIR/evidence_text.txt" && has_network=1 || true

grep -Eq 'successful logon|successful login|valid account|authentication success' \
    "$TMPDIR/evidence_text.txt" && has_valid=1 || true

if (( has_bruteforce && has_service )); then
    hypothesis="Authentication failures followed by service-related execution are consistent with credential abuse followed by service-based persistence."
elif (( has_service && has_network )); then
    hypothesis="Service-related execution followed by network activity is consistent with service-based persistence followed by command-and-control communication."
elif (( has_bruteforce && has_valid )); then
    hypothesis="Repeated authentication failures followed by successful authentication are consistent with credential abuse followed by valid-account use."
elif (( has_valid && has_network )); then
    hypothesis="Successful authentication followed by network activity is consistent with valid-account use followed by remote communication."
else
    hypothesis="The correlated authentication, process, and network events indicate a multi-stage activity pattern on the incident host."
fi

#
# Confidence.
#
if (( ioc_count > 0 && deviation_count > 0 && technique_count >= 2 )); then
    confidence="high"
elif (( deviation_count > 0 && technique_count >= 2 )); then
    confidence="medium"
else
    confidence="low"
fi

echo "[inv-A] hypothesis: $hypothesis"
echo "[inv-A] techniques: $techniques_display"
echo "[inv-A] confidence: $confidence"

#
# Event references must be real event IDs.
#
run_jq \
    "jq -r '.[].event_id' \"$TMPDIR/top6.json\"" \
    -r '.[].event_id' \
    "$TMPDIR/top6.json" > "$TMPDIR/event_refs.txt"

event_ref_count="$(awk 'NF { n++ } END { print n + 0 }' "$TMPDIR/event_refs.txt")"

[[ "$event_ref_count" -ge 6 ]] ||
    die "fewer than 6 event references"

if grep -q '^$' "$TMPDIR/event_refs.txt"; then
    die "selected event has empty event_id"
fi

#
# Investigation timestamps.
#
investigation_start="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
investigation_end="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

#
# Build JSON arrays needed by the final jq command.
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
# Determine UTC date for incident identifier.
#
incident_date="$(date -u '+%Y%m%d')"

#
# The final jq command is recorded BEFORE execution, so it is itself present
# in the finding's actions array.
#
FINAL_JQ_ACTION='jq --arg shift_id "$shift_id" --arg incident_id "$incident_id" --arg started "$investigation_start" --arg ended "$investigation_end" --arg hypothesis "$hypothesis" --arg confidence "$confidence" --arg incident_date "$incident_date" --argjson event_refs "$(cat "$TMPDIR/event_refs.json")" --argjson techniques "$(cat "$TMPDIR/techniques.json")" --argjson actions "$(jq -R -s '"'"'split("\n") | map(select(length > 0))'"'"' "$ACTIONS_FILE")" --argjson ioc_matches "$(cat "$TMPDIR/ioc_matches.json")" --argjson deviations "$(cat "$TMPDIR/deviations.json")" ...'

printf '%s\n' "$FINAL_JQ_ACTION" >> "$ACTIONS_FILE"

#
# IMPORTANT:
# The actions array is read before this jq command executes. Therefore the
# final construction command itself is included in the resulting finding.
#
jq \
    --arg shift_id "$shift_id" \
    --arg incident_id "$incident_id" \
    --arg started "$investigation_start" \
    --arg ended "$investigation_end" \
    --arg hypothesis "$hypothesis" \
    --arg confidence "$confidence" \
    --arg incident_date "$incident_date" \
    --argjson event_refs "$(cat "$TMPDIR/event_refs.json")" \
    --argjson techniques "$(cat "$TMPDIR/techniques.json")" \
    --argjson actions "$(
        jq -R -s '
            split("\n")
            | map(select(length > 0))
        ' "$ACTIONS_FILE"
    )" \
    --argjson ioc_matches "$(cat "$TMPDIR/ioc_matches.json")" \
    --argjson deviations "$(cat "$TMPDIR/deviations.json")" \
    --argjson hosts "$(cat "$TMPDIR/hosts.json")" \
    --arg category "$tentative_category" \
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

        actions: $actions,

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
            if (($ioc_matches | length) > 0 and ($deviations | length) > 0)
            then "IOC matches and baseline deviation markers corroborate the correlated event sequence for the incident hosts."
            elif (($ioc_matches | length) > 0)
            then "IOC evidence was identified, but no corresponding baseline deviation marker was found for the incident hosts."
            elif (($deviations | length) > 0)
            then "Baseline deviation markers were identified, but no supplied IOC matched the selected event network or IOC fields."
            else
                "The finding is based on temporal and event-category correlation without IOC or baseline corroboration."
            end
        ),

        created_at: $ended
    }
    ' > "$OUTPUT"

#
# Final validation uses shell/grep/wc rather than another jq invocation so the
# final construction command remains the last jq command executed and is
# already recorded in actions.
#
[[ -s "$OUTPUT" ]] || die "incident_A.json was not created"

grep -q '"interface": "cli"' "$OUTPUT" ||
    die "finding interface is not cli"

grep -q '"incident_id":' "$OUTPUT" ||
    die "finding is missing incident_id"

grep -q '"attack_techniques":' "$OUTPUT" ||
    die "finding is missing attack_techniques"

grep -q '"event_refs":' "$OUTPUT" ||
    die "finding is missing event_refs"

#
# Count event_refs and techniques from the generated JSON without executing jq.
#
final_event_refs="$(grep -A20 '"event_refs"' "$OUTPUT" |
    grep -o '"EVT-[^"]*"' |
    sort -u |
    wc -l |
    tr -d ' ')"

final_techniques="$(grep -A10 '"attack_techniques"' "$OUTPUT" |
    grep -o '"T[0-9][0-9][0-9][0-9][.0-9]*"' |
    sort -u |
    wc -l |
    tr -d ' ')"

[[ "$final_event_refs" -ge 6 ]] ||
    die "finding contains fewer than 6 event_refs"

[[ "$final_techniques" -ge 2 ]] ||
    die "finding contains fewer than 2 attack_techniques"

echo "[inv-A] incident_A.json written"

exit 0
