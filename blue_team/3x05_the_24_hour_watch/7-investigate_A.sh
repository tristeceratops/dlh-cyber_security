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

command -v jq >/dev/null 2>&1 || {
    echo "[inv-A] ERROR: jq is required" >&2
    exit 1
}

die() {
    echo "[inv-A] ERROR: $*" >&2
    exit 1
}

require_file() {
    [[ -s "$1" ]] || die "required file missing or empty: $1"
}

require_file "$INCIDENTS"
require_file "$IOC_FEED"

if [[ -s "$EVENTS_JSONL" ]]; then
    EVENTS_FILE="$EVENTS_JSONL"
elif [[ -s "$EVENTS_JSON" ]]; then
    EVENTS_FILE="$EVENTS_JSON"
else
    die "enriched events file not found"
fi

if [[ -s "$BASELINE" ]]; then
    BASELINE_FILE="$BASELINE"
elif [[ -s "$BASELINE_RUN" ]]; then
    BASELINE_FILE="$BASELINE_RUN"
else
    die "baseline.json or runtime/baseline_run.json not found"
fi

mkdir -p "$WORKSPACE/investigations"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ACTIONS_FILE="$TMPDIR/actions.txt"
: > "$ACTIONS_FILE"

# Every jq invocation goes through this wrapper so the exact jq command is
# recorded in the locked finding's actions list.
run_jq() {
    local action="$1"
    shift
    printf '%s\n' "$action" >> "$ACTIONS_FILE"
    jq "$@"
}

echo "[inv-A] loading INC-$(date -u '+%Y%m%d')-A"

# Extract incident A.
run_jq \
    "jq -c '.incidents[] | select(.incident_id | test(\"^INC-[0-9]{8}-A$\"))' \"$INCIDENTS\"" \
    -c '.incidents[] | select(.incident_id | test("^INC-[0-9]{8}-A$"))' \
    "$INCIDENTS" > "$TMPDIR/incident_A.json"

[[ -s "$TMPDIR/incident_A.json" ]] ||
    die "INC-YYYYMMDD-A not found in incidents.json"

incident_id="$(run_jq \
    "jq -r '.incident_id' \"$TMPDIR/incident_A.json\"" \
    -r '.incident_id' "$TMPDIR/incident_A.json")"

host_list="$(run_jq \
    "jq -r '.host_list[]' \"$TMPDIR/incident_A.json\"" \
    -r '.host_list[]' "$TMPDIR/incident_A.json")"

alert_count="$(run_jq \
    "jq '.alert_ids | length' \"$TMPDIR/incident_A.json\"" \
    '.alert_ids | length' "$TMPDIR/incident_A.json")"

tentative_category="$(run_jq \
    "jq -r '.tentative_category' \"$TMPDIR/incident_A.json\"" \
    -r '.tentative_category' "$TMPDIR/incident_A.json")"

first_seen="$(run_jq \
    "jq -r '.first_seen' \"$TMPDIR/incident_A.json\"" \
    -r '.first_seen' "$TMPDIR/incident_A.json")"

last_seen="$(run_jq \
    "jq -r '.last_seen' \"$TMPDIR/incident_A.json\"" \
    -r '.last_seen' "$TMPDIR/incident_A.json")"

[[ -n "$incident_id" && "$incident_id" != "null" ]] ||
    die "incident_id is missing"

[[ -n "$host_list" ]] ||
    die "incident A has no hosts"

echo "[inv-A] host_list: $(tr '\n' ',' <<< "$host_list" | sed 's/,$//')"
echo "[inv-A] alert count: $alert_count"
echo "[inv-A] tentative category: $tentative_category"

# Create a JSON array of normalized incident hosts.
run_jq \
    "jq -c '.host_list | map(ascii_downcase) | unique' \"$TMPDIR/incident_A.json\"" \
    -c '.host_list | map(ascii_downcase) | unique' \
    "$TMPDIR/incident_A.json" > "$TMPDIR/hosts.json"

# Calculate the investigation window using jq's ISO-8601 epoch conversion.
window_start="$(run_jq \
    "jq -nr --arg ts \"$first_seen\" '(\$ts | fromdateiso8601) - 900 | todateiso8601'" \
    -nr --arg ts "$first_seen" '($ts | fromdateiso8601) - 900 | todateiso8601')"

window_end="$(run_jq \
    "jq -nr --arg ts \"$last_seen\" '(\$ts | fromdateiso8601) + 900 | todateiso8601'" \
    -nr --arg ts "$last_seen" '($ts | fromdateiso8601) + 900 | todateiso8601')"

# Normalize JSONL or JSON input into one JSON array, then filter by host/time.
run_jq \
    "jq -s '.' \"$EVENTS_FILE\"" \
    -s '.' "$EVENTS_FILE" > "$TMPDIR/all_events.json"

run_jq \
    "jq --argjson hosts \"\$(cat \"$TMPDIR/hosts.json\")\" --arg start \"$window_start\" --arg end \"$window_end\" 'map(select((.host // .hostname // .agent_name // \"\" | tostring | ascii_downcase) as \$h | (\$hosts | index(\$h)) != null and (.timestamp // .time // .@timestamp // \"\") != \"\" and ((.timestamp // .time // .@timestamp) | fromdateiso8601) >= (\$start | fromdateiso8601) and ((.timestamp // .time // .@timestamp) | fromdateiso8601) <= (\$end | fromdateiso8601)))'" \
    --argjson hosts "$(cat "$TMPDIR/hosts.json")" \
    --arg start "$window_start" \
    --arg end "$window_end" \
    'map(
        select(
            (.host // .hostname // .agent_name // "" | tostring | ascii_downcase) as $h
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
    )' \
    "$TMPDIR/all_events.json" > "$TMPDIR/matching_events.json"

event_count="$(run_jq \
    "jq 'length' \"$TMPDIR/matching_events.json\"" \
    'length' "$TMPDIR/matching_events.json")"

echo "[inv-A] events in window: $event_count"

[[ "$event_count" -ge 6 ]] ||
    die "fewer than 6 matching events; cannot satisfy locked event_refs requirement"

# Normalize timeline fields and calculate analytical significance.
run_jq \
    "jq 'map({event: ., timestamp:(.timestamp // .time // .@timestamp), host:((.host // .hostname // .agent_name // \"\") | tostring | ascii_downcase), source_type:(.source_type // .source // .log_type // \"unknown\"), event_category:(.event_category // .category // .event_type // .type // \"unknown\"), raw_message:(.raw_message // .message // .full_log // .log // \"\"), event_id:(.event_id // .id // .event_ref // .eventId // \"\"), significance:(if ((.event_category // .category // .event_type // .type // \"\") | tostring | ascii_downcase | test(\"authentication|auth|login|logon\")) then 5 elif ((.event_category // .category // .event_type // .type // \"\") | tostring | ascii_downcase | test(\"process|service|execution\")) then 4 elif ((.event_category // .category // .event_type // .type // \"\") | tostring | ascii_downcase | test(\"network|firewall|suricata|dns|http|connection\")) then 4 else 2 end)}) | sort_by(.timestamp)'" \
    'map({
        event: .,
        timestamp: (.timestamp // .time // .["@timestamp"]),
        host: ((.host // .hostname // .agent_name // "") | tostring | ascii_downcase),
        source_type: (.source_type // .source // .log_type // "unknown"),
        event_category: (.event_category // .category // .event_type // .type // "unknown"),
        raw_message: (.raw_message // .message // .full_log // .log // ""),
        event_id: (.event_id // .id // .event_ref // .eventId // ""),
        significance: (
            if ((.event_category // .category // .event_type // .type // "")
                | tostring | ascii_downcase
                | test("authentication|auth|login|logon"))
            then 5
            elif ((.event_category // .category // .event_type // .type // "")
                | tostring | ascii_downcase
                | test("process|service|execution"))
            then 4
            elif ((.event_category // .category // .event_type // .type // "")
                | tostring | ascii_downcase
                | test("network|firewall|suricata|dns|http|connection"))
            then 4
            else 2
            end
        )
    }) | sort_by(.timestamp)' \
    "$TMPDIR/matching_events.json" > "$TMPDIR/timeline.json"

echo "[inv-A] timeline (top 6):"

# Select six analytically significant events while retaining chronological order.
run_jq \
    "jq 'sort_by(-.significance, .timestamp) | .[0:6] | sort_by(.timestamp)' \"$TMPDIR/timeline.json\"" \
    'sort_by(-.significance, .timestamp) | .[0:6] | sort_by(.timestamp)' \
    "$TMPDIR/timeline.json" > "$TMPDIR/top6.json"

run_jq \
    "jq -r '.[] | \"  \\(.timestamp)  \\(.host)  \\(.source_type)  \\(.event_category)  \\(.raw_message | tostring | gsub(\"[[:space:]]+\"; \" \") | .[0:80])\"' \"$TMPDIR/top6.json\"" \
    -r '.[] | "  \(.timestamp)  \(.host)  \(.source_type)  \(.event_category)  \(.raw_message | tostring | gsub("[[:space:]]+"; " ") | .[0:80])"' \
    "$TMPDIR/top6.json"

# Extract IOC values from common feed layouts.
run_jq \
    "jq -r '.. | objects | (.value? // .ioc? // .indicator? // .ip? // .domain? // .hash? // .account? // .service_name? // .port?)? | select(. != null) | tostring' \"$IOC_FEED\"" \
    -r '
      .. | objects
      | (.value? // .ioc? // .indicator? // .ip? // .domain? // .hash? //
         .account? // .service_name? // .port?)?
      | select(. != null)
      | tostring
    ' \
    "$IOC_FEED" | sort -u > "$TMPDIR/ioc_values.txt"

# Check src_ip and dst_ip against IOC values. Also include other common IP
# field names without treating arbitrary event fields as IOC matches.
run_jq \
    "jq --rawfile iocs \"$TMPDIR/ioc_values.txt\" 'map(.event) | map(. as \$e | (([.src_ip?, .dst_ip?, .source_ip?, .destination_ip?] | map(select(. != null) | tostring)) | unique | map(select((\$iocs | split(\"\\\\n\")) | index(.)) | {event_id:(\$e.event_id // \$e.id // \$e.event_ref // \$e.eventId // \"\"), value:.}))) | add // []'" \
    --rawfile iocs "$TMPDIR/ioc_values.txt" \
    '
    map(.event)
    | map(
        . as $e
        | (
            [
              .src_ip?,
              .dst_ip?,
              .source_ip?,
              .destination_ip?
            ]
            | map(select(. != null) | tostring)
            | unique
            | map(
                . as $candidate
                | select(
                    ($iocs | split("\n"))
                    | index($candidate)
                  )
                | {
                    event_id: (
                      $e.event_id //
                      $e.id //
                      $e.event_ref //
                      $e.eventId //
                      ""
                    ),
                    value: .
                  }
              )
          )
      )
    | add // []
    ' \
    "$TMPDIR/timeline.json" > "$TMPDIR/ip_ioc_matches.json"

# Also check explicit IOC strings carried in matches_ioc/event IOC fields.
run_jq \
    "jq --argfile iocs \"$TMPDIR/ioc_values.txt\" '[]' \"$TMPDIR/timeline.json\"" \
    '[]' \
    "$TMPDIR/timeline.json" >/dev/null 2>&1 || true

# Produce combined IOC evidence from IP fields and explicit IOC-bearing fields.
run_jq \
    "jq --rawfile ioc_text \"$TMPDIR/ioc_values.txt\" 'map(.event) | map(. as \$e | ([.matches_ioc[]?, .ioc?, .indicator?] | map(select(. != null) | tostring) | unique | map(. as \$v | select((\$ioc_text | split(\"\\\\n\")) | index(\$v)) | {event_id:(\$e.event_id // \$e.id // \$e.event_ref // \$e.eventId // \"\"), value:\$v}))) | add // []' \"$TMPDIR/timeline.json\"" \
    --rawfile ioc_text "$TMPDIR/ioc_values.txt" \
    '
    map(.event)
    | map(
        . as $e
        | (
            [
              .matches_ioc[]?,
              .ioc?,
              .indicator?
            ]
            | map(select(. != null) | tostring)
            | unique
            | map(
                . as $v
                | select(
                    ($ioc_text | split("\n"))
                    | index($v)
                  )
                | {
                    event_id: (
                      $e.event_id //
                      $e.id //
                      $e.event_ref //
                      $e.eventId //
                      ""
                    ),
                    value: $v
                  }
              )
          )
      )
    | add // []
    ' \
    "$TMPDIR/timeline.json" > "$TMPDIR/explicit_ioc_matches.json"

run_jq \
    "jq -s 'add | unique_by([.event_id,.value])' \"$TMPDIR/ip_ioc_matches.json\" \"$TMPDIR/explicit_ioc_matches.json\"" \
    -s 'add | unique_by([.event_id, .value])' \
    "$TMPDIR/ip_ioc_matches.json" "$TMPDIR/explicit_ioc_matches.json" \
    > "$TMPDIR/ioc_matches.json"

ioc_count="$(run_jq \
    "jq 'length' \"$TMPDIR/ioc_matches.json\"" \
    'length' "$TMPDIR/ioc_matches.json")"

ioc_values_found="$(run_jq \
    "jq -r 'map(.value) | unique | join(\", \")' \"$TMPDIR/ioc_matches.json\"" \
    -r 'map(.value) | unique | join(", ")' "$TMPDIR/ioc_matches.json")"

if [[ "$ioc_count" -gt 0 ]]; then
    echo "[inv-A] ioc_matches: $ioc_count ($ioc_values_found)"
    run_jq \
        "jq -r '.[] | \"  IOC \\(.value) event=\\(.event_id)\"' \"$TMPDIR/ioc_matches.json\"" \
        -r '.[] | "  IOC \(.value) event=\(.event_id)"' \
        "$TMPDIR/ioc_matches.json"
else
    echo "[inv-A] ioc_matches: 0"
fi

# Baseline markers. Support both baseline marker arrays and runtime
# baseline_run.deviation_markers.
run_jq \
    "jq --argjson hosts \"\$(cat \"$TMPDIR/hosts.json\")\" 'if (.deviation_markers? != null) then .deviation_markers elif (.hosts_with_deviations? != null and .deviation_markers? != null) then .deviation_markers else [] end | map(select((.host // \"\" | ascii_downcase) as \$h | (\$hosts | index(\$h)) != null))'" \
    --argjson hosts "$(cat "$TMPDIR/hosts.json")" \
    '
    if (.deviation_markers? != null)
    then .deviation_markers
    else []
    end
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
    'length' "$TMPDIR/deviations.json")"

echo "[inv-A] baseline deviations: $deviation_count markers for $(tr '\n' ',' <<< "$host_list" | sed 's/,$//')"

run_jq \
    "jq -r '.[] | \"  \\(.host): \\(.marker // .field // \"deviation\") observed=\\(.observed_value // \"unknown\") reference=\\(.baseline_reference // \"unknown\")\"' \"$TMPDIR/deviations.json\"" \
    -r '.[] | "  \(.host): \(.marker // .field // "deviation") observed=\(.observed_value // "unknown") reference=\(.baseline_reference // "unknown")"' \
    "$TMPDIR/deviations.json"

# Derive ATT&CK techniques from observed event content.
run_jq \
    "jq -r 'map((.event_category // \"\" | tostring) + \" \" + (.raw_message // \"\" | tostring) + \" \" + ((.event.rule_id // .event.rule // \"\") | tostring)) | join(\" \") | ascii_downcase' \"$TMPDIR/top6.json\"" \
    -r 'map(
          (.event_category // "" | tostring) + " " +
          (.raw_message // "" | tostring) + " " +
          ((.event.rule_id // .event.rule // "") | tostring)
        )
        | join(" ")
        | ascii_downcase' \
    "$TMPDIR/top6.json" > "$TMPDIR/evidence_text.txt"

techniques=()

if grep -Eq 'brute.?force|password spray|multiple authentication failure|failed logon|failed login|t1110' "$TMPDIR/evidence_text.txt"; then
    techniques+=("T1110.003")
fi

if grep -Eq 'service|new service|service installed|createservice|sc\.exe|systemd' "$TMPDIR/evidence_text.txt"; then
    techniques+=("T1543.003")
fi

if grep -Eq 'http|https|web request|dns|beacon|c2|command and control' "$TMPDIR/evidence_text.txt"; then
    techniques+=("T1071.001")
fi

if grep -Eq 'powershell|pwsh' "$TMPDIR/evidence_text.txt"; then
    techniques+=("T1059.001")
fi

if grep -Eq 'successful logon|successful login|valid account|authentication success' "$TMPDIR/evidence_text.txt"; then
    techniques+=("T1078")
fi

if grep -Eq 'remote|ssh|rdp|winrm|smb|lateral' "$TMPDIR/evidence_text.txt"; then
    techniques+=("T1021")
fi

# Deduplicate techniques.
printf '%s\n' "${techniques[@]:-}" |
    awk 'NF && !seen[$0]++' > "$TMPDIR/techniques.txt"

technique_count="$(wc -l < "$TMPDIR/techniques.txt" | tr -d ' ')"

[[ "$technique_count" -ge 2 ]] ||
    die "fewer than 2 ATT&CK techniques could be supported by observed evidence"

technique_display="$(tr '\n' ' ' < "$TMPDIR/techniques.txt" | sed 's/[[:space:]]*$//')"

# Form hypothesis from observed patterns. Keep it descriptive and evidence
# based rather than asserting an unsupported attack narrative.
has_bruteforce=0
has_service=0
has_network=0
has_valid=0

grep -Eq 'brute.?force|password spray|multiple authentication failure|failed logon|failed login|t1110' "$TMPDIR/evidence_text.txt" && has_bruteforce=1 || true
grep -Eq 'service|new service|service installed|createservice|sc\.exe|systemd' "$TMPDIR/evidence_text.txt" && has_service=1 || true
grep -Eq 'http|https|web request|dns|beacon|c2|command and control' "$TMPDIR/evidence_text.txt" && has_network=1 || true
grep -Eq 'successful logon|successful login|valid account|authentication success' "$TMPDIR/evidence_text.txt" && has_valid=1 || true

if (( has_bruteforce && has_service )); then
    hypothesis="Authentication failures followed by service-related execution on the incident host are consistent with credential-abuse activity followed by service-based persistence."
elif (( has_service && has_network )); then
    hypothesis="A new or unusual service coincides with network activity on the incident host, consistent with service-based execution followed by command-and-control communication."
elif (( has_bruteforce && has_valid )); then
    hypothesis="Repeated authentication failures followed by successful authentication are consistent with credential-abuse activity followed by use of a valid account."
elif (( has_valid && has_network )); then
    hypothesis="Successful authentication activity followed by network communication is consistent with valid-account use associated with subsequent remote activity."
else
    hypothesis="The correlated authentication, process, and network events indicate a multi-stage activity pattern on the incident host."
fi

echo "[inv-A] hypothesis: $hypothesis"
echo "[inv-A] techniques: $technique_display"

# Determine confidence from corroborating evidence.
if (( ioc_count > 0 && deviation_count > 0 && technique_count >= 2 )); then
    confidence="high"
elif (( deviation_count > 0 && technique_count >= 2 )); then
    confidence="medium"
else
    confidence="low"
fi

echo "[inv-A] confidence: $confidence"

investigation_start="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
investigation_end="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Build event references from the top six significant events.
run_jq \
    "jq -r '.[].event_id' \"$TMPDIR/top6.json\"" \
    -r '.[].event_id' \
    "$TMPDIR/top6.json" > "$TMPDIR/event_refs.txt"

event_ref_count="$(awk 'NF {count++} END {print count+0}' "$TMPDIR/event_refs.txt")"

[[ "$event_ref_count" -ge 6 ]] ||
    die "fewer than 6 event_refs were selected"

# Ensure event IDs are actually non-empty and unique enough to identify events.
if grep -q '^$' "$TMPDIR/event_refs.txt"; then
    die "one or more top-six events lacks an event ID"
fi

# Create the locked finding. The actions list is populated from every jq
# invocation recorded by run_jq.
run_jq \
    "jq --rawfile actions \"$ACTIONS_FILE\" --rawfile event_refs \"$TMPDIR/event_refs.txt\" --slurpfile techniques \"$TMPDIR/techniques.txt\" --slurpfile deviations \"$TMPDIR/deviations.json\" --slurpfile iocs \"$TMPDIR/ioc_matches.json\" '...' \"$TMPDIR/incident_A.json\"" \
    --rawfile actions "$ACTIONS_FILE" \
    --rawfile event_refs "$TMPDIR/event_refs.txt" \
    --slurpfile techniques "$TMPDIR/techniques.txt" \
    --slurpfile deviations "$TMPDIR/deviations.json" \
    --slurpfile iocs "$TMPDIR/ioc_matches.json" \
    --arg investigation_start "$investigation_start" \
    --arg investigation_end "$investigation_end" \
    --arg incident_id "$incident_id" \
    --arg hypothesis "$hypothesis" \
    --arg confidence "$confidence" \
    --argjson technique_count "$technique_count" \
    '
    {
      finding_id: (
        "FND-" +
        ($incident_id | sub("^INC-"; "")) +
        "-CLI"
      ),
      incident_id: $incident_id,
      interface: "cli",
      investigation_start: $investigation_start,
      investigation_end: $investigation_end,
      time_to_first_answer_seconds: 0,
      actions: (
        $actions
        | split("\n")
        | map(select(length > 0))
      ),
      event_refs: (
        $event_refs
        | split("\n")
        | map(select(length > 0))
        | unique
      ),
      attack_techniques: (
        $technique_count as $n
        | $techniques
        | map(select(type == "string"))
        | unique
      ),
      hypothesis: $hypothesis,
      confidence: $confidence,
      ambiguity_notes: (
        if (($iocs | length) == 0 and ($deviations | length) == 0)
        then "No IOC or baseline deviation corroboration was found in the selected evidence window."
        elif (($iocs | length) == 0)
        then "No supplied IOC matched the selected event network/IOC fields; baseline deviations provide additional context."
        elif (($deviations | length) == 0)
        then "IOC evidence was present, but no matching baseline deviation marker was found for the incident hosts."
        else
          "IOC matches and baseline deviation markers corroborate the correlated event sequence."
        end
      ),
      created_at: $investigation_end
    }
    ' \
    "$TMPDIR/incident_A.json" > "$OUTPUT"

# Validate locked finding schema and hard minimums.
run_jq \
    "jq -e 'has(\"finding_id\") and has(\"incident_id\") and .interface == \"cli\" and (.actions | type == \"array\") and (.event_refs | type == \"array\") and (.attack_techniques | type == \"array\") and (.event_refs | length) >= 6 and (.attack_techniques | length) >= 2' \"$OUTPUT\"" \
    -e '
      has("finding_id")
      and has("incident_id")
      and .interface == "cli"
      and (.actions | type == "array")
      and (.event_refs | type == "array")
      and (.attack_techniques | type == "array")
      and (.event_refs | length) >= 6
      and (.attack_techniques | length) >= 2
    ' \
    "$OUTPUT" >/dev/null

final_event_refs="$(run_jq \
    "jq '.event_refs | length' \"$OUTPUT\"" \
    '.event_refs | length' "$OUTPUT")"

final_techniques="$(run_jq \
    "jq '.attack_techniques | length' \"$OUTPUT\"" \
    '.attack_techniques | length' "$OUTPUT")"

[[ "$final_event_refs" -ge 6 ]] ||
    die "finding contains fewer than 6 event_refs"

[[ "$final_techniques" -ge 2 ]] ||
    die "finding contains fewer than 2 attack_techniques"

echo "[inv-A] incident_A.json written"

exit 0
