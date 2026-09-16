#!/bin/bash
set -euo pipefail

: "${SHIFT_WORKSPACE:?SHIFT_WORKSPACE is not set}"
: "${ASSETS_DIR:?ASSETS_DIR is not set}"

REPORT_DIR="$SHIFT_WORKSPACE/reports"
INVESTIGATION_DIR="$SHIFT_WORKSPACE/investigations"
ALERT_DIR="$SHIFT_WORKSPACE/alerts"
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"

INCIDENTS_FILE="$ALERT_DIR/incidents.json"
ASSETS_FILE="$ASSETS_DIR/assets.json"
EVENTS_FILE="$ENRICHED_DIR/enriched_events.jsonl"

mkdir -p "$REPORT_DIR"

require_file() {
    local file="$1"
    [[ -s "$file" ]] || {
        echo "[report] ERROR: required file missing or empty: $file" >&2
        exit 1
    }
}

require_file "$INCIDENTS_FILE"
require_file "$ASSETS_FILE"
require_file "$EVENTS_FILE"

for suffix in A B C; do
    require_file "$INVESTIGATION_DIR/incident_${suffix}.json"
done

jq empty "$INCIDENTS_FILE" >/dev/null || {
    echo "[report] ERROR: invalid JSON: $INCIDENTS_FILE" >&2
    exit 1
}

jq empty "$ASSETS_FILE" >/dev/null || {
    echo "[report] ERROR: invalid JSON: $ASSETS_FILE" >&2
    exit 1
}

for suffix in A B C; do
    jq empty "$INVESTIGATION_DIR/incident_${suffix}.json" >/dev/null || {
        echo "[report] ERROR: invalid investigation JSON for $suffix" >&2
        exit 1
    }
done

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Normalize enriched events to a JSON array.
jq -s '
    if length == 1 and (.[0] | type) == "array" then .[0]
    elif length == 1 and (.[0] | type) == "object" then [.[0]]
    else .
    end
' "$EVENTS_FILE" > "$TMPDIR/events.json"

# Validate that enriched events have usable event IDs.
jq -e '
    all(.[]; ((.event_id? // .id? // .eventId?) != null))
' "$TMPDIR/events.json" >/dev/null || {
    echo "[report] ERROR: enriched events contain records without event IDs" >&2
    exit 1
}

# Normalize asset inventory whether it is an array or wrapped in .assets.
jq '
    if type == "array" then .
    elif .assets? then .assets
    elif .inventory? then .inventory
    else []
    end
' "$ASSETS_FILE" > "$TMPDIR/assets.json"

# Normalize incidents.json to an array.
jq '
    if type == "array" then .
    elif .incidents? then .incidents
    else []
    end
' "$INCIDENTS_FILE" > "$TMPDIR/incidents.json"

jq -e 'length >= 3' "$TMPDIR/incidents.json" >/dev/null || {
    echo "[report] ERROR: incidents.json does not contain all three incidents" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Defang IPv4 addresses in generated report text.
defang_ips() {
    sed -E 's/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/\1[.]\2[.]\3[.]\4/g'
}

json_string_or_unknown() {
    local value="$1"
    if [[ -n "$value" && "$value" != "null" ]]; then
        printf '%s' "$value"
    else
        printf '%s' "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Generate one report.
# ---------------------------------------------------------------------------
generate_report() {
    local suffix="$1"

    local finding="$INVESTIGATION_DIR/incident_${suffix}.json"
    local output="$REPORT_DIR/incident_${suffix}.md"

    echo "[report] generating incident_${suffix}.md"

    # Load finding and identify incident ID.
    local incident_id
    incident_id="$(jq -r '.incident_id // empty' "$finding")"

    [[ -n "$incident_id" ]] || {
        echo "[report] ERROR: finding $suffix has no incident_id" >&2
        exit 1
    }

    # Retrieve the corresponding incidents.json record.
    jq --arg id "$incident_id" '
        .[]
        | select(.incident_id == $id)
    ' "$TMPDIR/incidents.json" > "$TMPDIR/${suffix}_incident.json"

    [[ -s "$TMPDIR/${suffix}_incident.json" ]] || {
        echo "[report] ERROR: no incidents.json record for $incident_id" >&2
        exit 1
    }

    # -----------------------------------------------------------------------
    # Incident metadata.
    # -----------------------------------------------------------------------
    local first_seen last_seen category confidence hypothesis
    first_seen="$(jq -r '.first_seen // empty' "$TMPDIR/${suffix}_incident.json")"
    last_seen="$(jq -r '.last_seen // empty' "$TMPDIR/${suffix}_incident.json")"
    category="$(jq -r '.tentative_category // "unknown"' "$TMPDIR/${suffix}_incident.json")"
    confidence="$(jq -r '.confidence // (.confidence // "unknown")' "$finding")"
    hypothesis="$(jq -r '.hypothesis // "No hypothesis recorded."' "$finding")"

    [[ -n "$first_seen" && -n "$last_seen" ]] || {
        echo "[report] ERROR: incident $suffix is missing first_seen/last_seen" >&2
        exit 1
    }

    # -----------------------------------------------------------------------
    # Timeline
    #
    # Use finding event_refs to select actual enriched events. Sort by
    # timestamp and cap at 15.
    # -----------------------------------------------------------------------
    jq --slurpfile events "$TMPDIR/events.json" '
        def eid:
            (.event_id? // .id? // .eventId?) | tostring;

        def timestamp:
            (.timestamp? // .time? // .event_time? // .datetime? // "") | tostring;

        .event_refs
        | map(tostring)
        | . as $refs
        | ($events[0]
            | map(select((eid) as $id | ($refs | index($id)) != null))
          )
        | sort_by(timestamp)
        | .[:15]
    ' "$finding" > "$TMPDIR/${suffix}_timeline.json"

    local timeline_count
    timeline_count="$(jq 'length' "$TMPDIR/${suffix}_timeline.json")"

    # -----------------------------------------------------------------------
    # Affected assets
    # -----------------------------------------------------------------------
    jq --argjson hosts '
        .host_list // []
        | map(tostring | ascii_downcase)
        | unique
    ' "$TMPDIR/${suffix}_incident.json" > "$TMPDIR/${suffix}_hosts.json"

    jq --slurpfile assets "$TMPDIR/assets.json" '
        def asset_host:
            (.host? // .hostname? // .name? // .asset_name? // "") |
            tostring | ascii_downcase;

        ($assets[0]) as $inventory
        | . as $hosts
        | [
            $inventory[]
            | select(
                ($hosts | index(asset_host)) != null
            )
            | {
                host: (.host? // .hostname? // .name? // .asset_name? // "unknown"),
                criticality: (.criticality? // .criticality_level? // "unknown"),
                data_class: (
                    .data_class?
                    // .data_classification?
                    // .classification?
                    // "unknown"
                ),
                zone: (.zone? // .network_zone? // .security_zone? // "unknown")
            }
        ]
    ' "$TMPDIR/${suffix}_hosts.json" > "$TMPDIR/${suffix}_assets.json"

    local asset_count
    asset_count="$(jq 'length' "$TMPDIR/${suffix}_assets.json")"

    # -----------------------------------------------------------------------
    # IOC list
    #
    # Primary IOC values come from matches_ioc in the finding. If that field
    # does not exist, fall back to ioc_list in incidents.json. Confidence and
    # source are derived from available finding/incidents metadata.
    # -----------------------------------------------------------------------
    jq --slurpfile incident "$TMPDIR/${suffix}_incident.json" '
        (
            .matches_ioc
            // .ioc_matches
            // ($incident[0].ioc_list // $incident[0].matches_ioc // [])
        )
        | map(
            if type == "object" then
                {
                    type: (.type // "indicator"),
                    value: (.value // .ioc // .indicator // .ip // .domain // .hash // .account // .service_name // .port // tostring),
                    confidence: (.confidence // "unknown"),
                    source: (.source // "IOC feed")
                }
            else
                {
                    type: "indicator",
                    value: tostring,
                    confidence: "unknown",
                    source: "IOC feed"
                }
            end
        )
        | map(select(.value != "null" and .value != ""))
        | unique_by(.value)
        | .[:15]
    ' "$finding" > "$TMPDIR/${suffix}_iocs.json"

    local ioc_count
    ioc_count="$(jq 'length' "$TMPDIR/${suffix}_iocs.json")"

    # -----------------------------------------------------------------------
    # ATT&CK mapping
    #
    # Technique names are taken from finding evidence where available.
    # Otherwise retain the technique ID and use "Technique <ID>" so that no
    # incident-specific technique values are hardcoded.
    # -----------------------------------------------------------------------
    jq '
        .attack_techniques
        | map(tostring)
        | unique
        | .[:8]
        | map({
            technique: .,
            name: ("Technique " + .),
            evidence: "Recorded in investigation finding attack_techniques."
        })
    ' "$finding" > "$TMPDIR/${suffix}_techniques.json"

    local technique_count
    technique_count="$(jq 'length' "$TMPDIR/${suffix}_techniques.json")"

    # -----------------------------------------------------------------------
    # Recommended actions
    #
    # Use the finding actions as the source. The locked report allows at most
    # six numbered actions.
    # -----------------------------------------------------------------------
    jq '
        (.recommended_actions // .actions // [])
        | map(tostring)
        | map(select(length > 0))
        | .[:6]
    ' "$finding" > "$TMPDIR/${suffix}_actions.json"

    local action_count
    action_count="$(jq 'length' "$TMPDIR/${suffix}_actions.json")"

    # -----------------------------------------------------------------------
    # Evidence references
    # -----------------------------------------------------------------------
    jq '
        .event_refs
        | map(tostring)
        | unique
        | .[:12]
    ' "$finding" > "$TMPDIR/${suffix}_refs.json"

    local ref_count
    ref_count="$(jq 'length' "$TMPDIR/${suffix}_refs.json")"

    # Verify every reference against enriched_events.jsonl.
    jq --argjson refs "$(cat "$TMPDIR/${suffix}_refs.json")" '
        def eid:
            (.event_id? // .id? // .eventId?) | tostring;

        [
            .[]
            | select(($refs | index(eid)) != null)
            | eid
        ]
        | unique
    ' "$TMPDIR/events.json" > "$TMPDIR/${suffix}_verified_refs.json"

    local verified_count
    verified_count="$(jq 'length' "$TMPDIR/${suffix}_verified_refs.json")"

    if [[ "$verified_count" -ne "$ref_count" ]]; then
        echo "[report] ERROR: $suffix has event references missing from enriched_events.jsonl" >&2
        jq --argjson verified "$(cat "$TMPDIR/${suffix}_verified_refs.json")" '
            . - ($verified | map(.))
        ' "$TMPDIR/${suffix}_refs.json" >&2 || true
        exit 1
    fi

    # -----------------------------------------------------------------------
    # Detection performance
    #
    # Finding data is authoritative. Fire rules are obtained from an optional
    # detection_rules/rules_fired/rule_ids field. Missed rules are obtained
    # from explicit finding fields when present.
    # -----------------------------------------------------------------------
    jq '
        (
            .rules_fired
            // .detection_rules
            // .fired_rules
            // []
        )
        | if type == "array" then
            map(
                if type == "object" then
                    (.rule_id // .id // .name // tostring)
                else tostring
                end
            )
          elif type == "object" then
            keys
          else []
          end
        | unique
    ' "$finding" > "$TMPDIR/${suffix}_fired_rules.json"

    jq '
        (
            .rules_should_have_fired
            // .missed_rules
            // .detection_gaps
            // []
        )
        | if type == "array" then
            map(
                if type == "object" then
                    (.rule_id // .id // .name // tostring)
                else tostring
                end
            )
          elif type == "object" then
            keys
          else []
          end
        | unique
    ' "$finding" > "$TMPDIR/${suffix}_missed_rules.json"

    # -----------------------------------------------------------------------
    # Generate Markdown.
    #
    # Content is constructed in a temporary file and then all IPv4 addresses
    # are defanged over the complete report body.
    # -----------------------------------------------------------------------
    : > "$TMPDIR/${suffix}_report_raw.md"

    {
        echo "## Incident Identifier"
        echo "$incident_id"
        echo

        echo "## Executive Summary"

        # Construct 3 sentences from finding/incident metadata.
        sentence_one="$incident_id is a ${category} incident affecting $(jq -r '(.host_list // []) | join(", ")' "$TMPDIR/${suffix}_incident.json")."
        sentence_two="The investigation recorded ${confidence} confidence and identified the following working hypothesis: ${hypothesis}"
        sentence_three="The incident window spans ${first_seen} through ${last_seen}, with $(jq '.event_refs | length' "$finding") evidence references recorded in the finding."

        echo "$sentence_one $sentence_two $sentence_three"
        echo

        echo "## Timeline"
        jq -r '
            .[]
            | [
                (.timestamp? // .time? // .event_time? // .datetime? // "unknown" | tostring),
                (.host? // .hostname? // "unknown" | tostring),
                (
                    .event_description?
                    // .event_category?
                    // .description?
                    // .raw_message?
                    // .message?
                    // "event recorded"
                    | tostring
                    | gsub("[\r\n]+"; " ")
                    | .[0:240]
                )
            ]
            | join(" | ")
        ' "$TMPDIR/${suffix}_timeline.json"
        echo

        echo "## Affected Assets"
        echo "| HOST | CRITICALITY | DATA_CLASS | ZONE |"
        echo "|---|---|---|---|"
        jq -r '
            .[]
            | "| \(.host) | \(.criticality) | \(.data_class) | \(.zone) |"
        ' "$TMPDIR/${suffix}_assets.json"
        echo

        echo "## Indicators of Compromise"
        echo "| TYPE | VALUE | CONFIDENCE | SOURCE |"
        echo "|---|---|---|---|"
        jq -r '
            .[]
            | "| \(.type) | \(.value) | \(.confidence) | \(.source) |"
        ' "$TMPDIR/${suffix}_iocs.json"
        echo

        echo "## ATT&CK Mapping"
        echo "| TECHNIQUE | NAME | EVIDENCE |"
        echo "|---|---|---|"
        jq -r '
            .[]
            | "| \(.technique) | \(.name) | \(.evidence) |"
        ' "$TMPDIR/${suffix}_techniques.json"
        echo

        echo "## Detection Performance"

        jq -r '
            .[]
            | "Rule fired: " + .
        ' "$TMPDIR/${suffix}_fired_rules.json"

        jq -r '
            .[]
            | "Rule should have fired but did not: " + .
        ' "$TMPDIR/${suffix}_missed_rules.json"

        # Guarantee a useful one-line section even when the finding explicitly
        # contains no rule metadata.
        if [[ \
            "$(jq 'length' "$TMPDIR/${suffix}_fired_rules.json")" -eq 0 && \
            "$(jq 'length' "$TMPDIR/${suffix}_missed_rules.json")" -eq 0 \
        ]]; then
            echo "No rule-level detection performance records were supplied in the investigation finding."
        fi
        echo

        echo "## Recommended Actions"
        jq -r '
            to_entries[]
            | "\(.key + 1). \(.value)"
        ' "$TMPDIR/${suffix}_actions.json"

        if [[ "$action_count" -eq 0 ]]; then
            echo "1. Review the investigation finding and establish incident-specific response actions."
        fi
        echo

        echo "## Evidence References"
        jq -r '.[]' "$TMPDIR/${suffix}_refs.json"
    } > "$TMPDIR/${suffix}_report_raw.md"

    # Defang every IPv4 address in the complete report body.
    defang_ips < "$TMPDIR/${suffix}_report_raw.md" > "$output"

    [[ -s "$output" ]] || {
        echo "[report] ERROR: generated report is empty: $output" >&2
        exit 1
    }

    # -----------------------------------------------------------------------
    # Hard-cap validation.
    # -----------------------------------------------------------------------

    # Timeline: non-empty lines that are not a Markdown heading.
    local timeline_lines
    timeline_lines="$(
        awk '
            /^## Timeline$/ { in_section=1; next }
            /^## / && in_section { exit }
            in_section && NF { count++ }
            END { print count+0 }
        ' "$output"
    )"

    # Assets: table data rows, excluding header and separator.
    local asset_rows
    asset_rows="$(
        awk '
            /^## Affected Assets$/ { in_section=1; next }
            /^## / && in_section { exit }
            in_section && /^\|/ && $0 !~ /^\|---/ && $0 !~ /^\| HOST / { count++ }
            END { print count+0 }
        ' "$output"
    )"

    # IOCs: table data rows.
    local ioc_rows
    ioc_rows="$(
        awk '
            /^## Indicators of Compromise$/ { in_section=1; next }
            /^## / && in_section { exit }
            in_section && /^\|/ && $0 !~ /^\|---/ && $0 !~ /^\| TYPE / { count++ }
            END { print count+0 }
        ' "$output"
    )"

    # ATT&CK techniques: table data rows.
    local technique_rows
    technique_rows="$(
        awk '
            /^## ATT&CK Mapping$/ { in_section=1; next }
            /^## / && in_section { exit }
            in_section && /^\|/ && $0 !~ /^\|---/ && $0 !~ /^\| TECHNIQUE / { count++ }
            END { print count+0 }
        ' "$output"
    )"

    # Recommended actions: numbered lines only.
    local action_lines
    action_lines="$(
        awk '
            /^## Recommended Actions$/ { in_section=1; next }
            /^## / && in_section { exit }
            in_section && /^[0-9]+\.[[:space:]]/ { count++ }
            END { print count+0 }
        ' "$output"
    )"

    # Evidence references: one non-empty line per reference.
    local evidence_lines
    evidence_lines="$(
        awk '
            /^## Evidence References$/ { in_section=1; next }
            /^## / && in_section { exit }
            in_section && NF { count++ }
            END { print count+0 }
        ' "$output"
    )"

    # Executive summary sentence count.
    local summary_sentence_count
    summary_sentence_count="$(
        awk '
            /^## Executive Summary$/ { in_section=1; next }
            /^## / && in_section { exit }
            in_section && NF {
                text = text " " $0
            }
            END {
                n = split(text, parts, /[.!?]+[[:space:]]*/)
                count = 0
                for (i = 1; i <= n; i++) {
                    if (parts[i] ~ /[[:alnum:]]/) count++
                }
                print count+0
            }
        ' "$output"
    )"

    if [[ "$summary_sentence_count" -lt 3 || "$summary_sentence_count" -gt 5 ]]; then
        echo "[report] ERROR: $suffix Executive Summary has $summary_sentence_count sentences; cap is 3-5" >&2
        exit 1
    fi

    if [[ "$timeline_lines" -gt 15 ]]; then
        echo "[report] ERROR: $suffix timeline has $timeline_lines events; cap is 15" >&2
        exit 1
    fi

    if [[ "$asset_rows" -gt 10 ]]; then
        echo "[report] ERROR: $suffix affected assets has $asset_rows rows; cap is 10" >&2
        exit 1
    fi

    if [[ "$ioc_rows" -gt 15 ]]; then
        echo "[report] ERROR: $suffix IOC section has $ioc_rows rows; cap is 15" >&2
        exit 1
    fi

    if [[ "$technique_rows" -gt 8 ]]; then
        echo "[report] ERROR: $suffix ATT&CK mapping has $technique_rows techniques; cap is 8" >&2
        exit 1
    fi

    if [[ "$action_lines" -gt 6 ]]; then
        echo "[report] ERROR: $suffix recommended actions has $action_lines actions; cap is 6" >&2
        exit 1
    fi

    if [[ "$evidence_lines" -gt 12 ]]; then
        echo "[report] ERROR: $suffix evidence references has $evidence_lines IDs; cap is 12" >&2
        exit 1
    fi

    # Ensure no IPv4 address remains defanged incorrectly.
    if grep -Eq \
        '(^|[^0-9])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9]|$)' \
        "$output"; then
        echo "[report] ERROR: un-defanged IPv4 address found in incident_${suffix}.md" >&2
        exit 1
    fi

    echo "[report] $suffix: timeline=$timeline_lines assets=$asset_rows IOCs=$ioc_rows techniques=$technique_rows actions=$action_lines refs=$evidence_lines"
    echo "[report] $suffix: section caps respected"
}

generate_report A
generate_report B
generate_report C

# ---------------------------------------------------------------------------
# Global evidence-reference verification.
# ---------------------------------------------------------------------------
TOTAL_VERIFIED=0

for suffix in A B C; do
    refs_file="$TMPDIR/${suffix}_refs.json"

    while IFS= read -r event_id; do
        [[ -z "$event_id" ]] && continue

        if ! jq -e --arg id "$event_id" '
            any(
                .[];
                ((.event_id? // .id? // .eventId?) | tostring) == $id
            )
        ' "$TMPDIR/events.json" >/dev/null; then
            echo "[report] ERROR: event reference $event_id from $suffix not found in enriched_events.jsonl" >&2
            exit 1
        fi

        TOTAL_VERIFIED=$((TOTAL_VERIFIED + 1))
    done < <(jq -r '.[]' "$refs_file")
done

echo "[report] $TOTAL_VERIFIED event references verified against enriched_events.jsonl"
echo "[report] reports written"

exit 0
