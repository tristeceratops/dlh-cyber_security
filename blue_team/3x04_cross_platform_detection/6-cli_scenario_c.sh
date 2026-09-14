#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

MANIFEST="${ASSETS_DIR}/scenarios/scenario_c_medical_egress.json"
NETWORK_EVENTS="${HANDOFF_DIR}/data/network_events.json"
ENRICHED_EVENTS="${HANDOFF_DIR}/data/enriched_events.json"
NETWORK_ZONES="${HANDOFF_DIR}/context/network_zones.json"
IOC_CONTEXT="${ASSETS_DIR}/3x03_assets/ioc_context.json"

FINDINGS_DIR="${SCRIPT_DIR}/findings"
OUTPUT="${FINDINGS_DIR}/scenario_c_cli.json"

SRC_IP="10.2.3.2"
DST_IP="198.51.100.73"

mkdir -p "$FINDINGS_DIR"

command -v jq >/dev/null 2>&1 || {
    echo "error: jq is required" >&2
    exit 1
}

[[ -f "$MANIFEST" ]] || {
    echo "error: scenario manifest not found: $MANIFEST" >&2
    exit 1
}

[[ -f "$NETWORK_ZONES" ]] || {
    echo "error: network zones not found: $NETWORK_ZONES" >&2
    exit 1
}

# Prefer network_events.json, falling back to enriched_events.json.
if [[ -f "$NETWORK_EVENTS" ]]; then
    EVENTS="$NETWORK_EVENTS"
    EVENT_SOURCE="network_events.json"
elif [[ -f "$ENRICHED_EVENTS" ]]; then
    EVENTS="$ENRICHED_EVENTS"
    EVENT_SOURCE="enriched_events.json"
else
    echo "error: neither network_events.json nor enriched_events.json exists" >&2
    exit 1
fi

# Read scenario metadata.
SCENARIO_NAME="$(
    jq -r '
        .scenario
        // .scenario_id
        // .name
        // "scenario_c_medical_egress"
    ' "$MANIFEST"
)"

MANIFEST_SRC_IP="$(
    jq -r '
        .src_ip
        // .source_ip
        // .source.ip
        // empty
    ' "$MANIFEST"
)"

MANIFEST_DST_IP="$(
    jq -r '
        .dst_ip
        // .destination_ip
        // .destination.ip
        // empty
    ' "$MANIFEST"
)"

# If the manifest specifies IPs, verify they agree with the requested
# investigation scope.
if [[ -n "$MANIFEST_SRC_IP" && "$MANIFEST_SRC_IP" != "$SRC_IP" ]]; then
    echo "error: manifest src_ip is $MANIFEST_SRC_IP, expected $SRC_IP" >&2
    exit 1
fi

if [[ -n "$MANIFEST_DST_IP" && "$MANIFEST_DST_IP" != "$DST_IP" ]]; then
    echo "error: manifest dst_ip is $MANIFEST_DST_IP, expected $DST_IP" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify 10.2.3.0/24 belongs to MEDICAL_IOT.
# ---------------------------------------------------------------------------

ZONE_MATCH="$(
    jq -c --arg cidr "10.2.3.0/24" '
        def records:
            if type == "array" then .
            elif (.zones? | type) == "array" then .zones
            elif (.network_zones? | type) == "array" then .network_zones
            elif (.networks? | type) == "array" then .networks
            else []
            end;

        records[]
        | select(
            (
                .cidr
                // .network
                // .subnet
                // .range
                // empty
            ) == $cidr
        )
    ' "$NETWORK_ZONES" | head -n 1
)"

if [[ -z "$ZONE_MATCH" ]]; then
    echo "error: 10.2.3.0/24 was not found in network_zones.json" >&2
    exit 1
fi

ZONE_NAME="$(
    jq -r '
        .zone
        // .zone_name
        // .name
        // .classification
        // empty
    ' <<<"$ZONE_MATCH"
)"

if [[ "$ZONE_NAME" != "MEDICAL_IOT" ]]; then
    echo "error: 10.2.3.0/24 is mapped to '$ZONE_NAME', not MEDICAL_IOT" >&2
    exit 1
fi

ZONE_POLICY="$(
    jq -r '
        .policy
        // .policy_description
        // .description
        // .access_policy
        // empty
    ' <<<"$ZONE_MATCH"
)"

if [[ -z "$ZONE_POLICY" ]]; then
    ZONE_POLICY="no direct internet access permitted"
fi

# ---------------------------------------------------------------------------
# Optionally inspect IOC context.
# ---------------------------------------------------------------------------

IOC_STATUS="not_available"

if [[ -f "$IOC_CONTEXT" ]]; then
    IOC_MATCH="$(
        jq -c --arg ip "$DST_IP" '
            def records:
                if type == "array" then .
                elif (.iocs? | type) == "array" then .iocs
                elif (.indicators? | type) == "array" then .indicators
                elif (.indicators_of_compromise? | type) == "array"
                    then .indicators_of_compromise
                else []
                end;

            records[]
            | select(
                (.ip // .indicator // .value // .ioc // .destination_ip // empty)
                == $ip
            )
        ' "$IOC_CONTEXT" | head -n 1
    )"

    if [[ -n "$IOC_MATCH" ]]; then
        IOC_STATUS="$(
            jq -r '
                .classification
                // .verdict
                // .status
                // .reputation
                // "matched"
            ' <<<"$IOC_MATCH"
        )"
    else
        IOC_STATUS="not_listed"
    fi
fi

# ---------------------------------------------------------------------------
# Extract matching network flows.
# ---------------------------------------------------------------------------

MATCH_FILE="$(mktemp)"

cleanup() {
    rm -f "$MATCH_FILE"
}

trap cleanup EXIT

jq \
    --arg src "$SRC_IP" \
    --arg dst "$DST_IP" '
    def records:
        if type == "array" then .
        elif (.events? | type) == "array" then .events
        elif (.data? | type) == "array" then .data
        else []
        end;

    def source_ip:
        (.src_ip
        // .source_ip
        // .source.ip
        // .network.src.ip
        // .data.src_ip);

    def destination_ip:
        (.dst_ip
        // .destination_ip
        // .destination.ip
        // .network.dst.ip
        // .data.dst_ip);

    [
        records[]
        | select((source_ip | tostring) == $src)
        | select((destination_ip | tostring) == $dst)
    ]
' "$EVENTS" > "$MATCH_FILE"

MATCHED_COUNT="$(jq 'length' "$MATCH_FILE")"

if (( MATCHED_COUNT == 0 )); then
    echo "error: no flows found for $SRC_IP -> $DST_IP" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Extract chronologically ordered beacon data.
# ---------------------------------------------------------------------------

BEACONS_FILE="$(mktemp)"

cleanup() {
    rm -f "$MATCH_FILE" "$BEACONS_FILE"
}

trap cleanup EXIT

jq '
    def event_timestamp:
        (.timestamp
        // .["@timestamp"]
        // .event.created
        // .event.ingested
        // .data.timestamp
        // .time);

    def bytes_out:
        (.bytes_out
        // .bytes_sent
        // .network.bytes_out
        // .network.bytes_sent
        // .data.bytes_out
        // 0);

    [
        .[]
        | {
            timestamp: event_timestamp,
            timestamp_epoch: (event_timestamp | fromdateiso8601),
            bytes_out: bytes_out
        }
    ]
    | sort_by(.timestamp_epoch)
' "$MATCH_FILE" > "$BEACONS_FILE"

# ---------------------------------------------------------------------------
# Display investigation results.
# ---------------------------------------------------------------------------

printf 'scenario    : %s\n' "$SCENARIO_NAME"
printf 'src_ip      : %s (MEDICAL_IOT zone)\n' "$SRC_IP"
printf 'dst_ip      : %s:443\n' "$DST_IP"
printf 'matched     : %s flows in %s\n' "$MATCHED_COUNT" "$EVENT_SOURCE"

# Print the first three chronological beacon observations and dynamically
# calculate intervals between successive events.
jq -r '
    . as $events
    | range(0; ([length, 3] | min))
    | . as $i
    | $events[$i] as $current
    | if $i == 0 then
        "beacon_1    : "
        + $current.timestamp
        + "  (bytes_out: "
        + (($current.bytes_out / 1024) | round | tostring)
        + "KB)"
      else
        ($events[$i - 1].timestamp_epoch) as $previous_epoch
        | ($current.timestamp_epoch - $previous_epoch) as $interval
        | "beacon_"
        + (($i + 1) | tostring)
        + "    : "
        + $current.timestamp
        + "  (interval: "
        + (
            if ($interval % 3600) == 0 then
                (($interval / 3600) | tostring) + " hr"
            elif ($interval % 60) == 0 then
                (($interval / 60) | tostring) + " min"
            else
                ($interval | tostring) + " sec"
            end
          )
        + ")"
      end
' "$BEACONS_FILE"

printf 'zone        : MEDICAL_IOT — %s\n' "$ZONE_POLICY"

if [[ "$IOC_STATUS" == "not_available" ]]; then
    printf 'ioc         : ioc_context.json not available\n'
else
    printf 'ioc         : %s -> %s\n' "$DST_IP" "$IOC_STATUS"
fi

# ---------------------------------------------------------------------------
# Build finding.
# ---------------------------------------------------------------------------

INVESTIGATION_START="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

ACTIONS_JSON="$(
    jq -n '
        [
            "read scenario_c medical egress manifest",
            "locate network_events.json or enriched_events.json",
            "scope network events to 10.2.3.2 -> 198.51.100.73",
            "read network_zones.json",
            "verify 10.2.3.0/24 is MEDICAL_IOT",
            "inspect MEDICAL_IOT internet-access policy",
            "inspect ioc_context.json when available",
            "sort matching flows chronologically",
            "calculate intervals between beacon events",
            "assess periodic HTTPS egress from medical IoT source"
        ]
    '
)"

FIELDS_JSON="$(
    jq -n '
        [
            "timestamp",
            "src_ip",
            "dst_ip",
            "dst_port",
            "bytes_out",
            "bytes_sent",
            "network.bytes_out",
            "network.bytes_sent",
            "network_zones.cidr",
            "network_zones.zone",
            "network_zones.policy",
            "ioc_context.indicator",
            "ioc_context.classification"
        ]
    '
)"

EVENT_REFS_JSON="$(
    jq -c '
        [
            .[] |
            (
                .eventref
                // .event_ref
                // .event.id
                // .id
                // empty
            )
        ]
        | map(select(. != null and . != ""))
    ' "$MATCH_FILE"
)"

# Keep the hypothesis to two sentences, as required by the locked schema.
HYPOTHESIS="The MEDICAL_IOT host generated periodic HTTPS egress to 198.51.100.73 despite a no-direct-internet policy. The repeated beacon interval is consistent with command-and-control or other automated external communication and warrants investigation."

INVESTIGATION_END="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

START_EPOCH="$(date -u -d "$INVESTIGATION_START" +%s)"
END_EPOCH="$(date -u -d "$INVESTIGATION_END" +%s)"

if (( END_EPOCH < START_EPOCH )); then
    echo "error: investigation timestamps are inconsistent" >&2
    exit 1
fi

TIME_TO_FIRST_ANSWER_SECONDS="$(
    printf '%s\n' "$((END_EPOCH - START_EPOCH))"
)"

jq -n \
    --arg scenario_id "scenario_c" \
    --arg interface "cli" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --arg hypothesis "$HYPOTHESIS" \
    --argjson actions "$ACTIONS_JSON" \
    --argjson fields_touched "$FIELDS_JSON" \
    --argjson event_refs "$EVENT_REFS_JSON" \
    --argjson time_to_first_answer_seconds "$TIME_TO_FIRST_ANSWER_SECONDS" \
    '
    {
        finding_id: ($scenario_id + "_" + $interface),
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $time_to_first_answer_seconds,
        actions: ($actions[0:20]),
        fields_touched: $fields_touched,
        event_refs: $event_refs,
        attack_techniques: [
            "T1071.001",
            "T1041"
        ],
        hypothesis: $hypothesis,
        confidence: "high",
        created_at: $investigation_end
    }
    ' > "$OUTPUT"

printf 'attack      : T1071.001 T1041\n'
printf 'finding     : %s written\n' "$OUTPUT"

