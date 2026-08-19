#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
fi

#$1
PCAP_PATH="${1:-/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap}"

TMPDIR="/tmp/suricata-$(basename "$PCAP_PATH" .pcap)"

mkdir -p "$TMPDIR"

echo "Running Suricata against: $PCAP_PATH"
echo "Output directory: $TMPDIR"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

suricata \
	-c ./suricata.yaml \
	-r "$PCAP_PATH" \
	-l "$TMPDIR"

echo "Suricata analysis completed."

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

EVE_JSON="$TMPDIR/eve.json"
SIGNATURE_CATEGORIES="./signature_categories.json"

if [[ ! -f "$EVE_JSON" ]]; then
    echo "ERROR: $EVE_JSON not found." >&2
    exit 1
fi

if [[ ! -f "$SIGNATURE_CATEGORIES" ]]; then
    echo "ERROR: $SIGNATURE_CATEGORIES not found." >&2
    exit 1
fi

ALERTS_JSON="$TMPDIR/alerts.json"

echo "Parsing alerts..."

jq -c '
    select(.event_type == "alert") |
    {
        timestamp,
        src_ip,
        src_port,
        dst_ip: .dest_ip,
        dst_port: .dest_port,
        proto,
        signature: .alert.signature,
        signature_id: .alert.signature_id,
        category: .alert.category,
        severity: .alert.severity
    }
' "$EVE_JSON" > "$ALERTS_JSON"

total_alerts=$(wc -l < "$ALERTS_JSON")

unique_signatures=$(jq -s '
    map(.signature) |
    unique |
    length
' "$ALERTS_JSON")

echo "Total alerts:       $total_alerts"
echo "Unique signatures:  $unique_signatures"

echo "Alert count per signature:"
jq -s '
    group_by(.signature) |
    map({
        signature: .[0].signature,
        count: length
    }) |
    sort_by(-.count)
' "$ALERTS_JSON"

echo "Alert count per source IP:"
jq -s '
    group_by(.src_ip) |
    map({
        src_ip: .[0].src_ip,
        count: length
    }) |
    sort_by(-.count)
' "$ALERTS_JSON"

echo "Alert count per destination IP:"
jq -s '
    group_by(.dst_ip) |
    map({
        dst_ip: .[0].dst_ip,
        count: length
    }) |
    sort_by(-.count)
' "$ALERTS_JSON"

echo "Severity distribution:"
jq -s '
    group_by(.severity) |
    map({
        severity: .[0].severity,
        count: length
    }) |
    sort_by(.severity)
' "$ALERTS_JSON"

CLASSIFIED_ALERTS_JSON="$TMPDIR/alerts_classified.json"

#Classify each signature into one of: reconnaissance, exploit, lateral_movement, exfiltration, malware_c2, policy_violation, other using a provided signature_categories.json map shipped with the project

echo "Classifying alerts..."

jq -c --slurpfile categories "$SIGNATURE_CATEGORIES" '
    . as $alert |
    $alert + {
        classification: (
            $categories[0].signatures[($alert.signature_id | tostring)]
            // "other"
        )
    }
' "$ALERTS_JSON" > "$CLASSIFIED_ALERTS_JSON"

echo "Alert classification distribution:"

jq -s '
    group_by(.classification) |
    map({
        classification: .[0].classification,
        count: length
    }) |
    sort_by(-.count)
' "$CLASSIFIED_ALERTS_JSON"

# Emit suricata_alerts.json with pcap, started_at, finished_at, total_alerts, unique_signatures, severity_distribution, by_category, top_sources, top_destinations, alerts (full array)

OUTPUT_JSON="suricata_alerts.json"

echo "Generating $OUTPUT_JSON..."

jq -s \
    --slurpfile categories "$SIGNATURE_CATEGORIES" \
    --slurpfile alerts "$CLASSIFIED_ALERTS_JSON" \
    --arg pcap "$PCAP_PATH" \
    --arg started_at "$STARTED_AT" \
    --arg finished_at "$FINISHED_AT" \
    '
    {
        pcap: $pcap,
        started_at: $started_at,
        finished_at: $finished_at,

        total_alerts: ($alerts | length),

        unique_signatures: (
            $alerts |
            map(.signature) |
            unique |
            length
        ),

        severity_distribution: (
            $alerts |
            group_by(.severity) |
            map({
                severity: .[0].severity,
                count: length
            }) |
            sort_by(.severity)
        ),

        by_category: (
            $alerts |
            group_by(.classification) |
            map({
                category: .[0].classification,
                count: length
            }) |
            sort_by(-.count)
        ),

        top_sources: (
            $alerts |
            group_by(.src_ip) |
            map({
                src_ip: .[0].src_ip,
                count: length
            }) |
            sort_by(-.count) |
            .[0:10]
        ),

        top_destinations: (
            $alerts |
            group_by(.dst_ip) |
            map({
                dst_ip: .[0].dst_ip,
                count: length
            }) |
            sort_by(-.count) |
            .[0:10]
        ),

        alerts: $alerts
    }
    ' /dev/null > "$OUTPUT_JSON"

echo "Analysis written to $OUTPUT_JSON"

