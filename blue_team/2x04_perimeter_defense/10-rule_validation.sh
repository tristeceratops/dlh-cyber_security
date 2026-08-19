#!/bin/bash

set -euo pipefail

RULE_FILE="./meddefense.rules"
LABEL_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"
JSON_OUTPUT="./rule_validation.json"

declare -A TESTS=(
    [9000001]="MEDDEV to Internet|meddev_egress.pcap"
    [9000002]="Guest to SMB|guest_smb.pcap"
    [9000003]="Large Outbound From Server|large_outbound.pcap"
    [9000004]="DNS Tunneling Long Label|dns_tunnel.pcap"
    [9000005]="Clinical to Unauthorized DB|clinical_wrong_db.pcap"
    [9000006]="Telnet to MEDDEV|telnet_meddev.pcap"
)

if [[ ! -f "$RULE_FILE" ]]; then
    echo "ERROR: $RULE_FILE not found." >&2
    exit 1
fi

if [[ ! -d "$LABEL_DIR" ]]; then
    echo "ERROR: $LABEL_DIR not found." >&2
    exit 1
fi

rule_count=$(grep -cE 'sid:900000[1-6];' "$RULE_FILE" || true)

echo "[*] Loading meddefense.rules...          $rule_count rules"

if [[ "$rule_count" -ne 6 ]]; then
    echo "ERROR: expected 6 validation rules." >&2
    exit 1
fi

echo "[*] Validating rule syntax..."

if ! suricata -T -c ./suricata.yaml >/tmp/meddefense-rule-test.log 2>&1; then
    cat /tmp/meddefense-rule-test.log >&2
    echo "ERROR: Suricata rule validation failed." >&2
    exit 1
fi

echo "[*] Running validation against labeled PCAPs..."
echo

passed=0
failed=0
results="[]"

for sid in 9000001 9000002 9000003 9000004 9000005 9000006; do
    IFS='|' read -r name pcap <<< "${TESTS[$sid]}"

    output_dir="/tmp/meddefense-rule-$sid"
    rm -rf "$output_dir"
    mkdir -p "$output_dir"

    echo "sid $sid $name"
    echo "  target: $pcap"
    echo "  expected: fire"

    status="fail"
    hits=0

    if [[ ! -f "$LABEL_DIR/$pcap" ]]; then
        echo "  observed: PCAP NOT FOUND                  FAIL"
    elif suricata \
        -c ./suricata.yaml \
        -r "$LABEL_DIR/$pcap" \
        -l "$output_dir" >/dev/null 2>&1; then

        hits=$(jq -r \
            --arg sid "$sid" \
            'select(
                .event_type == "alert" and
                (.alert.signature_id | tostring) == $sid
            )' \
            "$output_dir/eve.json" 2>/dev/null | wc -l)

        if (( hits > 0 )); then
            status="pass"
            passed=$((passed + 1))
            echo "  observed: fire ($hits hits)                PASS"
        else
            failed=$((failed + 1))
            echo "  observed: no hits                         FAIL"
        fi
    else
        failed=$((failed + 1))
        echo "  observed: Suricata execution failed        FAIL"
    fi

    results=$(jq \
        --arg sid "$sid" \
        --arg name "$name" \
        --arg pcap "$pcap" \
        --arg status "$status" \
        --argjson hits "$hits" \
        '. + [{
            sid: ($sid | tonumber),
            name: $name,
            target: $pcap,
            expected: "fire",
            observed: $status,
            hits: $hits
        }]' <<< "$results")

    echo
done

jq -n \
    --argjson rules "$rule_count" \
    --argjson passed "$passed" \
    --argjson failed "$failed" \
    --argjson results "$results" \
    '{
        rules: $rules,
        passed: $passed,
        failed: $failed,
        results: $results
    }' > "$JSON_OUTPUT"

echo "Rules:  $((passed + failed))"
echo "Passed: $passed"
echo "Failed: $failed"
echo "JSON:   $JSON_OUTPUT"

if (( failed != 0 )); then
    exit 1
fi

