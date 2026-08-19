#!/bin/bash

set -euo pipefail

CONFIG_FILE="./suricata.yaml"
RULE_FILE="./meddefense.rules"
LABEL_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"
RESULT_FILE="./rule_validation.json"

declare -A TESTS=(
    [9000001]="MEDDEV to Internet|meddev_egress.pcap"
    [9000002]="Guest to SMB|guest_smb.pcap"
    [9000003]="Large Outbound From Server|large_outbound.pcap"
    [9000004]="DNS Tunneling Long Label|dns_tunnel.pcap"
    [9000005]="Clinical to Unauthorized DB|clinical_wrong_db.pcap"
    [9000006]="Telnet to MEDDEV|telnet_meddev.pcap"
)

[[ $EUID -eq 0 ]] || {
    echo "ERROR: run as root." >&2
    exit 1
}

[[ -f "$RULE_FILE" ]] || {
    echo "ERROR: $RULE_FILE not found." >&2
    exit 1
}

[[ -f "$CONFIG_FILE" ]] || {
    echo "ERROR: $CONFIG_FILE not found." >&2
    exit 1
}

[[ -d "$LABEL_DIR" ]] || {
    echo "ERROR: $LABEL_DIR not found." >&2
    exit 1
}

rule_count=$(grep -cE '^[[:space:]]*alert .*sid:900000[1-7];' "$RULE_FILE" || true)

echo "[*] Loading meddefense.rules...          $rule_count rules"

echo "[*] Validating rule syntax..."
if ! suricata -T -c "$CONFIG_FILE" >/dev/null 2>&1; then
    echo "ERROR: Suricata configuration/rules failed validation." >&2
    exit 1
fi

echo "[*] Running validation against labeled PCAPs..."
echo

results_file="/tmp/rule-validation-results.jsonl"
: > "$results_file"

passed=0
failed=0

for sid in 9000001 9000002 9000003 9000004 9000005 9000006; do
    IFS='|' read -r name pcap <<< "${TESTS[$sid]}"

    output_dir="/tmp/meddefense-rule-$sid"
    rm -rf "$output_dir"
    mkdir -p "$output_dir"

    echo "sid $sid $name"
    echo "  target: $pcap"
    echo "  expected: fire"

    if [[ ! -f "$LABEL_DIR/$pcap" ]]; then
        echo "  observed: PCAP NOT FOUND                FAIL"

        jq -n \
            --arg sid "$sid" \
            --arg name "$name" \
            --arg pcap "$pcap" \
            '{
                sid: ($sid | tonumber),
                name: $name,
                target: $pcap,
                expected: "fire",
                observed: "pcap_not_found",
                hits: 0,
                passed: false
            }' >> "$results_file"

        failed=$((failed + 1))
        echo
        continue
    fi

    if ! suricata \
        -c "$CONFIG_FILE" \
        -r "$LABEL_DIR/$pcap" \
        -l "$output_dir" \
        >/dev/null 2>&1; then

        echo "  observed: Suricata execution failed    FAIL"

        jq -n \
            --arg sid "$sid" \
            --arg name "$name" \
            --arg pcap "$pcap" \
            '{
                sid: ($sid | tonumber),
                name: $name,
                target: $pcap,
                expected: "fire",
                observed: "suricata_failed",
                hits: 0,
                passed: false
            }' >> "$results_file"

        failed=$((failed + 1))
        echo
        continue
    fi

    hits=$(jq -s \
        --arg sid "$sid" \
        'map(select(
            .event_type == "alert" and
            ((.alert.signature_id | tostring) == $sid)
        )) | length' \
        "$output_dir/eve.json")

    if (( hits > 0 )); then
        echo "  observed: fire ($hits hits)                PASS"
        passed=$((passed + 1))
        result=true
        observed="fire"
    else
        echo "  observed: no hits                         FAIL"
        failed=$((failed + 1))
        result=false
        observed="no_hits"
    fi

    jq -n \
        --arg sid "$sid" \
        --arg name "$name" \
        --arg pcap "$pcap" \
        --arg observed "$observed" \
        --argjson hits "$hits" \
        --argjson passed "$result" \
        '{
            sid: ($sid | tonumber),
            name: $name,
            target: $pcap,
            expected: "fire",
            observed: $observed,
            hits: $hits,
            passed: $passed
        }' >> "$results_file"

    echo
done

overall_passed=false
if (( failed == 0 )); then
    overall_passed=true
fi

jq -s \
    --argjson rule_count "$rule_count" \
    --argjson passed "$passed" \
    --argjson failed "$failed" \
    --argjson overall_passed "$overall_passed" \
    '{
        rules: $rule_count,
        tests: length,
        passed: $passed,
        failed: $failed,
        overall_passed: $overall_passed,
        results: .
    }' \
    "$results_file" > "$RESULT_FILE"

rm -f "$results_file"

echo "Rules:  6"
echo "Passed: $passed"
echo "Failed: $failed"
echo "Result: $RESULT_FILE"

if (( failed != 0 )); then
    exit 1
fi

