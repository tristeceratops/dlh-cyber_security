#!/bin/bash

set -euo pipefail

RULE_FILE="./meddefense.rules"
RULE_DEST="/var/lib/suricata/rules/meddefense.rules"
LABEL_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"

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

mkdir -p "$(dirname "$RULE_DEST")"
cp "$RULE_FILE" "$RULE_DEST"

rule_count=$(grep -c 'sid:900000' "$RULE_FILE" || true)

echo "[*] Loading meddefense.rules...          $rule_count rules"
echo "[*] Running validation against labeled PCAPs..."
echo

passed=0
failed=0

for sid in "${!TESTS[@]}"; do
    IFS='|' read -r name pcap <<< "${TESTS[$sid]}"

    output_dir="/tmp/meddefense-rule-$sid"
    mkdir -p "$output_dir"
    rm -f "$output_dir/eve.json"

    echo "sid $sid $name"
    echo "  target: $pcap"
    echo "  expected: fire"

    if [[ ! -f "$LABEL_DIR/$pcap" ]]; then
        echo "  observed: PCAP not found                 FAIL"
        failed=$((failed + 1))
        echo
        continue
    fi

    if ! suricata \
        -c ./suricata.yaml \
        -r "$LABEL_DIR/$pcap" \
        -l "$output_dir"; then
        echo "  observed: Suricata failed                FAIL"
        failed=$((failed + 1))
        echo
        continue
    fi

    hits=$(jq -r \
        --arg sid "$sid" \
        'select(
            .event_type == "alert" and
            (.alert.signature_id | tostring) == $sid
        )' \
        "$output_dir/eve.json" |
        wc -l)

    if (( hits > 0 )); then
        echo "  observed: fire ($hits hits)                PASS"
        passed=$((passed + 1))
    else
        echo "  observed: no hits                         FAIL"
        failed=$((failed + 1))
    fi

    echo
done

echo "Rules:  $((passed + failed))"
echo "Passed: $passed"
echo "Failed: $failed"

if (( failed > 0 )); then
    exit 1
fi

exit 0

