#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root." >&2
	exit 1
fi

if ! command -v suricata >/dev/null 2>&1; then
	echo "Suricata not found, installing..."
	apt-get update
	apt-get install -y suricata
fi

if ! command -v jq >/dev/null 2>&1; then
	echo "jq not found, installing..."
	apt-get update
	apt-get install -y jq
fi

RULES_SRC="/home/analyst/MedDefense_Lab/suricata/rules"
RULES_DIR="/var/lib/suricata/rules"
MEDDEFENSE_RULES="$RULES_DIR/meddefense.rules"

echo "Copying Suricata rules..."

mkdir -p "$RULES_DIR"
cp -a "$RULES_SRC"/. "$RULES_DIR"/

src_count=$(find "$RULES_SRC" -type f | wc -l)
dst_count=$(find "$RULES_DIR" -type f ! -name 'meddefense.rules' | wc -l)

echo "Source rule files:      $src_count"
echo "Destination rule files: $dst_count"

if [[ ! -f "$MEDDEFENSE_RULES" ]]; then
    echo "meddefense.rules not found, creating placeholder..."
    touch "$MEDDEFENSE_RULES"
fi

if [[ "$src_count" -ne "$dst_count" ]]; then
    echo "ERROR: Rule file count mismatch." >&2
    exit 1
fi

echo "Rule file count verified."

CONFIG_FILE="suricata.yaml"

echo "Generating $CONFIG_FILE..."

{
    cat <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.10.0.0/16]"
    EXTERNAL_NET: "!\$HOME_NET"

default-rule-path: $RULES_DIR

rule-files:
EOF
#fileinfo does not work on older version, change to files
    find "$RULES_DIR" -maxdepth 1 -type f -name '*.rules' -printf '  - %f\n' | sort

    cat <<EOF
  - meddefense.rules

default-log-dir: /var/log/suricata

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files

pcap-file:
  enabled: yes
EOF
} > "$CONFIG_FILE"

echo "Created $CONFIG_FILE"

echo "Validating Suricata configuration..."

config_test_exit=0

config_test_output=$(suricata -T -c "$CONFIG_FILE" -v 2>&1) || config_test_exit=$?

echo "$config_test_output"

if [[ "$config_test_exit" -ne 0 ]]; then
    echo "ERROR: Suricata configuration validation failed." >&2
    exit 1
fi

rule_count=$(echo "$config_test_output" \
    | grep -oE '[0-9]+ rules successfully loaded' \
    | awk '{print $1}' \
    | tail -n 1)

if [[ -z "$rule_count" ]]; then
    echo "ERROR: Could not determine loaded rule count." >&2
    exit 1
fi

echo "Suricata configuration validated successfully."
echo "Rules loaded: $rule_count"

echo "Running Suricata smoke test..."

SMOKE_PCAP="/home/analyst/MedDefense_Lab/PCAPs/smoke.pcap"
SMOKE_LOG_DIR="/tmp/suricata-smoke"
SMOKE_EVE="$SMOKE_LOG_DIR/eve.json"

mkdir -p "$SMOKE_LOG_DIR"

# not run suricata.service

suricata \
    -c "$CONFIG_FILE" \
    -r "$SMOKE_PCAP" \
    -l "$SMOKE_LOG_DIR"

if [[ ! -f "$SMOKE_EVE" ]]; then
    echo "ERROR: eve.json was not created." >&2
    exit 1
fi

alert_count=$(jq -c 'select(.event_type == "alert")' "$SMOKE_EVE" | wc -l)

if [[ "$alert_count" -lt 1 ]]; then
    echo "ERROR: No alert records found in eve.json." >&2
    exit 1
fi

echo "Smoke test passed: $alert_count alert record(s) found in eve.json."

VERIFICATION_FILE="setup_verification.json"

installed_version=$(suricata --build-info | head -n 1 | sed 's/^This is Suricata version //')

rule_files_loaded=$(find "$RULES_DIR" -maxdepth 1 -type f -name '*.rules' ! -name 'meddefense.rules' | wc -l)

jq -n \
    --arg installed_version "$installed_version" \
    --argjson rule_files_loaded "$rule_files_loaded" \
    --argjson rule_count "$rule_count" \
    --argjson config_test_exit "$config_test_exit" \
    --arg smoke_pcap "$SMOKE_PCAP" \
    --argjson smoke_alerts "$alert_count" \
    '{
        installed_version: $installed_version,
        rule_files_loaded: $rule_files_loaded,
        rule_count: $rule_count,
        config_test_exit: $config_test_exit,
        smoke_pcap: $smoke_pcap,
        smoke_alerts: $smoke_alerts
    }' > "$VERIFICATION_FILE"

echo "Setup verification written to $VERIFICATION_FILE"


