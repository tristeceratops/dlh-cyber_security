#!/bin/bash

# Exit codes: 0 success, 1 controlled failure, 2 environment error.

set -o pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$BASE_DIR/capstone/network"
SUMMARY_FILE="$NETWORK_DIR/network_deploy.json"
LOG_FILE="$NETWORK_DIR/network_deploy.log"

# for hawthorne-app-01 Hawthorne
SEGMENTATION_FILE="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json"
PCAP_DIR="/home/analyst/MedDefense_Lab/capstone/PCAPs"
DNS_BLOCKLIST="/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt"

PIPELINE_SCRIPT="${NETWORK_PIPELINE_SCRIPT:-$BASE_DIR/6-patch_pipeline.sh}"
FIREWALL_SCRIPT="${FIREWALL_VALIDATION_SCRIPT:-$BASE_DIR/5-firewall_test.sh}"
CUSTOM_RULE_SCRIPT="${CUSTOM_RULE_VALIDATION_SCRIPT:-$BASE_DIR/15-custom_rule_validation.sh}"

DNSMASQ_CONFIG="/etc/dnsmasq.d/meddefense-capstone.conf"
status=0

fail_control() {
    printf 'error=%s\n' "$1" >&2
    status=1
}

fail_environment() {
    printf 'error=%s\n' "$1" >&2
    exit 2
}

for command in jq find suricata dnsmasq systemctl cmp install mktemp; do
    command -v "$command" >/dev/null 2>&1 ||
        fail_environment "missing dependency: $command"
done

[[ "$EUID" -eq 0 ]] ||
    fail_environment "script must run as root"

[[ -r "$SEGMENTATION_FILE" ]] ||
    fail_environment "missing input file: $SEGMENTATION_FILE"

[[ -r "$DNS_BLOCKLIST" ]] ||
    fail_environment "missing input file: $DNS_BLOCKLIST"

[[ -d "$PCAP_DIR" ]] ||
    fail_environment "missing input directory: $PCAP_DIR"

for script in "$PIPELINE_SCRIPT" "$FIREWALL_SCRIPT" "$CUSTOM_RULE_SCRIPT"; do
    [[ -f "$script" ]] ||
        fail_environment "missing script: $script"
done

jq empty "$SEGMENTATION_FILE" >/dev/null 2>&1 ||
    fail_environment "invalid segmentation file: $SEGMENTATION_FILE"

mkdir -p "$NETWORK_DIR" "$NETWORK_DIR/suricata" ||
    fail_environment "unable to create network artifact directory"

cp "$SEGMENTATION_FILE" "$NETWORK_DIR/segmentation_rules.json" ||
    fail_environment "unable to copy segmentation rules"

printf 'network_deploy_start=%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$LOG_FILE" ||
    fail_environment "unable to create log file"

CAPSTONE_ARTIFACTS_DIR="$NETWORK_DIR" \
SEGMENTATION_FILE="$NETWORK_DIR/segmentation_rules.json" \
"$PIPELINE_SCRIPT" >> "$LOG_FILE" 2>&1
pipeline_exit_code=$?

if [[ "$pipeline_exit_code" -ne 0 ]]; then
    fail_control "network pipeline failed"
fi

"$FIREWALL_SCRIPT" \
    "$NETWORK_DIR/segmentation_rules.json" >> "$LOG_FILE" 2>&1
firewall_exit_code=$?

if [[ "$firewall_exit_code" -ne 0 ]]; then
    fail_control "firewall validation failed"
fi

if [[ "$firewall_exit_code" -eq 0 ]]; then
    pcap_count=0
    suricata_failures=0
    SURICATA_ALERTS="$NETWORK_DIR/suricata_alerts.json"

    printf '[]\n' > "$SURICATA_ALERTS" ||
        fail_environment "unable to create Suricata alerts file"

    while IFS= read -r -d '' pcap; do
        pcap_count=$((pcap_count + 1))
        name="$(basename "$pcap")"
        stem="${name%.*}"
        output="$NETWORK_DIR/suricata/$stem"

        mkdir -p "$output" || {
            fail_control "unable to create Suricata output directory"
            suricata_failures=$((suricata_failures + 1))
            continue
        }

        if ! suricata -r "$pcap" -l "$output" >> "$LOG_FILE" 2>&1; then
            fail_control "Suricata replay failed: $pcap"
            suricata_failures=$((suricata_failures + 1))
            continue
        fi

        [[ -f "$output/eve.json" ]] || {
            fail_control "missing Suricata alerts: $pcap"
            suricata_failures=$((suricata_failures + 1))
            continue
        }

        if ! jq -c \
            --slurpfile existing "$SURICATA_ALERTS" \
            '$existing[0] + [inputs | select(.event_type == "alert")]' \
            "$output/eve.json" > "$SURICATA_ALERTS.tmp"; then
            fail_control "unable to parse Suricata alerts: $pcap"
            suricata_failures=$((suricata_failures + 1))
            rm -f "$SURICATA_ALERTS.tmp"
            continue
        fi

        mv "$SURICATA_ALERTS.tmp" "$SURICATA_ALERTS" || {
            fail_control "unable to persist Suricata alerts: $pcap"
            suricata_failures=$((suricata_failures + 1))
            continue
        }

        cp "$output/eve.json" \
            "$NETWORK_DIR/${stem}_alerts.json" || {
            fail_control "unable to persist alerts: $pcap"
            suricata_failures=$((suricata_failures + 1))
        }
    done < <(
        find "$PCAP_DIR" -type f \
            \( -iname '*.pcap' -o -iname '*.pcapng' \) \
            -print0 | sort -z
    )


    [[ "$pcap_count" -gt 0 ]] ||
        fail_environment "no PCAP files found in $PCAP_DIR"

    [[ "$suricata_failures" -eq 0 ]] || status=1

    "$CUSTOM_RULE_SCRIPT" \
        "$PCAP_DIR" "$NETWORK_DIR" >> "$LOG_FILE" 2>&1
    custom_rule_exit_code=$?

    if [[ "$custom_rule_exit_code" -ne 0 ]]; then
        fail_control "custom rule validation failed"
    fi

    dnsmasq_tmp="$(mktemp)" ||
        fail_environment "unable to create temporary dnsmasq configuration"

    trap 'rm -f "$dnsmasq_tmp"' EXIT

	# apply DNS filter

    {
        printf '%s\n' "# Managed by 7-network_deploy.sh"
        while IFS= read -r domain; do
            domain="${domain#"${domain%%[![:space:]]*}"}"
            domain="${domain%"${domain##*[![:space:]]}"}"
            [[ -z "$domain" || "${domain:0:1}" == "#" ]] && continue
            printf 'address=/%s/#\n' "$domain"
        done < "$DNS_BLOCKLIST"
    } > "$dnsmasq_tmp" ||
        fail_environment "unable to generate dnsmasq configuration"

    if [[ ! -f "$DNSMASQ_CONFIG" ]] ||
        ! cmp -s "$dnsmasq_tmp" "$DNSMASQ_CONFIG"; then
        install -m 0644 "$dnsmasq_tmp" "$DNSMASQ_CONFIG" ||
            fail_environment "unable to install dnsmasq configuration"
    fi

    rm -f "$dnsmasq_tmp"
    trap - EXIT

    dnsmasq --test >/dev/null 2>&1 ||
        fail_control "dnsmasq configuration validation failed"

    if systemctl is-active --quiet dnsmasq; then
        systemctl reload dnsmasq >/dev/null 2>&1 ||
            fail_control "unable to reload dnsmasq"
    else
        systemctl enable --now dnsmasq >/dev/null 2>&1 ||
            fail_control "unable to start dnsmasq"
    fi

    systemctl is-active --quiet dnsmasq ||
        fail_control "dnsmasq is not active"
else
    custom_rule_exit_code=1
    fail_control "network validation stopped after firewall failure"
fi

artifact_json='[]'

while IFS= read -r artifact; do
    relative_path="${artifact#"$BASE_DIR"/}"
    artifact_json="$(
        jq -c --arg path "$relative_path" '. + [$path]' \
            <<< "$artifact_json"
    )" || fail_control "unable to record artifact"
done < <(
    find "$NETWORK_DIR" -type f \
        ! -name 'network_deploy.json' -print | sort
)

# for labeled PCAPs
jq -n \
    --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg pipeline "$PIPELINE_SCRIPT" \
    --arg firewall "$FIREWALL_SCRIPT" \
    --arg custom_rules "$CUSTOM_RULE_SCRIPT" \
    --arg segmentation "$NETWORK_DIR/segmentation_rules.json" \
    --arg pcap_dir "$PCAP_DIR" \
    --arg blocklist "$DNS_BLOCKLIST" \
    --arg dnsmasq "$DNSMASQ_CONFIG" \
    --argjson pipeline_exit_code "$pipeline_exit_code" \
    --argjson firewall_exit_code "$firewall_exit_code" \
    --argjson custom_rule_exit_code "${custom_rule_exit_code:-1}" \
    --argjson artifacts "$artifact_json" \
    '{
        timestamp: $timestamp,
        pipeline: $pipeline,
        firewall_validation: $firewall,
        custom_rule_validation: $custom_rules,
        segmentation_file: $segmentation,
        pcap_directory: $pcap_dir,
        dns_blocklist: $blocklist,
        dnsmasq_config: $dnsmasq,
        pipeline_exit_code: $pipeline_exit_code,
        firewall_exit_code: $firewall_exit_code,
        custom_rule_exit_code: $custom_rule_exit_code,
        artifacts: $artifacts
    }' > "$SUMMARY_FILE" ||
    fail_environment "unable to create summary"

if [[ "$pipeline_exit_code" -eq 0 &&
    "$firewall_exit_code" -eq 0 &&
    "$custom_rule_exit_code" -eq 0 &&
    "$status" -eq 0 ]]; then
    exit 0
fi

exit 1