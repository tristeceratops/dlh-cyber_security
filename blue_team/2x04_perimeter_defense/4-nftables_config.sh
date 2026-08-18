#!/bin/bash

set -euo pipefail

SEGMENTATION_FILE="segmentation_rules.json"
OUTPUT_NFT="nftables.conf"
LOG_PREFIX="nft-meddefense"

BACKUP_DIR="/var/backups"
TIMESTAMP=$(date '+%Y%m%d%H%M%S')

# pattern /var/backups/nftables-rollback-<timestamp>.nft
ROLLBACK="$BACKUP_DIR/nftables-rollback-$TIMESTAMP.nft"
PRECHANGE_JSON="nftables_prechange.json"
POSTCHANGE_JSON="nftables_postchange.json"

if [[ ! -f "$SEGMENTATION_FILE" ]]; then
    echo "Error: $SEGMENTATION_FILE not found." >&2
    exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
    echo "Error: nft is not installed." >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is not installed." >&2
    exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "Error: ip is not installed." >&2
    exit 1
fi

jq -e '
    (.zones | length == 4) and
    ([.zones[].name] | sort == ["DMZ", "INTERNAL", "MEDDEV", "MGMT"]) and
    (.flows | type == "array")
' "$SEGMENTATION_FILE" >/dev/null

ip_set_for_zone() {
    local zone="$1"

    case "$zone" in
        DMZ)
            printf '%s\n' "dmz_net"
            ;;
        INTERNAL)
            printf '%s\n' "internal_net"
            ;;
        MGMT)
            printf '%s\n' "mgmt_net"
            ;;
        MEDDEV)
            printf '%s\n' "meddev_net"
            ;;
        *)
            echo "Unknown zone: $zone" >&2
            return 1
            ;;
    esac
}

LOCAL_ZONES=()

while IFS=$'\t' read -r zone cidr; do
    network="${cidr%/*}"
    prefix="${cidr#*/}"

    IFS=. read -r n1 n2 n3 n4 <<< "$network"
    network_int=$((n1 * 16777216 + n2 * 65536 + n3 * 256 + n4))

    if [[ "$prefix" -eq 0 ]]; then
        mask=0
    else
        mask=$((0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF))
    fi

    while IFS= read -r local_ip; do
        IFS=. read -r a b c d <<< "$local_ip"
        ip_int=$((a * 16777216 + b * 65536 + c * 256 + d))

        if [[ $((ip_int & mask)) -eq $((network_int & mask)) ]]; then
            if [[ ! " ${LOCAL_ZONES[*]} " =~ [[:space:]]${zone}[[:space:]] ]]; then
                LOCAL_ZONES+=("$zone")
            fi
        fi
    done < <(
        ip -4 -o addr show scope global |
        awk '{split($4, a, "/"); print a[1]}'
    )
done < <(
    jq -r '.zones[] | [.name, .cidr] | @tsv' "$SEGMENTATION_FILE"
)

if [[ "${#LOCAL_ZONES[@]}" -eq 0 ]]; then
    echo "Error: could not determine any local zone." >&2
    exit 1
fi

echo "Detected local zones: ${LOCAL_ZONES[*]}"
echo "Available zones from segmentation: DMZ, INTERNAL, MGMT, MEDDEV"

mkdir -p "$BACKUP_DIR"

echo "Capturing current nftables state..."

nft -j list ruleset > "$PRECHANGE_JSON"

nft list ruleset > "$ROLLBACK"

echo "Rollback saved to: $ROLLBACK"
echo "Pre-change state saved to: $PRECHANGE_JSON"

{
    echo '#!/usr/sbin/nft -f'
    if nft list table inet meddefense >/dev/null 2>&1; then
        echo 'flush table inet meddefense'
    fi
    echo ''
    echo 'table inet meddefense {'

    for zone in DMZ INTERNAL MGMT MEDDEV; do
        cidr=$(jq -r --arg zone "$zone" '
            .zones[]
            | select(.name == $zone)
            | .cidr
        ' "$SEGMENTATION_FILE")

        set_name=$(ip_set_for_zone "$zone")

        echo "    set $set_name {"
        echo "        type ipv4_addr"
        echo "        flags interval"
        echo "        elements = { $cidr }"
        echo "    }"
        echo ''
    done

    echo '    chain input {'
    echo '        type filter hook input priority filter; policy drop;'
    echo '        ct state established,related accept'
    echo '        iifname "lo" accept'
    echo '        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept'
    echo '        ip6 nexthdr icmpv6 accept'

    for local_zone in "${LOCAL_ZONES[@]}"; do
        jq -c --arg local_zone "$local_zone" '
            .flows[]
            | select(.action == "allow" and .dst_zone == $local_zone)
        ' "$SEGMENTATION_FILE" |
        while IFS= read -r flow; do
            src_zone=$(jq -r '.src_zone' <<< "$flow")
            proto=$(jq -r '.proto' <<< "$flow")
            dport=$(jq -r '.dport // empty' <<< "$flow")
            justification=$(jq -r '.justification' <<< "$flow")

            rule="        "

            if [[ "$src_zone" != "ALL" ]]; then
                src_set=$(ip_set_for_zone "$src_zone")
                rule+="ip saddr @$src_set "
            fi

            if [[ "$proto" == "any" ]]; then
                rule+="accept"
            else
                rule+="$proto dport $dport accept"
            fi

            rule+=" comment \"$justification\""

            echo "$rule"
        done
    done

    echo '        log prefix "nft-meddefense-input-drop: " flags all'
    echo '        drop'
    echo '    }'
    echo ''

    echo '    chain forward {'
    echo '        type filter hook forward priority filter; policy drop;'
    echo '        ct state established,related accept'

    jq -c '
        .flows[]
        | select(.action == "allow" and .src_zone != .dst_zone)
    ' "$SEGMENTATION_FILE" |
    while IFS= read -r flow; do
        src_zone=$(jq -r '.src_zone' <<< "$flow")
        dst_zone=$(jq -r '.dst_zone' <<< "$flow")
        proto=$(jq -r '.proto' <<< "$flow")
        dport=$(jq -r '.dport // empty' <<< "$flow")
        justification=$(jq -r '.justification' <<< "$flow")

        rule="        "

        if [[ "$src_zone" != "ALL" ]]; then
            src_set=$(ip_set_for_zone "$src_zone")
            rule+="ip saddr @$src_set "
        fi

        dst_set=$(ip_set_for_zone "$dst_zone")
        rule+="ip daddr @$dst_set "

        if [[ "$proto" == "any" ]]; then
            rule+="accept"
        else
            rule+="$proto dport $dport accept"
        fi

        rule+=" comment \"$justification\""

        echo "$rule"
    done

    jq -c '
        .flows[]
        | select(.action == "deny_all")
    ' "$SEGMENTATION_FILE" |
    while IFS= read -r flow; do
        src_zone=$(jq -r '.src_zone' <<< "$flow")
        dst_zone=$(jq -r '.dst_zone' <<< "$flow")
        justification=$(jq -r '.justification' <<< "$flow")

        src_set=$(ip_set_for_zone "$src_zone")
        dst_set=$(ip_set_for_zone "$dst_zone")

        echo "        ip saddr @$src_set ip daddr @$dst_set log prefix \"${LOG_PREFIX}-deny-${src_zone}-${dst_zone}: \" flags all drop comment \"$justification\""
    done

    echo '        log prefix "nft-meddefense-forward-drop: " flags all'
    echo '        drop'
    echo '    }'
    echo ''

    echo '    chain output {'
    echo '        type filter hook output priority filter; policy accept;'
    echo '        ct state established,related accept'
    echo '        oifname "lo" accept'

    for local_zone in "${LOCAL_ZONES[@]}"; do
        local_set=$(ip_set_for_zone "$local_zone")

        jq -r --arg local_zone "$local_zone" '
            .zones[]
            | select(.name == $local_zone)
            | .default_outbound.restrictions[]
        ' "$SEGMENTATION_FILE" |
        while IFS= read -r restriction; do
            case "$restriction" in
                no_mgmt_access)
                    echo "        ip saddr @$local_set ip daddr @mgmt_net log prefix \"${LOG_PREFIX}-output-drop: \" flags all drop"
                    ;;
                no_meddev_access)
                    echo "        ip saddr @$local_set ip daddr @meddev_net log prefix \"${LOG_PREFIX}-output-drop: \" flags all drop"
                    ;;
                no_dmz_access)
                    echo "        ip saddr @$local_set ip daddr @dmz_net log prefix \"${LOG_PREFIX}-output-drop: \" flags all drop"
                    ;;
                no_public_internet_access)
                    echo "        ip saddr @$local_set ip daddr != @dmz_net ip daddr != @internal_net ip daddr != @mgmt_net ip daddr != @meddev_net log prefix \"${LOG_PREFIX}-output-drop: \" flags all drop"
                    ;;
                *)
                    echo "Error: unknown outbound restriction '$restriction'." >&2
                    exit 1
                    ;;
            esac
        done
    done

    echo '    }'
    echo '}'
} > "$OUTPUT_NFT"

echo "Generated: $OUTPUT_NFT"
echo "Validating ruleset syntax with nft -c -f..."

if NFT_CHECK_OUTPUT=$(nft -c -f "$OUTPUT_NFT" 2>&1); then
    echo "$NFT_CHECK_OUTPUT"
    echo "Syntax validation passed."
else
    NFT_CHECK_STATUS=$?
    echo "$NFT_CHECK_OUTPUT" >&2
    echo "Error: nftables syntax validation failed. Aborting." >&2
    exit "$NFT_CHECK_STATUS"
fi


EXPECTED_INPUT_RULES=$(
    jq --argjson local_zones "$(printf '%s\n' "${LOCAL_ZONES[@]}" | jq -R . | jq -s .)" '
        4 + (
            [.flows[]
             | select(
                 .action == "allow"
                 and (.dst_zone as $dst | $local_zones | index($dst) != null)
             )
            ] | length
        ) + 2
    ' "$SEGMENTATION_FILE"
)

EXPECTED_FORWARD_RULES=$(
    jq '
        1 +
        ([.flows[] | select(.action == "allow" and .src_zone != .dst_zone)] | length) +
        ([.flows[] | select(.action == "deny_all")] | length) +
        2
    ' "$SEGMENTATION_FILE"
)

EXPECTED_OUTPUT_RULES=$(
    jq --argjson local_zones "$(printf '%s\n' "${LOCAL_ZONES[@]}" | jq -R . | jq -s .)" '
        2 + (
            [
                .zones[]
                | select(.name as $name | $local_zones | index($name) != null)
                | .default_outbound.restrictions[]
            ] | length
        )
    ' "$SEGMENTATION_FILE"
)

EXPECTED_RULES=$((EXPECTED_INPUT_RULES + EXPECTED_FORWARD_RULES + EXPECTED_OUTPUT_RULES))

echo "Expected nftables rules: $EXPECTED_RULES"

echo "Applying nftables ruleset..."

if ! nft -f "$OUTPUT_NFT"; then
    echo "Error: nftables ruleset application failed." >&2
    echo "Rollback remains available at: $ROLLBACK" >&2
    exit 1
fi

echo "Ruleset applied."

echo "Verifying loaded ruleset..."

nft -j list table inet meddefense > "$POSTCHANGE_JSON"

ACTUAL_RULES=$(jq '
    [
        .nftables[]
        | select(.rule != null)
    ] | length
' "$POSTCHANGE_JSON")

echo "Expected rules: $EXPECTED_RULES"
echo "Actual rules:   $ACTUAL_RULES"

if [[ "$ACTUAL_RULES" -ne "$EXPECTED_RULES" ]]; then
    echo "Error: loaded rule count does not match expected rule count." >&2
    echo "Rollback available at: $ROLLBACK" >&2
    exit 1
fi

echo "Rule count verification passed."
echo "Post-change state saved to: $POSTCHANGE_JSON"
echo "nftables configuration successfully applied."

