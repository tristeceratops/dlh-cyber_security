#!/bin/bash

OUTPUT_JSON="pre_patch_state.json"

get_system_info() {
    SNAPSHOT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    HOST_NAME=$(hostname)
    KERNEL_VERSION=$(uname -r)

    if [ -f /var/run/reboot-required ]; then
        REBOOT_FLAG="true"
    else
        REBOOT_FLAG="false"
    fi
}

get_package_snapshot() {
    dpkg-query -W -f='${binary:Package}\t${Version}\n' |
        jq -R -s -c '
            split("\n")[:-1]
            | map(split("\t"))
            | map({
                package: .[0],
                version: .[1]
            })
        '
}

get_service_snapshot() {
    systemctl list-units --type=service --state=active --no-legend |
        awk '{print $1}' |
        while read -r SERVICE_NAME; do
            SERVICE_INFO=$(systemctl show \
                -p ActiveState \
                -p SubState \
                -p MainPID \
                "$SERVICE_NAME")

            ACTIVE_STATE=$(echo "$SERVICE_INFO" | awk -F= '/^ActiveState=/ {print $2}')
            SUB_STATE=$(echo "$SERVICE_INFO" | awk -F= '/^SubState=/ {print $2}')
            MAIN_PID=$(echo "$SERVICE_INFO" | awk -F= '/^MainPID=/ {print $2}')

            jq -n -c \
                --arg service "$SERVICE_NAME" \
                --arg active "$ACTIVE_STATE" \
                --arg sub "$SUB_STATE" \
                --arg pid "$MAIN_PID" \
                '{
                    service: $service,
                    ActiveState: $active,
                    SubState: $sub,
                    MainPID: $pid
                }'
        } |
        jq -s -c '.'
}

get_listening_snapshot() {
    ss -tulnp | jq -R -s -c 'split("\n")[:-1]'
}

get_config_hashes() {
    dpkg-query -W -f='${Conffiles}\n' |
        awk '/ \/etc\// {print $1}' |
        while read -r CONFIG_FILE; do
            if [ -f "$CONFIG_FILE" ]; then
                CONFIG_HASH=$(sha256sum "$CONFIG_FILE" 2>/dev/null | awk '{print $1}')

                if [ -n "$CONFIG_HASH" ]; then
                    jq -n -c \
                        --arg file "$CONFIG_FILE" \
                        --arg hash "$CONFIG_HASH" \
                        '{file: $file, hash: $hash}'
                fi
            fi
        done |
        jq -s -c '.'
}

build_snapshot() {
    PACKAGE_DATA=$(get_package_snapshot)
    SERVICE_DATA=$(get_service_snapshot)
    LISTENING_DATA=$(get_listening_snapshot)
    CONFIG_DATA=$(get_config_hashes)

    jq -n \
        --arg timestamp "$SNAPSHOT_TIME" \
        --arg hostname "$HOST_NAME" \
        --arg kernel "$KERNEL_VERSION" \
        --argjson packages "${PACKAGE_DATA:-[]}" \
        --argjson services "${SERVICE_DATA:-[]}" \
        --argjson listening "${LISTENING_DATA:-[]}" \
        --argjson configs "${CONFIG_DATA:-[]}" \
        --argjson reboot "$REBOOT_FLAG" \
        '{
            timestamp: $timestamp,
            hostname: $hostname,
            kernel: $kernel,
            packages: $packages,
            services: $services,
            listening: $listening,
            conffile_hashes: $configs,
            reboot_required: $reboot
        }' > "$OUTPUT_JSON"
}

print_summary() {
    FILE_SIZE=$(du -k "$OUTPUT_JSON" | awk '{print $1}')

    echo "Snapshot: $OUTPUT_JSON"
    echo "Size: ${FILE_SIZE} KB"
    echo "Kernel: $KERNEL_VERSION"
    echo "Reboot required: $REBOOT_FLAG"
}

get_system_info
build_snapshot
print_summary

