#!/bin/bash

set -euo pipefail

DISABLED_COUNT=0

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


echo "[*] Scanning enabled services..."


mapfile -t ENABLED_SERVICES < <(
    systemctl list-unit-files \
        --type=service \
        --state=enabled \
        --no-legend \
    | awk '{print $1}'
)

BEFORE_COUNT=${#ENABLED_SERVICES[@]}

echo "    Enabled services found: $BEFORE_COUNT"

echo
echo "[*] Comparing against MedDefense whitelist (9 required services)..."

# Secure remote administration
# Required for administrator SSH access
#
# Web server hosting MedDefense application
#
# Database backend for MedDefense
#
# Host firewall
#
# Security auditing
#
# Mandatory Access Control
#
# Scheduled system maintenance
#
# Centralized logging
#
# Time synchronization
WHITELIST=(
"ssh.service"
"apache2.service"
"mysql.service"
"ufw.service"
"auditd.service"
"apparmor.service"
"cron.service"
"rsyslog.service"
"systemd-timesyncd.service"
)


is_whitelisted() {

    local service="$1"

    for allowed in "${WHITELIST[@]}"; do
        [[ "$service" == "$allowed" ]] && return 0
    done

    return 1
}


for service in "${ENABLED_SERVICES[@]}"; do

    if is_whitelisted "$service"; then
        continue
    fi

    systemctl stop "$service" 2>/dev/null || true
    systemctl disable "$service" >/dev/null 2>&1 || true

    echo "  $service     [STOPPED] [DISABLED]"

    DISABLED_COUNT=$((DISABLED_COUNT + 1))

done


for service in "${WHITELIST[@]}"; do

    systemctl enable "$service" >/dev/null 2>&1 || true
    systemctl start "$service" >/dev/null 2>&1 || true

    if systemctl is-active --quiet "$service"; then
        echo "  $service     [ACTIVE]"
    else
        echo "  $service     [FAILED]"
    fi

done


mapfile -t REMAINING_SERVICES < <(
    systemctl list-unit-files \
        --type=service \
        --state=enabled \
        --no-legend \
    | awk '{print $1}'
)

AFTER_COUNT=${#REMAINING_SERVICES[@]}

echo
echo "Before: $BEFORE_COUNT | After: $AFTER_COUNT | Disabled: $DISABLED_COUNT"
