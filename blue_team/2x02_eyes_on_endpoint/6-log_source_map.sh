#!/bin/bash

#
# name: 6-log_source_map.sh
# purpose: Discover and assess active security-relevant Linux log sources
# author: Tristeceratops
#

set -euo pipefail

echo "[*] Discovering log sources..."

declare -a SOURCES=(
    "auth.log|/var/log/auth.log|syslog|critical"
    "syslog|/var/log/syslog|syslog|high"
    "audit.log|/var/log/audit/audit.log|audit|critical"
    "kern.log|/var/log/kern.log|syslog|medium"
    "dpkg.log|/var/log/dpkg.log|custom|medium"
    "apache2 access|/var/log/apache2/access.log|custom|high"
    "apache2 error|/var/log/apache2/error.log|custom|high"
)

printf "%-20s %-32s %-9s %-12s %-10s %s\n" \
    "Source" "Path" "Format" "Rotation" "events/hr" "Relevance"
printf "%-20s %-32s %-9s %-12s %-10s %s\n" \
    "------" "----" "------" "--------" "---------" "---------"

FOUND=0
MISSING=0

rotation() {
    local path="$1"
    local rule

    rule=$(grep -RlF "$path" /etc/logrotate.d /etc/logrotate.conf 2>/dev/null | head -n1 || true)

    if [[ -z "$rule" ]]; then
        echo "unknown"
        return
    fi

    if grep -Eq 'daily' "$rule"; then
        echo "daily"
    elif grep -Eq 'weekly' "$rule"; then
        echo "weekly"
    elif grep -Eq 'monthly' "$rule"; then
        echo "monthly"
    elif grep -Eq 'yearly' "$rule"; then
        echo "yearly"
    else
        echo "configured"
    fi
}

events_per_hour() {
    local path="$1"

    [[ -f "$path" ]] || {
        echo "0"
        return
    }

    awk -v cutoff="$(date -d '1 hour ago' '+%b %e %H:%M:%S')" '
        $0 >= cutoff { count++ }
        END { print count + 0 }
    ' "$path" 2>/dev/null
}

for entry in "${SOURCES[@]}"; do
    IFS='|' read -r name path format relevance <<< "$entry"

    if [[ -f "$path" ]]; then
        FOUND=$((FOUND + 1))
        size=$(du -h "$path" 2>/dev/null | awk '{print $1}')
        rotation_policy=$(rotation "$path")
        events=$(events_per_hour "$path")

        printf "%-20s %-32s %-9s %-12s %-10s %s\n" \
            "$name" "$path" "$format" "$rotation_policy" "$events" "$relevance"

        if [[ "$events" -eq 0 ]]; then
            echo "    [!] $name exists but is not generating events"
        fi
    else
        MISSING=$((MISSING + 1))
        echo "    [MISSING] $name: $path"
    fi
done

# Discover additional security-relevant log files.
while IFS= read -r path; do
    [[ -f "$path" ]] || continue

    known=false
    for entry in "${SOURCES[@]}"; do
        IFS='|' read -r _ known_path _ _ <<< "$entry"
        [[ "$path" == "$known_path" ]] && known=true
    done

    if [[ "$known" == false ]]; then
        size=$(du -h "$path" 2>/dev/null | awk '{print $1}')
        events=$(events_per_hour "$path")
        printf "%-20s %-32s %-9s %-12s %-10s %s\n" \
            "$(basename "$path")" "$path" "custom" "unknown" "$events" "low"
        FOUND=$((FOUND + 1))
    fi
done < <(
    find /var/log -maxdepth 2 -type f \
        \( -name "*.log" -o -name "*.log.*" \) 2>/dev/null |
    grep -Ev '\.(gz|xz|bz2)$' |
    sort -u
)

echo "Sources found: $FOUND | Missing: $MISSING"
