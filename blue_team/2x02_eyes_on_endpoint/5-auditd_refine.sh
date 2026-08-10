#!/bin/bash
#
# name: 5-auditd_refine.sh
# purpose: Add and validate detection-focused auditd rules
# author: Tristeceratops
#

set -euo pipefail

RULE_FILE="/etc/audit/rules.d/99-refine.rules"
PASS=0
ADDED=0

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo ./5-auditd_refine.sh"
    exit 1
fi

CURRENT=$(auditctl -l 2>/dev/null | wc -l)
echo "[*] Current auditd rules: $CURRENT"
echo "[*] Adding detection-focused rules..."

rule_exists() {
    local rule="$1"

    grep -RqsF -- "$rule" /etc/audit/rules.d/*.rules 2>/dev/null ||
        auditctl -l 2>/dev/null | grep -qsF -- "$rule"
}

add_rule() {
    local name="$1"
    local rule="$2"

    if rule_exists "$rule"; then
        printf "    %-38s [EXISTS]\n" "$name"
    else
        echo "$rule" >> "$RULE_FILE"
        printf "    %-38s [ADDED]\n" "$name"
        ADDED=$((ADDED + 1))
    fi
}

touch "$RULE_FILE"

add_rule "execve syscall tracking" \
    "-a always,exit -F arch=b64 -S execve -k process_exec"

add_rule "socket/connect syscall tracking" \
    "-a always,exit -F arch=b64 -S socket -S connect -k network_connect"

add_rule "SSH key file monitoring" \
    "-w /home/analyst/.ssh/ -p rwa -k ssh_keys"

add_rule "Cron directory monitoring" \
    "-w /etc/cron.d/ -p wa -k cron_persist"

add_rule "Cron spool monitoring" \
    "-w /var/spool/cron/ -p wa -k cron_persist"

add_rule "sudoers.d monitoring" \
    "-w /etc/sudoers.d/ -p wa -k sudoers"

echo "[*] Loading rules..."

if OUTPUT=$(augenrules --load 2>&1); then
    echo "[*] Loading rules... augenrules --load: OK"
else
    echo "$OUTPUT"
    echo "[*] Loading rules... augenrules --load: FAILED"
    exit 1
fi

TOTAL=$(auditctl -l 2>/dev/null | wc -l)
echo "[*] Total rules: $TOTAL"

echo "[*] Validating new rules..."

check_rule() {
    local name="$1"
    local key="$2"
    local action="$3"

    local before
    before=$(date '+%H:%M:%S')

    eval "$action" >/dev/null 2>&1 || true
    sleep 1

    if ausearch -k "$key" -ts "$before" 2>/dev/null | grep -q "$key"; then
        echo "    $name -> ausearch -k $key    [CAPTURED]"
        PASS=$((PASS + 1))
    else
        echo "    $name -> ausearch -k $key    [MISSED]"
    fi
}

check_rule "execve: ran /usr/bin/id" \
    "process_exec" \
    "/usr/bin/id"

check_rule "socket: curl localhost" \
    "network_connect" \
    "curl -s --connect-timeout 1 http://127.0.0.1 >/dev/null"

SSH_TEST="/home/analyst/.ssh/audit_test"

check_rule "ssh_keys: touch ~/.ssh/test" \
    "ssh_keys" \
    "touch '$SSH_TEST'"
rm -f "$SSH_TEST"

CRON_TEST="/etc/cron.d/audit_test"

check_rule "cron: touch /etc/cron.d/test" \
    "cron_persist" \
    "touch '$CRON_TEST'"
rm -f "$CRON_TEST"

SUDO_TEST="/etc/sudoers.d/audit_test"

check_rule "sudoers: touch /etc/sudoers.d/test" \
    "sudoers" \
    "touch '$SUDO_TEST'"
rm -f "$SUDO_TEST"

echo "Rules added: $ADDED | Validation: $PASS/5 PASS"
