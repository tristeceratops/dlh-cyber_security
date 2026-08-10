#!/bin/bash

# name: 7-linux_export.sh
# purpose: Parse auth.log, audit.log and syslog into normalized telemetry
# author: Tristeceratops

set -euo pipefail

OUTPUT="linux_events_export.json"
AUTH="/var/log/auth.log"
AUDIT="/var/log/audit/audit.log"
SYSLOG="/var/log/syslog"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "[*] Parsing auth.log..."

auth_count=0
ssh_count=0
sudo_count=0
su_count=0
pam_count=0

if [[ -f "$AUTH" ]]; then
    auth_count=$(grep -Eic 'sshd|sudo:|su:|pam_' "$AUTH" || true)
    ssh_count=$(grep -Eic 'sshd.*(Accepted|Failed|Invalid user)' "$AUTH" || true)
    sudo_count=$(grep -Eic 'sudo:' "$AUTH" || true)
    su_count=$(grep -Eic 'su:' "$AUTH" || true)
    pam_count=$(grep -Eic 'pam_' "$AUTH" || true)
fi

echo "    SSH logins: $ssh_count | sudo: $sudo_count | su: $su_count | PAM: $pam_count"

echo "[*] Parsing audit.log..."

exec_count=0
file_count=0
network_count=0
audit_count=0

if [[ -f "$AUDIT" ]]; then
    exec_count=$(grep -Ec 'type=EXECVE|syscall=execve' "$AUDIT" || true)
    file_count=$(grep -Ec 'type=PATH' "$AUDIT" || true)
    network_count=$(grep -Eic 'socket|connect' "$AUDIT" || true)
    audit_count=$(wc -l < "$AUDIT")
fi

echo "    execve: $exec_count | file_access: $file_count | network: $network_count | other: $((audit_count - exec_count - file_count - network_count))"

echo "[*] Parsing syslog..."

service_count=0
error_count=0
syslog_count=0

if [[ -f "$SYSLOG" ]]; then
    syslog_count=$(wc -l < "$SYSLOG")
    service_count=$(grep -Eic 'systemd.*(Started|Stopped)|service.*(start|stop)' "$SYSLOG" || true)
    error_count=$(grep -Eic 'error|failed|failure|critical|emergency' "$SYSLOG" || true)
fi

echo "    service: $service_count | error: $error_count | other: $((syslog_count - service_count - error_count))"

total=$((auth_count + audit_count + syslog_count))

echo "Total events: $total"

if [[ -f "$AUTH" ]]; then
    start=$(head -n 1 "$AUTH" | cut -c1-15)
    end=$(tail -n 1 "$AUTH" | cut -c1-15)
elif [[ -f "$SYSLOG" ]]; then
    start=$(head -n 1 "$SYSLOG" | cut -c1-15)
    end=$(tail -n 1 "$SYSLOG" | cut -c1-15)
else
    start=""
    end=""
fi

echo "Time range: $start to $end"

cat > "$OUTPUT" <<EOF
{
  "hostname": "$(hostname)",
  "source_type": "linux",
  "event_category": "telemetry_export",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "counts": {
    "auth": $auth_count,
    "audit": $audit_count,
    "syslog": $syslog_count
  },
  "categories": {
    "ssh": $ssh_count,
    "sudo": $sudo_count,
    "su": $su_count,
    "pam": $pam_count,
    "execve": $exec_count,
    "file_access": $file_count,
    "network": $network_count,
    "service": $service_count,
    "error": $error_count
  },
  "total_events": $total
}
EOF

echo "Output: $OUTPUT"
