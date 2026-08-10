#!/bin/bash

# name: 7-linux_export.sh
# purpose: Parse auth.log, audit.log via ausearch and syslog into normalized telemetry
# author: Tristeceratops

set -euo pipefail

OUTPUT="linux_events_export.json"
AUTH="/var/log/auth.log"
AUDIT="/var/log/audit/audit.log"
SYSLOG="/var/log/syslog"

echo "[*] Parsing auth.log..."

ssh_count=0
sudo_count=0
su_count=0
pam_count=0

if [[ -f "$AUTH" ]]; then
    ssh_count=$(grep -Eic 'sshd.*(Accepted|Failed|Invalid user)' "$AUTH" || true)
    sudo_count=$(grep -Eic 'sudo:' "$AUTH" || true)
    su_count=$(grep -Eic 'su:' "$AUTH" || true)
    pam_count=$(grep -Eic 'pam_' "$AUTH" || true)
fi

auth_count=$((ssh_count + sudo_count + su_count + pam_count))

echo "    SSH logins: $ssh_count | sudo: $sudo_count | su: $su_count | PAM: $pam_count"

echo "[*] Parsing audit.log..."

exec_count=0
file_count=0
network_count=0
audit_count=0

if command -v ausearch >/dev/null 2>&1 && [[ -f "$AUDIT" ]]; then
    AUDIT_DATA=$(ausearch -ts today -i 2>/dev/null || true)

    audit_count=$(printf '%s\n' "$AUDIT_DATA" | grep -c '^type=' || true)
    exec_count=$(printf '%s\n' "$AUDIT_DATA" | grep -Ec 'type=EXECVE|syscall=execve' || true)
    file_count=$(printf '%s\n' "$AUDIT_DATA" | grep -c '^type=PATH' || true)
    network_count=$(printf '%s\n' "$AUDIT_DATA" | grep -Eic 'socket|connect' || true)
fi

other_count=$((audit_count - exec_count - file_count - network_count))
(( other_count < 0 )) && other_count=0

echo "    execve: $exec_count | file_access: $file_count | network: $network_count | other: $other_count"

echo "[*] Parsing syslog..."

service_count=0
error_count=0
syslog_count=0

if [[ -f "$SYSLOG" ]]; then
    syslog_count=$(wc -l < "$SYSLOG")
    service_count=$(grep -Eic 'systemd.*(Started|Stopped)|service.*(start|stop)' "$SYSLOG" || true)
    error_count=$(grep -Eic 'error|failed|failure|critical|emergency' "$SYSLOG" || true)
fi

other_syslog=$((syslog_count - service_count - error_count))
(( other_syslog < 0 )) && other_syslog=0

echo "    service: $service_count | error: $error_count | other: $other_syslog"

total=$((auth_count + audit_count + syslog_count))

echo "Total events: $total"

cat > "$OUTPUT" <<EOF
{
  "hostname": "$(hostname)",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "source_type": "linux",
  "event_category": "telemetry_export",
  "counts": {
    "auth.log": $auth_count,
    "audit.log": $audit_count,
    "syslog": $syslog_count
  },
  "audit": {
    "execve": $exec_count,
    "file_access": $file_count,
    "network": $network_count,
    "other": $other_count
  },
  "auth": {
    "sshd": $ssh_count,
    "sudo": $sudo_count,
    "su": $su_count,
    "PAM": $pam_count
  },
  "syslog": {
    "service": $service_count,
    "error": $error_count,
    "other": $other_syslog
  },
  "total_events": $total
}
EOF

echo "Output: $OUTPUT"
