#!/bin/bash

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

set -o pipefail

RULES_FILE="/etc/audit/rules.d/meddefense.rules"
OUTPUT_DIR="capstone/telemetry"
# capstone/telemetry/linux_events.json
OUTPUT_FILE="$OUTPUT_DIR/linux_events.json"

status=0
TEST_USER="meddefense-audit-test"
CRON_FILE="/etc/cron.d/meddefense-audit-test"

fail_control() {
    printf 'error=%s\n' "$1" >&2
    status=1
}

fail_environment() {
    printf 'error=%s\n' "$1" >&2
    exit 2
}

for command in systemctl augenrules ausearch journalctl useradd userdel find jq; do
    if ! command -v "$command" >/dev/null 2>&1; then
        fail_environment "missing dependency: $command"
    fi
done

if [[ "$EUID" -ne 0 ]]; then
    fail_environment "script must run as root"
fi

if [[ ! -r "$RULES_FILE" ]]; then
    fail_environment "missing input file: $RULES_FILE"
fi

mkdir -p "$OUTPUT_DIR" || {
    fail_environment "unable to create $OUTPUT_DIR"
}

# Ensure auditd is active.
if ! systemctl is-active --quiet auditd; then
    if ! systemctl start auditd >/dev/null 2>&1; then
        fail_control "unable to start auditd"
    fi
fi

if ! systemctl is-active --quiet auditd; then
    fail_control "auditd is not active"
fi

# Load project rules.
if ! augenrules --load >/dev/null 2>&1; then
    fail_control "unable to load audit rules"
fi

if ! audit_rules=$(auditctl -l 2>/dev/null); then
    fail_environment "unable to query loaded audit rules"
fi

if ! grep -Fq "meddefense" <<< "$audit_rules"; then
    fail_control "meddefense audit rules are not loaded"
fi

verify_audit_key() {
    local key="$1"

    if ausearch -k "$key" -ts recent 2>/dev/null |
        grep -qE 'type=|time->|^[[:space:]]*node='; then
        printf 'audit_check=%s=present\n' "$key"
    else
        printf 'audit_check=%s=missing\n' "$key" >&2
        fail_control "expected audit record missing: $key"
    fi
}

# User management test with ausearch -k meddefense-user-mgmt.
userdel -r "$TEST_USER" >/dev/null 2>&1 || true

if ! useradd "$TEST_USER" >/dev/null 2>&1; then
    fail_control "unable to create test user"
else
    verify_audit_key "meddefense-user-mgmt"
fi

if ! userdel -r "$TEST_USER" >/dev/null 2>&1; then
    fail_control "unable to remove test user"
else
    verify_audit_key "meddefense-user-mgmt"
fi

# Service management test.
if systemctl list-units --type=service --no-pager >/dev/null 2>&1; then
    verify_audit_key "meddefense-service-mgmt"
else
    fail_control "service management test failed"
fi

# Cron test.
rm -f "$CRON_FILE"

if printf '%s\n' \
    '* * * * * root /usr/bin/true # meddefense-audit-test' \
    > "$CRON_FILE"; then
    chmod 0644 "$CRON_FILE"
    verify_audit_key "meddefense-cron"
else
    fail_control "unable to create cron test"
fi

if ! rm -f "$CRON_FILE"; then
    fail_control "unable to remove cron test"
else
    verify_audit_key "meddefense-cron"
fi

# Authorized root find test.
if find /etc -maxdepth 1 -type f -print >/dev/null 2>&1; then
    verify_audit_key "meddefense-find"
else
    fail_control "root find test failed"
fi

# Export auditd and syslog records from the last 30 minutes.
audit_json=$(mktemp) || fail_environment "unable to create temporary file"
syslog_json=$(mktemp) || {
    rm -f "$audit_json"
    fail_environment "unable to create temporary file"
}

trap 'rm -f "$audit_json" "$syslog_json"' EXIT

if ! ausearch -ts recent -i --format json > "$audit_json" 2>/dev/null; then
    fail_control "unable to export auditd records"
    printf '[]\n' > "$audit_json"
fi

if ! journalctl --since "30 minutes ago" -o json > "$syslog_json" 2>/dev/null; then
    fail_control "unable to export syslog records"
    printf '[]\n' > "$syslog_json"
fi

# ausearch JSON may be a JSON object per line depending on audit version.
# Normalize both sources into arrays.
audit_records=$(jq -s '.' "$audit_json" 2>/dev/null)

if [[ $? -ne 0 ]]; then
    fail_control "auditd export is not valid JSON"
    audit_records='[]'
fi

syslog_records=$(jq -s '.' "$syslog_json" 2>/dev/null)

if [[ $? -ne 0 ]]; then
    fail_control "syslog export is not valid JSON"
    syslog_records='[]'
fi

timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || {
    fail_environment "unable to generate timestamp"
}

if ! jq -n \
    --arg timestamp "$timestamp" \
    --arg hostname "$(hostname)" \
    --arg rules_file "$RULES_FILE" \
    --argjson audit_records "$audit_records" \
    --argjson syslog_records "$syslog_records" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        audit_rules_file: $rules_file,
        collection_window_minutes: 30,
        auditd: {
            active: true,
            records: $audit_records
        },
        syslog: {
            records: $syslog_records
        }
    }' > "$OUTPUT_FILE"; then
    fail_control "unable to create $OUTPUT_FILE"
fi

if [[ "$status" -eq 0 ]]; then
    exit 0
fi

exit 1
