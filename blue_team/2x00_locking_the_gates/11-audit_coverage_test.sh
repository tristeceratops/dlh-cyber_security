#!/bin/bash

set -euo pipefail

REPORT="audit_validation.json"

STARTUP_TEST="/etc/init.d/meddefense_test"
CRON_TEST="/etc/cron.d/meddefense_test"

TOTAL=0
CAPTURED=0
MISSED=0

RESPONSES="[]"

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi

cleanup() {
    rm -f "$STARTUP_TEST"
    rm -f "$CRON_TEST"
}

trap cleanup EXIT

echo "[*] Running audit telemetry coverage tests..."

run_test() {

    local number="$1"
    local name="$2"
    local key="$3"
    local command="$4"

    TOTAL=$((TOTAL + 1))

    local timestamp
    timestamp=$(date --iso-8601=seconds)

    eval "$command"

    sleep 2

    local excerpt
    excerpt=$(ausearch -ts recent -k "$key" 2>/dev/null | tail -5)

    local events
    events=$(grep -c "^type=" <<<"$excerpt" || true)

    local status

    if [[ "$events" -gt 0 ]]; then
        status="CAPTURED"
        CAPTURED=$((CAPTURED + 1))
    else
        status="MISSED"
        MISSED=$((MISSED + 1))
    fi

    printf "[%d/6] %-32s [%s]\n" "$number" "$name" "$status"

    RESPONSES=$(
        jq \
        --arg test "$name" \
        --arg key "$key" \
        --arg cmd "$command" \
        --arg ts "$timestamp" \
        --arg status "$status" \
        --arg excerpt "$excerpt" \
        --argjson count "$events" \
        '. += [{
            test_name:$test,
            expected_audit_key:$key,
            command:$cmd,
            timestamp:$ts,
            capture_status:$status,
            matching_event_count:$count,
            event_excerpt:$excerpt
        }]' <<<"$RESPONSES"
    )
}


run_test \
1 \
"sudo execution" \
"priv_esc" \
"sudo -l >/dev/null 2>&1 || true"


run_test \
2 \
"shadow access" \
"identity" \
"head -1 /etc/shadow >/dev/null"


run_test \
3 \
"suspicious download tool" \
"suspicious_download" \
"curl --version >/dev/null"


run_test \
4 \
"sshd config read" \
"sshd_config" \
"stat /etc/ssh/sshd_config >/dev/null"


run_test \
5 \
"monitored test file write" \
"startup_scripts" \
"echo test > $STARTUP_TEST"


run_test \
6 \
"cron configuration check" \
"cron_config" \
"touch $CRON_TEST"


echo
echo "[*] Cleaning test artifacts..."

cleanup

jq -n \
--arg generated "$(date --iso-8601=seconds)" \
--argjson tests "$RESPONSES" \
--argjson executed "$TOTAL" \
--argjson captured "$CAPTURED" \
--argjson missed "$MISSED" \
'{
    generated: $generated,
    tests_executed: $executed,
    captured: $captured,
    missed: $missed,
    results: $tests
}' > "$REPORT"

echo "Tests executed: $TOTAL"
echo "Captured: $CAPTURED"
echo "Missed: $MISSED"
echo "Report saved to: $REPORT"
