#!/bin/bash

BASELINE_FILE="pre_patch_state.json"
DEPENDENCY_FILE="service_dependency_map.json"
PROBE_FILE="service_probes.json"
REPORT_FILE="post_patch_validation.json"
DETAILS_FILE="tmp_validation.jsonl"

SERVICE_TOTAL=0
SERVICE_PASSED=0
SOCKET_TOTAL=0
SOCKET_PASSED=0
PROBE_TOTAL=0
PROBE_PASSED=0

validate_service_states() {
    local service_count
    service_count=$(jq '.services | length' "$BASELINE_FILE" 2>/dev/null || echo 0)

    for ((index=0; index<service_count; index++)); do
        ((SERVICE_TOTAL++))

        local service_name
        local previous_state
        local current_state
        local check_status

        service_name=$(jq -r ".services[$index].service" "$BASELINE_FILE")
        previous_state=$(jq -r ".services[$index].ActiveState" "$BASELINE_FILE")

        current_state=$(systemctl show \
            -p ActiveState \
            --value \
            "$service_name" 2>/dev/null)

        check_status="pass"

        if [ "$previous_state" = "active" ] &&
           [ "$current_state" != "active" ]; then
            check_status="regression"
        fi

        if [ "$check_status" = "pass" ]; then
            ((SERVICE_PASSED++))
        fi

        write_detail \
            "service_state" \
            "$service_name" \
            "$check_status"
    done
}

validate_listening_sockets() {
    local socket_count
    local current_connections

    socket_count=$(jq '.listening | length' "$BASELINE_FILE" 2>/dev/null || echo 0)
    current_connections=$(ss -tulnp 2>/dev/null)

    for ((index=0; index<socket_count; index++)); do
        local socket_line
        local port_number
        local check_status

        socket_line=$(jq -r ".listening[$index]" "$BASELINE_FILE")

        port_number=$(echo "$socket_line" |
            awk '{print $5}' |
            rev |
            cut -d: -f1 |
            rev)

        if [[ "$port_number" == *"Port"* ]] ||
           [ -z "$port_number" ]; then
            continue
        fi

        ((SOCKET_TOTAL++))
        check_status="regression"

        if echo "$current_connections" |
            grep -q ":$port_number\b"; then
            check_status="pass"
        fi

        if [ "$check_status" = "pass" ]; then
            ((SOCKET_PASSED++))
        fi

        write_detail \
            "socket" \
            "$port_number" \
            "$check_status"
    done
}

validate_critical_probes() {
    if [ ! -f "$DEPENDENCY_FILE" ] ||
       [ ! -f "$PROBE_FILE" ]; then
        return
    fi

    local critical_services

    critical_services=$(jq -r \
        '.[] | select(.criticality == "critical") | .service' \
        "$DEPENDENCY_FILE" 2>/dev/null)

    while IFS= read -r service_name; do
        [ -z "$service_name" ] && continue

        local probe_command
        local check_status

        probe_command=$(jq -r \
            --arg service "$service_name" \
            '.[$service] // empty' \
            "$PROBE_FILE" 2>/dev/null)

        if [ -z "$probe_command" ] ||
           [ "$probe_command" = "null" ]; then
            continue
        fi

        ((PROBE_TOTAL++))

        if eval "$probe_command" >/dev/null 2>&1; then
            check_status="pass"
            ((PROBE_PASSED++))
        else
            check_status="probe_failed"
        fi

        write_detail \
            "probe" \
            "$service_name" \
            "$check_status"

    done <<< "$critical_services"
}

write_detail() {
    local check_type="$1"
    local check_name="$2"
    local check_status="$3"

    jq -n -c \
        --arg type "$check_type" \
        --arg name "$check_name" \
        --arg status "$check_status" \
        '{
            type: $type,
            name: $name,
            status: $status
        }' >> "$DETAILS_FILE"
}

build_report() {
    local check_total
    local passed_total
    local failed_total
    local details

    check_total=$((SERVICE_TOTAL + SOCKET_TOTAL + PROBE_TOTAL))
    passed_total=$((SERVICE_PASSED + SOCKET_PASSED + PROBE_PASSED))
    failed_total=$((check_total - passed_total))

    if [ -s "$DETAILS_FILE" ]; then
        details=$(jq -s '.' "$DETAILS_FILE")
    else
        details="[]"
    fi

    jq -n \
        --argjson total "$check_total" \
        --argjson passed "$passed_total" \
        --argjson failed "$failed_total" \
        --argjson details "$details" \
        '{
            total_checks: $total,
            passed: $passed,
            failed: $failed,
            details: $details
        }' > "$REPORT_FILE"

    rm -f "$DETAILS_FILE"

    print_results \
        "$check_total" \
        "$passed_total" \
        "$failed_total"
}

print_results() {
    local total_checks="$1"
    local passed_checks="$2"
    local failed_checks="$3"

    local service_result="PASS"
    local socket_result="PASS"
    local probe_result="PASS"
    local final_result="PASS"

    if [ "$SERVICE_PASSED" -lt "$SERVICE_TOTAL" ]; then
        service_result="FAIL"
    fi

    if [ "$SOCKET_PASSED" -lt "$SOCKET_TOTAL" ]; then
        socket_result="FAIL"
    fi

    if [ "$PROBE_PASSED" -lt "$PROBE_TOTAL" ]; then
        probe_result="FAIL"
    fi

    if [ "$failed_checks" -gt 0 ]; then
        final_result="FAIL"
    fi

    printf "Service state checks:     %-2d/%-2d   %s\n" \
        "$SERVICE_PASSED" "$SERVICE_TOTAL" "$service_result"

    printf "Listening socket checks:  %-2d/%-2d   %s\n" \
        "$SOCKET_PASSED" "$SOCKET_TOTAL" "$socket_result"

    printf "Critical liveness probes: %-2d/%-2d   %s\n" \
        "$PROBE_PASSED" "$PROBE_TOTAL" "$probe_result"

    printf "VERDICT: %s (%d/%d)\n" \
        "$final_result" "$passed_checks" "$total_checks"

    echo "Report saved to: $REPORT_FILE"
}

run_validation() {
    : > "$DETAILS_FILE"

    validate_service_states
    validate_listening_sockets
    validate_critical_probes
    build_report

    local failed_checks
    failed_checks=$((SERVICE_TOTAL + SOCKET_TOTAL + PROBE_TOTAL -
        SERVICE_PASSED - SOCKET_PASSED - PROBE_PASSED))

    if [ "$failed_checks" -gt 0 ]; then
        return 1
    fi

    return 0
}

run_validation
exit $?

