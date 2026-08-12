#!/bin/bash

REPORT_PATH="apt_recovery.json"
DEPENDENCY_PATH="service_dependency_map.json"
ACTION_PATH=$(mktemp)

START_TS=$(date +%s)
START_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RECOVERY_OK=false

LOCK_LIST=(
    "/var/lib/dpkg/lock-frontend"
    "/var/lib/dpkg/lock"
    "/var/cache/apt/archives/lock"
)

cleanup() {
    rm -f "$ACTION_PATH"
}

trap cleanup EXIT

record_action() {
    local operation="$1"
    local outcome="$2"
    local information="${3:-}"

    jq -n -c \
        --arg operation "$operation" \
        --arg outcome "$outcome" \
        --arg information "$information" \
        '{
            action: $operation,
            result: $outcome,
            detail: $information
        }' >> "$ACTION_PATH"
}

collect_processes() {
    pgrep -fa 'dpkg|apt' 2>/dev/null || true
}

find_stale_locks() {
    local lock_path

    for lock_path in "${LOCK_LIST[@]}"; do
        if [[ -f "$lock_path" ]] &&
           ! fuser "$lock_path" >/dev/null 2>&1; then
            printf '%s\n' "$lock_path"
        fi
    done
}

collect_broken_packages() {
    local listed
    local selected

    listed=$(
        dpkg -l 2>/dev/null |
        awk '
            /^[uhi]F/ || /^[uhi]H/ || /^[uhi]W/ || /^[uhi]T/ {print $2}
            /^iF/ {print $2}
            /^hH/ {print $2}
        ' |
        sort -u
    )

    selected=$(
        dpkg --get-selections 2>/dev/null |
        awk '$2 ~ /half-configured|half-installed|unpacked|triggers-pending/ {print $1}'
    )

    printf '%s\n%s\n' "$listed" "$selected" |
        sort -u |
        grep -v '^$' || true
}

collect_disk_space() {
    df -m / 2>/dev/null | awk 'NR==2 {print $4}'
}

collect_var_space() {
    df -m /var 2>/dev/null | awk 'NR==2 {print $4}'
}

build_diagnosis() {
    local processes="$1"
    local stale="$2"
    local audit="$3"
    local broken="$4"
    local root_space="$5"
    local var_space="$6"

    local stale_json
    local broken_json

    if [[ -n "$stale" ]]; then
        stale_json=$(printf '%s\n' "$stale" | jq -R -s 'split("\n") | map(select(length > 0))')
    else
        stale_json='[]'
    fi

    if [[ -n "$broken" ]]; then
        broken_json=$(printf '%s\n' "$broken" | jq -R -s 'split("\n") | map(select(length > 0))')
    else
        broken_json='[]'
    fi

    jq -n \
        --arg processes "${processes:-none}" \
        --argjson locks "$stale_json" \
        --arg audit "${audit:-clean}" \
        --argjson broken "$broken_json" \
        --arg root "${root_space:-unknown}MB" \
        --arg var "${var_space:-unknown}MB" \
        '{
            live_processes: $processes,
            stale_locks: $locks,
            dpkg_audit: $audit,
            broken_packages: $broken,
            free_space_root: $root,
            free_space_var: $var
        }'
}

remove_stale_locks() {
    local lock_path

    while IFS= read -r lock_path; do
        [[ -z "$lock_path" ]] && continue

        if fuser "$lock_path" >/dev/null 2>&1; then
            printf "    remove stale lock %-40s SKIPPED\n" "$lock_path"
            record_action \
                "remove stale lock ${lock_path}" \
                "SKIPPED" \
                "lock still held by process"
            continue
        fi

        if rm -f "$lock_path"; then
            printf "    remove stale lock %-40s OK\n" "$lock_path"
            record_action \
                "remove stale lock ${lock_path}" \
                "OK" \
                ""
        else
            printf "    remove stale lock %-40s FAILED\n" "$lock_path"
            record_action \
                "remove stale lock ${lock_path}" \
                "FAILED" \
                "unable to remove lock"
        fi
    done <<< "$STALE_LOCKS"
}

configure_packages() {
    local output
    local rc

    printf "    %-45s" "dpkg --configure -a"

    output=$(
        DEBIAN_FRONTEND=noninteractive \
        dpkg --configure -a 2>&1
    )
    rc=$?

    if [[ "$rc" -eq 0 ]]; then
        echo "OK"
        record_action \
            "dpkg --configure -a" \
            "OK" \
            "$output"
    else
        echo "FAILED (exit ${rc})"
        record_action \
            "dpkg --configure -a" \
            "FAILED" \
            "$output"
    fi

    return "$rc"
}

repair_dependencies() {
    local output
    local rc
    local detail

    printf "    %-45s" "apt-get --fix-broken install"

    output=$(
        DEBIAN_FRONTEND=noninteractive \
        apt-get --fix-broken install -y 2>&1
    )
    rc=$?

    detail=$(printf '%s\n' "$output" | tail -5)

    if [[ "$rc" -eq 0 ]]; then
        echo "OK"
        record_action \
            "apt-get --fix-broken install -y" \
            "OK" \
            "$detail"
    else
        echo "FAILED (exit ${rc})"
        record_action \
            "apt-get --fix-broken install -y" \
            "FAILED" \
            "$detail"
    fi

    return "$rc"
}

verify_package_state() {
    local result

    printf "    %-45s" "dpkg --audit (re-run)"

    result=$(dpkg --audit 2>/dev/null || true)

    if [[ -z "$result" ]]; then
        echo "clean"
        record_action \
            "dpkg --audit re-run" \
            "clean" \
            ""
        return 0
    fi

    echo "RESIDUAL BROKEN"

    record_action \
        "dpkg --audit re-run" \
        "residual broken" \
        "$result"

    return 1
}

service_exists() {
    local unit="$1"

    systemctl list-unit-files "$unit" >/dev/null 2>&1 ||
    systemctl list-units --all "$unit" >/dev/null 2>&1
}

restart_unit() {
    local package="$1"
    local unit="$2"
    local rc=0
    local state

    [[ -z "$unit" ]] && return

    systemctl try-restart "$unit" >/dev/null 2>&1 || rc=$?
    state=$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")

    printf "    %-40s %s\n" "$unit" "$state"

    if [[ "$rc" -eq 0 ]]; then
        record_action \
            "systemctl try-restart ${unit}" \
            "$state" \
            "package: ${package}"
    else
        record_action \
            "systemctl try-restart ${unit}" \
            "failed" \
            "package: ${package}; exit: ${rc}; state: ${state}"
    fi
}

restart_mapped_services() {
    local count
    local index
    local package
    local unit

    if [[ ! -f "$DEPENDENCY_PATH" ]]; then
        restart_package_services
        return
    fi

    if ! jq -e 'type == "array"' "$DEPENDENCY_PATH" >/dev/null 2>&1; then
        restart_package_services
        return
    fi

    count=$(jq 'length' "$DEPENDENCY_PATH")

    for ((index=0; index<count; index++)); do
        package=$(jq -r ".[$index].package // empty" "$DEPENDENCY_PATH")
        unit=$(jq -r ".[$index].service // empty" "$DEPENDENCY_PATH")

        [[ -z "$unit" ]] && continue

        if grep -Fxq "$package" <<< "$BROKEN_PACKAGES"; then
            restart_unit "$package" "$unit"
        fi
    done
}

restart_package_services() {
    local package
    local unit

    while IFS= read -r package; do
        [[ -z "$package" ]] && continue

        unit="${package}.service"

        if service_exists "$unit"; then
            restart_unit "$package" "$unit"
        fi
    done <<< "$BROKEN_PACKAGES"
}

build_report() {
    local finished
    local elapsed
    local final_state
    local recovered_json
    local actions_json

    finished=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    elapsed=$(($(date +%s) - START_TS))

    if [[ "$RECOVERY_OK" == "true" ]]; then
        final_state="clean"
        recovered_json=true
    else
        final_state="residual broken packages"
        recovered_json=false
    fi

    if [[ -s "$ACTION_PATH" ]]; then
        actions_json=$(jq -s '.' "$ACTION_PATH")
    else
        actions_json='[]'
    fi

    jq -n \
        --argjson diagnosis "$INITIAL_DIAGNOSIS" \
        --argjson actions "$actions_json" \
        --arg final "$final_state" \
        --argjson recovered "$recovered_json" \
        --argjson duration "$elapsed" \
        --arg started "$START_ISO" \
        --arg finished "$finished" \
        '{
            initial_diagnosis: $diagnosis,
            actions_taken: $actions,
            final_state: $final,
            recovered: $recovered,
            duration_seconds: $duration,
            started_at: $started,
            finished_at: $finished
        }' > "$REPORT_PATH"

    echo
    echo "RECOVERED: $( [[ "$RECOVERY_OK" == "true" ]] && echo yes || echo no )"
    echo "Duration: ${elapsed}s"
    echo "Report saved to: ${REPORT_PATH}"
}

diagnose() {
    local processes
    local stale
    local audit
    local broken
    local root_space
    local var_space

    echo "[*] Diagnosing..."

    processes=$(collect_processes)

    if [[ -n "$processes" ]]; then
        echo "    live dpkg/apt processes detected:"
        echo "$processes" | sed 's/^/      /'
    else
        echo "    live dpkg/apt processes: none"
    fi

    stale=$(find_stale_locks)

    if [[ -n "$stale" ]]; then
        echo "    stale locks:"
        echo "$stale" | sed 's/^/      /'
    else
        echo "    stale locks: none"
    fi

    audit=$(dpkg --audit 2>/dev/null || true)

    if [[ -n "$audit" ]]; then
        echo "    dpkg --audit:"
        echo "$audit" | sed 's/^/      /'
    else
        echo "    dpkg --audit: clean"
    fi

    broken=$(collect_broken_packages)

    echo "    broken packages: $(grep -c . <<< "$broken" 2>/dev/null || echo 0)"

    if [[ -n "$broken" ]]; then
        echo "$broken" | sed 's/^/      /'
    fi

    root_space=$(collect_disk_space)
    var_space=$(collect_var_space)

    echo "    free space  /: ${root_space:-unknown}MB   /var: ${var_space:-unknown}MB"

    LIVE_PROCESSES="$processes"
    STALE_LOCKS="$stale"
    BROKEN_PACKAGES="$broken"

    INITIAL_DIAGNOSIS=$(build_diagnosis \
        "$processes" \
        "$stale" \
        "$audit" \
        "$broken" \
        "$root_space" \
        "$var_space"
    )
}

main() {
    diagnose

    if [[ -n "$LIVE_PROCESSES" ]]; then
        echo
        echo "[!] Live dpkg/apt process detected. Cannot proceed safely."
        echo "    Diagnose complete. Refusing to repair while live process is running."

        build_report
        return 2
    fi

    echo "[*] Repairing..."

    remove_stale_locks

    configure_packages

    repair_dependencies

    if verify_package_state; then
        RECOVERY_OK=true
    else
        RECOVERY_OK=false
    fi

    echo "[*] Restarting affected services..."

    restart_mapped_services

    build_report

    if [[ "$RECOVERY_OK" == "true" ]]; then
        return 0
    fi

    return 1
}

main
exit $?

