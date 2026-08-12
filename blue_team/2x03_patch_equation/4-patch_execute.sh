#!/bin/bash

LOCK_FILE="/var/lock/meddefense-patch.lock"
PLAN_FILE="patch_plan.json"
LOG_FILE="patch_execution_log.json"
LOCK_FD=9
LOCK_TIMEOUT=120

START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOST_NAME=$(hostname)

acquire_lock() {
    echo "[*] Acquiring lock ${LOCK_FILE}..."

    exec {LOCK_FD}>"${LOCK_FILE}" || {
        echo "[-] Cannot open lock file: ${LOCK_FILE}" >&2
        exit 2
    }

    if ! flock -n "$LOCK_FD"; then
        echo "[-] Could not acquire lock. Another instance may be running." >&2
        exit 2
    fi

    echo "    OK"
}

release_lock() {
    flock -u "$LOCK_FD" 2>/dev/null
    exec {LOCK_FD}>&-
}

trap release_lock EXIT INT TERM

get_version() {
    local package_name="$1"

    dpkg-query -W -f='${Version}' "$package_name" 2>/dev/null ||
        echo "not-installed"
}

get_service_states() {
    local services="$1"

    if ! jq -e 'type == "array"' <<< "$services" >/dev/null 2>&1; then
        echo '{}'
        return
    fi

    local states='{}'

    while IFS= read -r service_name; do
        [ -z "$service_name" ] && continue

        local service_state
        service_state=$(systemctl is-active "$service_name" 2>/dev/null || true)

        [ -z "$service_state" ] && service_state="unknown"

        states=$(jq \
            --arg name "$service_name" \
            --arg state "$service_state" \
            '. + {($name): $state}' \
            <<< "$states")
    done < <(jq -r '.[]' <<< "$services")

    jq -c '.' <<< "$states"
}

build_state_block() {
    local package_name="$1"
    local services="$2"

    local installed_version
    local service_states

    installed_version=$(get_version "$package_name")
    service_states=$(get_service_states "$services")

    if ! jq -e . <<< "$service_states" >/dev/null 2>&1; then
        service_states='{}'
    fi

    jq -n -c \
        --arg version "$installed_version" \
        --argjson states "$service_states" \
        '{
            installed_version: $version,
            service_states: $states
        }'
}

run_apt_upgrade() {
    local package_name="$1"
    local output_file="$2"
    local error_file="$3"

    local elapsed=0
    local delay=1
    local exit_code

    while true; do
        DEBIAN_FRONTEND=noninteractive \
            apt-get install --only-upgrade -y "$package_name" \
            >"$output_file" 2>"$error_file"

        exit_code=$?

        if [ "$exit_code" -eq 0 ]; then
            return 0
        fi

        if grep -qiE \
            'Could not get lock|Unable to acquire.*lock|Could not open lock file|dpkg frontend lock' \
            "$error_file"; then

            if [ "$elapsed" -ge "$LOCK_TIMEOUT" ]; then
                return "$exit_code"
            fi

            echo "    [!] dpkg lock busy, retrying in ${delay}s..."

            sleep "$delay"

            elapsed=$((elapsed + delay))
            delay=$((delay * 2))

            if [ "$delay" -gt 30 ]; then
                delay=30
            fi

            continue
        fi

        return "$exit_code"
    done
}

restart_services() {
    local services="$1"
    local results="{}"

    while IFS= read -r service_name; do
        [ -z "$service_name" ] && continue

        printf "      try-restart %-35s" "$service_name"

        local restart_code=0
        systemctl try-restart "$service_name" 2>/dev/null || restart_code=$?

        if [ "$restart_code" -eq 0 ]; then
            echo "OK"

            results=$(jq \
                --arg service "$service_name" \
                '. + {($service): "restarted"}' <<< "$results")
        else
            echo "FAILED"

            results=$(jq \
                --arg service "$service_name" \
                '. + {($service): "failed"}' <<< "$results")
        fi
    done < <(jq -r '.[]' <<< "$services")

    echo "$results"
}

build_entry() {
    local package_name="$1"
    local priority="$2"
    local pre_state="$3"
    local post_state="$4"
    local status="$5"
    local duration="$6"
    local stdout_tail="$7"
    local stderr_tail="$8"
    local apt_status="$9"
    local restart_results="${10}"

    jq -n -c \
        --arg package "$package_name" \
        --arg priority "$priority" \
        --arg status "$status" \
        --arg duration "$duration" \
        --arg stdout "$stdout_tail" \
        --arg stderr "$stderr_tail" \
        --arg apt_status "$apt_status" \
        --argjson pre "$pre_state" \
        --argjson post "$post_state" \
        --argjson restarts "$restart_results" \
        '{
            package: $package,
            priority: $priority,
            pre: $pre,
            post: $post,
            status: $status,
            duration_seconds: ($duration | tonumber),
            stdout_tail: $stdout,
            stderr_tail: $stderr,
            apt_exit_status: ($apt_status | tonumber),
            restart_results: $restarts
        }'
}

write_log() {
    local finished_at="$1"
    local source_hash="$2"
    local entries="$3"

    jq -n \
        --arg started "$START_TIME" \
        --arg finished "$finished_at" \
        --arg host "$HOST_NAME" \
        --arg hash "$source_hash" \
        --argjson entries "$entries" \
        '{
            started_at: $started,
            finished_at: $finished,
            hostname: $host,
            plan_source_hash: $hash,
            entries: $entries
        }' > "$LOG_FILE"
}

acquire_lock
trap release_lock EXIT INT TERM

if [ ! -f "$PLAN_FILE" ]; then
    echo "[-] Plan file not found: ${PLAN_FILE}" >&2
    exit 1
fi

if ! jq -e '.plan | type == "array"' "$PLAN_FILE" >/dev/null 2>&1; then
    echo "[-] Invalid patch plan: .plan must be an array" >&2
    exit 1
fi

PLAN_HASH=$(sha256sum "$PLAN_FILE" | awk '{print $1}')
TOTAL_ENTRIES=$(jq '.plan | length' "$PLAN_FILE")

echo "[*] Loading plan: ${PLAN_FILE} (${TOTAL_ENTRIES} entries)"

LOG_ENTRIES="[]"
SUCCESS_COUNT=0
FAIL_COUNT=0

for ((index=0; index<TOTAL_ENTRIES; index++)); do

    PLAN_ENTRY=$(jq ".plan[$index]" "$PLAN_FILE")

    PACKAGE_NAME=$(jq -r '.package' <<< "$PLAN_ENTRY")
    PRIORITY=$(jq -r '.bucket // .priority // "unknown"' <<< "$PLAN_ENTRY")
    AFFECTED_SERVICES=$(jq -c '.affected_services // []' <<< "$PLAN_ENTRY")
    NEEDS_RESTART=$(jq -r '.requires_restart // false' <<< "$PLAN_ENTRY")
    NEEDS_REBOOT=$(jq -r '.requires_reboot // false' <<< "$PLAN_ENTRY")

    DISPLAY_INDEX=$((index + 1))

    printf "[%d/%d] %-25s %-12s apt-get ... " \
        "$DISPLAY_INDEX" \
        "$TOTAL_ENTRIES" \
        "$PACKAGE_NAME" \
        "$PRIORITY"

    PRE_STATE=$(build_state_block "$PACKAGE_NAME" "$AFFECTED_SERVICES")

    TEMP_OUT=$(mktemp)
    TEMP_ERR=$(mktemp)

    START_NS=$(date +%s%N)

    run_apt_upgrade "$PACKAGE_NAME" "$TEMP_OUT" "$TEMP_ERR"
    APT_EXIT_CODE=$?

    END_NS=$(date +%s%N)

    DURATION=$(awk \
        "BEGIN {printf \"%.1f\", (${END_NS} - ${START_NS}) / 1000000000}")

    STDOUT_TAIL=$(tail -5 "$TEMP_OUT")
    STDERR_TAIL=$(tail -5 "$TEMP_ERR")

    rm -f "$TEMP_OUT" "$TEMP_ERR"

    STATUS="success"
    RESTART_RESULTS="{}"

    if [ "$APT_EXIT_CODE" -ne 0 ]; then
        STATUS="failed"

        if grep -qiE \
            'Could not get lock|Unable to acquire.*lock|Could not open lock file|dpkg frontend lock' \
            <<< "$STDERR_TAIL"; then
            STDERR_TAIL="${STDERR_TAIL}
dpkg lock remained busy for ${LOCK_TIMEOUT} seconds."
        fi

        echo "FAILED (apt exit ${APT_EXIT_CODE})"

    else
        echo "OK (${DURATION}s)"

        if [ "$NEEDS_RESTART" = "true" ] &&
           [ "$NEEDS_REBOOT" = "false" ]; then

            RESTART_RESULTS=$(restart_services "$AFFECTED_SERVICES")
        fi
    fi

    POST_STATE=$(build_state_block "$PACKAGE_NAME" "$AFFECTED_SERVICES")

if ! jq -e . >/dev/null 2>&1 <<< "$PRE_STATE"; then
    PRE_STATE='{
        "installed_version": "unknown",
        "service_states": {}
    }'
fi

if ! jq -e . >/dev/null 2>&1 <<< "$POST_STATE"; then
    POST_STATE='{
        "installed_version": "unknown",
        "service_states": {}
    }'
fi

if ! jq -e . >/dev/null 2>&1 <<< "$RESTART_RESULTS"; then
    RESTART_RESULTS='{}'
fi


    ENTRY_RESULT=$(build_entry \
        "$PACKAGE_NAME" \
        "$PRIORITY" \
        "$PRE_STATE" \
        "$POST_STATE" \
        "$STATUS" \
        "$DURATION" \
        "$STDOUT_TAIL" \
        "$STDERR_TAIL" \
        "$APT_EXIT_CODE" \
        "$RESTART_RESULTS")

    LOG_ENTRIES=$(jq \
        --argjson entry "$ENTRY_RESULT" \
        '. + [$entry]' <<< "$LOG_ENTRIES")

    if [ "$STATUS" = "success" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        break
    fi
done

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo "Succeeded: ${SUCCESS_COUNT}  Failed: ${FAIL_COUNT}"

write_log "$FINISHED_AT" "$PLAN_HASH" "$LOG_ENTRIES"

echo "Log saved to: ${LOG_FILE}"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi

exit 0
