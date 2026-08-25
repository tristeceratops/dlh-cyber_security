#!/bin/bash

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

set -o pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="$BASE_DIR/capstone"
EXEC_DIR="$CAPSTONE_DIR/exec"
# capstone/exec/linux_harden.log
LOG_FILE="$EXEC_DIR/linux_harden.log"
# capstone/exec/linux_harden.json
HARDEN_FILE="$EXEC_DIR/linux_harden.json"
# capstone/baseline_linux.json
BASELINE_FILE="$CAPSTONE_DIR/baseline_linux.json"
# capstone/target_state.json
TARGET_FILE="$CAPSTONE_DIR/target_state.json"

status=0
steps_json="[]"

fail_environment() {
    printf 'error=%s\n' "$1" >&2
    exit 2
}

mkdir -p "$EXEC_DIR" || fail_environment "unable to create $EXEC_DIR"

for command in jq lynis hostname date; do
    if ! command -v "$command" >/dev/null 2>&1; then
        fail_environment "missing dependency: $command"
    fi
done

for file in "$BASELINE_FILE" "$TARGET_FILE"; do
    if [[ ! -f "$file" ]]; then
        fail_environment "missing input file: $file"
    fi
done

if ! jq empty "$BASELINE_FILE" >/dev/null 2>&1; then
    fail_environment "invalid JSON: $BASELINE_FILE"
fi

if ! jq empty "$TARGET_FILE" >/dev/null 2>&1; then
    fail_environment "invalid JSON: $TARGET_FILE"
fi

lynis_before=$(jq -r '
    .lynis_after //
    .lynis_before //
    .hardening_index //
    .linux.hardening_index //
    empty
' "$BASELINE_FILE")

if [[ ! "$lynis_before" =~ ^[0-9]+$ ]]; then
    fail_environment "baseline Linux hardening index is missing"
fi

target_index=$(jq -r '
    .linux.hardening_index //
    (.controls[] |
        select(.id == "LNX-LYN-01") |
        .expected_value) //
    empty
' "$TARGET_FILE")

if [[ ! "$target_index" =~ ^[0-9]+$ ]]; then
    fail_environment "target Linux hardening index is missing"
fi

if ! lynis audit system --no-colors > /tmp/linux_harden_lynis_before.log 2>&1; then
    fail_environment "initial Lynis audit failed"
fi

steps=(
    "SSH hardening|4-ssh_hardening.sh|LNX-SSH-01,LNX-SSH-02"
    "sysctl hardening|5-sysctl_hardening.sh|LNX-SYS-01,LNX-SYS-02"
    "permission sweep|6-filesystem_hardening.sh|"
    "service minimization|7-service_minimization.sh|"
    "PAM configuration|8-pam_hardening.sh|"
    "AppArmor enforcement|9-apparmor_config.sh|LNX-APP-01"
    "auditd deployment|10-auditd_config.sh|LNX-AUD-01,LNX-AUD-02"
)

: > "$LOG_FILE" || fail_environment "unable to create $LOG_FILE"

run_step() {
    local name="$1"
    local script_name="$2"
    local controls="$3"
    local script_path="$BASE_DIR/$script_name"
    local start_time
    local end_time
    local duration
    local exit_code
    local changed=false

    if [[ ! -f "$script_path" ]]; then
        printf 'error=missing hardening script: %s\n' "$script_path" >&2
        status=1

        steps_json=$(
            jq -c \
                --arg name "$name" \
                --arg path "$script_path" \
                '. + [{
                    name: $name,
                    script_path: $path,
                    exit_code: 1,
                    duration_seconds: 0,
                    changed: false
                }]' <<< "$steps_json"
        )
        return
    fi

    if [[ ! -x "$script_path" ]]; then
        printf 'error=hardening script is not executable: %s\n' "$script_path" >&2
        status=1

        steps_json=$(
            jq -c \
                --arg name "$name" \
                --arg path "$script_path" \
                '. + [{
                    name: $name,
                    script_path: $path,
                    exit_code: 1,
                    duration_seconds: 0,
                    changed: false
                }]' <<< "$steps_json"
        )
        return
    fi

    start_time=$(date +%s)

    {
        printf '\n[%s] START %s\n' \
            "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            "$name"

        printf '[%s] SCRIPT=%s\n' \
            "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            "$script_path"

        "$script_path"

        exit_code=$?

        printf '[%s] EXIT_CODE=%s\n' \
            "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            "$exit_code"
    } >> "$LOG_FILE" 2>&1 #stdout in log

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    if [[ "$exit_code" -ne 0 ]]; then
        status=1
    else
        changed=true
    fi

    steps_json=$(
        jq -c \
            --arg name "$name" \
            --arg path "$script_path" \
            --argjson exit_code "$exit_code" \
            --argjson duration "$duration" \
            --argjson changed "$changed" \
            '. + [{
                name: $name,
                script_path: $path,
                exit_code: $exit_code,
                duration_seconds: $duration,
                changed: $changed
            }]' <<< "$steps_json"
    )

    if [[ -n "$controls" ]]; then
        controls_touched+=("$controls")
    fi
}


controls_touched=()

for step in "${steps[@]}"; do
    IFS='|' read -r name script_name controls <<< "$step"
    run_step "$name" "$script_name" "$controls"
done

lynis_after_log=$(mktemp) || fail_environment "unable to create temporary file"

trap 'rm -f "$lynis_after_log" /tmp/linux_harden_lynis_before.log' EXIT

if lynis audit system --no-colors > "$lynis_after_log" 2>&1; then
    :
else
    status=1
fi

cat "$lynis_after_log" >> "$LOG_FILE"

lynis_after=$(grep -Eio 'hardening index[^0-9]*[0-9]+' "$lynis_after_log" |
    tail -n 1 |
    grep -Eo '[0-9]+' |
    tail -n 1)

if [[ ! "$lynis_after" =~ ^[0-9]+$ ]]; then
    status=1
    lynis_after=null
fi

if [[ "$lynis_after" =~ ^[0-9]+$ ]] &&
    (( lynis_after < target_index )); then
    status=1
fi

index_delta=null

if [[ "$lynis_after" =~ ^[0-9]+$ ]]; then
    index_delta=$((lynis_after - lynis_before))
fi

controls_json="[]"

for control_group in "${controls_touched[@]}"; do
    IFS=',' read -ra control_ids <<< "$control_group"

    for control_id in "${control_ids[@]}"; do
        if [[ -n "$control_id" ]]; then
            controls_json=$(
                jq -c \
                    --arg id "$control_id" \
                    '. + [$id]' <<< "$controls_json"
            )
        fi
    done
done

controls_json=$(jq -c 'unique' <<< "$controls_json")

timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ') ||
    fail_environment "unable to generate timestamp"

if ! jq -n \
    --arg timestamp "$timestamp" \
    --arg hostname "$(hostname)" \
    --argjson steps "$steps_json" \
    --argjson lynis_before "$lynis_before" \
    --argjson lynis_after "${lynis_after:-null}" \
    --argjson index_delta "${index_delta:-null}" \
    --argjson controls_touched "$controls_json" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        steps: $steps,
        lynis_before: $lynis_before,
        lynis_after: $lynis_after,
        index_delta: $index_delta,
        controls_touched: $controls_touched
    }' > "$HARDEN_FILE"; then
    fail_environment "unable to create $HARDEN_FILE"
fi

if [[ "$status" -eq 0 ]]; then
    exit 0
fi

exit 1
