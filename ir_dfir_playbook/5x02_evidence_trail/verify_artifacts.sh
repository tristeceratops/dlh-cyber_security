#!/bin/bash

set -u
set -o pipefail

HASH_FILE="hashes.txt"
LOG_FILE="verification_log.txt"
ACTOR="${USER:-unknown}"

ARTIFACTS=(
    "ART-001:wst-ws-031.dd"
    "ART-002:wst-ws-031.mem"
    "ART-003:wst-ws-017.mem"
)

compute_hash() {
    local file="$1"
    local output

    output=$(sha256sum -- "$file") || return 1
    printf '%s\n' "${output%% *}"
}

log_event() {
    printf '%s | %s | %s | %s | expected=%s | computed=%s\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" >> "$LOG_FILE"
}

for entry in "${ARTIFACTS[@]}"; do
    file="${entry#*:}"

    if [[ ! -f "$file" || ! -r "$file" ]]; then
        echo "[FAIL] Artifact missing or unreadable: $file" >&2
        exit 1
    fi
done

if [[ ! -f "$HASH_FILE" ]]; then
    declare -A BASELINES

    for entry in "${ARTIFACTS[@]}"; do
        id="${entry%%:*}"
        file="${entry#*:}"

        hash=$(compute_hash "$file") || {
            echo "[FAIL] Cannot hash $file" >&2
            exit 1
        }

        BASELINES["$id"]="$hash"
    done

    tmp_file=$(mktemp) || exit 1

    for entry in "${ARTIFACTS[@]}"; do
        id="${entry%%:*}"
        file="${entry#*:}"

        printf '%s %s %s\n' \
            "$id" "$file" "${BASELINES[$id]}" >> "$tmp_file"
    done

    if ! mv -- "$tmp_file" "$HASH_FILE"; then
        rm -f -- "$tmp_file"
        echo "[FAIL] Cannot write $HASH_FILE" >&2
        exit 1
    fi

    for entry in "${ARTIFACTS[@]}"; do
        id="${entry%%:*}"
        file="${entry#*:}"
        hash="${BASELINES[$id]}"
        timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

        printf '[BASELINE_SET] %s %s sha256=%s\n' \
            "$id" "$file" "$hash"

        if ! log_event "$timestamp" "$ACTOR" "$id" \
            "BASELINE_SET" "NONE" "$hash"; then
            echo "[FAIL] Cannot write $LOG_FILE" >&2
            exit 1
        fi
    done

    echo "Baseline written to $HASH_FILE. Run again to verify."
    exit 0
fi

declare -A EXPECTED_HASHES
declare -A EXPECTED_FILES

while read -r id file hash extra; do
    [[ -z "${id:-}" ]] && continue

    if [[ -n "${extra:-}" ||
          ! "$hash" =~ ^[[:xdigit:]]{64}$ ]]; then
        echo "[FAIL] Invalid baseline entry: $id" >&2
        exit 1
    fi

    if [[ -n "${EXPECTED_HASHES[$id]+x}" ]]; then
        echo "[FAIL] Duplicate baseline ID: $id" >&2
        exit 1
    fi

    EXPECTED_HASHES["$id"]="$hash"
    EXPECTED_FILES["$id"]="$file"
done < "$HASH_FILE"

if [[ "${#EXPECTED_HASHES[@]}" -ne 3 ]]; then
    echo "[FAIL] Baseline must contain exactly 3 artifacts" >&2
    exit 1
fi

failures=0

for entry in "${ARTIFACTS[@]}"; do
    id="${entry%%:*}"
    file="${entry#*:}"
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    if [[ -z "${EXPECTED_HASHES[$id]+x}" ||
          "${EXPECTED_FILES[$id]:-}" != "$file" ]]; then
        echo "[FAIL] Missing or mismatched baseline entry: $id"

        if ! log_event "$timestamp" "$ACTOR" "$id" \
            "FAIL" "MISSING_OR_MISMATCHED" "NOT_COMPUTED"; then
            echo "[FAIL] Cannot write $LOG_FILE" >&2
            exit 1
        fi

        failures=$((failures + 1))
        continue
    fi

    expected="${EXPECTED_HASHES[$id]}"

    computed=$(compute_hash "$file") || {
        echo "[FAIL] $id $file expected=$expected computed=ERROR"

        if ! log_event "$timestamp" "$ACTOR" "$id" \
            "FAIL" "$expected" "ERROR"; then
            echo "[FAIL] Cannot write $LOG_FILE" >&2
            exit 1
        fi

        failures=$((failures + 1))
        continue
    }

    if [[ "${computed,,}" == "${expected,,}" ]]; then
        result="PASS"

        printf '[PASS] %s %s expected=%s computed=%s\n' \
            "$id" "$file" "$expected" "$computed"
    else
        result="FAIL"

        printf '[FAIL] %s %s expected=%s computed=%s\n' \
            "$id" "$file" "$expected" "$computed"

        printf 'DEVIATION: %s hash mismatch at %s\n' \
            "$id" "$timestamp" >&2

        failures=$((failures + 1))
    fi

    if ! log_event "$timestamp" "$ACTOR" "$id" \
        "$result" "$expected" "$computed"; then
        echo "[FAIL] Cannot write $LOG_FILE" >&2
        exit 1
    fi
done

if [[ "$failures" -eq 0 ]]; then
    echo "ALL ARTIFACTS VERIFIED"
    exit 0
fi

echo "VERIFICATION FAILED: $failures issue(s) detected" >&2
exit 1