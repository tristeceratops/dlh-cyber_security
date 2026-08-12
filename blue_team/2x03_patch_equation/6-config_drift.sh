#!/bin/bash

PRE_FILE="pre_patch_state.json"
EXEC_FILE="patch_execution_log.json"
REPORT_FILE="config_drift.json"
DETAIL_FILE=$(mktemp)

UNCHANGED=0
MODIFIED=0
MISSING=0
NEW_FILES=0
UNEXPECTED=0

cleanup() {
    rm -f "$DETAIL_FILE"
}

trap cleanup EXIT

validate_files() {
    if [[ ! -f "$PRE_FILE" ]]; then
        echo "[-] ${PRE_FILE} not found." >&2
        exit 1
    fi

    if [[ ! -f "$EXEC_FILE" ]]; then
        echo "[-] ${EXEC_FILE} not found." >&2
        exit 1
    fi

    if ! jq -e '.conffile_hashes | type == "object"' "$PRE_FILE" >/dev/null 2>&1; then
        echo "[-] Invalid ${PRE_FILE}: conffile_hashes must be an object." >&2
        exit 1
    fi

    if ! jq -e '.entries | type == "array"' "$EXEC_FILE" >/dev/null 2>&1; then
        echo "[-] Invalid ${EXEC_FILE}: entries must be an array." >&2
        exit 1
    fi
}

get_pre_hash() {
    local path="$1"

    jq -r \
        --arg path "$path" \
        '.conffile_hashes[$path].hash // ""' \
        "$PRE_FILE"
}

get_owner() {
    local path="$1"
    local owner

    owner=$(jq -r \
        --arg path "$path" \
        '.conffile_hashes[$path].owning_package // ""' \
        "$PRE_FILE")

    if [[ -n "$owner" && "$owner" != "null" ]]; then
        printf '%s\n' "$owner"
        return
    fi

    dpkg-query -S "$path" 2>/dev/null |
        head -1 |
        cut -d: -f1 |
        tr -d ' '
}

get_upgraded_packages() {
    jq -r '
        .entries[]
        | select(.status == "success")
        | .package
    ' "$EXEC_FILE" 2>/dev/null
}

package_was_upgraded() {
    local package="$1"

    grep -Fxq "$package" <<< "$UPGRADED_PACKAGES"
}

calculate_hash() {
    local path="$1"

    if [[ -f "$path" ]]; then
        sha256sum "$path" 2>/dev/null | awk '{print $1}'
    fi
}

get_diff() {
    local path="$1"
    local old_hash="$2"

    if [[ -f "$path" ]]; then
        diff -u \
            <(printf '# pre-patch hash: %s\n' "$old_hash") \
            "$path" 2>/dev/null |
            head -40 || true
    fi
}

write_result() {
    local path="$1"
    local owner="$2"
    local classification="$3"
    local old_hash="$4"
    local new_hash="$5"
    local expected="$6"
    local diff_text="$7"

    jq -n -c \
        --arg path "$path" \
        --arg owner "$owner" \
        --arg classification "$classification" \
        --arg old_hash "$old_hash" \
        --arg new_hash "$new_hash" \
        --argjson expected "$expected" \
        --arg diff "$diff_text" \
        '{
            path: $path,
            owning_package: $owner,
            classification: $classification,
            old_hash: $old_hash,
            new_hash: $new_hash,
            expected: $expected,
            diff: $diff
        }' >> "$DETAIL_FILE"
}

classify_file() {
    local path="$1"
    local old_hash
    local new_hash
    local owner
    local classification
    local expected
    local diff_text

    old_hash=$(get_pre_hash "$path")
    owner=$(get_owner "$path")
    new_hash=""
    classification=""
    expected=false
    diff_text=""

    if [[ ! -f "$path" ]]; then
        classification="missing"
        ((MISSING++))
    else
        new_hash=$(calculate_hash "$path")

        if [[ "$new_hash" == "$old_hash" ]]; then
            classification="unchanged"
            ((UNCHANGED++))
        else
            classification="modified"
            ((MODIFIED++))

            diff_text=$(get_diff "$path" "$old_hash")

            if [[ -n "$owner" ]] && package_was_upgraded "$owner"; then
                expected=true
            else
                ((UNEXPECTED++))
                echo "  [!] unexpected drift: ${path} (owning_package: ${owner:-unknown})"
            fi
        fi
    fi

    write_result \
        "$path" \
        "${owner:-unknown}" \
        "$classification" \
        "$old_hash" \
        "$new_hash" \
        "$expected" \
        "$diff_text"
}

scan_existing_files() {
    jq -r '.conffile_hashes | keys[]' "$PRE_FILE" |
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        classify_file "$path"
    done
}

is_known_file() {
    local path="$1"

    jq -e \
        --arg path "$path" \
        '.conffile_hashes | has($path)' \
        "$PRE_FILE" >/dev/null 2>&1
}

scan_new_files() {
    while IFS= read -r package; do
        [[ -z "$package" ]] && continue

        while IFS= read -r path; do
            [[ -z "$path" ]] && continue

            if ! is_known_file "$path" && [[ -f "$path" ]]; then
                local hash

                hash=$(calculate_hash "$path")

                ((NEW_FILES++))

                write_result \
                    "$path" \
                    "$package" \
                    "new" \
                    "" \
                    "$hash" \
                    true \
                    ""
            fi
        done < <(
            dpkg-query -W -f='${Conffiles}\n' "$package" 2>/dev/null |
                awk '{print $1}' |
                grep '^/' || true
        )
    done <<< "$UPGRADED_PACKAGES"
}

build_report() {
    local total
    local passed
    local failed

    total=$((UNCHANGED + MODIFIED + MISSING + NEW_FILES))
    passed=$((UNCHANGED + NEW_FILES))
    failed=$((MODIFIED + MISSING))

    jq -n \
        --argjson unchanged "$UNCHANGED" \
        --argjson modified "$MODIFIED" \
        --argjson missing "$MISSING" \
        --argjson new "$NEW_FILES" \
        --argjson unexpected "$UNEXPECTED" \
        --slurpfile files "$DETAIL_FILE" \
        '{
            summary: {
                unchanged: $unchanged,
                modified: $modified,
                missing: $missing,
                new: $new,
                unexpected: $unexpected
            },
            files: $files
        }' > "$REPORT_FILE"
}

print_report() {
    echo
    echo "Summary: unchanged=${UNCHANGED} modified=${MODIFIED} missing=${MISSING} new=${NEW_FILES} unexpected=${UNEXPECTED}"
    echo "Log saved to: ${REPORT_FILE}"

    jq -c '
        .files[]
        | select(.classification == "modified")
        | {
            path,
            owning_package,
            expected
        }
    ' "$REPORT_FILE"
}

main() {
    validate_files

    echo "[*] Loading pre-patch conffile_hashes from ${PRE_FILE}..."

    UPGRADED_PACKAGES=$(get_upgraded_packages)

    if [[ -n "$UPGRADED_PACKAGES" ]]; then
        echo "[*] Packages upgraded this run:"
        echo "$UPGRADED_PACKAGES"
    else
        echo "[*] Packages upgraded this run: none"
    fi

    echo "[*] Recomputing SHA-256 hashes and classifying files..."

    scan_existing_files
    scan_new_files
    build_report
    print_report

    if [[ "$UNEXPECTED" -gt 0 ]]; then
        return 1
    fi

    return 0
}

main
exit $?

