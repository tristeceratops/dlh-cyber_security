#!/bin/bash

# Exit codes: 0 success, 1 validation failure, 2 environment error.

# total controls

set -o pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_STATE="$BASE_DIR/capstone/target_state.json"

fail_environment() {
    printf 'error=%s\n' "$1" >&2
    exit 2
}

command -v jq >/dev/null 2>&1 ||
    fail_environment "missing dependency: jq"

command -v grep >/dev/null 2>&1 ||
    fail_environment "missing dependency: grep"

[[ -r "$TARGET_STATE" ]] ||
    fail_environment "missing input file: $TARGET_STATE"

jq empty "$TARGET_STATE" >/dev/null 2>&1 ||
    fail_environment "invalid JSON: $TARGET_STATE"

control_count="$(jq '.controls | length' "$TARGET_STATE")" || {
    fail_environment "unable to read controls"
}

[[ "$control_count" =~ ^[0-9]+$ ]] ||
    fail_environment "invalid control count"

printf '%-16s %-9s %-6s %-6s %-7s\n' \
    "FAMILY" "TOTAL" "PASS" "FAIL" "ERROR"
printf '%s\n' '------------------------------------------------'

families="$(
    jq -r '.controls[].family' "$TARGET_STATE" | sort -u
)"

total=0
pass_count=0
fail_count=0
error_count=0

while IFS= read -r family; do
    [[ -z "$family" ]] && continue

    family_total=0
    family_pass=0
    family_fail=0
    family_error=0

    while IFS= read -r control; do
        family_total=$((family_total + 1))
        total=$((total + 1))

        id="$(jq -r '.id' <<< "$control")"
        check_type="$(jq -r '.check_type' <<< "$control")"
        target="$(jq -r '.check_target' <<< "$control")"
        expected="$(jq -c '.expected_value' <<< "$control")"

        verdict="error"
        evidence=""

        case "$check_type" in
            file_exists)
                if [[ -e "$target" ]]; then
                    verdict="pass"
                    evidence="path exists: $target"
                else
                    verdict="fail"
                    evidence="path missing: $target"
                fi
                ;;

            json_field_equals|json_field_gte)
                json_file="${target%%.*}"
                field="${target#*.}"

                if [[ ! -r "$BASE_DIR/$json_file" ]]; then
                    if [[ -r "$json_file" ]]; then
                        json_file="$json_file"
                    else
                        verdict="error"
                        evidence="JSON file missing: $json_file"
                        field=""
                    fi
                else
                    json_file="$BASE_DIR/$json_file"
                fi

                if [[ -n "$field" ]]; then
                    actual="$(
                        jq -r --arg path "$field" '
                            getpath(($path | split(".")))
                        ' "$json_file" 2>/dev/null
                    )" || {
                        verdict="error"
                        evidence="unable to read JSON field: $target"
                        actual=""
                    }

                    if [[ -n "$actual" ]]; then
                        case "$check_type" in
                            json_field_equals)
                                expected_value="$(jq -r '.' <<< "$expected")"
                                if [[ "$actual" == "$expected_value" ]]; then
                                    verdict="pass"
                                    evidence="path=$target value=$actual"
                                else
                                    verdict="fail"
                                    evidence="path=$target value=$actual expected=$expected_value"
                                fi
                                ;;

                            json_field_gte)
                                expected_value="$(jq -r '.' <<< "$expected")"
                                if ! [[ "$actual" =~ ^-?[0-9]+([.][0-9]+)?$ ]] ||
                                    ! [[ "$expected_value" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
                                    verdict="error"
                                    evidence="non-numeric value at $target"
                                elif awk -v actual="$actual" -v expected="$expected_value" \
                                    'BEGIN { exit !(actual >= expected) }'; then
                                    verdict="pass"
                                    evidence="path=$target value=$actual expected>=$expected_value"
                                else
                                    verdict="fail"
                                    evidence="path=$target value=$actual expected>=$expected_value"
                                fi
                                ;;
                        esac
                    fi
                fi
                ;;

            command_exit_zero)
                if bash -c "$target" >/dev/null 2>&1; then
                    verdict="pass"
                    evidence="command succeeded: $target"
                else
                    rc=$?
                    verdict="fail"
                    evidence="command exit=$rc: $target"
                fi
                ;;

            grep_match)
                if [[ -f "$target" ]]; then
                    if grep -Eq "$expected" "$target"; then
                        verdict="pass"
                        evidence="match=$expected file=$target"
                    else
                        verdict="fail"
                        evidence="no match=$expected file=$target"
                    fi
                elif [[ "$target" == *" "* ]]; then
                    if bash -c "$target" 2>/dev/null | grep -Eq "$expected"; then
                        verdict="pass"
                        evidence="match=$expected command=$target"
                    else
                        verdict="fail"
                        evidence="no match=$expected command=$target"
                    fi
                else
                    verdict="error"
                    evidence="file missing: $target"
                fi
                ;;

            *)
                verdict="error"
                evidence="unsupported check_type=$check_type"
                ;;
        esac

        case "$verdict" in
            pass)
                family_pass=$((family_pass + 1))
                pass_count=$((pass_count + 1))
                ;;
            fail)
                family_fail=$((family_fail + 1))
                fail_count=$((fail_count + 1))
                ;;
            error)
                family_error=$((family_error + 1))
                error_count=$((error_count + 1))
                ;;
        esac

        printf '%s: %s (%s)\n' "$id" "$verdict" "$evidence" >&2
    done < <(
        jq -c --arg family "$family" \
            '.controls[] | select(.family == $family)' "$TARGET_STATE"
    )

    printf '%-16s %-9d %-6d %-6d %-7d\n' \
        "$family" "$family_total" "$family_pass" \
        "$family_fail" "$family_error"
done <<< "$families"

# pass percentage
if [[ "$total" -gt 0 ]]; then
    pass_percentage="$(awk \
        -v pass="$pass_count" \
        -v total="$total" \
        'BEGIN { printf "%.2f", (pass / total) * 100 }')"
else
    pass_percentage="0.00"
fi

# clean table
printf '%s\n' '------------------------------------------------'
printf 'TOTAL: %d  PASS: %d  FAIL: %d  ERROR: %d  PASS%%: %s\n' \
    "$total" "$pass_count" "$fail_count" "$error_count" "$pass_percentage"

if [[ "$fail_count" -eq 0 && "$error_count" -eq 0 ]]; then
    exit 0
fi

exit 1
