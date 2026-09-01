#!/bin/bash
set -euo pipefail

REGISTRY="hold_registry.json"
REPORT="hold_management.json"
PRE_STATE="hold_management_pre.json"
PIN_FILE="/etc/apt/preferences.d/meddefense-pins"
PIN_BACKUP="${PIN_FILE}.pre-$(date +%Y%m%d%H%M%S).$$"

die() {
    printf '[!] %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

cleanup() {
    rm -f "${PIN_FILE}.tmp" "${REPORT}.tmp" "${PRE_STATE}.tmp"
}

trap cleanup EXIT

require_cmd apt-mark
require_cmd dpkg-query
require_cmd jq
require_cmd date
require_cmd cmp
require_cmd install

[[ $EUID -eq 0 ]] || die "Run as root (for example: sudo ./10-version_hold.sh)"
[[ -f "$REGISTRY" ]] || die "Registry not found: $REGISTRY"

# Validate the complete declarative input before changing package state.
jq -e '
    . as $root
    | ($root | keys | sort) == ["holds"]
    and (.holds | type == "array")
    and all(.holds[];
        (. | type == "object")
        and ((keys | sort) == ["owner", "package", "pin_version", "reason", "review_date"])
        and (.package | type == "string")
        and (.reason | type == "string")
        and (.owner | type == "string")
        and (.review_date | type == "string")
        and (.pin_version | type == "string")
        and (.package | test("^[a-z0-9][a-z0-9+.-]*$"))
        and (.review_date | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
        and (.pin_version | test("^[^[:space:]]+$"))
    )
    and ([.holds[].package] | length == unique | length)
' "$REGISTRY" >/dev/null || die "Invalid hold_registry.json schema or duplicate/unsafe package name"

TODAY="$(date +%F)"
TODAY_EPOCH="$(date -d "$TODAY" +%s)" || die "Unable to determine today's date"

mapfile -t REGISTRY_PACKAGES < <(jq -r '.holds[].package' "$REGISTRY")
REGISTRY_COUNT="${#REGISTRY_PACKAGES[@]}"

mapfile -t CURRENT_HOLDS < <(apt-mark showhold | sort)
CURRENT_COUNT="${#CURRENT_HOLDS[@]}"

printf '[*] Reading hold_registry.json...           (%d entries)\n' "$REGISTRY_COUNT"
printf '[*] Reading current apt-mark showhold...    (%d entries)\n' "$CURRENT_COUNT"

# Measure-before-change artifact. It contains package versions, current holds,
# and the previous contents of the managed preferences fragment.
{
    printf '{\n'
    printf '  "captured_at": %s,\n' "$(jq -Rn --arg v "$(date --iso-8601=seconds)" '$v')"
    printf '  "today": %s,\n' "$(jq -Rn --arg v "$TODAY" '$v')"
    printf '  "current_holds": %s,\n' \
        "$(printf '%s\n' "${CURRENT_HOLDS[@]}" | jq -R -s 'split("\n") | map(select(length > 0))')"
    printf '  "packages": [\n'

    first=1
    while IFS= read -r package; do
        [[ -n "$package" ]] || continue

        installed_version="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)"

        if [[ -z "$installed_version" ]]; then
            installed_json='null'
        else
            installed_json="$(jq -Rn --arg v "$installed_version" '$v')"
        fi

        if (( first == 0 )); then
            printf ',\n'
        fi
        first=0

        jq -cn \
            --arg package "$package" \
            --argjson installed_version "$installed_json" \
            '{
                package: $package,
                installed_version: $installed_version
            }'
    done < <(jq -r '.holds[].package' "$REGISTRY")

    printf '\n  ],\n'

    if [[ -e "$PIN_FILE" ]]; then
        cp -- "$PIN_FILE" "$PIN_BACKUP"
        PIN_EXISTS=true
        PIN_CONTENT="$(cat -- "$PIN_FILE")"
    else
        PIN_EXISTS=false
        PIN_CONTENT=""
    fi

    jq -cn \
        --arg path "$PIN_FILE" \
        --arg backup "$PIN_BACKUP" \
        --arg content "$PIN_CONTENT" \
        --argjson exists "$PIN_EXISTS" \
        '{
            pin_file: {
                path: $path,
                existed: $exists,
                backup: (if $exists then $backup else null end),
                content: $content
            }
        }' | sed 's/^/  /'

    printf '\n}\n'
} > "${PRE_STATE}.tmp"

mv -- "${PRE_STATE}.tmp" "$PRE_STATE"

# Build the desired preferences fragment deterministically.
PIN_TMP="${PIN_FILE}.tmp"
{
    printf '# Managed exclusively by 10-version_hold.sh\n'
    printf '# Source: hold_registry.json\n'
    printf '# Do not edit manually.\n\n'

    while IFS=$'\t' read -r package reason owner review_date pin_version; do
        printf '# Package: %s\n' "$package"
        printf '# Reason: %s\n' "$reason"
        printf '# Owner: %s\n' "$owner"
        printf '# Review date: %s\n' "$review_date"
        printf 'Package: %s\n' "$package"
        printf 'Pin: version %s\n' "$pin_version"
        printf 'Pin-Priority: 1001\n\n'
    done < <(
        jq -r '.holds[] | [
            .package,
            .reason,
            .owner,
            .review_date,
            .pin_version
        ] | @tsv' "$REGISTRY"
    )
} > "$PIN_TMP"

# Only replace the pin fragment if its desired contents differ.
pin_changed=true
if [[ -f "$PIN_FILE" ]] && cmp -s "$PIN_TMP" "$PIN_FILE"; then
    pin_changed=false
    rm -f -- "$PIN_TMP"
else
    install -o root -g root -m 0644 "$PIN_TMP" "$PIN_FILE"
    rm -f -- "$PIN_TMP"
fi

printf 'Applying holds:\n'

applied_json='[]'
overdue_json='[]'

while IFS=$'\t' read -r package reason owner review_date pin_version; do
    hold_action="already held"

    if ! printf '%s\n' "${CURRENT_HOLDS[@]}" | grep -Fxq -- "$package"; then
        apt-mark hold "$package" >/dev/null
        hold_action="hold applied"
    fi

    review_epoch="$(date -d "$review_date" +%s 2>/dev/null)" ||
        die "Invalid review_date for $package: $review_date"

    days_to_review=$(( (review_epoch - TODAY_EPOCH) / 86400 ))

    applied_json="$(
        jq -cn \
            --argjson current "$applied_json" \
            --arg package "$package" \
            --arg reason "$reason" \
            --arg owner "$owner" \
            --arg review_date "$review_date" \
            --arg pin_version "$pin_version" \
            --arg action "$hold_action" \
            --argjson days "$days_to_review" \
            '$current + [{
                package: $package,
                reason: $reason,
                owner: $owner,
                review_date: $review_date,
                pin_version: $pin_version,
                days_to_review: $days,
                action: $action
            }]'
    )"

    if (( days_to_review < 0 )); then
        overdue_json="$(
            jq -cn \
                --argjson current "$overdue_json" \
                --arg package "$package" \
                --arg review_date "$review_date" \
                --argjson days "$days_to_review" \
                '$current + [{
                    package: $package,
                    review_date: $review_date,
                    days_to_review: $days
                }]'
        )"
    fi

    printf '  %-25s hold + pin %-30s OK\n' "$package" "$pin_version"
done < <(
    jq -r '.holds[] | [
        .package,
        .reason,
        .owner,
        .review_date,
        .pin_version
    ] | @tsv' "$REGISTRY"
)

# Convergence: release every existing hold not declared by the registry.
released_json='[]'
released_count=0

printf 'Releasing holds no longer in registry:\n'

for package in "${CURRENT_HOLDS[@]}"; do
    if ! printf '%s\n' "${REGISTRY_PACKAGES[@]}" | grep -Fxq -- "$package"; then
        apt-mark unhold "$package" >/dev/null
        released_json="$(
            jq -cn \
                --argjson current "$released_json" \
                --arg package "$package" \
                '$current + [$package]'
        )"
        released_count=$((released_count + 1))
        printf '  %s                                                   OK\n' "$package"
    fi
done

if (( released_count == 0 )); then
    printf '  (none)\n'
fi

# Validate the resulting package state after modifications.
mapfile -t FINAL_HOLDS < <(apt-mark showhold | sort)

expected_holds="$(
    jq -r '.holds[].package' "$REGISTRY" | sort
)"

actual_holds="$(printf '%s\n' "${FINAL_HOLDS[@]}")"

if [[ "$expected_holds" != "$actual_holds" ]]; then
    die "Post-operation validation failed: apt-mark holds do not match registry"
fi

# Validate the managed preferences fragment against the desired content.
if [[ "$pin_changed == true" ]]; then
    :
fi

# Recompute the pin content hash-equivalent by comparing against the registry
# generated representation. This also catches an unexpected modification.
VALIDATION_TMP="$(mktemp)"
trap 'rm -f "$VALIDATION_TMP"; cleanup' EXIT

{
    printf '# Managed exclusively by 10-version_hold.sh\n'
    printf '# Source: hold_registry.json\n'
    printf '# Do not edit manually.\n\n'

    while IFS=$'\t' read -r package reason owner review_date pin_version; do
        printf '# Package: %s\n' "$package"
        printf '# Reason: %s\n' "$reason"
        printf '# Owner: %s\n' "$owner"
        printf '# Review date: %s\n' "$review_date"
        printf 'Package: %s\n' "$package"
        printf 'Pin: version %s\n' "$pin_version"
        printf 'Pin-Priority: 1001\n\n'
    done < <(
        jq -r '.holds[] | [
            .package,
            .reason,
            .owner,
            .review_date,
            .pin_version
        ] | @tsv' "$REGISTRY"
    )
} > "$VALIDATION_TMP"

cmp -s "$VALIDATION_TMP" "$PIN_FILE" ||
    die "Post-operation validation failed: pin fragment differs from registry"

# Final machine-readable deliverable.
jq -n \
    --arg generated_at "$(date --iso-8601=seconds)" \
    --arg today "$TODAY" \
    --argjson applied "$applied_json" \
    --argjson released "$released_json" \
    --argjson overdue "$overdue_json" \
    --argjson total_held "${#FINAL_HOLDS[@]}" \
    '{
        generated_at: $generated_at,
        today: $today,
        applied: $applied,
        released: $released,
        overdue_reviews: $overdue,
        total_held: $total_held
    }' > "${REPORT}.tmp"

mv -- "${REPORT}.tmp" "$REPORT"

printf 'Overdue reviews: %d\n' "$(jq 'length' <<< "$overdue_json")"
printf 'Report saved to: %s\n' "$REPORT"
