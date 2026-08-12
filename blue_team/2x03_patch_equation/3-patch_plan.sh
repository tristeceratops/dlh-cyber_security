#!/bin/bash

VULNERABILITY_JSON="vulnerability_inventory.json"
DEPENDENCY_JSON="service_dependency_map.json"
PLAN_JSON="patch_plan.json"
TEMP_PLAN="plan_tmp.jsonl"

WEIGHT_CVSS=0.5
WEIGHT_KEV=2.0
WEIGHT_CRITICALITY=1.0
WEIGHT_EXPOSURE=0.5

GENERATED_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

EMERGENCY_COUNT=0
URGENT_COUNT=0
SCHEDULED_COUNT=0
REBOOT_NEEDED="no"

initialize_plan() {
    jq -n \
        --arg timestamp "$GENERATED_TIME" \
        --argjson cvss "$WEIGHT_CVSS" \
        --argjson kev "$WEIGHT_KEV" \
        --argjson criticality "$WEIGHT_CRITICALITY" \
        --argjson exposure "$WEIGHT_EXPOSURE" \
        '{
            generated_at: $timestamp,
            weights: {
                cvss_weight: $cvss,
                kev_weight: $kev,
                criticality_weight: $criticality,
                exposure_weight: $exposure
            },
            plan: [],
            summary: {}
        }' > "$PLAN_JSON"

    : > "$TEMP_PLAN"
}

get_criticality_score() {
    local service_name="$1"
    local level

    level=$(jq -s -r \
        --arg service "$service_name" \
        'map(select(.service == $service)) | .[0].criticality // "low"' \
        "$DEPENDENCY_JSON" 2>/dev/null)

    case "$level" in
        critical) echo 4 ;;
        high) echo 3 ;;
        medium) echo 2 ;;
        *) echo 1 ;;
    esac
}

get_affected_services() {
    local package_name="$1"

    jq -s -r \
        --arg package "$package_name" \
        'map(
            select(
                (.linked_packages[]? == $package) or
                (.owning_package == $package)
            )
        ) | .[].service' \
        "$DEPENDENCY_JSON" 2>/dev/null |
        sort -u
}

build_affected_services() {
    local package_name="$1"
    local affected
    local highest_score=0

    affected=$(get_affected_services "$package_name")

    if [ -z "$affected" ]; then
        echo "[]"
        return
    fi

    while read -r service_name; do
        [ -z "$service_name" ] && continue

        current_score=$(get_criticality_score "$service_name")

        if [ "$current_score" -gt "$highest_score" ]; then
            highest_score="$current_score"
        fi
    done <<< "$affected"

    AFFECTED_CRITICALITY="$highest_score"

    echo "$affected" |
        awk 'NF' |
        jq -R . |
        jq -s -c .
}

check_reboot_requirement() {
    local package_name="$1"
    local affected_services="$2"

    PACKAGE_REBOOT="false"

    if [[ "$package_name" == *"linux-image"* ]] ||
       [[ "$package_name" == "systemd" ]]; then
        PACKAGE_REBOOT="true"
        REBOOT_NEEDED="yes"

        if [ "$affected_services" = "[]" ]; then
            echo '["(kernel-wide)"]'
            return
        fi
    fi

    echo "$affected_services"
}

calculate_restart_requirement() {
    local affected_services="$1"
    local package_reboot="$2"

    if [ "$affected_services" != "[]" ] &&
       [ "$package_reboot" = "false" ]; then
        echo "true"
    else
        echo "false"
    fi
}

calculate_score() {
    local cvss_value="$1"
    local kev_value="$2"
    local criticality_value="$3"
    local exposure_value="$4"

    awk "BEGIN {
        printf \"%.2f\", \
        ($WEIGHT_CVSS * $cvss_value) +
        ($WEIGHT_KEV * $kev_value) +
        ($WEIGHT_CRITICALITY * $criticality_value) +
        ($WEIGHT_EXPOSURE * $exposure_value)
    }"
}

get_bucket() {
    local score_value="$1"

    if awk "BEGIN {exit !($score_value >= 7.0)}"; then
        echo "emergency"
    elif awk "BEGIN {exit !($score_value >= 4.0 && $score_value < 7.0)}"; then
        echo "urgent"
    else
        echo "scheduled"
    fi
}

update_bucket_count() {
    case "$1" in
        emergency)
            ((EMERGENCY_COUNT++))
            ;;
        urgent)
            ((URGENT_COUNT++))
            ;;
        scheduled)
            ((SCHEDULED_COUNT++))
            ;;
    esac
}

process_package() {
    local index="$1"

    local package_name
    local cvss_value
    local kev_status
    local installed_version
    local kev_score
    local affected_services
    local restart_flag
    local reboot_flag
    local priority_score
    local priority_bucket
    local rollback_version

    package_name=$(jq -r ".packages[$index].package" "$VULNERABILITY_JSON")
    cvss_value=$(jq -r ".packages[$index].max_cvss" "$VULNERABILITY_JSON")
    kev_status=$(jq -r ".packages[$index].in_cisa_kev" "$VULNERABILITY_JSON")
    installed_version=$(jq -r ".packages[$index].installed_version" "$VULNERABILITY_JSON")

    if [ -z "$cvss_value" ] || [ "$cvss_value" = "null" ]; then
        cvss_value=0.0
    fi

    if [ "$kev_status" = "true" ]; then
        kev_score=1
    else
        kev_score=0
    fi

    affected_services=$(build_affected_services "$package_name")

    affected_services=$(check_reboot_requirement \
        "$package_name" \
        "$affected_services")

    reboot_flag="$PACKAGE_REBOOT"

    restart_flag=$(calculate_restart_requirement \
        "$affected_services" \
        "$reboot_flag")

    priority_score=$(calculate_score \
        "$cvss_value" \
        "$kev_score" \
        "$AFFECTED_CRITICALITY" \
        1)

    priority_bucket=$(get_bucket "$priority_score")

    update_bucket_count "$priority_bucket"

    rollback_version="$installed_version"

    jq -n -c \
        --arg package "$package_name" \
        --argjson score "$priority_score" \
        --arg bucket "$priority_bucket" \
        --argjson affected "$affected_services" \
        --argjson restart "$restart_flag" \
        --argjson reboot "$reboot_flag" \
        --arg rollback "$rollback_version" \
        '{
            package: $package,
            score: $score,
            bucket: $bucket,
            affected_services: $affected,
            requires_restart: $restart,
            requires_reboot: $reboot,
            rollback_target_version: $rollback
        }' >> "$TEMP_PLAN"
}

build_plan() {
    local package_count
    local index

    package_count=$(jq '.packages | length' "$VULNERABILITY_JSON" 2>/dev/null || echo 0)

    for ((index=0; index<package_count; index++)); do
        process_package "$index"
    done
}

sort_plan() {
    if [ -s "$TEMP_PLAN" ]; then
        jq -s '
            sort_by(.score)
            | reverse
            | to_entries
            | map(.value + {rank: (.key + 1)})
        ' "$TEMP_PLAN"
    else
        echo "[]"
    fi
}

build_summary() {
    local reboot_message="no"

    if [ "$REBOOT_NEEDED" = "yes" ]; then
        reboot_message="yes (kernel update present)"
    fi

    jq -n \
        --argjson emergency "$EMERGENCY_COUNT" \
        --argjson urgent "$URGENT_COUNT" \
        --argjson scheduled "$SCHEDULED_COUNT" \
        --arg reboot "$reboot_message" \
        '{
            emergency: $emergency,
            urgent: $urgent,
            scheduled: $scheduled,
            reboot_required: $reboot
        }'
}

write_final_plan() {
    local ordered_plan
    local summary

    ordered_plan=$(sort_plan)
    summary=$(build_summary)

    jq \
        --argjson plan "$ordered_plan" \
        --argjson summary "$summary" \
        '.plan = $plan | .summary = $summary' \
        "$PLAN_JSON" > "${PLAN_JSON}.tmp" &&
        mv "${PLAN_JSON}.tmp" "$PLAN_JSON"
}

print_result() {
    local reboot_message="no"

    if [ "$REBOOT_NEEDED" = "yes" ]; then
        reboot_message="yes (kernel update present)"
    fi

    echo "Emergency: $EMERGENCY_COUNT   Urgent: $URGENT_COUNT   Scheduled: $SCHEDULED_COUNT"
    echo "Reboot required by plan: $reboot_message"
    echo "Report saved to: $PLAN_JSON"
}

main() {
    initialize_plan
    build_plan
    write_final_plan
    rm -f "$TEMP_PLAN"
    print_result
}

main

