#!/bin/bash

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

set -o pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPSTONE_DIR="$BASE_DIR/capstone"
PATCH_DIR="$CAPSTONE_DIR/patch"
SUMMARY_FILE="$PATCH_DIR/patch_pipeline.json"

CVE_FEED="/home/analyst/MedDefense_Lab/capstone/cve_feed.json"
# mandated blacklist
BLACKLIST_FILE="/home/analyst/MedDefense_Lab/capstone/blacklist.json"
PATCH_PIPELINE_SCRIPT="${PATCH_PIPELINE_SCRIPT:-$BASE_DIR/13-patch_pipeline.sh}"

APT_CONFIG="/etc/apt/apt.conf.d/52meddefense-unattended-upgrades"
LOG_FILE="$PATCH_DIR/patch_pipeline.log"

status=0

fail_control() {
    printf 'error=%s\n' "$1" >&2
    status=1
}

fail_environment() {
    printf 'error=%s\n' "$1" >&2
    exit 2
}

for command in jq apt-get systemctl unattended-upgrade find; do
    if ! command -v "$command" >/dev/null 2>&1; then
        fail_environment "missing dependency: $command"
    fi
done

if [[ "$EUID" -ne 0 ]]; then
    fail_environment "script must run as root"
fi

if [[ ! -r "$CVE_FEED" ]]; then
    fail_environment "missing input file: $CVE_FEED"
fi

if [[ ! -r "$BLACKLIST_FILE" ]]; then
    fail_environment "missing input file: $BLACKLIST_FILE"
fi

if [[ ! -f "$PATCH_PIPELINE_SCRIPT" ]]; then
    fail_environment "missing pipeline script: $PATCH_PIPELINE_SCRIPT"
fi

if ! jq empty "$CVE_FEED" >/dev/null 2>&1; then
    fail_environment "invalid CVE feed: $CVE_FEED"
fi

if ! jq empty "$BLACKLIST_FILE" >/dev/null 2>&1; then
    fail_environment "invalid blacklist: $BLACKLIST_FILE"
fi

mkdir -p "$PATCH_DIR" || {
    fail_environment "unable to create $PATCH_DIR"
}

# Copy inputs into the capstone package.
if ! cp "$CVE_FEED" "$PATCH_DIR/cve_feed.json"; then
    fail_environment "unable to copy CVE feed"
fi

if ! cp "$BLACKLIST_FILE" "$PATCH_DIR/blacklist.json"; then
    fail_environment "unable to copy blacklist"
fi

# Build the unattended-upgrades blacklist.
blacklist=$(jq -r '
    if type == "array" then
        .[]
    elif .blacklist then
        .blacklist[]
    elif .packages then
        .packages[]
    else
        empty
    end
' "$BLACKLIST_FILE")

if [[ -z "$blacklist" ]]; then
    fail_environment "blacklist.json contains no blacklist entries"
fi

{
    printf '// MedDefense unattended-upgrades configuration\n'
    printf 'Unattended-Upgrade::Package-Blacklist {\n'

    while IFS= read -r package; do
        [[ -z "$package" ]] && continue
        printf '    "%s";\n' "$package"
    done <<< "$blacklist"

    printf '};\n'
} > "$APT_CONFIG" || {
    fail_environment "unable to configure unattended-upgrades"
}

if ! unattended-upgrade --dry-run >/dev/null 2>&1; then
    fail_control "unattended-upgrades configuration validation failed"
fi

# Ensure the package metadata is available.
if ! apt-get update >/dev/null 2>&1; then
    fail_control "apt-get update failed"
fi

printf 'pipeline_start=%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$LOG_FILE"

pipeline_start=$(date +%s)

# CAPSTONE_ARTIFACTS_DIR=capstone/patch/
CAPSTONE_ARTIFACTS_DIR="$PATCH_DIR" \
CVE_FEED="$PATCH_DIR/cve_feed.json" \
BLACKLIST_FILE="$PATCH_DIR/blacklist.json" \
"$PATCH_PIPELINE_SCRIPT" >> "$LOG_FILE" 2>&1

pipeline_exit_code=$?

pipeline_end=$(date +%s)
pipeline_duration=$((pipeline_end - pipeline_start))

printf 'pipeline_exit_code=%s\n' "$pipeline_exit_code" >> "$LOG_FILE"
printf 'pipeline_duration_seconds=%s\n' "$pipeline_duration" >> "$LOG_FILE"

if [[ "$pipeline_exit_code" -ne 0 ]]; then
    fail_control "patch pipeline failed with exit code $pipeline_exit_code"
fi

# Collect every artifact generated under the patch directory.
artifact_json='[]'

while IFS= read -r artifact; do
    [[ -z "$artifact" ]] && continue

    relative_path="${artifact#"$BASE_DIR"/}"

    artifact_json=$(
        jq -c \
            --arg path "$relative_path" \
            '. + [$path]' <<< "$artifact_json"
    ) || {
        fail_control "unable to record pipeline artifact"
        break
    }
done < <(
    find "$PATCH_DIR" \
        -type f \
        ! -name 'patch_pipeline.json' \
        -print 2>/dev/null |
        sort
)

# failed_entries == 0
failed_entries=0

# Prefer the pipeline's own summary fields when available.
for summary in \
    "$PATCH_DIR/patch_summary.json" \
    "$PATCH_DIR/pipeline_summary.json" \
    "$PATCH_DIR/summary.json"; do

    if [[ -r "$summary" ]] &&
        jq -e '.failed_entries != null' "$summary" >/dev/null 2>&1; then

        failed_entries=$(jq -r '.failed_entries' "$summary")

        if ! [[ "$failed_entries" =~ ^[0-9]+$ ]]; then
            fail_control "invalid failed_entries in $summary"
            failed_entries=1
        fi

        break
    fi
done

# Fall back to counting explicit failed entries in generated JSON artifacts.
if [[ "$failed_entries" -eq 0 ]]; then
    discovered_failures=$(
        find "$PATCH_DIR" \
            -type f \
            -name '*.json' \
            ! -name 'patch_pipeline.json' \
            -print0 2>/dev/null |
            xargs -0 -r jq -r '
                .. |
                objects |
                .state? // empty
            ' 2>/dev/null |
            grep -Eic '^failed$' || true
    )

    if [[ "$discovered_failures" =~ ^[0-9]+$ ]]; then
        failed_entries="$discovered_failures"
    else
        failed_entries=0
    fi
fi

if [[ "$failed_entries" -ne 0 ]]; then
    fail_control "patch pipeline contains $failed_entries failed entries"
fi

timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

if ! jq -n \
    --arg timestamp "$timestamp" \
    --arg hostname "$(hostname)" \
    --arg pipeline_script "${PATCH_PIPELINE_SCRIPT#"$BASE_DIR"/}" \
    --arg cve_feed "$PATCH_DIR/cve_feed.json" \
    --arg blacklist "$PATCH_DIR/blacklist.json" \
    --arg artifacts_dir "$PATCH_DIR" \
    --argjson pipeline_exit_code "$pipeline_exit_code" \
    --argjson pipeline_duration "$pipeline_duration" \
    --argjson failed_entries "$failed_entries" \
    --argjson artifacts "$artifact_json" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        pipeline_script: $pipeline_script,
        artifacts_directory: $artifacts_dir,
        cve_feed: $cve_feed,
        blacklist: $blacklist,
        pipeline_exit_code: $pipeline_exit_code,
        pipeline_duration_seconds: $pipeline_duration,
        failed_entries: $failed_entries,
        artifacts: $artifacts
    }' > "$SUMMARY_FILE"; then
    fail_environment "unable to create $SUMMARY_FILE"
fi

if [[ "$pipeline_exit_code" -eq 0 && "$failed_entries" -eq 0 && "$status" -eq 0 ]]; then
    exit 0
fi

exit 1
