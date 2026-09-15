#!/bin/bash
set -euo pipefail

fail() {
    echo "[intake] ERROR: $*" >&2
    exit 1
}

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || fail "$name is not set"
}

version_of() {
    local binary="$1"
    case "$binary" in
        jq)
            jq --version 2>&1 | sed 's/^jq-//'
            ;;
        python3)
            python3 --version 2>&1 | awk '{print $2}'
            ;;
        yq)
            yq --version 2>&1 | sed -E 's/.*version[[:space:]]+v?([^,[:space:]]+).*/\1/'
            ;;
        sigma-cli)
            sigma-cli --version 2>&1 | awk '{print $NF}'
            ;;
        sha256sum)
            sha256sum --version 2>&1 | head -n 1 | awk '{print $NF}'
            ;;
        *)
            fail "unsupported version lookup: $binary"
            ;;
    esac
}

require_env CAPSTONE_PACK
require_env ASSETS_DIR
require_env WAZUH_EXPORTS
require_env SHIFT_WORKSPACE
require_env PIPELINE_BIN
require_env BASELINE_BIN
require_env CATALOG_DIR
require_env TRIAGE_BIN

declare -A TOOL_VERSIONS

for binary in jq python3 yq sigma-cli sha256sum; do
    command -v "$binary" >/dev/null 2>&1 || fail "missing binary: $binary"

    if [[ "$binary" == "sha256sum" ]]; then
        TOOL_VERSIONS["$binary"]="present"
        echo "[intake] sha256sum OK"
    else
        version="$(version_of "$binary")"
        [[ -n "$version" ]] || fail "could not determine version of $binary"
        TOOL_VERSIONS["$binary"]="$version"
        echo "[intake] $binary $version OK"
    fi
done

[[ -x "$PIPELINE_BIN" ]] || fail "PIPELINE_BIN is not an executable file: $PIPELINE_BIN"
echo "[intake] PIPELINE_BIN OK"

[[ -x "$BASELINE_BIN" ]] || fail "BASELINE_BIN is not an executable file: $BASELINE_BIN"
echo "[intake] BASELINE_BIN OK"

[[ -d "$CATALOG_DIR" && -r "$CATALOG_DIR" ]] || \
    fail "CATALOG_DIR is not a readable directory: $CATALOG_DIR"

catalog_count="$(find "$CATALOG_DIR" -maxdepth 1 -type f -name '*.yml' -printf '.' | wc -c)"
(( catalog_count > 0 )) || fail "CATALOG_DIR contains no .yml files: $CATALOG_DIR"
echo "[intake] CATALOG_DIR OK ($catalog_count rules)"

[[ -x "$TRIAGE_BIN" ]] || fail "TRIAGE_BIN is not an executable file: $TRIAGE_BIN"
echo "[intake] TRIAGE_BIN OK"

[[ -d "$CAPSTONE_PACK" && -r "$CAPSTONE_PACK" && -x "$CAPSTONE_PACK" ]] || \
    fail "CAPSTONE_PACK is not an accessible non-empty directory: $CAPSTONE_PACK"

capstone_entries="$(find "$CAPSTONE_PACK" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)"
[[ -n "$capstone_entries" ]] || fail "CAPSTONE_PACK is empty: $CAPSTONE_PACK"

echo "[intake] CAPSTONE_PACK OK"
echo "[intake] CAPSTONE_PACK top-level entries:"
while IFS= read -r entry; do
    printf '%s\n' "$entry"
done <<< "$capstone_entries"

required_assets=(
    assets.json
    ioc_feed.json
    hc_red7_advisory.md
    change_tickets.json
    prior_shift_notes.md
)

for file in "${required_assets[@]}"; do
    [[ -f "$ASSETS_DIR/$file" && -r "$ASSETS_DIR/$file" ]] || \
        fail "missing or unreadable context file: $ASSETS_DIR/$file"
done
echo "[intake] ASSETS_DIR: 5 meta files OK"

required_exports=(
    incident_A_search_results.json
    incident_B_search_results.json
    incident_C_search_results.json
    campaign_dashboard_summary.md
)

for file in "${required_exports[@]}"; do
    [[ -f "$WAZUH_EXPORTS/$file" && -r "$WAZUH_EXPORTS/$file" ]] || \
        fail "missing or unreadable export file: $WAZUH_EXPORTS/$file"
done
echo "[intake] WAZUH_EXPORTS: 4 export files OK"

ioc_count="$(jq -e '.iocs | length' "$ASSETS_DIR/ioc_feed.json")" || \
    fail "could not read IOC count from $ASSETS_DIR/ioc_feed.json"
[[ "$ioc_count" =~ ^[0-9]+$ ]] || fail "IOC count is not numeric: $ioc_count"
echo "[intake] ioc_feed.json OK ($ioc_count entries)"

advisory_cluster_id="$(
    awk '/HC-RED7/ {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /HC-RED7/) {
                gsub(/[^A-Za-z0-9._-]/, "", $i)
                print $i
                exit
            }
        }
    }' "$ASSETS_DIR/hc_red7_advisory.md"
)"

[[ -n "$advisory_cluster_id" ]] || \
    fail "HC-RED7 cluster ID not found in advisory"

echo "[intake] advisory $advisory_cluster_id loaded"

mkdir -p \
    "$SHIFT_WORKSPACE/runtime" \
    "$SHIFT_WORKSPACE/enriched" \
    "$SHIFT_WORKSPACE/alerts" \
    "$SHIFT_WORKSPACE/investigations" \
    "$SHIFT_WORKSPACE/campaign" \
    "$SHIFT_WORKSPACE/reports" \
    "$SHIFT_WORKSPACE/response" \
    "$SHIFT_WORKSPACE/handoff"

touch \
    "$SHIFT_WORKSPACE/MANIFEST.json" \
    "$SHIFT_WORKSPACE/runtime/pipeline_run.json" \
    "$SHIFT_WORKSPACE/runtime/baseline_run.json" \
    "$SHIFT_WORKSPACE/runtime/catalog_run.json" \
    "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" \
    "$SHIFT_WORKSPACE/enriched/timeline.jsonl" \
    "$SHIFT_WORKSPACE/enriched/baseline.json" \
    "$SHIFT_WORKSPACE/enriched/source_stats.json" \
    "$SHIFT_WORKSPACE/alerts/alert_queue.json" \
    "$SHIFT_WORKSPACE/alerts/shift_briefing.json" \
    "$SHIFT_WORKSPACE/alerts/triage_log.jsonl" \
    "$SHIFT_WORKSPACE/alerts/incidents.json" \
    "$SHIFT_WORKSPACE/investigations/incident_A.json" \
    "$SHIFT_WORKSPACE/investigations/incident_B.json" \
    "$SHIFT_WORKSPACE/investigations/incident_C_cli.json" \
    "$SHIFT_WORKSPACE/investigations/incident_C_export.json" \
    "$SHIFT_WORKSPACE/campaign/campaign_assessment.json" \
    "$SHIFT_WORKSPACE/reports/incident_A.md" \
    "$SHIFT_WORKSPACE/reports/incident_B.md" \
    "$SHIFT_WORKSPACE/reports/incident_C.md" \
    "$SHIFT_WORKSPACE/response/tuning_recommendations.json" \
    "$SHIFT_WORKSPACE/response/containment.json" \
    "$SHIFT_WORKSPACE/response/ioc_package.json" \
    "$SHIFT_WORKSPACE/handoff/shift_handoff.md"

echo "[intake] workspace layout created at $SHIFT_WORKSPACE"

started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
shift_id="$(date -u '+SHIFT-%Y%m%d-%H%M')"
analyst_host="$(hostname)"
capstone_resolved="$(readlink -f "$CAPSTONE_PACK")"

jq -n \
    --arg shift_id "$shift_id" \
    --arg analyst_host "$analyst_host" \
    --arg started_at "$started_at" \
    --arg jq_version "${TOOL_VERSIONS[jq]}" \
    --arg python3_version "${TOOL_VERSIONS[python3]}" \
    --arg yq_version "${TOOL_VERSIONS[yq]}" \
    --arg sigma_cli_version "${TOOL_VERSIONS[sigma-cli]}" \
    --arg capstone_pack "$capstone_resolved" \
    --arg advisory_cluster_id "$advisory_cluster_id" \
    --argjson ioc_feed_count "$ioc_count" \
    '{
      shift_id: $shift_id,
      analyst_host: $analyst_host,
      started_at: $started_at,
      tools: {
        jq: $jq_version,
        python3: $python3_version,
        yq: $yq_version,
        "sigma-cli": $sigma_cli_version,
        sha256sum: "present"
      },
      prior_project_bins: {
        pipeline: true,
        baseline: true,
        catalog: true,
        triage: true
      },
      capstone_pack: $capstone_pack,
      ioc_feed_count: $ioc_feed_count,
      advisory_cluster_id: $advisory_cluster_id,
      wazuh_exports_verified: true
    }' > "$SHIFT_WORKSPACE/runtime/shift_start.json"

echo "[intake] shift_start.json written"
