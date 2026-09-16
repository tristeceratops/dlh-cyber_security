#!/bin/bash
set -euo pipefail

fail() {
    echo "[brief] ERROR: $*" >&2
    exit 1
}

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || fail "$name is not set"
}

require_file() {
    local file="$1"
    [[ -f "$file" && -r "$file" && -s "$file" ]] || \
        fail "required input missing, unreadable, or empty: $file"
}

require_env ASSETS_DIR
require_env SHIFT_WORKSPACE

ADVISORY="$ASSETS_DIR/hc_red7_advisory.md"
IOC_FEED="$ASSETS_DIR/ioc_feed.json"
CHANGE_TICKETS="$ASSETS_DIR/change_tickets.json"
PRIOR_NOTES="$ASSETS_DIR/prior_shift_notes.md"
BASELINE_RUN="$SHIFT_WORKSPACE/runtime/baseline_run.json"
SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"
OUTPUT="$SHIFT_WORKSPACE/alerts/shift_briefing.json"

echo -n "[brief] checking input files... "

require_file "$ADVISORY"
require_file "$IOC_FEED"
require_file "$CHANGE_TICKETS"
require_file "$PRIOR_NOTES"
require_file "$BASELINE_RUN"
require_file "$SHIFT_START"

echo "OK"

jq -e . "$IOC_FEED" >/dev/null 2>&1 || \
    fail "ioc_feed.json is invalid JSON"

jq -e . "$CHANGE_TICKETS" >/dev/null 2>&1 || \
    fail "change_tickets.json is invalid JSON"

jq -e . "$BASELINE_RUN" >/dev/null 2>&1 || \
    fail "baseline_run.json is invalid JSON"

jq -e . "$SHIFT_START" >/dev/null 2>&1 || \
    fail "shift_start.json is invalid JSON"

# ----------------------------------------------------------------------
# Advisory
# ----------------------------------------------------------------------

cluster_id="$(
    awk '
        /HC-RED7/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /HC-RED7/) {
                    gsub(/[^A-Za-z0-9._-]/, "", $i)
                    print $i
                    exit
                }
            }
        }
    ' "$ADVISORY"
)"

[[ -n "$cluster_id" ]] || fail "cluster ID HC-RED7 not found in advisory"

echo "[brief] cluster $cluster_id loaded"

# Lines beginning with T1 are interpreted as ATT&CK tactic/technique IDs.
mapfile -t cluster_tactics < <(
    awk '
        /^[[:space:]]*T1[0-9]/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^T1[0-9]+(\.[0-9]+)?[,:;]?$/) {
                    gsub(/[,:;]$/, "", $i)
                    print $i
                }
            }
        }
    ' "$ADVISORY" | sort -u
)

[[ "${#cluster_tactics[@]}" -gt 0 ]] || \
    fail "no tactics/technique IDs found in advisory"

echo "[brief] tactics: ${cluster_tactics[*]}"

note_count="$(
    awk '
        BEGIN { count=0 }
        /^[[:space:]]*[-*][[:space:]]/ {
            count++
        }
        END { print count }
    ' "$ADVISORY"
)"

# ----------------------------------------------------------------------
# IOC feed
# ----------------------------------------------------------------------

ioc_count="$(
    jq -e '.iocs | length' "$IOC_FEED"
)" || fail "unable to determine IOC count"

[[ "$ioc_count" =~ ^[0-9]+$ ]] || fail "IOC count is not numeric"

ioc_types=(ip domain hash account service_name port)

declare -A ioc_by_type

for type in "${ioc_types[@]}"; do
    count="$(
        jq --arg type "$type" '
            [
                .iocs[]?
                | select(
                    (.type // .ioc_type // .kind // "") == $type
                )
            ]
            | length
        ' "$IOC_FEED"
    )"

    ioc_by_type["$type"]="$count"
done

ioc_values_json="$(
    jq -c '
        [
            .iocs[]?
            | .value
            // .ioc
            // .indicator
            // .indicator_value
            | tostring
        ]
        | map(select(length > 0))
    ' "$IOC_FEED"
)"

echo "[brief] IOCs: ip=${ioc_by_type[ip]} domain=${ioc_by_type[domain]} hash=${ioc_by_type[hash]} account=${ioc_by_type[account]} service_name=${ioc_by_type[service_name]} port=${ioc_by_type[port]} total=$ioc_count"

# ----------------------------------------------------------------------
# Change tickets
# ----------------------------------------------------------------------

# The expected source structure is:
# {
#   "change_tickets": [
#     {
#       "ticket_id": "...",
#       "window_start": "...",
#       "window_end": "...",
#       "hosts": [...],
#       "owner": "...",
#       "approved_activity": "..."
#     }
#   ]
# }
#
# The fallback fields make the parser tolerant of the common 3x05
# ticket naming variants.

active_tickets_json="$(
    jq -c '
        def tickets:
            if (.change_tickets? | type) == "array" then .change_tickets
            elif (.tickets? | type) == "array" then .tickets
            elif type == "array" then .
            else []
            end;

        tickets
        | map({
            ticket_id: (.ticket_id // .id // .ticket // ""),
            window_start: (.window_start // .start // .approved_window_start // ""),
            window_end: (.window_end // .end // .approved_window_end // ""),
            hosts: (
                .hosts
                // .host_list
                // .affected_hosts
                // []
                | if type == "array" then . else [.] end
            ),
            owner: (.owner // .approved_by // .requestor // ""),
            approved_activity: (
                .approved_activity
                // .activity
                // .description
                // .approved_description
                // ""
            )
        })
        | map(
            select(
                .ticket_id != ""
                and .window_start != ""
                and .window_end != ""
            )
        )
    ' "$CHANGE_TICKETS"
)"

active_ticket_count="$(jq 'length' <<< "$active_tickets_json")"

echo "[brief] active change tickets in window: $active_ticket_count"

# ----------------------------------------------------------------------
# Prior shift open items
# ----------------------------------------------------------------------

mapfile -t open_items < <(
    awk '
        BEGIN { in_open=0 }

        /^[[:space:]]*#{1,6}[[:space:]]+Open Items[[:space:]]*$/ {
            in_open=1
            next
        }

        in_open && /^[[:space:]]*#{1,6}[[:space:]]+/ {
            exit
        }

        in_open && /^[[:space:]]*[-*][[:space:]]+/ {
            sub(/^[[:space:]]*[-*][[:space:]]+/, "")
            if (length($0) > 0)
                print
        }
    ' "$PRIOR_NOTES"
)

open_items_json="$(
    printf '%s\n' "${open_items[@]:-}" |
        jq -R -s '
            split("\n")
            | map(select(length > 0))
        '
)"

echo "[brief] prior shift open items: ${#open_items[@]}"

# ----------------------------------------------------------------------
# Baseline
# ----------------------------------------------------------------------

hot_hosts_json="$(
    jq -c '
        if (.hot_hosts? | type) == "array" then
            .hot_hosts
        else
            []
        end
    ' "$BASELINE_RUN"
)"

hosts_with_deviations="$(
    jq -r '.hosts_with_deviations // 0' "$BASELINE_RUN"
)"

[[ "$hosts_with_deviations" =~ ^[0-9]+$ ]] || \
    fail "invalid hosts_with_deviations in baseline_run.json"

hot_host_count="$(jq 'length' <<< "$hot_hosts_json")"

echo "[brief] baseline hot hosts: $hot_host_count"

# ----------------------------------------------------------------------
# Cluster cross-check
# ----------------------------------------------------------------------

shift_cluster_id="$(
    jq -r '.advisory_cluster_id // ""' "$SHIFT_START"
)"

[[ "$shift_cluster_id" == "$cluster_id" ]] || \
    fail "cluster ID cross-check failed: shift_start=$shift_cluster_id advisory=$cluster_id"

echo "[brief] cluster ID cross-check: OK"

# ----------------------------------------------------------------------
# Write shift briefing
# ----------------------------------------------------------------------

jq -n \
    --arg cluster_id "$cluster_id" \
    --argjson cluster_tactics "$(printf '%s\n' "${cluster_tactics[@]}" | jq -R -s 'split("\n") | map(select(length > 0))')" \
    --argjson ioc_count "$ioc_count" \
    --argjson ip "${ioc_by_type[ip]}" \
    --argjson domain "${ioc_by_type[domain]}" \
    --argjson hash "${ioc_by_type[hash]}" \
    --argjson account "${ioc_by_type[account]}" \
    --argjson service_name "${ioc_by_type[service_name]}" \
    --argjson port "${ioc_by_type[port]}" \
    --argjson ioc_values "$ioc_values_json" \
    --argjson active_change_tickets "$active_tickets_json" \
    --argjson prior_shift_open_items "$open_items_json" \
    --argjson baseline_hot_hosts "$hot_hosts_json" \
    --argjson hosts_with_deviations "$hosts_with_deviations" \
    '{
      cluster_id: $cluster_id,
      cluster_tactics: $cluster_tactics,
      ioc_count: $ioc_count,
      ioc_by_type: {
        ip: $ip,
        domain: $domain,
        hash: $hash,
        account: $account,
        service_name: $service_name,
        port: $port
      },
      ioc_values: $ioc_values,
      active_change_tickets: $active_change_tickets,
      prior_shift_open_items: $prior_shift_open_items,
      baseline_hot_hosts: $baseline_hot_hosts,
      hosts_with_deviations: $hosts_with_deviations
    }' > "$OUTPUT"

[[ -s "$OUTPUT" ]] || fail "failed to write shift_briefing.json"

echo "[brief] shift_briefing.json written"
