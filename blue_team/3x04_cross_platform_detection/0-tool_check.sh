#!/bin/bash

set -u

# Resolve this script's directory so execution does not depend on $PWD.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

failed=0

fail() {
    failed=1
    printf 'ERROR: %s\n' "$*" >&2
}

version_line() {
    local name="$1"
    local command_name="$2"
    local version_output

    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf '%-12s: MISSING\n' "$name"
        fail "$command_name is not on PATH"
        return
    fi

    case "$command_name" in
        jq)
            version_output="$(jq --version 2>/dev/null || true)"
            ;;
        yq)
            version_output="$(yq --version 2>/dev/null || true)"
            ;;
        python3)
            version_output="$(python3 --version 2>&1 || true)"
            ;;
        sigma-cli)
            version_output="$(sigma-cli --version 2>&1 || true)"
            ;;
        xmllint)
            version_output="$(xmllint --version 2>&1 | head -n 1 || true)"
            ;;
        curl)
            version_output="$(curl --version 2>&1 | head -n 1 || true)"
            ;;
        *)
            version_output="unknown"
            ;;
    esac

    if [[ -z "$version_output" ]]; then
        printf '%-12s: UNKNOWN\n' "$name"
        fail "unable to determine $command_name version"
    else
        printf '%-12s: %s\n' "$name" "$version_output"
    fi
}

check_dir() {
    local label="$1"
    local path="$2"

    if [[ -d "$path" ]]; then
        return 0
    fi

    fail "$label directory does not exist: $path"
    return 1
}

check_file_nonempty() {
    local path="$1"

    if [[ -s "$path" ]]; then
        return 0
    fi

    fail "required non-empty file is missing or empty: $path"
    return 1
}

printf '%s\n' '=== Toolkit ==='

version_line "jq" "jq"
version_line "yq" "yq"
version_line "python3" "python3"
version_line "sigma-cli" "sigma-cli"
version_line "xmllint" "xmllint"
version_line "curl" "curl"

printf '\n%s\n' '=== Directories ==='

check_dir "HANDOFF_DIR" "$HANDOFF_DIR"
check_dir "BASELINE_PKG" "$BASELINE_PKG"
check_dir "CATALOG_DIR" "$CATALOG_DIR"
check_dir "TRIAGE_PKG" "$TRIAGE_PKG"
check_dir "ASSETS_DIR" "$ASSETS_DIR"

printf '\n%s\n' '=== Handoff ==='

ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"

if check_file_nonempty "$ENRICHED_EVENTS"; then
    printf '%-12s: ok (enriched_events.json present)\n' "handoff"
else
    printf '%-12s: FAILED\n' "handoff"
fi

printf '\n%s\n' '=== Sigma Catalog ==='

SIGMA_DIR="$CATALOG_DIR/rules/sigma"

if [[ -d "$SIGMA_DIR" ]]; then
    # Count YAML Sigma rule files recursively. Hidden files are included through find.
    sigma_rule_count="$(
        find "$SIGMA_DIR" -type f \
            \( -iname '*.yml' -o -iname '*.yaml' \) \
            -print 2>/dev/null |
        wc -l |
        tr -d '[:space:]'
    )"

    if [[ "$sigma_rule_count" =~ ^[0-9]+$ ]] && (( sigma_rule_count > 0 )); then
        printf '%-12s: ok (%s sigma rules)\n' "catalog" "$sigma_rule_count"
    else
        printf '%-12s: FAILED (0 sigma rules)\n' "catalog"
        fail "no Sigma rules found under $SIGMA_DIR"
    fi
else
    printf '%-12s: FAILED\n' "catalog"
    fail "Sigma directory does not exist: $SIGMA_DIR"
fi

printf '\n%s\n' '=== Wazuh Exports ==='

required_exports=(
    "field_mapping.json"
    "index_metadata.json"
    "anchor_search_results.json"
    "scenario_a_search_results.json"
    "scenario_b_search_results.json"
    "scenario_c_search_results.json"
)

wazuh_export_failed=0

for export_file in "${required_exports[@]}"; do
    if [[ ! -s "$WAZUH_EXPORTS/$export_file" ]]; then
        fail "missing or empty Wazuh export: $WAZUH_EXPORTS/$export_file"
        wazuh_export_failed=1
    fi
done

dashboard_trace_count=0

for trace_file in \
    "anchor_dashboard_trace.json" \
    "scenario_a_dashboard_trace.json" \
    "scenario_b_dashboard_trace.json" \
    "scenario_c_dashboard_trace.json"; do
    if [[ -s "$WAZUH_EXPORTS/$trace_file" ]]; then
        dashboard_trace_count=$((dashboard_trace_count + 1))
    else
        fail "missing or empty Wazuh dashboard trace: $WAZUH_EXPORTS/$trace_file"
        wazuh_export_failed=1
    fi
done

if (( wazuh_export_failed == 0 )); then
    printf '%-14s: ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)\n' \
        "wazuh_exports"
else
    printf '%-14s: FAILED\n' "wazuh_exports"
fi

printf '\n%s\n' '=== Anchor ==='

ANCHOR_EVENT="$ASSETS_DIR/anchor_event.json"

if [[ ! -s "$ANCHOR_EVENT" ]]; then
    printf '%-12s: FAILED\n' "anchor"
    fail "anchor event file is missing or empty: $ANCHOR_EVENT"
else
    if ! jq empty "$ANCHOR_EVENT" >/dev/null 2>&1; then
        printf '%-12s: FAILED\n' "anchor"
        fail "invalid JSON: $ANCHOR_EVENT"
    elif ! jq empty "$ENRICHED_EVENTS" >/dev/null 2>&1; then
        printf '%-12s: FAILED\n' "anchor"
        fail "invalid JSON: $ENRICHED_EVENTS"
    else
        anchor_result="$(
            python3 - "$ANCHOR_EVENT" "$ENRICHED_EVENTS" <<'PY'
import json
import sys
from datetime import datetime, timezone

anchor_path = sys.argv[1]
events_path = sys.argv[2]


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def find_first(obj, names):
    """Recursively find the first scalar value for any named key."""
    if isinstance(obj, dict):
        for key in names:
            if key in obj and not isinstance(obj[key], (dict, list)):
                return obj[key]
        for value in obj.values():
            result = find_first(value, names)
            if result is not None:
                return result
    elif isinstance(obj, list):
        for value in obj:
            result = find_first(value, names)
            if result is not None:
                return result
    return None


def find_value(obj, names):
    """Recursively find the first value, including objects/lists."""
    if isinstance(obj, dict):
        for key in names:
            if key in obj:
                return obj[key]
        for value in obj.values():
            result = find_value(value, names)
            if result is not None:
                return result
    elif isinstance(obj, list):
        for value in obj:
            result = find_value(value, names)
            if result is not None:
                return result
    return None


def parse_time(value):
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if not isinstance(value, str):
        return None

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def extract_window(value):
    """
    Accept common representations:
      {"start": "...", "end": "..."}
      {"from": "...", "to": "..."}
      ["...", "..."]
      "start/end"
    """
    if isinstance(value, dict):
        start = (
            value.get("start")
            or value.get("from")
            or value.get("begin")
            or value.get("start_time")
            or value.get("from_time")
        )
        end = (
            value.get("end")
            or value.get("to")
            or value.get("finish")
            or value.get("end_time")
            or value.get("to_time")
        )
        return parse_time(start), parse_time(end)

    if isinstance(value, list) and len(value) >= 2:
        return parse_time(value[0]), parse_time(value[1])

    if isinstance(value, str):
        separators = ["..", "/", " to ", " - "]
        for separator in separators:
            if separator in value:
                left, right = value.split(separator, 1)
                start = parse_time(left.strip())
                end = parse_time(right.strip())
                if start and end:
                    return start, end

    return None, None


def all_events(obj):
    """
    Support common enriched-events layouts:
      - top-level list
      - {"events": [...]}
      - {"data": [...]}
      - {"enriched_events": [...]}
    """
    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict):
        for key in ("events", "data", "enriched_events", "results"):
            value = obj.get(key)
            if isinstance(value, list):
                return value

    return [obj]


anchor = load_json(anchor_path)
events_doc = load_json(events_path)

target_host = find_first(anchor, ("target_host", "targetHost", "host"))
time_window = find_value(anchor, ("time_window", "timeWindow"))

if target_host is None:
    print("FAIL|anchor_event.json does not contain target_host")
    sys.exit(1)

if time_window is None:
    print("FAIL|anchor_event.json does not contain time_window")
    sys.exit(1)

window_start, window_end = extract_window(time_window)

if window_start is None or window_end is None:
    print("FAIL|unable to parse anchor time_window")
    sys.exit(1)

if window_start > window_end:
    window_start, window_end = window_end, window_start

events = all_events(events_doc)

host_keys = (
    "target_host",
    "targetHost",
    "host",
    "hostname",
    "host_name",
    "agent_name",
    "agentName",
)

time_keys = (
    "@timestamp",
    "timestamp",
    "event_time",
    "eventTime",
    "time",
    "datetime",
    "date",
)


for event in events:
    if not isinstance(event, dict):
        continue

    event_host = find_first(event, host_keys)

    if event_host is None:
        continue

    # Host matching is exact and case-insensitive.
    if str(event_host).strip().lower() != str(target_host).strip().lower():
        continue

    event_time_value = find_first(event, time_keys)
    event_time = parse_time(event_time_value)

    # If an event has a matching host but no parseable timestamp, it cannot
    # establish that it falls inside the anchor window.
    if event_time is None:
        continue

    if window_start <= event_time <= window_end:
        print(f"OK|{target_host}")
        sys.exit(0)

print(f"FAIL|no event for {target_host} found inside anchor time_window")
sys.exit(1)
PY
        )"

        anchor_status="${anchor_result%%|*}"
        anchor_message="${anchor_result#*|}"

        if [[ "$anchor_status" == "OK" ]]; then
            printf '%-12s: ok (%s matched in enriched_events.json)\n' \
                "anchor" "$anchor_message"
        else
            printf '%-12s: FAILED (%s)\n' "anchor" "$anchor_message"
            fail "$anchor_message"
        fi
    fi
fi

printf '\n%s\n' '=== Result ==='

if (( failed == 0 )); then
    printf '%s\n' 'all checks  : passed'
    exit 0
fi

printf '%s\n' 'all checks  : FAILED'
exit 1

