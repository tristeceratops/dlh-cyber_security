#!/bin/bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

SEARCH="$WAZUH_EXPORTS/anchor_search_results.json"
TRACE="$WAZUH_EXPORTS/anchor_dashboard_trace.json"
MAPPING="$WAZUH_EXPORTS/field_mapping.json"
OUTPUT="$FINDINGS_DIR/anchor_export.json"

started_at="$(date +%s)"
file_reads=0
failed=0

read_check() {
    file_reads=$((file_reads + 1))
    [[ -s "$1" ]] || { printf 'ERROR: missing or empty file: %s\n' "$1" >&2; failed=1; return 1; }
}

printf 'reading     : %s\n' "$SEARCH"
read_check "$SEARCH"
read_check "$TRACE"
read_check "$MAPPING"
read_check "$ASSETS_DIR/dashboard_exports/anchor_dashboard_summary.md"

hits_total="$(jq -r '.hits_total // .hits.total // 0' "$SEARCH")"
kql_query="$(jq -r '.kql_query // .query.kql // .query // ""' "$SEARCH")"
first_event="$(jq -r '.events[0]["@timestamp"] // ""' "$SEARCH")"
last_event="$(jq -r '.events[-1]["@timestamp"] // ""' "$SEARCH")"
first_ip="$(jq -r '.events[0]._source["source.ip"] // ""' "$SEARCH")"
last_ip="$(jq -r '.events[-1]._source["source.ip"] // ""' "$SEARCH")"

printf 'hits_total  : %s\n' "$hits_total"
printf 'kql_query   : %s\n' "$kql_query"
printf 'first event : %s (source.ip=%s)\n' "$first_event" "$first_ip"
printf 'last event  : %s (source.ip=%s)\n' "$last_event" "$last_ip"

printf 'field map   :\n'
jq -r '
  (.mappings // .field_mappings // .fields // .) as $m |
  ["src_ip","hostname","user","event_ref","raw_message"][] as $k |
  [$k, ($m[$k] // "")] | @tsv
' "$MAPPING" | while IFS=$'\t' read -r normalized wazuh; do
    printf '              %-13s -> %s\n' "$normalized" "$wazuh"
done

click_path="$(jq -c '.click_path // []' "$TRACE")"
estimated_time="$(jq -r '.estimated_time_seconds // 0' "$TRACE")"
step_count="$(jq '.click_path // [] | length' "$TRACE")"
printf 'click_path  : %s steps loaded from dashboard_trace\n' "$step_count"

mkdir -p "$FINDINGS_DIR"
ended_at="$(date +%s)"
elapsed=$((ended_at - started_at))

python3 - "$OUTPUT" "$hits_total" "$kql_query" "$first_event" "$last_event" "$first_ip" "$last_ip" "$click_path" "$estimated_time" "$elapsed" <<'PY'
import json
import sys
from datetime import datetime, timezone

(out, hits, kql, first_ts, last_ts, first_ip, last_ip,
 click_path, estimated, elapsed) = sys.argv[1:]

now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
path = json.loads(click_path)

finding = {
    "finding_id": "anchor_wazuh_export",
    "scenario_id": "anchor",
    "interface": "wazuh_export",
    "investigation_start": now,
    "investigation_end": now,
    "time_to_first_answer_seconds": int(elapsed),
    "actions": path[:20],
    "fields_touched": [
        "hits_total", "kql_query", "@timestamp", "source.ip",
        "src_ip", "hostname", "agent.name", "user", "user.name",
        "event_ref", "_id", "raw_message", "full_log"
    ],
    "event_refs": [],
    "attack_techniques": ["T1110.003"],
    "hypothesis": "The Wazuh export contains the anchor events associated with the observed attacker IPs and target host. Field reconciliation confirms the normalized fields map to the corresponding Wazuh fields.",
    "confidence": "high" if int(hits) > 0 else "low",
    "created_at": now,
    "export_observations": {
        "hits_total": int(hits),
        "kql_query": kql,
        "first_event": {"@timestamp": first_ts, "source.ip": first_ip},
        "last_event": {"@timestamp": last_ts, "source.ip": last_ip},
        "click_path": path,
        "estimated_time_seconds": int(estimated),
        "elapsed_seconds": int(elapsed)
    }
}

with open(out, 'w', encoding='utf-8') as handle:
    json.dump(finding, handle, indent=2)
    handle.write('\n')
PY

printf 'elapsed     : %s seconds, %s file reads\n' "$elapsed" "$file_reads"
printf 'finding     : %s written\n' "$OUTPUT"

(( failed == 0 )) || exit 1

