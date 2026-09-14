#!/bin/bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${WORKSPACE_DIR:-$SCRIPT_DIR/workspace}"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"
QUERY_RESULTS="${QUERY_RESULTS:-$ASSETS_DIR/query_results}"

INDEX_METADATA="$WAZUH_EXPORTS/index_metadata.json"
FIELD_MAPPING="$WAZUH_EXPORTS/field_mapping.json"
CREDENTIALS="$ASSETS_DIR/dashboard_credentials.json"
OUTPUT="$WORKSPACE_DIR/workspace_init.json"

failed=0
fail() { printf 'ERROR: %s\n' "$*" >&2; failed=1; }

require_file() {
    if [[ ! -s "$1" ]]; then
        fail "missing or empty file: $1"
        return 1
    fi
    return 0
}

extract_first() {
    # Recursively find the first scalar value matching one of the supplied keys.
    python3 - "$1" "${@:2}" <<'PY'
import json, sys
path, *keys = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    obj = json.load(f)

def walk(x):
    if isinstance(x, dict):
        for k in keys:
            if k in x and not isinstance(x[k], (dict, list)):
                return x[k]
        for v in x.values():
            r = walk(v)
            if r is not None:
                return r
    elif isinstance(x, list):
        for v in x:
            r = walk(v)
            if r is not None:
                return r
    return None

v = walk(obj)
if v is not None:
    print(v)
PY
}

printf '%s\n' 'mode          : wazuh_export (no live dashboard required)'

require_file "$INDEX_METADATA"
require_file "$FIELD_MAPPING"
require_file "$CREDENTIALS"

index_name=""
total_documents=""
earliest=""
latest=""
username=""

if [[ -s "$INDEX_METADATA" ]]; then
    index_name="$(extract_first "$INDEX_METADATA" index_name index source_index name || true)"
    total_documents="$(extract_first "$INDEX_METADATA" total_documents document_count total_count count || true)"
    earliest="$(extract_first "$INDEX_METADATA" earliest earliest_timestamp min_timestamp start || true)"
    latest="$(extract_first "$INDEX_METADATA" latest latest_timestamp max_timestamp end || true)"
fi

if [[ -n "$index_name" ]]; then
    printf 'index         : %s\n' "$index_name"
else
    printf 'index         : unavailable\n'
    fail "could not extract index name"
fi

if [[ "$total_documents" =~ ^[0-9]+$ ]]; then
    printf 'documents     : %s\n' "$(printf '%s' "$total_documents" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')"
else
    printf 'documents     : unavailable\n'
    fail "could not extract total document count"
fi

if [[ -n "$earliest" && -n "$latest" ]]; then
    printf 'time range    : %s to %s\n' "$earliest" "$latest"
else
    printf 'time range    : unavailable\n'
    fail "could not extract time range"
fi

if [[ -s "$CREDENTIALS" ]]; then
    username="$(extract_first "$CREDENTIALS" username user user_name || true)"
fi
if [[ -n "$username" ]]; then
    printf 'credentials   : %s (from dashboard_credentials.json)\n' "$username"
else
    printf 'credentials   : unavailable\n'
    fail "could not extract credentials username"
fi

mapping_count=0
if [[ -s "$FIELD_MAPPING" ]]; then
    mapping_count="$(python3 - "$FIELD_MAPPING" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    obj=json.load(f)
if isinstance(obj, dict):
    for key in ("mappings", "field_mappings", "fields"):
        if isinstance(obj.get(key), dict):
            print(len(obj[key])); break
    else:
        print(len(obj))
else:
    print(0)
PY
)"
fi

printf 'field mapping : loaded (%s mappings)\n' "$mapping_count"
printf '%s\n' '  field       -> mapped field'

if [[ -s "$FIELD_MAPPING" ]]; then
    python3 - "$FIELD_MAPPING" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    obj=json.load(f)
m = obj.get("mappings", obj.get("field_mappings", obj.get("fields", obj)))
items = list(m.items()) if isinstance(m, dict) else []
for source, target in items[:10]:
    if isinstance(target, dict):
        target = target.get("field", target.get("path", target.get("mapped_to", target)))
    print(f"  {source:<11} -> {target}")
PY
fi

required_wazuh=(
  field_mapping.json
  index_metadata.json
  anchor_search_results.json
  scenario_a_search_results.json
  scenario_b_search_results.json
  scenario_c_search_results.json
)
required_queries=(
  kql_anchor_query.json
  lucene_anchor_query.json
  kql_scenario_a.json
  kql_scenario_b.json
  kql_scenario_c.json
)

verified=0
for f in "${required_wazuh[@]}"; do
    if [[ -s "$WAZUH_EXPORTS/$f" ]]; then
        verified=$((verified+1))
    else
        fail "missing Wazuh export: $WAZUH_EXPORTS/$f"
    fi
done
for f in "${required_queries[@]}"; do
    if [[ -s "$QUERY_RESULTS/$f" ]]; then
        verified=$((verified+1))
    else
        fail "missing query result: $QUERY_RESULTS/$f"
    fi
done

if (( failed == 0 )); then
    printf 'export files  : all present (%s files verified)\n' "$verified"
else
    printf 'export files  : verification failed (%s files present)\n' "$verified"
fi

mkdir -p "$WORKSPACE_DIR"
python3 - "$OUTPUT" "$index_name" "$total_documents" "$earliest" "$latest" "$failed" <<'PY'
import json, sys
from datetime import datetime, timezone

out, index_name, count, earliest, latest, failed = sys.argv[1:]
payload = {
    "mode": "wazuh_export",
    "source_index": index_name,
    "total_documents": int(count) if count.isdigit() else 0,
    "time_range": {"earliest": earliest, "latest": latest},
    "export_files_verified": failed == "0",
    "field_mapping_loaded": True,
    "initialized_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
PY

printf '%s\n' 'workspace_init.json written'

if (( failed != 0 )); then
    exit 1
fi
exit 0


