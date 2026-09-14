#!/bin/bash
set -u

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

MANIFEST="$ASSETS_DIR/anchor_event.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
RULE="$CATALOG_DIR/rules/sigma/001_ssh_brute_force.yml"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"
OUT="$OUT_DIR/anchor_cli.json"

start_epoch=$(date +%s)
commands=0
failed=0
run() { commands=$((commands + 1)); "$@"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; failed=1; }

printf 'reading     : %s\n' "$MANIFEST"
[[ -s "$MANIFEST" ]] || fail "missing manifest: $MANIFEST"
[[ -s "$EVENTS" ]] || fail "missing enriched events: $EVENTS"

host=$(run jq -r '.target_host // empty' "$MANIFEST") || host=""
start=$(run jq -r '.time_window.start // .time_window.from // empty' "$MANIFEST") || start=""
end=$(run jq -r '.time_window.end // .time_window.to // empty' "$MANIFEST") || end=""
ips_json=$(run jq -c '.attacker_ips // []' "$MANIFEST") || ips_json='[]'

printf 'host        : %s\n' "$host"
printf 'window      : %s -> %s\n' "$start" "$end"
printf 'attacker ips: %s\n' "$(jq -r '.[]' <<<"$ips_json" | paste -sd' ' -)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [[ -s "$EVENTS" ]]; then
  run jq --arg host "$host" --arg start "$start" --arg end "$end" --argjson ips "$ips_json" '
    def rows:
      if type == "array" then .
      elif (.events? | type) == "array" then .events
      elif (.data? | type) == "array" then .data
      elif (.enriched_events? | type) == "array" then .enriched_events
      else [.] end;
    def ts: .["@timestamp"] // .timestamp // .event_time // .eventTime // .time;
    def host_value: .target_host // .targetHost // .hostname // .host.name // .host // .agent.name // .agent_name;
    def ip_value: .attacker_ip // .source.ip // .src_ip // .source_ip // .client.ip;
    [rows[] | select(host_value == $host) | select((ts // "") >= $start and (ts // "") <= $end) | select(($ips|length)==0 or (($ips|index(ip_value)) != null))]
  ' "$EVENTS" > "$work/matches.json" || { printf '[]\n' > "$work/matches.json"; fail 'jq filtering failed'; }
else
  printf '[]\n' > "$work/matches.json"
fi

count=$(run jq 'length' "$work/matches.json") || count=0
first=$(run jq -r 'sort_by((.["@timestamp"] // .timestamp // .event_time // .eventTime // .time)) | if length then (.[0]["@timestamp"] // .[0].timestamp // .[0].event_time // .[0].eventTime // .[0].time) else "" end' "$work/matches.json") || first=""
last=$(run jq -r 'sort_by((.["@timestamp"] // .timestamp // .event_time // .eventTime // .time)) | if length then (.[-1]["@timestamp"] // .[-1].timestamp // .[-1].event_time // .[-1].eventTime // .[-1].time) else "" end' "$work/matches.json") || last=""

printf 'matched     : %s events in enriched_events.json\n' "$count"
printf 'first event : %s\n' "${first:-unavailable}"
printf 'last event  : %s\n' "${last:-unavailable}"

technique="T1110.003"
if [[ -s "$RULE" ]]; then
  printf 'rule        : 001_ssh_brute_force (%s)\n' "$technique"
  printf '%s\n' 'logsource:'
  run yq '.logsource' "$RULE" || fail 'could not read logsource'
  printf '%s\n' 'detection:'
  run yq '.detection' "$RULE" || fail 'could not read detection'
else
  printf 'rule        : unavailable\n'
  fail "missing Sigma rule: $RULE"
fi

end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))
mkdir -p "$OUT_DIR"

python3 - "$OUT" "$host" "$start" "$end" "$ips_json" "$count" "$first" "$last" "$elapsed" <<'PY'
import json, sys
from datetime import datetime, timezone

out, host, start, end, ips, count, first, last, elapsed = sys.argv[1:]
now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

finding = {
    "finding_id": "anchor_cli",
    "scenario_id": "anchor",
    "interface": "cli",
    "investigation_start": now,
    "investigation_end": now,
    "time_to_first_answer_seconds": int(elapsed),
    "actions": [
        "Read anchor manifest",
        "Extracted target_host, time_window, and attacker_ips",
        "Filtered enriched_events.json with jq",
        "Counted matching records",
        "Extracted earliest and latest matching timestamps",
        "Read Sigma logsource and detection with yq",
        "Recorded wall-clock duration",
        "Wrote anchor_cli.json",
    ],
    "fields_touched": ["target_host", "time_window", "attacker_ips", "@timestamp", "timestamp", "host", "hostname", "source.ip", "attacker_ip", "eventref"],
    "event_refs": [],
    "attack_techniques": ["T1110.003"],
    "hypothesis": "The matching records indicate SSH brute-force activity against the anchor host during the specified time window. The activity is associated with the listed attacker IPs.",
    "confidence": "high" if int(count) > 0 else "low",
    "created_at": now,
    "anchor_details": {
        "target_host": host,
        "time_window": {"start": start, "end": end},
        "attacker_ips": json.loads(ips),
        "matching_event_count": int(count),
        "earliest_matching_event": first,
        "latest_matching_event": last,
        "elapsed_seconds": int(elapsed),
    },
}
with open(out, 'w', encoding='utf-8') as f:
    json.dump(finding, f, indent=2)
    f.write('\n')
PY

printf 'elapsed     : %s seconds, %s commands\n' "$elapsed" "$commands"
printf 'finding     : %s written\n' "$OUT"
(( failed == 0 ))

