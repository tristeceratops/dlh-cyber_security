#!/bin/bash
set -euo pipefail

DRY_RUN=false
COUNT_ONLY=false
WINDOW=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --count-only) COUNT_ONLY=true ;;
        --window) WINDOW="$2"; shift ;;
        -*) echo "Unknown option: $1" >&2; exit 2 ;;
        *)
            if [[ -z "${RULE:-}" ]]; then
                RULE="$1"
            else
                EVIDENCE="$1"
            fi
            ;;
    esac
    shift
done

: "${RULE:?Usage: $0 [options] RULE.yml [EVIDENCE.json]}"

EVIDENCE="${EVIDENCE:-${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}/data/normalized_events.json}"

python3 - "$RULE" "$EVIDENCE" "$WINDOW" "$DRY_RUN" "$COUNT_ONLY" <<'PY'
import json
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime

import yaml

rule_file, evidence_file, window, dry_run, count_only = sys.argv[1:]
dry_run = dry_run == "true"
count_only = count_only == "true"

try:
    with open(rule_file, encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    if dry_run:
        uuid.UUID(rule["id"])
        print("VALID")
        sys.exit(0)

    with open(evidence_file, encoding="utf-8") as f:
        data = [json.loads(line) for line in f if line.strip()]

except Exception as e:
    if dry_run:
        print(f"PARSE ERROR: {e}")
        sys.exit(1)
    raise


def ts(event):
    return datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )


def match(event, selection):
    return all(
        event.get(key) in value if isinstance(value, list)
        else event.get(key) == value
        for key, value in selection.items()
    )


events = data if isinstance(data, list) else data["events"]
detection = rule["detection"]

condition = detection.get("condition", rule.get("condition", "selection"))

# Support: selection | count() by src_ip > 5
aggregation = None

if "count()" in condition:
    parts = condition.split("|", 1)
    base = parts[0].strip()
    right = parts[1].strip()

    tokens = right.replace("(", " ").replace(")", " ").split()
    group_field = tokens[tokens.index("by") + 1]
    operator = tokens[-2]
    threshold = int(tokens[-1])

    timeframe = detection.get("timeframe", "120s")
    seconds = int(timeframe.rstrip("smh"))
    if timeframe.endswith("m"):
        seconds *= 60
    elif timeframe.endswith("h"):
        seconds *= 3600

    aggregation = (
        base, group_field, operator, threshold, seconds
    )

selection_names = [
    name for name in detection
    if name not in ("condition", "timeframe")
]

if aggregation:
    base, group_field, operator, threshold, seconds = aggregation
    selection = detection[base]

    groups = defaultdict(list)

    for event in events:
        if match(event, selection):
            groups[event.get(group_field)].append(event)

    matches = []

    for group in groups.values():
        group.sort(key=ts)

        for i, event in enumerate(group):
            recent = [
                e for e in group
                if 0 <= (ts(event) - ts(e)).total_seconds() <= seconds
            ]

            count = len(recent)

            if (
                (operator == ">" and count > threshold)
                or (operator == ">=" and count >= threshold)
            ):
                matches.extend(recent)

else:
    selections = {
        name: detection[name]
        for name in selection_names
    }

    matches = [
        event for event in events
        if any(match(event, selection) for selection in selections.values())
    ]

if window:
    start, end = map(
        lambda x: datetime.fromisoformat(x.replace("Z", "+00:00")),
        window.split(",", 1)
    )
    matches = [
        e for e in matches
        if start <= ts(e) <= end
    ]

# Remove duplicate events while preserving deterministic order.
matches = {
    e.get("event_ref", e.get("id", str(i))): e
    for i, e in enumerate(matches)
}

matches = sorted(
    matches.values(),
    key=lambda e: (e["timestamp"], e.get("hostname", ""), e.get("event_ref", ""))
)

if count_only:
    print(len(matches))
    sys.exit(0)

print(json.dumps({
    "rule_id": rule["id"],
    "rule_title": rule["title"],
    "level": rule["level"],
    "evidence_path": evidence_file,
    "match_count": len(matches),
    "matches": [
        {
            "timestamp": e["timestamp"],
            "hostname": e.get("hostname", ""),
            "event_ref": e.get("event_ref", e.get("id", ""))
        }
        for e in matches
    ],
    "execution_time_ms": 0
}))
PY
