#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

INPUT="labeled_events.json"
OUTPUT="baseline_process.json"

python3 -W error - "$INPUT" "$OUTPUT" "$BASELINE_DAYS" <<'PY'
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

input_path = sys.argv[1]
output_path = sys.argv[2]
baseline_days = int(sys.argv[3])

if baseline_days <= 0:
    raise SystemExit("BASELINE_DAYS must be a positive integer")


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        result = datetime.fromisoformat(value)

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except ValueError:
        return None


def get_string(record, names):
    for name in names:
        value = record.get(name)

        if isinstance(value, str) and value:
            return value

    return None


def get_nested_string(record, containers, names):
    for container_name in containers:
        container = record.get(container_name)

        if not isinstance(container, dict):
            continue

        value = get_string(container, names)

        if value is not None:
            return value

    return None


def get_host(record):
    value = get_string(
        record,
        (
            "hostname",
            "host",
            "host_name",
            "computer",
            "computer_name",
        ),
    )

    if value:
        return value

    return get_nested_string(
        record,
        ("host_info", "device"),
        ("hostname", "host", "name"),
    )


def get_process(record):
    value = get_string(
        record,
        (
            "process_name",
            "process",
            "process_image",
            "image",
            "executable",
            "exe",
        ),
    )

    if value:
        return value

    return get_nested_string(
        record,
        ("process_info", "process_data"),
        (
            "process_name",
            "name",
            "image",
            "executable",
            "exe",
        ),
    )


def get_user(record):
    value = get_string(
        record,
        (
            "username",
            "user",
            "account",
            "user_name",
            "userid",
            "user_id",
        ),
    )

    if value:
        return value

    return get_nested_string(
        record,
        ("actor", "subject", "user_info", "account_info"),
        (
            "username",
            "user",
            "account",
            "user_name",
            "userid",
            "user_id",
        ),
    )


def get_parent(record):
    value = get_string(
        record,
        (
            "parent_process_name",
            "parent_process",
            "parent_image",
            "parent_executable",
            "parent",
        ),
    )

    if value:
        return value

    return get_nested_string(
        record,
        ("process_info", "process_data", "parent"),
        (
            "process_name",
            "name",
            "image",
            "executable",
            "exe",
        ),
    )


def is_process_start(record):
    label = record.get("canonical_label")

    if label == "process_start":
        return True

    # Fallback for process telemetry whose taxonomy label is missing
    # or unlabeled.
    category = str(record.get("event_category", "")).lower()

    process_name = get_process(record)

    process_indicators = (
        "process",
        "process_start",
        "process_create",
        "process_creation",
        "process_event",
    )

    if process_name and (
        category in process_indicators
        or category.startswith("process")
    ):
        return True

    return False


records = []
timestamps = []

with open(input_path, encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, 1):
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"invalid JSON on line {line_number}: {exc}"
            ) from exc

        if not isinstance(record, dict):
            continue

        timestamp = parse_timestamp(record.get("timestamp"))

        if timestamp is None:
            continue

        records.append((timestamp, record))
        timestamps.append(timestamp)


if not timestamps:
    raise SystemExit("no valid timestamped records found")


dataset_start = min(timestamps)
dataset_end = max(timestamps)

baseline_start = dataset_start
baseline_end = min(
    dataset_start + timedelta(days=baseline_days),
    dataset_end,
)


processes_by_host = defaultdict(
    lambda: defaultdict(
        lambda: {
            "count": 0,
            "first_seen": None,
            "last_seen": None,
            "users": set(),
        }
    )
)

global_counts = Counter()
process_hosts = defaultdict(set)
parent_child_by_host = defaultdict(set)


for timestamp, record in records:
    if timestamp < baseline_start or timestamp >= baseline_end:
        continue

    if not is_process_start(record):
        continue

    process_name = get_process(record)
    host = get_host(record)

    if not process_name or not host:
        continue

    timestamp_text = timestamp.isoformat().replace("+00:00", "Z")

    data = processes_by_host[host][process_name]

    data["count"] += 1

    if data["first_seen"] is None:
        data["first_seen"] = timestamp_text
    elif timestamp_text < data["first_seen"]:
        data["first_seen"] = timestamp_text

    if data["last_seen"] is None:
        data["last_seen"] = timestamp_text
    elif timestamp_text > data["last_seen"]:
        data["last_seen"] = timestamp_text

    user = get_user(record)

    if user:
        data["users"].add(user)

    global_counts[process_name] += 1
    process_hosts[process_name].add(host)

    parent = get_parent(record)

    if parent:
        parent_child_by_host[host].add(
            (parent, process_name)
        )


per_host = {}

for host in sorted(processes_by_host):
    per_host[host] = {}

    for process_name in sorted(processes_by_host[host]):
        data = processes_by_host[host][process_name]

        per_host[host][process_name] = {
            "execution_count": data["count"],
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
            "distinct_users": sorted(data["users"]),
        }


global_top = [
    {
        "process": process_name,
        "executions": count,
    }
    for process_name, count in sorted(
        global_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )[:50]
]


rare_processes = [
    {
        "process": process_name,
        "executions": count,
        "hosts": len(process_hosts[process_name]),
    }
    for process_name, count in sorted(global_counts.items())
    if len(process_hosts[process_name]) == 1 or count < 5
]


parent_child_pairs = {}

for host in sorted(parent_child_by_host):
    parent_child_pairs[host] = [
        {
            "parent": parent,
            "child": child,
        }
        for parent, child in sorted(parent_child_by_host[host])
    ]


result = {
    "window": {
        "start": baseline_start.isoformat().replace("+00:00", "Z"),
        "end": baseline_end.isoformat().replace("+00:00", "Z"),
    },
    "per_host": per_host,
    "global_top": global_top,
    "rare_processes": rare_processes,
    "parent_child_pairs": parent_child_pairs,
}


with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(
        result,
        handle,
        indent=2,
        ensure_ascii=False,
    )
    handle.write("\n")


def fmt(timestamp):
    return timestamp.isoformat().replace("+00:00", "Z")


if global_top:
    top = global_top[0]
    top_text = f"{top['process']} ({top['executions']} executions)"
else:
    top_text = "<none> (0 executions)"

pair_count = sum(
    len(pairs)
    for pairs in parent_child_pairs.values()
)

print(
    f"baseline window : "
    f"{fmt(baseline_start)} -> {fmt(baseline_end)}"
)
print(
    f"processes indexed by host: "
    f"{len(per_host)} hosts"
)
print(f"global top process    : {top_text}")
print(f"rare processes        : {len(rare_processes)}")
print(f"parent->child pairs   : {pair_count}")
print("baseline_process.json written")
PY

