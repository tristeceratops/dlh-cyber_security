#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-"$HOME/3x00_handoff/evidence_handoff/"}"
BASELINE_PKG="${BASELINE_PKG:-"$(pwd)"}"
DATA_DIR="${BASELINE_PKG}/data"

SUMMARY_FILE="${DATA_DIR}/baseline_summary.json"
EVENTS_FILE="${DATA_DIR}/labeled_events.json"
OUTPUT_FILE="${DATA_DIR}/anomalies_process.json"

if [[ ! -f "$SUMMARY_FILE" ]]; then
    echo "ERROR: missing $SUMMARY_FILE" >&2
    exit 1
fi

if [[ ! -f "$EVENTS_FILE" ]]; then
    echo "ERROR: missing $EVENTS_FILE" >&2
    exit 1
fi

python3 -W error - "$SUMMARY_FILE" "$EVENTS_FILE" "$OUTPUT_FILE" <<'PY'
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone


summary_file = sys.argv[1]
events_file = sys.argv[2]
output_file = sys.argv[3]


# ----------------------------------------------------------------------
# Severity rubric
#
# Critical: high-risk tooling/interpreter or unknown execution relationship
# High:     unknown process or parent-child relationship
# Medium:   rare process spike
# ----------------------------------------------------------------------

SEVERITY_RUBRIC = {
    "unknown_process_for_host": "high",
    "unknown_parent_child": "high",
    "rare_process_spike": "medium",
    "high_risk_process": "critical",
}


HIGH_RISK_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "mshta.exe",
    "nc",
    "nmap",
    "wget",
    "curl",
    "python3",
    "bash",
}


def parse_ts(value):
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    result = datetime.fromisoformat(text)

    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)

    return result.astimezone(timezone.utc)


def iso_z(value):
    return value.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def get_nested(obj, *keys, default=None):
    current = obj

    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default

        current = current[key]

    return current


def get_host(record):
    value = record.get("host")

    if value is None:
        value = record.get("hostname")

    return value


def get_user(record):
    value = record.get("user")

    if value is None:
        value = record.get("username")

    return value


def get_process_name(record):
    value = record.get("process_name")

    if value is None:
        value = record.get("process")

    return value


def get_parent_process_name(record):
    value = record.get("parent_process_name")

    if value is None:
        value = record.get("parent_process")

    return value


def get_label(record):
    return record.get("canonical_label")


def get_event_ref(record):
    value = record.get("event_id")

    if value is None:
        value = record.get("id")

    if value is None:
        value = record.get("timestamp")

    return str(value)


def normalize_process(value):
    if not isinstance(value, str):
        return None

    value = value.strip().lower()

    if not value:
        return None

    return value


def process_sort_key(event):
    return (
        event["_timestamp"],
        str(get_host(event) or ""),
        str(get_user(event) or ""),
        str(get_process_name(event) or ""),
        str(get_parent_process_name(event) or ""),
        str(get_event_ref(event)),
    )


# ----------------------------------------------------------------------
# Load baseline summary
# ----------------------------------------------------------------------

with open(summary_file, "r", encoding="utf-8") as handle:
    summary = json.load(handle)


evaluation = summary.get("evaluation_window", {})

if "start" not in evaluation or "end" not in evaluation:
    raise ValueError(
        "baseline_summary.json is missing evaluation_window start/end"
    )

evaluation_start = parse_ts(evaluation["start"])
evaluation_end = parse_ts(evaluation["end"])

if evaluation_end <= evaluation_start:
    raise ValueError("invalid evaluation window")


process_baseline = summary.get("process", {})


# ----------------------------------------------------------------------
# Baseline process information
#
# Expected baseline_summary process structure:
#
# process:
#   per_host:
#       host:
#           processes:
#               process_name: ...
#           expected_processes: [...]
#           parent_child_pairs: [...]
#
# global_top / rare_processes / parent_child_pairs are also supported.
# ----------------------------------------------------------------------

per_host = process_baseline.get("per_host", {})

if not isinstance(per_host, dict):
    per_host = {}


def extract_process_names(profile):
    names = set()

    if not isinstance(profile, dict):
        return names

    candidates = [
        profile.get("processes"),
        profile.get("expected_processes"),
    ]

    for candidate in candidates:
        if isinstance(candidate, dict):
            names.update(
                normalize_process(name)
                for name in candidate
            )

        elif isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, str):
                    names.add(normalize_process(item))

                elif isinstance(item, dict):
                    name = (
                        item.get("process_name")
                        or item.get("process")
                        or item.get("name")
                    )
                    names.add(normalize_process(name))

    return {
        name for name in names
        if name is not None
    }


def extract_pairs(profile):
    pairs = set()

    if not isinstance(profile, dict):
        return pairs

    candidates = [
        profile.get("parent_child_pairs"),
        profile.get("parent_children"),
    ]

    for candidate in candidates:
        if isinstance(candidate, list):
            for item in candidate:
                parent = None
                child = None

                if isinstance(item, dict):
                    parent = (
                        item.get("parent_process_name")
                        or item.get("parent")
                    )
                    child = (
                        item.get("process_name")
                        or item.get("child")
                    )

                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    parent = item[0]
                    child = item[1]

                if parent is not None and child is not None:
                    parent = normalize_process(parent)
                    child = normalize_process(child)

                    if parent is not None and child is not None:
                        pairs.add((parent, child))

        elif isinstance(candidate, dict):
            for parent, children in candidate.items():
                parent = normalize_process(parent)

                if parent is None:
                    continue

                if isinstance(children, list):
                    for child in children:
                        child = normalize_process(child)

                        if child is not None:
                            pairs.add((parent, child))

    return pairs


baseline_processes_by_host = defaultdict(set)
baseline_pairs_by_host = defaultdict(set)

for host, profile in per_host.items():
    baseline_processes_by_host[str(host)].update(
        extract_process_names(profile)
    )

    baseline_pairs_by_host[str(host)].update(
        extract_pairs(profile)
    )


# ----------------------------------------------------------------------
# Also support the common baseline_process structure where
# parent_child_pairs is represented globally as:
#
# parent_child_pairs:
#   host:
#       parent->child: count
# ----------------------------------------------------------------------

global_pairs = process_baseline.get("parent_child_pairs", {})

if isinstance(global_pairs, dict):
    for host, pairs in global_pairs.items():
        host = str(host)

        if isinstance(pairs, dict):
            for pair in pairs:
                if not isinstance(pair, str):
                    continue

                if "->" in pair:
                    parent, child = pair.split("->", 1)

                    parent = normalize_process(parent)
                    child = normalize_process(child)

                    if parent is not None and child is not None:
                        baseline_pairs_by_host[host].add(
                            (parent, child)
                        )

        elif isinstance(pairs, list):
            for item in pairs:
                if not isinstance(item, dict):
                    continue

                parent = (
                    item.get("parent_process_name")
                    or item.get("parent")
                )

                child = (
                    item.get("process_name")
                    or item.get("child")
                )

                parent = normalize_process(parent)
                child = normalize_process(child)

                if parent is not None and child is not None:
                    baseline_pairs_by_host[host].add(
                        (parent, child)
                    )


# ----------------------------------------------------------------------
# Global baseline process counts
# ----------------------------------------------------------------------

global_process_counts = {}

global_top = process_baseline.get("global_top", [])

if isinstance(global_top, dict):
    for name, value in global_top.items():
        process_name = normalize_process(name)

        if process_name is None:
            continue

        if isinstance(value, dict):
            value = (
                value.get("count")
                or value.get("executions")
                or value.get("execution_count")
                or 0
            )

        try:
            global_process_counts[process_name] = int(value)
        except (TypeError, ValueError):
            continue

elif isinstance(global_top, list):
    for item in global_top:
        if not isinstance(item, dict):
            continue

        process_name = (
            item.get("process_name")
            or item.get("process")
            or item.get("name")
        )

        process_name = normalize_process(process_name)

        if process_name is None:
            continue

        value = (
            item.get("executions")
            or item.get("execution_count")
            or item.get("count")
            or 0
        )

        try:
            global_process_counts[process_name] = int(value)
        except (TypeError, ValueError):
            continue


# Rare processes are explicitly listed by the baseline when available.
rare_processes = set()

for item in process_baseline.get("rare_processes", []):
    if isinstance(item, str):
        name = normalize_process(item)

    elif isinstance(item, dict):
        name = (
            item.get("process_name")
            or item.get("process")
            or item.get("name")
        )
        name = normalize_process(name)

    else:
        name = None

    if name is not None:
        rare_processes.add(name)


# If rare_processes was not explicitly preserved, derive it from
# global_top counts. The assignment defines rare as fewer than 5
# baseline executions.
for process_name, count in global_process_counts.items():
    if count < 5:
        rare_processes.add(process_name)


# ----------------------------------------------------------------------
# Read evaluation process events only
# ----------------------------------------------------------------------

process_labels = {
    "process_start",
    "process_stop",
    "child_process_spawn",
}

evaluation_process_events = []

with open(events_file, "r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON on line {line_number}"
            ) from exc

        if get_label(record) not in process_labels:
            continue

        timestamp_value = record.get("timestamp")

        if timestamp_value is None:
            continue

        timestamp = parse_ts(timestamp_value)

        if evaluation_start <= timestamp <= evaluation_end:
            record["_timestamp"] = timestamp
            evaluation_process_events.append(record)


evaluation_process_events.sort(key=process_sort_key)


# ----------------------------------------------------------------------
# Anomaly output helper
# ----------------------------------------------------------------------

anomalies = []


def add_anomaly(
    event,
    anomaly_type,
    severity,
    event_refs,
):
    anomalies.append(
        {
            "timestamp": iso_z(event["_timestamp"]),
            "host": get_host(event),
            "user": get_user(event),
            "process_name": get_process_name(event),
            "parent_process_name": get_parent_process_name(event),
            "anomaly_type": anomaly_type,
            "severity": severity,
            "event_refs": sorted(
                set(str(ref) for ref in event_refs)
            ),
        }
    )


# ----------------------------------------------------------------------
# 1. unknown_process_for_host
# ----------------------------------------------------------------------

for event in evaluation_process_events:
    host = get_host(event)
    process_name = normalize_process(
        get_process_name(event)
    )

    if host is None or process_name is None:
        continue

    host = str(host)

    if process_name not in baseline_processes_by_host.get(
        host,
        set(),
    ):
        add_anomaly(
            event=event,
            anomaly_type="unknown_process_for_host",
            severity=SEVERITY_RUBRIC[
                "unknown_process_for_host"
            ],
            event_refs=[get_event_ref(event)],
        )


# ----------------------------------------------------------------------
# 2. unknown_parent_child
# ----------------------------------------------------------------------

for event in evaluation_process_events:
    host = get_host(event)

    child = normalize_process(
        get_process_name(event)
    )

    parent = normalize_process(
        get_parent_process_name(event)
    )

    if host is None or parent is None or child is None:
        continue

    host = str(host)
    pair = (parent, child)

    if pair not in baseline_pairs_by_host.get(host, set()):
        add_anomaly(
            event=event,
            anomaly_type="unknown_parent_child",
            severity=SEVERITY_RUBRIC[
                "unknown_parent_child"
            ],
            event_refs=[get_event_ref(event)],
        )


# ----------------------------------------------------------------------
# 3. rare_process_spike
#
# Baseline: process ran fewer than 5 times globally.
# Evaluation: process runs more than 10 times on one host.
# ----------------------------------------------------------------------

evaluation_counts = defaultdict(int)
evaluation_events_by_process_host = defaultdict(list)

for event in evaluation_process_events:
    process_name = normalize_process(
        get_process_name(event)
    )

    host = get_host(event)

    if process_name is None or host is None:
        continue

    host = str(host)

    evaluation_counts[(process_name, host)] += 1

    evaluation_events_by_process_host[
        (process_name, host)
    ].append(event)


for process_host in sorted(evaluation_counts):
    process_name, host = process_host
    observed = evaluation_counts[process_host]

    baseline_count = global_process_counts.get(
        process_name
    )

    is_rare = process_name in rare_processes

    if baseline_count is not None:
        is_rare = baseline_count < 5

    if not is_rare:
        continue

    if observed <= 10:
        continue

    process_events = evaluation_events_by_process_host[
        process_host
    ]

    refs = [
        get_event_ref(event)
        for event in process_events
    ]

    for event in process_events:
        add_anomaly(
            event=event,
            anomaly_type="rare_process_spike",
            severity=SEVERITY_RUBRIC[
                "rare_process_spike"
            ],
            event_refs=refs,
        )


# ----------------------------------------------------------------------
# 4. high_risk_process
#
# A watchlisted process is anomalous when it appears on a host where
# that process never appeared in the baseline.
# ----------------------------------------------------------------------

for event in evaluation_process_events:
    host = get_host(event)

    process_name = normalize_process(
        get_process_name(event)
    )

    if host is None or process_name is None:
        continue

    if process_name not in HIGH_RISK_PROCESSES:
        continue

    host = str(host)

    if process_name in baseline_processes_by_host.get(
        host,
        set(),
    ):
        continue

    add_anomaly(
        event=event,
        anomaly_type="high_risk_process",
        severity=SEVERITY_RUBRIC[
            "high_risk_process"
        ],
        event_refs=[get_event_ref(event)],
    )


# ----------------------------------------------------------------------
# Deterministic output
# ----------------------------------------------------------------------

anomalies.sort(
    key=lambda item: (
        item["timestamp"],
        item["anomaly_type"],
        str(item["host"]),
        str(item["user"]),
        str(item["process_name"]),
        str(item["parent_process_name"]),
        tuple(item["event_refs"]),
    )
)


output = {
    "anomalies": anomalies,
    "evaluation_window": {
        "start": iso_z(evaluation_start),
        "end": iso_z(evaluation_end),
        "duration_hours": round(
            (
                evaluation_end - evaluation_start
            ).total_seconds() / 3600,
            6,
        ),
    },
    "severity_rubric": SEVERITY_RUBRIC,
}


with open(output_file, "w", encoding="utf-8") as handle:
    json.dump(
        output,
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")


# ----------------------------------------------------------------------
# Required console output
# ----------------------------------------------------------------------

counts = defaultdict(int)

for anomaly in anomalies:
    counts[anomaly["anomaly_type"]] += 1


print(
    f"evaluation window : "
    f"{iso_z(evaluation_start)} -> {iso_z(evaluation_end)}"
)

print(
    f"unknown_process_for_host : "
    f"{counts['unknown_process_for_host']}"
)

print(
    f"unknown_parent_child     : "
    f"{counts['unknown_parent_child']}"
)

print(
    f"rare_process_spike       : "
    f"{counts['rare_process_spike']}"
)

print(
    f"high_risk_process        : "
    f"{counts['high_risk_process']}"
)

print(
    f"total anomalies          : "
    f"{len(anomalies)}"
)

print("anomalies_process.json written")
PY
