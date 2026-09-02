#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-"$HOME/3x00_handoff/evidence_handoff/"}"
BASELINE_PKG="${BASELINE_PKG:-"$(pwd)/baseline_package"}"

AUTH="${BASELINE_PKG}/baseline_auth.json"
PROCESS="${BASELINE_PKG}/baseline_process.json"
NETWORK="${BASELINE_PKG}/baseline_network.json"
FILE_BASELINE="${BASELINE_PKG}/baseline_file.json"
TEMPORAL="${BASELINE_PKG}/temporal_profile.json"

ENRICHED="${HANDOFF_DIR}/data/enriched_events.json"
OUTPUT="${BASELINE_PKG}/baseline_summary.json"

BASELINE_DAYS="${BASELINE_DAYS:-7}"

if [[ ! -d "$HANDOFF_DIR" ]]; then
    echo "ERROR: HANDOFF_DIR does not exist: $HANDOFF_DIR" >&2
    exit 1
fi

if [[ ! -f "$ENRICHED" ]]; then
    echo "ERROR: missing enriched dataset: $ENRICHED" >&2
    exit 1
fi

for input in "$AUTH" "$PROCESS" "$NETWORK" "$FILE_BASELINE" "$TEMPORAL"; do
    if [[ ! -f "$input" ]]; then
        echo "ERROR: missing baseline file: $input" >&2
        exit 1
    fi
done

if ! [[ "$BASELINE_DAYS" =~ ^[0-9]+$ ]] || [[ "$BASELINE_DAYS" -lt 1 ]]; then
    echo "ERROR: BASELINE_DAYS must be a positive integer" >&2
    exit 1
fi

mkdir -p "$BASELINE_PKG"

python3 -W error - "$ENRICHED" "$AUTH" "$PROCESS" "$NETWORK" \
    "$FILE_BASELINE" "$TEMPORAL" "$OUTPUT" "$BASELINE_DAYS" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone


enriched_path = sys.argv[1]
auth_path = sys.argv[2]
process_path = sys.argv[3]
network_path = sys.argv[4]
file_path = sys.argv[5]
temporal_path = sys.argv[6]
output_path = sys.argv[7]
baseline_days = int(sys.argv[8])


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_timestamp(value):
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    timestamp = datetime.fromisoformat(text)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def format_timestamp(timestamp):
    return timestamp.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def find_dataset_window(path):
    first_timestamp = None
    last_timestamp = None

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"ERROR: invalid JSON in {path} at line "
                    f"{line_number}: {exc}"
                ) from exc

            timestamp = parse_timestamp(event.get("timestamp"))

            if timestamp is None:
                continue

            if first_timestamp is None or timestamp < first_timestamp:
                first_timestamp = timestamp

            if last_timestamp is None or timestamp > last_timestamp:
                last_timestamp = timestamp

    if first_timestamp is None or last_timestamp is None:
        raise SystemExit(
            f"ERROR: no valid timestamps found in {path}"
        )

    return first_timestamp, last_timestamp


def add_hosts(document, key, hosts):
    value = document.get(key)

    if isinstance(value, dict):
        for host in value:
            hosts.add(str(host))


# ---------------------------------------------------------------------
# Derive baseline/evaluation windows from the actual dataset.
# ---------------------------------------------------------------------

dataset_start, dataset_end = find_dataset_window(enriched_path)

baseline_start = dataset_start
baseline_end = baseline_start + timedelta(days=baseline_days)

if baseline_end > dataset_end:
    raise SystemExit(
        "ERROR: BASELINE_DAYS extends beyond the dataset"
    )

evaluation_start = baseline_end
evaluation_end = dataset_end

evaluation_duration_hours = (
    evaluation_end - evaluation_start
).total_seconds() / 3600.0

if evaluation_duration_hours <= 0:
    raise SystemExit(
        "ERROR: evaluation window is empty"
    )


# ---------------------------------------------------------------------
# Load previous baseline artifacts.
# ---------------------------------------------------------------------

auth = load_json(auth_path)
process = load_json(process_path)
network = load_json(network_path)
file_baseline = load_json(file_path)
temporal = load_json(temporal_path)


# ---------------------------------------------------------------------
# Host inventory.
# ---------------------------------------------------------------------

hosts = set()

add_hosts(auth, "per_host", hosts)

add_hosts(process, "per_host", hosts)

add_hosts(network, "per_host_destinations", hosts)
add_hosts(network, "per_host_ports", hosts)

add_hosts(file_baseline, "per_host_paths", hosts)

host_inventory = sorted(hosts)


# ---------------------------------------------------------------------
# Threshold policy.
#
# These values are stored in baseline_summary.json for anomaly scripts
# to consume. They are not hidden in anomaly-script source code.
# ---------------------------------------------------------------------

thresholds = {
    "failure_rate_multiplier": {
        "value": 3,
        "comment": (
            "Authentication failure rate must exceed three times "
            "the baseline rate before rate-based anomaly scoring."
        ),
    },
    "unknown_process_penalty": {
        "value": 5,
        "comment": (
            "Five anomaly points are assigned to a process absent "
            "from the host's baseline process footprint."
        ),
    },
    "unknown_port_penalty": {
        "value": 4,
        "comment": (
            "Four anomaly points are assigned to a destination port "
            "absent from the host's baseline service profile."
        ),
    },
    "unknown_destination_penalty": {
        "value": 4,
        "comment": (
            "Four anomaly points are assigned to a destination IP "
            "not observed during the baseline."
        ),
    },
    "rare_file_access_penalty": {
        "value": 5,
        "comment": (
            "Five anomaly points are assigned to a sensitive path "
            "whose baseline access count is below three."
        ),
    },
    "unknown_file_actor_penalty": {
        "value": 5,
        "comment": (
            "Five anomaly points are assigned when the accessing "
            "process or user is absent from the normal file footprint."
        ),
    },
    "offhours_penalty": {
        "value": 2,
        "comment": (
            "Two anomaly points are assigned to activity occurring "
            "outside the established business-hours profile."
        ),
    },
    "temporal_deviation_multiplier": {
        "value": 3,
        "comment": (
            "Temporal activity above three times the corresponding "
            "baseline average is considered anomalous."
        ),
    },
}


# ---------------------------------------------------------------------
# Deterministic generated_at.
#
# datetime.now() would make repeated executions differ. Using the
# dataset-derived evaluation end keeps the output idempotent.
# ---------------------------------------------------------------------

generated_at = format_timestamp(evaluation_end)


summary = {
    "version": "1.0",

    "generated_at": generated_at,

    "baseline_window": {
        "start": format_timestamp(baseline_start),
        "end": format_timestamp(baseline_end),
        "duration_days": round(
            (baseline_end - baseline_start).total_seconds()
            / 86400.0,
            6,
        ),
    },

    "evaluation_window": {
        "start": format_timestamp(evaluation_start),
        "end": format_timestamp(evaluation_end),
        "duration_hours": round(
            evaluation_duration_hours,
            6,
        ),
    },

    "host_inventory": host_inventory,

    "auth": auth,
    "process": process,
    "network": network,
    "file": file_baseline,
    "temporal": temporal,

    "thresholds": thresholds,
}


# Deterministic serialization.
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(
        summary,
        handle,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    )
    handle.write("\n")


print("version           : 1.0")
print(
    f"baseline window   : "
    f"{format_timestamp(baseline_start)} -> "
    f"{format_timestamp(baseline_end)}  "
    f"({baseline_days} days)"
)
print(
    f"evaluation window : "
    f"{format_timestamp(evaluation_start)} -> "
    f"{format_timestamp(evaluation_end)}  "
    f"({evaluation_duration_hours:g}h)"
)
print(f"hosts             : {len(host_inventory)}")
print(
    "sections included : "
    "auth, process, network, file, temporal, thresholds"
)
print("baseline_summary.json written")
PY
