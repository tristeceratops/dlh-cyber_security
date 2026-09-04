#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

EVENTS="${HANDOFF_DIR}/data/enriched_events.json"
SCHEMA="${HANDOFF_DIR}/schema/event_schema.json"
BASELINE="${BASELINE_PKG}/baselines/baseline_summary.json"
OUTPUT="detection_matrix.json"

for file in "$EVENTS" "$SCHEMA" "$BASELINE"; do
    if [[ ! -f "$file" ]]; then
        printf 'error: required file not found: %s\n' "$file" >&2
        exit 1
    fi
done

python3 -W error - "$EVENTS" "$SCHEMA" "$BASELINE" "$OUTPUT" <<'PY'
import json
import sys
from collections import defaultdict
from pathlib import Path


events_path = Path(sys.argv[1])
schema_path = Path(sys.argv[2])
baseline_path = Path(sys.argv[3])
output_path = Path(sys.argv[4])


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_ndjson(path):
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"error: invalid JSON on line {line_number} of {path}: {exc}"
                ) from exc

            if not isinstance(record, dict):
                raise SystemExit(
                    f"error: line {line_number} of {path} is not a JSON object"
                )

            records.append(record)

    return records


events = load_ndjson(events_path)
schema = load_json(schema_path)
baseline = load_json(baseline_path)

if not isinstance(schema, dict) or not isinstance(schema.get("fields"), list):
    raise SystemExit("error: event_schema.json has no valid fields list")

if not isinstance(baseline, dict):
    raise SystemExit("error: baseline_summary.json must contain a JSON object")


schema_fields = sorted(
    {
        field["name"]
        for field in schema["fields"]
        if isinstance(field, dict)
        and isinstance(field.get("name"), str)
    }
)


groups = defaultdict(list)

for event in events:
    source_type = event.get("source_type")
    if isinstance(source_type, str) and source_type:
        groups[source_type].append(event)


def is_present(event, field):
    value = event.get(field)
    return value is not None and value != ""


def candidate_fields(records):
    fields = set(schema_fields)
    for record in records:
        fields.update(record.keys())
    return fields


def stable_fields(records):
    count = len(records)
    if count == 0:
        return []

    result = []

    for field in candidate_fields(records):
        present = sum(
            is_present(record, field)
            for record in records
        )

        if present / count >= 0.95:
            result.append(field)

    return sorted(result)


def canonical_value(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def high_cardinality_fields(records):
    count = len(records)
    if count == 0:
        return []

    result = []
    threshold = 0.5 * count

    for field in candidate_fields(records):
        values = {
            canonical_value(record[field])
            for record in records
            if is_present(record, field)
        }

        if len(values) > threshold:
            result.append(field)

    return sorted(result)


def has_dict_value(obj, key):
    return isinstance(obj, dict) and bool(obj.get(key))


def detection_types(source, stable, cardinality):
    stable_set = set(stable)
    cardinality_set = set(cardinality)

    has_category = "event_category" in stable_set
    has_severity = "severity" in stable_set
    has_process = "process_name" in stable_set
    has_user = "user" in stable_set
    has_timestamp = "timestamp" in stable_set
    has_network = bool(
        {"src_ip", "dst_ip"} & stable_set
    )
    has_ports = bool(
        {"src_port", "dst_port"} & stable_set
    )

    temporal_profiles = baseline.get("temporal", {}).get("profiles", {})
    source_temporal = temporal_profiles.get(source, {})

    network_baseline = baseline.get("network", {})
    file_baseline = baseline.get("file", {})
    process_baseline = baseline.get("process", {})
    auth_baseline = baseline.get("auth", {})

    has_temporal = isinstance(source_temporal, dict) and bool(source_temporal)

    has_network_baseline = (
        isinstance(network_baseline, dict)
        and bool(
            network_baseline.get("per_host_destinations")
            or network_baseline.get("per_host_ports")
            or network_baseline.get("known_external_ips")
        )
    )

    has_file_baseline = (
        isinstance(file_baseline, dict)
        and bool(file_baseline.get("sensitive_paths"))
    )

    has_process_baseline = (
        isinstance(process_baseline, dict)
        and bool(process_baseline.get("per_host"))
    )

    has_auth_baseline = (
        isinstance(auth_baseline, dict)
        and bool(
            auth_baseline.get("per_user")
            or auth_baseline.get("per_host")
            or auth_baseline.get("known_accounts")
        )
    )

    supported = []
    rationale = {}

    # Signature detection is appropriate when deterministic fields exist.
    if (
        has_category
        or has_severity
        or has_ports
        or has_process
        or cardinality_set
    ):
        supported.append("signature")
        rationale["signature"] = (
            "stable categorical, severity, process, port, or "
            "high-cardinality fields support deterministic matching"
        )

    # Anomaly detection requires baseline-comparable telemetry.
    if (
        (has_timestamp and has_temporal)
        or (has_network and has_network_baseline)
        or (has_process and has_process_baseline)
        or (has_user and has_auth_baseline)
        or (has_file_baseline and has_category)
    ):
        supported.append("anomaly")
        rationale["anomaly"] = (
            "telemetry can be compared with available temporal, "
            "network, process, file, or authentication baselines"
        )

    # Behavioral detection requires context that can describe activity.
    if (
        (has_process and has_timestamp)
        or (has_user and has_process)
        or (
            has_network
            and has_timestamp
            and (has_user or has_process)
        )
        or (
            has_category
            and has_timestamp
            and (has_user or has_process)
        )
    ):
        supported.append("behavioral")
        rationale["behavioral"] = (
            "actor, process, network, category, and temporal "
            "context supports activity-pattern analysis"
        )

    # Correlation requires time plus a joinable entity.
    correlation_entities = {
        "hostname",
        "src_ip",
        "dst_ip",
        "user",
        "process_name",
    }

    if (
        has_timestamp
        and stable_set.intersection(correlation_entities)
    ):
        supported.append("correlation")
        rationale["correlation"] = (
            "timestamped events expose stable entities suitable "
            "for cross-event correlation"
        )

    return supported, rationale


def recommended_tactics(source, stable, supported):
    fields = set(stable)
    tactics = set()

    if {"src_ip", "dst_ip"} & fields:
        tactics.add("TA0001")  # Initial Access

    if "process_name" in fields:
        tactics.add("TA0002")  # Execution
        tactics.add("TA0003")  # Persistence
        tactics.add("TA0004")  # Privilege Escalation
        tactics.add("TA0005")  # Defense Evasion

    if "user" in fields:
        tactics.add("TA0006")  # Credential Access

    if {"src_ip", "dst_ip", "dst_port"} & fields:
        tactics.add("TA0007")  # Discovery

    if {"src_ip", "dst_ip", "dst_port"} <= fields:
        tactics.add("TA0008")  # Lateral Movement
        tactics.add("TA0011")  # Command and Control

    if (
        source == "linux_text"
        and "event_category" in fields
    ):
        tactics.add("TA0009")  # Collection

    if (
        {"src_ip", "dst_ip", "dst_port"} <= fields
        and "anomaly" in supported
    ):
        tactics.add("TA0010")  # Exfiltration

    return sorted(tactics)


matrix = {}

for source in sorted(groups):
    records = groups[source]

    stable = stable_fields(records)
    cardinality = high_cardinality_fields(records)

    supported, rationale = detection_types(
        source,
        stable,
        cardinality,
    )

    tactics = recommended_tactics(
        source,
        stable,
        supported,
    )

    matrix[source] = {
        "source_type": source,
        "record_count": len(records),
        "stable_fields": stable,
        "high_cardinality_fields": cardinality,
        "supported_detection_types": supported,
        "rationale": {
            detection_type: rationale[detection_type]
            for detection_type in supported
        },
        "recommended_attack_tactics": tactics,
    }


with output_path.open(
    "w",
    encoding="utf-8",
    newline="\n",
) as handle:
    json.dump(
        matrix,
        handle,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    handle.write("\n")


for source in sorted(matrix):
    entry = matrix[source]
    types = entry["supported_detection_types"]

    print(
        f"{source}     "
        f"{len(types)} types  "
        f"[{' '.join(types)}]"
    )

print(f"{len(matrix)} source types analyzed")
print(f"{output_path} written")
PY

