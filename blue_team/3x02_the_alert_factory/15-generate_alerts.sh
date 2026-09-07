#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:?BASELINE_PKG is not set}"
HANDOFF_DIR="${HANDOFF_DIR:?HANDOFF_DIR is not set}"

RULE_DIR="rules/sigma"
RUNNER="./3-sigma_runner.sh"

EVIDENCE="$HANDOFF_DIR/evidence_handoff/data/normalized_events.json"
ASSET_INVENTORY="$HANDOFF_DIR/context/asset_inventory.json"
PRIORITIZATION="rule_prioritization.json"
OUTPUT="alert_queue.json"
SCHEMA="alert_queue_schema.json"

if [[ ! -x "$RUNNER" ]]; then
    echo "ERROR: runner not executable: $RUNNER" >&2
    exit 1
fi

for file in "$EVIDENCE" "$ASSET_INVENTORY" "$PRIORITIZATION"; do
    [[ -f "$file" ]] || {
        echo "ERROR: missing input: $file" >&2
        exit 1
    }
done

python3 - \
    "$RULE_DIR" \
    "$RUNNER" \
    "$EVIDENCE" \
    "$ASSET_INVENTORY" \
    "$PRIORITIZATION" \
    "$OUTPUT" \
    "$SCHEMA" <<'PY'
import hashlib
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

rule_dir = Path(sys.argv[1])
runner = sys.argv[2]
evidence_file = sys.argv[3]
asset_file = sys.argv[4]
priority_file = sys.argv[5]
output_file = Path(sys.argv[6])
schema_file = Path(sys.argv[7])


def load_json(path):
    text = Path(path).read_text(encoding="utf-8").strip()

    if not text:
        return []

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [
            json.loads(line)
            for line in text.splitlines()
            if line.strip()
        ]


def records_from(data, keys=("events", "items", "records", "anomalies")):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in keys:
            if isinstance(data.get(key), list):
                return data[key]

        return [data]

    return []


def first(record, keys, default=""):
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return default


def parse_timestamp(value):
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def extract_event_ref(event):
    return str(first(
        event,
        ["event_ref", "eventRef", "event_id", "eventId", "id"],
        ""
    ))


def extract_techniques(rule):
    techniques = []

    for tag in rule.get("tags", []):
        match = re.search(
            r"^attack\.(t\d{4}(?:\.\d{3})?)$",
            str(tag),
            re.I
        )

        if match:
            technique = match.group(1).upper()

            if technique not in techniques:
                techniques.append(technique)

    return techniques


def rule_number(rule_path):
    match = re.match(r"(\d+)", rule_path.stem)

    if match:
        return match.group(1).zfill(3)

    return rule_path.stem


def short_rule_name(rule_path):
    name = rule_path.stem
    name = re.sub(r"^\d+[_-]", "", name)
    return name


# ----------------------------------------------------------------------
# Load evidence and build event lookup.
# ----------------------------------------------------------------------

evidence_data = load_json(evidence_file)

events = records_from(
    evidence_data,
    ("events", "items", "records")
)

events_by_ref = {}

for event in events:
    if not isinstance(event, dict):
        continue

    ref = extract_event_ref(event)

    if ref:
        events_by_ref[ref] = event


# ----------------------------------------------------------------------
# Load asset inventory.
# ----------------------------------------------------------------------

asset_data = load_json(asset_file)

asset_records = records_from(
    asset_data,
    ("assets", "hosts", "systems", "inventory", "items")
)

assets_by_host = {}

for asset in asset_records:
    if not isinstance(asset, dict):
        continue

    hostname = first(
        asset,
        ["hostname", "host", "name", "asset_name"],
        ""
    )

    if hostname:
        assets_by_host[str(hostname).lower()] = asset


# ----------------------------------------------------------------------
# Load prioritization scores.
# ----------------------------------------------------------------------

priority_data = load_json(priority_file)

priority_records = records_from(
    priority_data,
    ("rules", "prioritization", "results")
)

priority_by_rule = {}

for item in priority_records:
    if not isinstance(item, dict):
        continue

    rule_id = first(
        item,
        ["rule_id", "id", "rule"],
        ""
    )

    if rule_id:
        priority_by_rule[str(rule_id)] = float(
            item.get("priority_score", 0)
        )


# ----------------------------------------------------------------------
# Enumerate active rules.
#
# If rules/sigma/tuned/<same filename> exists, use it instead of the
# original rule.
# ----------------------------------------------------------------------

original_rules = sorted(
    rule_dir.glob("*.yml")
)

tuned_dir = rule_dir / "tuned"

active_rules = []

for original in original_rules:
    tuned = tuned_dir / original.name

    if tuned.is_file():
        active_rules.append(tuned)
    else:
        active_rules.append(original)


# ----------------------------------------------------------------------
# Execute rules.
# ----------------------------------------------------------------------

all_alerts = []
raw_match_count = 0
rules_executed = 0

for rule_path in active_rules:
    rules_executed += 1

    # Evaluation window is supplied through environment variables if
    # available. Otherwise the runner evaluates the complete evidence set.
    window = ""

    if (
        "EVAL_START" in __import__("os").environ
        and "EVAL_END" in __import__("os").environ
    ):
        window = (
            __import__("os").environ["EVAL_START"]
            + ","
            + __import__("os").environ["EVAL_END"]
        )

    cmd = [
        runner,
        str(rule_path)
    ]

    if window:
        cmd.extend(["--window", window])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True
    )

    runner_output = json.loads(result.stdout)

    rule_id = str(runner_output["rule_id"])
    rule_title = runner_output["rule_title"]
    rule_level = runner_output["level"]

    priority_score = priority_by_rule.get(rule_id, 0.0)

    # Load the rule itself for ATT&CK tags.
    rule_data = load_json(rule_path) if rule_path.suffix == ".json" else None

    import yaml

    with open(rule_path, encoding="utf-8") as f:
        sigma_rule = yaml.safe_load(f)

    techniques = extract_techniques(sigma_rule)

    for match in runner_output.get("matches", []):
        raw_match_count += 1

        event_ref = str(match.get("event_ref", ""))

        event = events_by_ref.get(event_ref)

        if event is None:
            continue

        hostname = str(first(
            event,
            ["hostname", "host", "computer", "asset"],
            match.get("hostname", "")
        ))

        user = str(first(
            event,
            ["user", "username", "account", "subject_user"],
            ""
        ))

        timestamp = str(first(
            event,
            ["timestamp", "event_timestamp", "@timestamp"],
            match.get("timestamp", "")
        ))

        # Deterministic UUID5 from rule_id + event_ref.
        alert_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{rule_id}+{event_ref}"
            )
        )

        # Hash the complete raw event record.
        raw_event = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        evidence_hash = hashlib.sha256(raw_event).hexdigest()

        event_summary = {
            "timestamp": timestamp,
            "hostname": hostname,
            "user": str(first(
                event,
                ["user", "username", "account", "subject_user"],
                ""
            )),
            "src_ip": str(first(
                event,
                ["src_ip", "source_ip", "srcip"],
                ""
            )),
            "dst_ip": str(first(
                event,
                ["dst_ip", "destination_ip", "dstip"],
                ""
            )),
            "process_name": str(first(
                event,
                ["process_name", "Image", "process", "processName"],
                ""
            )),
            "canonical_label": str(first(
                event,
                ["canonical_label", "label"],
                ""
            )),
            "event_category": str(first(
                event,
                ["event_category", "category"],
                ""
            ))
        }

        asset_context = assets_by_host.get(
            hostname.lower(),
            {}
        )

        all_alerts.append({
            "alert_id": alert_id,
            "generated_at": utc_now(),
            "rule_id": rule_id,
            "rule_title": rule_title,
            "rule_level": rule_level,
            "priority_score": priority_score,
            "event_ref": event_ref,
            "event_summary": event_summary,
            "asset_context": asset_context,
            "attack_techniques": techniques,
            "status": "new",
            "evidence_hash": evidence_hash
        })


# ----------------------------------------------------------------------
# Deduplicate within 60 seconds on:
#
#   (rule_id, hostname, user)
#
# Keep the first alert chronologically.
# ----------------------------------------------------------------------

all_alerts.sort(
    key=lambda alert: parse_timestamp(
        alert["event_summary"]["timestamp"]
    )
)

deduplicated = []
last_seen = {}

for alert in all_alerts:
    summary = alert["event_summary"]

    key = (
        alert["rule_id"],
        summary["hostname"],
        summary["user"]
    )

    current_time = parse_timestamp(summary["timestamp"])

    previous_time = last_seen.get(key)

    if previous_time is not None:
        delta = (current_time - previous_time).total_seconds()

        if 0 <= delta <= 60:
            continue

    last_seen[key] = current_time
    deduplicated.append(alert)


# ----------------------------------------------------------------------
# Final ordering:
#   priority_score descending
#   timestamp ascending
# ----------------------------------------------------------------------

deduplicated.sort(
    key=lambda alert: (
        -float(alert["priority_score"]),
        parse_timestamp(alert["event_summary"]["timestamp"])
    )
)


# ----------------------------------------------------------------------
# Write queue.
# ----------------------------------------------------------------------

output_file.write_text(
    json.dumps(deduplicated, indent=2) + "\n",
    encoding="utf-8"
)


# ----------------------------------------------------------------------
# Explicit queue contract for 3x03.
# ----------------------------------------------------------------------

schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "3x02 Alert Queue",
    "description": "Alert queue contract produced by 15-generate_alerts.sh",
    "type": "array",
    "items": {
        "type": "object",
        "required": [
            "alert_id",
            "generated_at",
            "rule_id",
            "rule_title",
            "rule_level",
            "priority_score",
            "event_ref",
            "event_summary",
            "asset_context",
            "attack_techniques",
            "status",
            "evidence_hash"
        ],
        "properties": {
            "alert_id": {
                "type": "string",
                "format": "uuid",
                "description": "Deterministic UUID5 derived from rule_id + event_ref"
            },
            "generated_at": {
                "type": "string",
                "format": "date-time"
            },
            "rule_id": {
                "type": "string"
            },
            "rule_title": {
                "type": "string"
            },
            "rule_level": {
                "type": "string",
                "enum": [
                    "informational",
                    "low",
                    "medium",
                    "high",
                    "critical",
                    "unknown"
                ]
            },
            "priority_score": {
                "type": "number",
                "minimum": 0
            },
            "event_ref": {
                "type": "string",
                "description": "Reference to the source event in normalized_events.json"
            },
            "event_summary": {
                "type": "object",
                "required": [
                    "timestamp",
                    "hostname",
                    "user",
                    "src_ip",
                    "dst_ip",
                    "process_name",
                    "canonical_label",
                    "event_category"
                ],
                "properties": {
                    "timestamp": {
                        "type": "string"
                    },
                    "hostname": {
                        "type": "string"
                    },
                    "user": {
                        "type": "string"
                    },
                    "src_ip": {
                        "type": "string"
                    },
                    "dst_ip": {
                        "type": "string"
                    },
                    "process_name": {
                        "type": "string"
                    },
                    "canonical_label": {
                        "type": "string"
                    },
                    "event_category": {
                        "type": "string"
                    }
                },
                "additionalProperties": false
            },
            "asset_context": {
                "type": "object",
                "description": "Matching asset inventory record"
            },
            "attack_techniques": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^T\\d{4}(\\.\\d{3})?$"
                }
            },
            "status": {
                "type": "string",
                "enum": [
                    "new"
                ]
            },
            "evidence_hash": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$"
            }
        },
        "additionalProperties": false
    }
}

schema_file.write_text(
    json.dumps(schema, indent=2) + "\n",
    encoding="utf-8"
)


# ----------------------------------------------------------------------
# Output.
# ----------------------------------------------------------------------

print(f"rules executed            : {rules_executed}")
print(f"raw matches               : {raw_match_count}")
print(f"after deduplication       : {len(deduplicated)}")
print("top 5 alerts")

for index, alert in enumerate(deduplicated[:5], start=1):
    title = alert["rule_title"]
    rule_id = alert["rule_id"]

    number_match = re.match(r"(\d+)", rule_id)

    if number_match:
        number = number_match.group(1).zfill(3)
    else:
        number = rule_id

    short_name = re.sub(
        r"^\d+[_-]",
        "",
        title.lower().replace(" ", "_")
    )

    short_name = short_name.replace(".yml", "")

    hostname = alert["event_summary"]["hostname"]

    print(
        f"{index:2}  "
        f"{alert['priority_score']:4.1f}  "
        f"{alert['rule_level']:<9} "
        f"{number} {short_name:<35} "
        f"{hostname}"
    )

print(f"alert_queue.json        : {len(deduplicated)} alerts")
print("alert_queue_schema.json : written")
PY
