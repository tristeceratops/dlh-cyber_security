#!/bin/bash

set -euo pipefail

# Usage:
#   ./6-network_normalize.sh
#   ./6-network_normalize.sh /path/to/network
#
# The first argument is the directory containing:
#   firewall.csv
#   suricata_eve.json
#   pcap_summary.json
#
# Output files are written to the current working directory.

NETWORK_DIR="${1:-../evidence_pack_primary/network}"
NORMALIZED_EVENTS="normalized_events.json"
NETWORK_EVENTS="network_events.json"
QUARANTINE="quarantine.json"

python3 -W error - "$NETWORK_DIR" "$NORMALIZED_EVENTS" "$NETWORK_EVENTS" "$QUARANTINE" <<'PY'
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


network_dir = Path(sys.argv[1])
normalized_path = Path(sys.argv[2])
network_path = Path(sys.argv[3])
quarantine_path = Path(sys.argv[4])


def iso_utc(value):
    """Convert supported input timestamps to ISO-8601 UTC."""

    if value is None:
        raise ValueError("missing timestamp")

    value = str(value).strip()

    # Firewall: Unix epoch.
    try:
        if value.isdigit():
            dt = datetime.fromtimestamp(int(value), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        raise ValueError(f"unparseable timestamp: {value!r}")

    # Suricata: ISO 8601 with either Z or +0000/+00:00.
    if "T" in value:
        candidate = value

        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"

        # datetime.fromisoformat() accepts +00:00 but not +0000
        # consistently across older Python versions.
        if len(candidate) >= 5:
            suffix = candidate[-5:]
            if (
                suffix[0] in "+-"
                and suffix[1:].isdigit()
                and ":" not in suffix
            ):
                candidate = candidate[:-5] + suffix[:3] + ":" + suffix[3:]

        try:
            dt = datetime.fromisoformat(candidate)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        except ValueError:
            raise ValueError(f"unparseable timestamp: {value!r}")

    # PCAP: MM/DD/YYYY HH:MM:SS AM/PM.
    try:
        dt = datetime.strptime(
            value,
            "%m/%d/%Y %I:%M:%S %p",
        )
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError(f"unparseable timestamp: {value!r}")


def required_check(event):
    """Validate only the required fields from the existing schema."""

    required = (
        "timestamp",
        "hostname",
        "source_type",
        "event_category",
        "severity",
        "raw_message",
    )

    missing = [
        field
        for field in required
        if field not in event or event[field] is None or event[field] == ""
    ]

    if missing:
        raise ValueError(
            "missing required fields: " + ", ".join(missing)
        )


def integer_field(value, field_name):
    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"invalid {field_name}: {value!r}"
        )


def normalize_firewall(row):
    timestamp = iso_utc(row.get("timestamp"))

    event = {
        "timestamp": timestamp,
        # Firewall has no hostname in its source format.
        # The existing schema does require hostname, so use a
        # deterministic source identifier rather than quarantine
        # an otherwise valid network event.
        "hostname": "network",
        "source_type": "firewall",
        "event_category": "network",
        "severity": 0,
        "raw_message": json.dumps(
            row,
            separators=(",", ":"),
        ),
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "src_port": integer_field(row.get("src_port"), "src_port"),
        "dst_port": integer_field(row.get("dst_port"), "dst_port"),
        "action": row.get("action"),
    }

    required_check(event)
    return event


def normalize_suricata(obj):
    timestamp = iso_utc(obj.get("timestamp"))

    alert = obj.get("alert") or {}

    severity = integer_field(
        alert.get("severity"),
        "severity",
    )

    if severity is None:
        raise ValueError("missing severity")

    signature = alert.get("signature")
    if signature is None or signature == "":
        raise ValueError("missing signature")

    event = {
        "timestamp": timestamp,
        "hostname": "network",
        "source_type": "suricata",
        "event_category": "network_alert",
        "severity": severity,
        "raw_message": json.dumps(
            obj,
            separators=(",", ":"),
        ),
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dest_ip"),
        "src_port": integer_field(
            obj.get("src_port"),
            "src_port",
        ),
        "dst_port": integer_field(
            obj.get("dest_port"),
            "dst_port",
        ),
        "signature": signature,
    }

    required_check(event)
    return event


def normalize_pcap(obj):
    timestamp = iso_utc(obj.get("start_time"))

    event = {
        "timestamp": timestamp,
        "hostname": "network",
        "source_type": "pcap",
        "event_category": "network_flow",
        "severity": 0,
        "raw_message": json.dumps(
            obj,
            separators=(",", ":"),
        ),
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dst_ip"),
        "src_port": integer_field(
            obj.get("src_port"),
            "src_port",
        ),
        "dst_port": integer_field(
            obj.get("dst_port"),
            "dst_port",
        ),
    }

    required_check(event)
    return event


network_events = []
quarantine = []

counts = {
    "firewall.csv": [0, 0],
    "suricata_eve.json": [0, 0],
    "pcap_summary.json": [0, 0],
}


def process(source_name, record, normalizer):
    try:
        event = normalizer(record)

        network_events.append(event)
        counts[source_name][0] += 1

    except (ValueError, TypeError, KeyError) as exc:
        quarantine.append({
            "source_type": source_name,
            "quarantine_reason": str(exc),
            "record": record,
        })
        counts[source_name][1] += 1


# ----------------------------------------------------------------------
# firewall.csv
# ----------------------------------------------------------------------

firewall_path = network_dir / "firewall.csv"

with firewall_path.open(
    "r",
    encoding="utf-8",
    newline="",
) as handle:
    reader = csv.DictReader(handle)

    for row in reader:
        process(
            "firewall.csv",
            row,
            normalize_firewall,
        )


# ----------------------------------------------------------------------
# suricata_eve.json
# ----------------------------------------------------------------------

suricata_path = network_dir / "suricata_eve.json"

with suricata_path.open(
    "r",
    encoding="utf-8",
) as handle:
    for line_number, line in enumerate(handle, start=1):
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            quarantine.append({
                "source_type": "suricata_eve.json",
                "quarantine_reason": (
                    f"invalid JSON at line {line_number}: {exc}"
                ),
                "record": line,
            })
            counts["suricata_eve.json"][1] += 1
            continue

        process(
            "suricata_eve.json",
            record,
            normalize_suricata,
        )


# ----------------------------------------------------------------------
# pcap_summary.json
# ----------------------------------------------------------------------

pcap_path = network_dir / "pcap_summary.json"

with pcap_path.open(
    "r",
    encoding="utf-8",
) as handle:
    for line_number, line in enumerate(handle, start=1):
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            quarantine.append({
                "source_type": "pcap_summary.json",
                "quarantine_reason": (
                    f"invalid JSON at line {line_number}: {exc}"
                ),
                "record": line,
            })
            counts["pcap_summary.json"][1] += 1
            continue

        process(
            "pcap_summary.json",
            record,
            normalize_pcap,
        )


# ----------------------------------------------------------------------
# Deterministic output.
#
# We deliberately WRITE rather than APPEND. This makes the script
# idempotent: running it twice against the same input produces the
# same files.
#
# NDJSON is requested for normalized_events.json/network_events.json.
# ----------------------------------------------------------------------

with network_path.open("w", encoding="utf-8") as handle:
    for event in network_events:
        handle.write(
            json.dumps(
                event,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )


with normalized_path.open("w", encoding="utf-8") as handle:
    for event in network_events:
        handle.write(
            json.dumps(
                event,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )


# quarantine.json is a JSON array so that:
#     jq empty quarantine.json
# succeeds.
#
# An empty quarantine is therefore simply [].

with quarantine_path.open("w", encoding="utf-8") as handle:
    json.dump(
        quarantine,
        handle,
        separators=(",", ":"),
        sort_keys=True,
    )
    handle.write("\n")


# ----------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------

for source_name in (
    "firewall.csv",
    "suricata_eve.json",
    "pcap_summary.json",
):
    normalized, quarantined = counts[source_name]

    print(
        f"{source_name:<20}: "
        f"{normalized:>7} records normalized "
        f"{quarantined:>6} quarantined"
    )

print("appended to normalized_events.json")
print("network_events.json written")
print("quarantine.json written")
PY

