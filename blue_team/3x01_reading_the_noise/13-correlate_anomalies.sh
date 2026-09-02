#!/bin/bash

set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-"$(pwd)"}"
DATA_DIR="${BASELINE_PKG}/data"

AUTH_FILE="${DATA_DIR}/anomalies_auth.json"
PROCESS_FILE="${DATA_DIR}/anomalies_process.json"
NETWORK_FILE="${DATA_DIR}/anomalies_network.json"
OUTPUT_FILE="${DATA_DIR}/correlated_anomalies.json"

CORRELATION_WINDOW="${CORRELATION_WINDOW:-300}"

# ----------------------------------------------------------------------
# Scoring rubric
#
# Score =
#   number of involved source categories
#   + number of distinct anomaly types
#   + asset criticality multiplier
#
# Criticality multiplier:
#   LOW      = 1
#   MEDIUM   = 2
#   HIGH     = 3
#   CRITICAL = 4
# ----------------------------------------------------------------------

if ! [[ "$CORRELATION_WINDOW" =~ ^[0-9]+$ ]]; then
    echo "ERROR: CORRELATION_WINDOW must be a non-negative integer" >&2
    exit 1
fi

for file in "$AUTH_FILE" "$PROCESS_FILE" "$NETWORK_FILE"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: missing $file" >&2
        exit 1
    fi
done

python3 -W error - \
    "$AUTH_FILE" \
    "$PROCESS_FILE" \
    "$NETWORK_FILE" \
    "$OUTPUT_FILE" \
    "$CORRELATION_WINDOW" <<'PY'
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone


auth_file = sys.argv[1]
process_file = sys.argv[2]
network_file = sys.argv[3]
output_file = sys.argv[4]
correlation_window = int(sys.argv[5])


CRITICALITY_MULTIPLIERS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
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


def load_anomalies(filename, source):
    with open(filename, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    anomalies = data.get("anomalies", [])

    if not isinstance(anomalies, list):
        raise ValueError(
            f"{filename}: anomalies must be a list"
        )

    result = []

    for index, anomaly in enumerate(anomalies):
        if not isinstance(anomaly, dict):
            raise ValueError(
                f"{filename}: anomaly {index} is not an object"
            )

        if "timestamp" not in anomaly:
            raise ValueError(
                f"{filename}: anomaly {index} missing timestamp"
            )

        if "host" not in anomaly:
            raise ValueError(
                f"{filename}: anomaly {index} missing host"
            )

        if "anomaly_type" not in anomaly:
            raise ValueError(
                f"{filename}: anomaly {index} missing anomaly_type"
            )

        timestamp = parse_ts(anomaly["timestamp"])

        host = anomaly.get("host")

        if host is None:
            continue

        host = str(host)

        anomaly_type = str(anomaly["anomaly_type"])

        # Prefer an explicit reference if supplied. Otherwise create a
        # deterministic source/index reference.
        event_refs = anomaly.get("event_refs", [])

        if isinstance(event_refs, list) and event_refs:
            member_ref = "|".join(
                sorted(str(ref) for ref in event_refs)
            )
        else:
            member_ref = f"{source}:{index}"

        criticality = (
            anomaly.get("asset_criticality")
            or anomaly.get("criticality")
            or anomaly.get("asset", {}).get("criticality")
            if isinstance(anomaly.get("asset"), dict)
            else (
                anomaly.get("asset_criticality")
                or anomaly.get("criticality")
            )
        )

        if not isinstance(criticality, str):
            criticality = "LOW"

        criticality = criticality.upper()

        if criticality not in CRITICALITY_MULTIPLIERS:
            criticality = "LOW"

        result.append(
            {
                "timestamp": timestamp,
                "host": host,
                "source": source,
                "anomaly_type": anomaly_type,
                "member_ref": member_ref,
                "criticality": criticality,
                "original": anomaly,
            }
        )

    return result


# ----------------------------------------------------------------------
# Load all single-source anomalies.
# ----------------------------------------------------------------------

all_anomalies = []

all_anomalies.extend(
    load_anomalies(auth_file, "auth")
)

all_anomalies.extend(
    load_anomalies(process_file, "process")
)

all_anomalies.extend(
    load_anomalies(network_file, "network")
)


# Deterministic ordering.
all_anomalies.sort(
    key=lambda item: (
        item["host"],
        item["timestamp"],
        item["source"],
        item["anomaly_type"],
        item["member_ref"],
    )
)


# ----------------------------------------------------------------------
# Group anomalies by host.
# ----------------------------------------------------------------------

by_host = defaultdict(list)

for anomaly in all_anomalies:
    by_host[anomaly["host"]].append(anomaly)


correlated_findings = []


# ----------------------------------------------------------------------
# Correlation.
#
# A group is formed when at least two anomalies from different source
# categories occur within CORRELATION_WINDOW seconds.
#
# The grouping uses connected time ranges so a chain such as:
#
#   auth @ 00:00
#   process @ 00:04
#   network @ 00:08
#
# is correlated when the configured window is 5 minutes.
# ----------------------------------------------------------------------

for host in sorted(by_host):
    host_events = sorted(
        by_host[host],
        key=lambda item: (
            item["timestamp"],
            item["source"],
            item["anomaly_type"],
            item["member_ref"],
        ),
    )

    if not host_events:
        continue

    current_group = [host_events[0]]
    group_start = host_events[0]["timestamp"]

    for event in host_events[1:]:
        previous = current_group[-1]

        gap = (
            event["timestamp"] - previous["timestamp"]
        ).total_seconds()

        if gap <= correlation_window:
            current_group.append(event)
        else:
            # Finalize the previous group.
            sources = {
                item["source"]
                for item in current_group
            }

            if len(sources) >= 2:
                correlated_findings.append(
                    {
                        "host": host,
                        "members": list(current_group),
                    }
                )

            current_group = [event]
            group_start = event["timestamp"]

    # Final group.
    sources = {
        item["source"]
        for item in current_group
    }

    if len(sources) >= 2:
        correlated_findings.append(
            {
                "host": host,
                "members": list(current_group),
            }
        )


# ----------------------------------------------------------------------
# Build final correlated findings.
# ----------------------------------------------------------------------

findings = []


for finding in correlated_findings:
    host = finding["host"]
    members = finding["members"]

    members.sort(
        key=lambda item: (
            item["timestamp"],
            item["source"],
            item["anomaly_type"],
            item["member_ref"],
        )
    )

    sources = sorted(
        {
            item["source"]
            for item in members
        }
    )

    anomaly_types = sorted(
        {
            item["anomaly_type"]
            for item in members
        }
    )

    window_start = min(
        item["timestamp"]
        for item in members
    )

    window_end = max(
        item["timestamp"]
        for item in members
    )

    # Use the highest criticality represented by the correlated
    # anomalies.
    criticality = max(
        (
            item["criticality"]
            for item in members
        ),
        key=lambda value: CRITICALITY_MULTIPLIERS[value],
    )

    source_score = len(sources)
    anomaly_type_bonus = len(anomaly_types)
    criticality_bonus = CRITICALITY_MULTIPLIERS[criticality]

    score = (
        source_score
        + anomaly_type_bonus
        + criticality_bonus
    )

    member_refs = []

    for item in members:
        member_refs.append(
            {
                "source": item["source"],
                "reference": item["member_ref"],
            }
        )

    # Short deterministic identifier based on the complete finding.
    identity = {
        "host": host,
        "window_start": iso_z(window_start),
        "window_end": iso_z(window_end),
        "sources": sources,
        "anomaly_types": anomaly_types,
        "member_refs": member_refs,
    }

    digest = hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:12]

    correlation_id = f"corr-{digest}"

    findings.append(
        {
            "correlation_id": correlation_id,
            "host": host,
            "window_start": iso_z(window_start),
            "window_end": iso_z(window_end),
            "sources_involved": sources,
            "anomaly_types": anomaly_types,
            "member_refs": member_refs,
            "score": int(score),
        }
    )


# ----------------------------------------------------------------------
# Deterministic finding order.
# ----------------------------------------------------------------------

findings.sort(
    key=lambda finding: (
        finding["host"],
        finding["window_start"],
        finding["window_end"],
        finding["correlation_id"],
    )
)


output = {
    "correlation_window_seconds": correlation_window,
    "single_source_anomalies": len(all_anomalies),
    "correlated_findings": findings,
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
# Required console output.
# ----------------------------------------------------------------------

max_score = max(
    (finding["score"] for finding in findings),
    default=0,
)

hosts = {
    finding["host"]
    for finding in findings
}

print(
    f"single-source anomalies  : "
    f"{len(all_anomalies)}"
)

print(
    f"correlated findings      : "
    f"{len(findings)}"
)

print(
    f"multi-host findings      : "
    f"{len(hosts)}"
)

print(
    f"max score                : "
    f"{max_score}"
)

print("correlated_anomalies.json written")
PY
