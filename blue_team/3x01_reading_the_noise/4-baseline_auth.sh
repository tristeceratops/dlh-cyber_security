#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"
INPUT="labeled_events.json"
OUTPUT="baseline_auth.json"

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


AUTH_LABELS = {
    "login_success",
    "login_failure",
    "logout",
    "account_lockout",
    "privilege_escalation",
}

SUCCESS_LABEL = "login_success"
FAILURE_LABEL = "login_failure"


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        # Handle the normal UTC form used by the dataset.
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        timestamp = datetime.fromisoformat(value)

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except ValueError:
        return None


def json_safe(value):
    return value


records = []
timestamps = []

# labeled_events.json is newline-delimited JSON.
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


# Dataset boundaries are derived from the actual data.
dataset_start = min(timestamps)
dataset_end = max(timestamps)

baseline_start = dataset_start
requested_end = baseline_start + timedelta(days=baseline_days)

# Never extend beyond the actual dataset.
baseline_end = min(requested_end, dataset_end)

# Authentication counters.
host_counts = defaultdict(Counter)
user_counts = defaultdict(lambda: Counter())
known_accounts = set()

# Hourly counters for business/off-hours.
business_success = 0
business_failure = 0
offhours_success = 0
offhours_failure = 0

# Track actual hours represented in the baseline.
business_hours = set()
offhours = set()

# Failure timestamps grouped by source IP.
failures_by_ip = defaultdict(list)


def get_user(record):
    """
    Authentication datasets commonly use one of several account fields.
    Prefer explicit username/account fields, then common nested locations.
    """
    candidates = (
        "username",
        "user",
        "account",
        "user_name",
        "userid",
        "user_id",
    )

    for key in candidates:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value

    for container_name in ("actor", "subject", "user_info", "account_info"):
        container = record.get(container_name)

        if isinstance(container, dict):
            for key in candidates:
                value = container.get(key)
                if isinstance(value, str) and value:
                    return value

    return None


for timestamp, record in records:
    if timestamp < baseline_start or timestamp >= baseline_end:
        continue

    label = record.get("canonical_label", "unlabeled")

    # Host can appear under hostname or host.
    host = record.get("hostname")
    if not isinstance(host, str) or not host:
        host = record.get("host")

    if isinstance(host, str) and host:
        # Only authentication labels contribute to the requested
        # per-host authentication statistics.
        if label in AUTH_LABELS:
            host_counts[host][label] += 1

    user = get_user(record)

    if user:
        known_accounts.add(user)

        if label == SUCCESS_LABEL:
            user_counts[user]["success"] += 1
        elif label == FAILURE_LABEL:
            user_counts[user]["failure"] += 1

    if label == FAILURE_LABEL:
        src_ip = record.get("src_ip")

        if isinstance(src_ip, str) and src_ip:
            failures_by_ip[src_ip].append(timestamp)

    # Business hours are 06:00 through 17:59.
    hour_start = timestamp.replace(
        minute=0,
        second=0,
        microsecond=0,
    )

    if 6 <= timestamp.hour <= 17:
        business_hours.add(hour_start)

        if label == SUCCESS_LABEL:
            business_success += 1
        elif label == FAILURE_LABEL:
            business_failure += 1

    else:
        offhours.add(hour_start)

        if label == SUCCESS_LABEL:
            offhours_success += 1
        elif label == FAILURE_LABEL:
            offhours_failure += 1


# Calculate the maximum failures from one source IP in any rolling
# one-hour interval.
max_failures = 0

for timestamps_for_ip in failures_by_ip.values():
    timestamps_for_ip.sort()

    left = 0

    for right in range(len(timestamps_for_ip)):
        current = timestamps_for_ip[right]

        while current - timestamps_for_ip[left] >= timedelta(hours=1):
            left += 1

        count = right - left + 1

        if count > max_failures:
            max_failures = count


# Averages are calculated over the actual hourly buckets represented
# in the baseline window. With no authentication records, the result
# is correctly 0.0 rather than failing.
business_hour_count = len(business_hours)
offhours_hour_count = len(offhours)

business_success_avg = (
    business_success / business_hour_count
    if business_hour_count
    else 0.0
)

business_failure_avg = (
    business_failure / business_hour_count
    if business_hour_count
    else 0.0
)

offhours_success_avg = (
    offhours_success / offhours_hour_count
    if offhours_hour_count
    else 0.0
)

offhours_failure_avg = (
    offhours_failure / offhours_hour_count
    if offhours_hour_count
    else 0.0
)


# Build deterministic output.
per_host = {}

for host in sorted(host_counts):
    per_host[host] = {
        "login_success": host_counts[host]["login_success"],
        "login_failure": host_counts[host]["login_failure"],
        "logout": host_counts[host]["logout"],
        "account_lockout": host_counts[host]["account_lockout"],
        "privilege_escalation": host_counts[host]["privilege_escalation"],
    }


per_user = []

for username in sorted(user_counts):
    per_user.append(
        {
            "username": username,
            "success": user_counts[username]["success"],
            "failure": user_counts[username]["failure"],
        }
    )


result = {
    "window": {
        "start": baseline_start.isoformat().replace("+00:00", "Z"),
        "end": baseline_end.isoformat().replace("+00:00", "Z"),
    },
    "per_host": per_host,
    "per_user": per_user,
    "known_accounts": sorted(known_accounts),
    "business_hours_avg": {
        "success": business_success_avg,
        "failure": business_failure_avg,
    },
    "offhours_avg": {
        "success": offhours_success_avg,
        "failure": offhours_failure_avg,
    },
    "max_failures_1h_window": max_failures,
}


# Write deterministically so repeated executions produce the same file.
with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(
        result,
        handle,
        indent=2,
        sort_keys=False,
        ensure_ascii=False,
    )
    handle.write("\n")


def format_timestamp(timestamp):
    return timestamp.isoformat().replace("+00:00", "Z")


print(
    f"baseline window : "
    f"{format_timestamp(baseline_start)} -> "
    f"{format_timestamp(baseline_end)}"
)
print(f"hosts           : {len(per_host)}")
print(f"known accounts  : {len(known_accounts)}")
print(
    f"business hours  : "
    f"{business_success_avg:.6f} success/h  |  "
    f"{business_failure_avg:.6f} failure/h"
)
print(
    f"off hours       : "
    f"{offhours_success_avg:.6f} success/h  |  "
    f"{offhours_failure_avg:.6f} failure/h"
)
print(f"max 1h src_ip failures : {max_failures}")
print("baseline_auth.json written")
PY

