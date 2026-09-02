#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-"$HOME/3x00_handoff/evidence_handoff/"}"
BASELINE_PKG="${BASELINE_PKG:-"$(pwd)"}"
DATA_DIR="${BASELINE_PKG}/data"

SUMMARY_FILE="${DATA_DIR}/baseline_summary.json"
EVENTS_FILE="${DATA_DIR}/labeled_events.json"
OUTPUT_FILE="${DATA_DIR}/anomalies_auth.json"

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
from datetime import datetime, timedelta, timezone


summary_file = sys.argv[1]
events_file = sys.argv[2]
output_file = sys.argv[3]


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


def event_sort_key(event):
    """
    Deterministic sort key that deliberately excludes the internal
    datetime object because datetime is not JSON serializable.
    """
    comparable = {
        key: value
        for key, value in event.items()
        if key != "_timestamp"
    }

    return (
        event["_timestamp"],
        str(event.get("host", "")),
        str(event.get("user", "")),
        str(event.get("src_ip", "")),
        str(event.get("canonical_label", "")),
        json.dumps(
            comparable,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


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


# ----------------------------------------------------------------------
# Thresholds come from baseline_summary.json.
# ----------------------------------------------------------------------

thresholds = summary.get("thresholds", {})

failure_multiplier = get_nested(
    thresholds,
    "failure_rate_multiplier",
    "value",
)

if failure_multiplier is None:
    raise ValueError(
        "baseline_summary.json is missing "
        "thresholds.failure_rate_multiplier.value"
    )

try:
    failure_multiplier = float(failure_multiplier)
except (TypeError, ValueError) as exc:
    raise ValueError(
        "failure_rate_multiplier.value must be numeric"
    ) from exc


# ----------------------------------------------------------------------
# Authentication baseline information contained in baseline_summary.json
# ----------------------------------------------------------------------

auth = summary.get("auth", {})


# Known accounts
known_accounts = set()

for account in auth.get("known_accounts", []):
    if isinstance(account, str):
        known_accounts.add(account)

    elif isinstance(account, dict):
        value = account.get("user", account.get("username"))

        if isinstance(value, str):
            known_accounts.add(value)


# Maximum baseline failures in any one-hour window
max_failures = auth.get("max_failures_1h_window", 0)

try:
    max_failures = float(max_failures)
except (TypeError, ValueError) as exc:
    raise ValueError(
        "auth.max_failures_1h_window must be numeric"
    ) from exc


failure_limit = max_failures * failure_multiplier


# ----------------------------------------------------------------------
# Business-hour profile
# ----------------------------------------------------------------------

business_hours = auth.get("business_hours")

business_start = None
business_end = None

if isinstance(business_hours, dict):
    business_start = business_hours.get("start")

    if business_start is None:
        business_start = business_hours.get("start_hour")

    business_end = business_hours.get("end")

    if business_end is None:
        business_end = business_hours.get("end_hour")


def hour_from_value(value):
    if isinstance(value, int):
        return value if 0 <= value <= 23 else None

    if isinstance(value, float) and value.is_integer():
        value = int(value)
        return value if 0 <= value <= 23 else None

    if isinstance(value, str):
        text = value.strip()

        if ":" in text:
            text = text.split(":", 1)[0]

        try:
            hour = int(text)
        except ValueError:
            return None

        return hour if 0 <= hour <= 23 else None

    return None


business_start = hour_from_value(business_start)
business_end = hour_from_value(business_end)


def is_business_hour(timestamp):
    if business_start is None or business_end is None:
        return None

    hour = timestamp.hour

    if business_start < business_end:
        return business_start <= hour < business_end

    if business_start > business_end:
        return hour >= business_start or hour < business_end

    return True


# ----------------------------------------------------------------------
# Event field helpers
# ----------------------------------------------------------------------

def get_user(record):
    value = record.get("user")

    if value is None:
        value = record.get("username")

    return value


def get_host(record):
    value = record.get("host")

    if value is None:
        value = record.get("hostname")

    # Some network records use hostname="network".
    if value == "network":
        value = record.get("src_ip")

    return value


def get_src_ip(record):
    return record.get("src_ip")


def get_label(record):
    return record.get("canonical_label")


def get_event_ref(record):
    value = record.get("event_id")

    if value is None:
        value = record.get("id")

    if value is None:
        value = record.get("timestamp")

    return str(value)


# ----------------------------------------------------------------------
# Read evaluation events only
# ----------------------------------------------------------------------

events = []

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

        timestamp_value = record.get("timestamp")

        if timestamp_value is None:
            continue

        timestamp = parse_ts(timestamp_value)

        if evaluation_start <= timestamp <= evaluation_end:
            record["_timestamp"] = timestamp
            events.append(record)


events.sort(key=event_sort_key)


auth_labels = {
    "login_success",
    "login_failure",
    "logout",
    "account_lockout",
    "privilege_escalation",
}

auth_events = [
    event
    for event in events
    if get_label(event) in auth_labels
]


anomalies = []


def add_anomaly(
    event,
    anomaly_type,
    baseline_value,
    observed_value,
    severity,
    event_refs,
):
    anomalies.append(
        {
            "timestamp": iso_z(event["_timestamp"]),
            "host": get_host(event),
            "user": get_user(event),
            "src_ip": get_src_ip(event),
            "anomaly_type": anomaly_type,
            "baseline_value": baseline_value,
            "observed_value": observed_value,
            "severity": severity,
            "event_refs": sorted(set(str(ref) for ref in event_refs)),
        }
    )


# ----------------------------------------------------------------------
# 1. unknown_account
# ----------------------------------------------------------------------

for event in auth_events:
    user = get_user(event)

    if isinstance(user, str) and user and user not in known_accounts:
        add_anomaly(
            event=event,
            anomaly_type="unknown_account",
            baseline_value=sorted(known_accounts),
            observed_value=user,
            severity="high",
            event_refs=[get_event_ref(event)],
        )


# ----------------------------------------------------------------------
# 2. failure_rate_burst
#
# Any one-hour window where failures from one src_ip exceed:
#
#     baseline max failures * failure_rate_multiplier
# ----------------------------------------------------------------------

failures_by_ip = defaultdict(list)

for event in auth_events:
    if get_label(event) != "login_failure":
        continue

    src_ip = get_src_ip(event)

    if isinstance(src_ip, str) and src_ip:
        failures_by_ip[src_ip].append(event)


for src_ip in sorted(failures_by_ip):
    ip_events = sorted(
        failures_by_ip[src_ip],
        key=lambda event: event["_timestamp"],
    )

    right = 0

    for left in range(len(ip_events)):
        window_start = ip_events[left]["_timestamp"]
        window_end = window_start + timedelta(hours=1)

        if right < left:
            right = left

        while (
            right < len(ip_events)
            and ip_events[right]["_timestamp"] < window_end
        ):
            right += 1

        window_events = ip_events[left:right]
        observed = len(window_events)

        if observed > failure_limit:
            first_event = window_events[0]

            refs = [
                get_event_ref(event)
                for event in window_events
            ]

            add_anomaly(
                event=first_event,
                anomaly_type="failure_rate_burst",
                baseline_value=failure_limit,
                observed_value=observed,
                severity="high",
                event_refs=refs,
            )


# ----------------------------------------------------------------------
# 3. offhours_login
#
# Only flag a user if the baseline says that user logged in during
# business hours and never during off-hours.
# ----------------------------------------------------------------------

per_user = auth.get("per_user", {})

business_only_users = set()

if isinstance(per_user, dict):
    for user, profile in per_user.items():
        if not isinstance(profile, dict):
            continue

        business_count = profile.get("business_hours_logins")

        if business_count is None:
            business_count = profile.get("business_hours_success")

        offhours_count = profile.get("offhours_logins")

        if offhours_count is None:
            offhours_count = profile.get("offhours_success")

        try:
            business_count = float(
                business_count
                if business_count is not None
                else 0
            )

            offhours_count = float(
                offhours_count
                if offhours_count is not None
                else 0
            )
        except (TypeError, ValueError):
            continue

        if business_count > 0 and offhours_count == 0:
            business_only_users.add(user)


for event in auth_events:
    if get_label(event) != "login_success":
        continue

    user = get_user(event)

    if user not in business_only_users:
        continue

    business_status = is_business_hour(event["_timestamp"])

    # Do not invent business-hour boundaries if the baseline does not
    # contain them.
    if business_status is not False:
        continue

    add_anomaly(
        event=event,
        anomaly_type="offhours_login",
        baseline_value="business_hours_only",
        observed_value=event["_timestamp"].hour,
        severity="medium",
        event_refs=[get_event_ref(event)],
    )


# ----------------------------------------------------------------------
# 4. privilege_escalation_surge
#
# A host with zero baseline privilege escalations is anomalous when
# privilege escalation appears in the evaluation window.
# ----------------------------------------------------------------------

baseline_per_host = auth.get("per_host", {})

baseline_privilege_by_host = {}

if isinstance(baseline_per_host, dict):
    for host, profile in baseline_per_host.items():
        if not isinstance(profile, dict):
            continue

        value = profile.get("privilege_escalation", 0)

        if isinstance(value, dict):
            value = value.get("count", 0)

        try:
            baseline_privilege_by_host[host] = float(value)
        except (TypeError, ValueError):
            baseline_privilege_by_host[host] = 0.0


privilege_events_by_host = defaultdict(list)

for event in auth_events:
    if get_label(event) != "privilege_escalation":
        continue

    host = get_host(event)

    if host is not None:
        privilege_events_by_host[host].append(event)


for host in sorted(privilege_events_by_host):
    baseline_value = baseline_privilege_by_host.get(host, 0.0)

    if baseline_value != 0:
        continue

    host_events = sorted(
        privilege_events_by_host[host],
        key=lambda event: event["_timestamp"],
    )

    refs = [
        get_event_ref(event)
        for event in host_events
    ]

    for event in host_events:
        add_anomaly(
            event=event,
            anomaly_type="privilege_escalation_surge",
            baseline_value=0,
            observed_value=len(host_events),
            severity="high",
            event_refs=refs,
        )


# ----------------------------------------------------------------------
# Deterministic anomaly ordering
# ----------------------------------------------------------------------

anomalies.sort(
    key=lambda item: (
        item["timestamp"],
        item["anomaly_type"],
        str(item["host"]),
        str(item["user"]),
        str(item["src_ip"]),
        json.dumps(
            item,
            sort_keys=True,
            separators=(",", ":"),
        ),
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
}


with open(output_file, "w", encoding="utf-8") as handle:
    json.dump(
        output,
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")


counts = defaultdict(int)

for anomaly in anomalies:
    counts[anomaly["anomaly_type"]] += 1


print(
    f"evaluation window  : "
    f"{iso_z(evaluation_start)} -> {iso_z(evaluation_end)}"
)

print(
    f"unknown_account           : "
    f"{counts['unknown_account']}"
)

print(
    f"failure_rate_burst        : "
    f"{counts['failure_rate_burst']}"
)

print(
    f"offhours_login            : "
    f"{counts['offhours_login']}"
)

print(
    f"privilege_escalation_surge: "
    f"{counts['privilege_escalation_surge']}"
)

print(
    f"total anomalies           : "
    f"{len(anomalies)}"
)

print("anomalies_auth.json written")
PY
