#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATASET="${HANDOFF_DIR}/data/enriched_events.json"
TAXONOMY="event_taxonomy.json"
LABELED="labeled_events.json"

[[ -f "$DATASET" ]] || {
    printf 'error: dataset not found: %s\n' "$DATASET" >&2
    exit 2
}

python3 -W error - "$DATASET" "$TAXONOMY" "$LABELED" <<'PY'
import json
import sys
from collections import Counter


DATASET = sys.argv[1]
TAXONOMY = sys.argv[2]
LABELED = sys.argv[3]


LABELS = [
    "login_success",
    "login_failure",
    "logout",
    "account_lockout",
    "privilege_escalation",
    "process_start",
    "process_stop",
    "child_process_spawn",
    "file_read_sensitive",
    "file_write_sensitive",
    "file_permission_change",
    "network_connection_outbound",
    "network_connection_inbound",
    "network_alert",
    "network_blocked",
]


# Rules use exact field/value matches.  Multiple rules may identify
# the same canonical label.
RULES = [
    # Authentication
    {
        "source_type": "auth",
        "match": {"action": "LOGIN_SUCCESS"},
        "label": "login_success",
    },
    {
        "source_type": "auth",
        "match": {"action": "SUCCESS", "event_category": "authentication"},
        "label": "login_success",
    },
    {
        "source_type": "authentication",
        "match": {"action": "LOGIN_SUCCESS"},
        "label": "login_success",
    },
    {
        "source_type": "authentication",
        "match": {"event_category": "authentication", "action": "SUCCESS"},
        "label": "login_success",
    },
    {
        "source_type": "auth",
        "match": {"action": "LOGIN_FAILURE"},
        "label": "login_failure",
    },
    {
        "source_type": "auth",
        "match": {"action": "FAILURE", "event_category": "authentication"},
        "label": "login_failure",
    },
    {
        "source_type": "authentication",
        "match": {"action": "LOGIN_FAILURE"},
        "label": "login_failure",
    },
    {
        "source_type": "authentication",
        "match": {"event_category": "authentication", "action": "FAILURE"},
        "label": "login_failure",
    },
    {
        "source_type": "auth",
        "match": {"action": "LOGOUT"},
        "label": "logout",
    },
    {
        "source_type": "authentication",
        "match": {"action": "LOGOUT"},
        "label": "logout",
    },
    {
        "source_type": "auth",
        "match": {"action": "ACCOUNT_LOCKOUT"},
        "label": "account_lockout",
    },
    {
        "source_type": "authentication",
        "match": {"action": "ACCOUNT_LOCKOUT"},
        "label": "account_lockout",
    },
    {
        "source_type": "auth",
        "match": {"event_category": "authentication", "action": "LOCKOUT"},
        "label": "account_lockout",
    },
    {
        "source_type": "auth",
        "match": {"action": "PRIVILEGE_ESCALATION"},
        "label": "privilege_escalation",
    },
    {
        "source_type": "authentication",
        "match": {"action": "PRIVILEGE_ESCALATION"},
        "label": "privilege_escalation",
    },
    {
        "source_type": "auth",
        "match": {"event_category": "privilege_escalation"},
        "label": "privilege_escalation",
    },

    # Process events
    {
        "source_type": "process",
        "match": {"action": "START"},
        "label": "process_start",
    },
    {
        "source_type": "process",
        "match": {"action": "PROCESS_START"},
        "label": "process_start",
    },
    {
        "source_type": "process",
        "match": {"event_category": "process", "action": "CREATE"},
        "label": "process_start",
    },
    {
        "source_type": "process",
        "match": {"action": "STOP"},
        "label": "process_stop",
    },
    {
        "source_type": "process",
        "match": {"action": "PROCESS_STOP"},
        "label": "process_stop",
    },
    {
        "source_type": "process",
        "match": {"event_category": "process", "action": "TERMINATE"},
        "label": "process_stop",
    },
    {
        "source_type": "process",
        "match": {"action": "CHILD_PROCESS"},
        "label": "child_process_spawn",
    },
    {
        "source_type": "process",
        "match": {"action": "CHILD_PROCESS_SPAWN"},
        "label": "child_process_spawn",
    },
    {
        "source_type": "process",
        "match": {"event_category": "process", "action": "SPAWN"},
        "label": "child_process_spawn",
    },

    # File events
    {
        "source_type": "file",
        "match": {"action": "READ", "sensitivity": "SENSITIVE"},
        "label": "file_read_sensitive",
    },
    {
        "source_type": "file",
        "match": {"action": "FILE_READ", "sensitivity": "SENSITIVE"},
        "label": "file_read_sensitive",
    },
    {
        "source_type": "file",
        "match": {"event_category": "file", "action": "READ", "sensitivity": "SENSITIVE"},
        "label": "file_read_sensitive",
    },
    {
        "source_type": "file",
        "match": {"action": "WRITE", "sensitivity": "SENSITIVE"},
        "label": "file_write_sensitive",
    },
    {
        "source_type": "file",
        "match": {"action": "FILE_WRITE", "sensitivity": "SENSITIVE"},
        "label": "file_write_sensitive",
    },
    {
        "source_type": "file",
        "match": {"event_category": "file", "action": "WRITE", "sensitivity": "SENSITIVE"},
        "label": "file_write_sensitive",
    },
    {
        "source_type": "file",
        "match": {"action": "PERMISSION_CHANGE"},
        "label": "file_permission_change",
    },
    {
        "source_type": "file",
        "match": {"action": "FILE_PERMISSION_CHANGE"},
        "label": "file_permission_change",
    },
    {
        "source_type": "file",
        "match": {"event_category": "file", "action": "CHMOD"},
        "label": "file_permission_change",
    },

    # Network events
    {
        "source_type": "firewall",
        "match": {"event_category": "network", "action": "BLOCK"},
        "label": "network_blocked",
    },
    {
        "source_type": "firewall",
        "match": {"action": "BLOCK"},
        "label": "network_blocked",
    },
    {
        "source_type": "network",
        "match": {"action": "BLOCK"},
        "label": "network_blocked",
    },
    {
        "source_type": "firewall",
        "match": {"event_category": "network", "action": "ALERT"},
        "label": "network_alert",
    },
    {
        "source_type": "network",
        "match": {"action": "ALERT"},
        "label": "network_alert",
    },
    {
        "source_type": "ids",
        "match": {"action": "ALERT"},
        "label": "network_alert",
    },
    {
        "source_type": "ids",
        "match": {"event_category": "network", "action": "ALERT"},
        "label": "network_alert",
    },
    {
        "source_type": "firewall",
        "match": {"event_category": "network", "direction": "OUTBOUND"},
        "label": "network_connection_outbound",
    },
    {
        "source_type": "network",
        "match": {"event_category": "network", "direction": "OUTBOUND"},
        "label": "network_connection_outbound",
    },
    {
        "source_type": "firewall",
        "match": {"event_category": "network", "direction": "INBOUND"},
        "label": "network_connection_inbound",
    },
    {
        "source_type": "network",
        "match": {"event_category": "network", "direction": "INBOUND"},
        "label": "network_connection_inbound",
    },
    {
        "source_type": "network",
        "match": {"event_category": "network", "action": "OUTBOUND"},
        "label": "network_connection_outbound",
    },
    {
        "source_type": "network",
        "match": {"event_category": "network", "action": "INBOUND"},
        "label": "network_connection_inbound",
    },
]


def load_ndjson(path):
    records = []

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()

            if not text:
                continue

            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                print(
                    f"error: invalid JSON on line {line_number}: {exc.msg}",
                    file=sys.stderr,
                )
                sys.exit(2)

            if not isinstance(record, dict):
                print(
                    f"error: line {line_number} is not a JSON object",
                    file=sys.stderr,
                )
                sys.exit(2)

            records.append(record)

    return records


def rule_matches(record, rule):
    if record.get("source_type") != rule["source_type"]:
        return False

    for field, expected in rule["match"].items():
        if record.get(field) != expected:
            return False

    return True


def classify(record):
    for rule in RULES:
        if rule_matches(record, rule):
            return rule["label"]

    # Additional deterministic classification for the observed firewall
    # schema.  The explicit rules above remain the taxonomy definition.
    source_type = record.get("source_type")
    category = record.get("event_category")
    action = record.get("action")

    if source_type == "firewall" and category == "network":
        if action == "BLOCK":
            return "network_blocked"

        if action == "ALERT":
            return "network_alert"

        if action == "ALLOW":
            src_zone = str(record.get("src_zone", "")).upper()
            dst_zone = str(record.get("dst_zone", "")).upper()

            if dst_zone == "INTERNET" and src_zone != "INTERNET":
                return "network_connection_outbound"

            if src_zone == "INTERNET" and dst_zone != "INTERNET":
                return "network_connection_inbound"

    return "unlabeled"


def build_taxonomy():
    taxonomy = {}

    for label in LABELS:
        taxonomy[label] = []

    for rule in RULES:
        taxonomy[rule["label"]].append(
            {
                "source_type": rule["source_type"],
                "match": rule["match"],
                "label": rule["label"],
            }
        )

    # Keep canonical labels deterministic and ensure every required
    # canonical label exists, even when its rule list is empty.
    return taxonomy


def write_json_atomic(path, value):
    temporary = f"{path}.tmp"

    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(
            value,
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")

    # Atomic replacement makes repeated execution safe.
    import os
    os.replace(temporary, path)


def write_labeled(path, records):
    temporary = f"{path}.tmp"

    with open(temporary, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(
                json.dumps(
                    record,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            handle.write("\n")

    import os
    os.replace(temporary, path)


def main():
    records = load_ndjson(DATASET)
    taxonomy = build_taxonomy()

    labeled_records = []
    distribution = Counter()

    for record in records:
        labeled = dict(record)
        label = classify(record)
        labeled["canonical_label"] = label

        labeled_records.append(labeled)
        distribution[label] += 1

    write_json_atomic(TAXONOMY, taxonomy)
    write_labeled(LABELED, labeled_records)

    rule_count = sum(len(rules) for rules in taxonomy.values())
    labeled_count = len(records) - distribution["unlabeled"]
    unlabeled_count = distribution["unlabeled"]

    print(f"taxonomy rules         : {rule_count}")
    print(f"records labeled        : {labeled_count}")
    print(f"records unlabeled      : {unlabeled_count}")
    print("canonical label distribution (top 10):")

    for label, count in sorted(
        distribution.items(),
        key=lambda item: (-item[1], item[0]),
    )[:10]:
        print(f"  {label:<28} {count}")

    print("event_taxonomy.json written")
    print("labeled_events.json written")


if __name__ == "__main__":
    main()
PY

