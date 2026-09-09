#!/bin/bash
set -euo pipefail

QUEUE_FILE="${1:-enriched_queue.json}"
OUTPUT_FILE="tickets/batch6_incidents.json"

mkdir -p tickets

QUEUE_FILE="$QUEUE_FILE" OUTPUT_FILE="$OUTPUT_FILE" python3 -W error <<'PY'
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


queue_file = Path(os.environ["QUEUE_FILE"])
output_file = Path(os.environ["OUTPUT_FILE"])

if not queue_file.is_file():
    raise SystemExit(f"error: missing {queue_file}")

with queue_file.open("r", encoding="utf-8") as handle:
    document = json.load(handle)

if isinstance(document, dict):
    for key in ("alerts", "enriched_queue", "queue", "items"):
        if isinstance(document.get(key), list):
            alerts = document[key]
            break
    else:
        alerts = []
else:
    alerts = document

if not isinstance(alerts, list):
    raise SystemExit("error: enriched_queue.json must contain an alert list")


def first_value(obj: Any, *paths: str) -> Any:
    for path in paths:
        value = obj
        found = True
        for part in path.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                found = False
                break
        if found and value is not None:
            return value
    return None


def alert_id(alert: dict) -> str:
    value = first_value(alert, "alert_id", "id")
    if not value:
        raise ValueError("alert missing alert_id")
    return str(value)


def hostname(alert: dict) -> str:
    value = first_value(
        alert,
        "hostname",
        "host",
        "asset.hostname",
        "asset_record.hostname",
        "event_record.hostname",
        "event.hostname",
        "event_summary.hostname",
    )
    if isinstance(value, dict):
        value = value.get("hostname") or value.get("name")
    return str(value or "unknown-host")


def timestamp(alert: dict) -> datetime:
    value = first_value(
        alert,
        "event_summary.timestamp",
        "event_record.event_summary.timestamp",
        "event_record.timestamp",
        "event.timestamp",
        "timestamp",
    )
    if not value:
        raise ValueError(f"{alert_id(alert)} missing event_summary.timestamp")

    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def priority_score(alert: dict) -> float:
    value = first_value(
        alert,
        "priority_score",
        "alert.priority_score",
        "event_summary.priority_score",
    )
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def priority_band(alert: dict, score: float) -> str:
    value = first_value(alert, "priority_band", "alert.priority_band")
    if value:
        return str(value).lower()

    if score >= 20:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def techniques(alert: dict) -> list[str]:
    candidates = [
        first_value(alert, "attack_techniques"),
        first_value(alert, "rule.attack_techniques"),
        first_value(alert, "rule.techniques"),
        first_value(alert, "detection.attack_techniques"),
    ]

    result = []
    for value in candidates:
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, list):
            result.extend(str(item) for item in value if item is not None)
        elif isinstance(value, dict):
            result.extend(str(item) for item in value.values())

    return sorted(set(result))


def rule_name(alert: dict) -> str:
    value = first_value(
        alert,
        "rule_name",
        "rule.name",
        "rule_id",
        "detection.rule_name",
        "detection.name",
    )
    return str(value or "unknown_rule")


def previous_true_positive(alert: dict) -> bool:
    classification = first_value(
        alert,
        "classification",
        "ticket.classification",
        "triage.classification",
    )
    if str(classification).lower() == "true_positive":
        return True

    for key in ("handled_batches", "processed_batches", "previous_batches"):
        value = alert.get(key)
        if isinstance(value, list) and any(
            str(item).lower() in {"true_positive", "tp", "batch1", "batch4", "batch5"}
            for item in value
        ):
            return True

    return False


def asset_is_high_priority(alert: dict) -> bool:
    score = priority_score(alert)
    band = priority_band(alert, score)

    if band in {"critical", "high"}:
        return True

    for path in (
        "asset.priority_band",
        "asset_record.priority_band",
        "asset.priority",
        "asset_record.priority",
        "asset.criticality",
        "asset_record.criticality",
    ):
        value = first_value(alert, path)
        if str(value).lower() in {"critical", "high"}:
            return True

    return False


def existing_ticket_files() -> list[Path]:
    return sorted(
        path for path in Path("tickets").glob("*.json")
        if path.name != output_file.name
    )


def mark_grouped(alert_ids: set[str]) -> None:
    """
    Add grouped:true to any existing individual ticket containing one of
    the contributing alert IDs. Preserve all existing ticket content and
    ordering so repeated runs are idempotent.
    """
    for path in existing_ticket_files():
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        changed = False

        if isinstance(data, list):
            for ticket in data:
                if not isinstance(ticket, dict):
                    continue

                candidate = ticket.get("alert_id")
                if candidate is not None and str(candidate) in alert_ids:
                    if ticket.get("grouped") is not True:
                        ticket["grouped"] = True
                        changed = True

        elif isinstance(data, dict):
            candidate = data.get("alert_id")
            if candidate is not None and str(candidate) in alert_ids:
                if data.get("grouped") is not True:
                    data["grouped"] = True
                    changed = True

            for key in ("tickets", "alerts", "items"):
                values = data.get(key)
                if isinstance(values, list):
                    for ticket in values:
                        if not isinstance(ticket, dict):
                            continue
                        candidate = ticket.get("alert_id")
                        if candidate is not None and str(candidate) in alert_ids:
                            if ticket.get("grouped") is not True:
                                ticket["grouped"] = True
                                changed = True

        if changed:
            temporary = path.with_suffix(path.suffix + ".tmp")
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
            temporary.replace(path)


# Normalize and sort alerts deterministically.
normalized = []
for alert in alerts:
    if not isinstance(alert, dict):
        continue

    normalized.append(
        {
            "alert": alert,
            "alert_id": alert_id(alert),
            "hostname": hostname(alert),
            "timestamp": timestamp(alert),
            "priority_score": priority_score(alert),
        }
    )

normalized.sort(
    key=lambda item: (
        item["hostname"],
        item["timestamp"],
        item["alert_id"],
    )
)

# Connected-components grouping:
# two alerts are connected when they share a hostname and their timestamps
# differ by <= 600 seconds. Transitive membership is retained, so A-B and
# B-C also place A, B, and C into one incident.
incidents = []
current = []

for item in normalized:
    if not current:
        current = [item]
        continue

    previous = current[-1]

    same_host = item["hostname"] == previous["hostname"]
    within_window = (
        item["timestamp"] - previous["timestamp"]
    ).total_seconds() <= 600

    if same_host and within_window:
        current.append(item)
    else:
        incidents.append(current)
        current = [item]

if current:
    incidents.append(current)

# Only two-or-more-alert groups are incidents.
correlated = [group for group in incidents if len(group) >= 2]

all_grouped_ids = set()

incident_tickets = []

for group in correlated:
    group.sort(
        key=lambda item: (
            item["timestamp"],
            item["alert_id"],
        )
    )

    host = group[0]["hostname"]
    start = group[0]["timestamp"]
    end = max(item["timestamp"] for item in group)
    highest_score = max(item["priority_score"] for item in group)

    confidence = (
        "high_confidence"
        if len(group) >= 3
        else "medium_confidence"
    )

    any_prior_tp = any(
        previous_true_positive(item["alert"])
        for item in group
    )

    # Fresh incident classification:
    # high/critical scoring incidents are true positives; lower scoring
    # incidents remain benign/monitor candidates rather than being escalated.
    if any_prior_tp:
        classification = "true_positive"
    elif highest_score >= 10:
        classification = "true_positive"
    else:
        classification = "benign"

    asset_high = any(
        asset_is_high_priority(item["alert"])
        for item in group
    )

    if confidence == "high_confidence" and asset_high:
        recommended_action = "escalate_tier2"
    else:
        recommended_action = "monitor"

    contributing_alerts = [
        item["alert_id"]
        for item in group
    ]

    attack_techniques = sorted(
        {
            technique
            for item in group
            for technique in techniques(item["alert"])
        }
    )

    rules = sorted(
        {
            rule_name(item["alert"])
            for item in group
        }
    )

    justification = (
        f"Correlated {len(group)} alerts on {host} from "
        f"{iso_z(start)} through {iso_z(end)}; highest priority_score "
        f"was {highest_score:g}. Contributing rules: {', '.join(rules)}."
    )

    if any_prior_tp:
        justification += (
            " At least one contributing alert was already classified "
            "true_positive by an earlier triage batch."
        )
    else:
        justification += (
            " No contributing alert had a prior true_positive classification; "
            "the incident classification was evaluated from the highest "
            "priority_score in the group."
        )

    incident_key = f"{host}_{iso_z(start)}"
    ticket_id = f"incident_{incident_key}"

    incident_tickets.append(
        {
            "ticket_id": ticket_id,
            "classification": classification,
            "justification": justification,
            "contributing_alerts": contributing_alerts,
            "incident_window": {
                "start": iso_z(start),
                "end": iso_z(end),
            },
            "confidence": confidence,
            "attack_techniques": attack_techniques,
            "recommended_action": recommended_action,
            "highest_priority_score": highest_score,
            "hostname": host,
            "grouped": True,
            "analyst_time_seconds": 90,
            "created_at": iso_z(start),
        }
    )

    all_grouped_ids.update(contributing_alerts)

incident_tickets.sort(
    key=lambda ticket: (
        ticket["incident_window"]["start"],
        ticket["hostname"],
        ticket["ticket_id"],
    )
)

mark_grouped(all_grouped_ids)

temporary = output_file.with_suffix(output_file.suffix + ".tmp")
with temporary.open("w", encoding="utf-8") as handle:
    json.dump(
        incident_tickets,
        handle,
        indent=2,
        ensure_ascii=False,
    )
    handle.write("\n")
temporary.replace(output_file)

print("batch 6 correlated incidents")

for ticket in incident_tickets:
    print(
        f"  {ticket['ticket_id']}  "
        f"alerts={len(ticket['contributing_alerts'])}  "
        f"{ticket['confidence']}  "
        f"{'escalate' if ticket['recommended_action'] == 'escalate_tier2' else 'monitor'}"
    )

print(f"incidents assembled      : {len(incident_tickets)}")
print(f"alerts regrouped         : {len(all_grouped_ids)}")
print(str(output_file))
PY

