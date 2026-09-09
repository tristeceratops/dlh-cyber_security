#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

EVENTS_FILE="${HANDOFF_DIR}/data/enriched_events.json"
ASSETS_FILE="${HANDOFF_DIR}/context/asset_inventory.json"
TICKETS_DIR="tickets"
OUTPUT_FILE="incidents.json"

EVENTS_FILE="$EVENTS_FILE" \
ASSETS_FILE="$ASSETS_FILE" \
TICKETS_DIR="$TICKETS_DIR" \
OUTPUT_FILE="$OUTPUT_FILE" \
python3 -W error <<'PY'
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


events_file = Path(os.environ["EVENTS_FILE"])
assets_file = Path(os.environ["ASSETS_FILE"])
tickets_dir = Path(os.environ["TICKETS_DIR"])
output_file = Path(os.environ["OUTPUT_FILE"])


def load_json(path: Path) -> Any:
    if not path.is_file():
        raise SystemExit(f"error: missing {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


events_doc = load_json(events_file)
assets_doc = load_json(assets_file)


def as_list(document: Any, keys: tuple[str, ...]) -> list:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in keys:
            value = document.get(key)
            if isinstance(value, list):
                return value
    return []


events = as_list(
    events_doc,
    ("events", "enriched_events", "items", "records"),
)

assets = as_list(
    assets_doc,
    ("assets", "asset_inventory", "items", "records"),
)


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


def event_key(event: dict) -> str | None:
    value = first_value(
        event,
        "event_ref",
        "event_id",
        "id",
        "event_summary.event_ref",
        "event_summary.event_id",
    )
    return str(value) if value is not None else None


event_by_ref = {}
for event in events:
    if isinstance(event, dict):
        key = event_key(event)
        if key:
            event_by_ref[key] = event


def asset_hostname(asset: dict) -> str | None:
    value = first_value(
        asset,
        "hostname",
        "host",
        "asset.hostname",
        "name",
    )
    return str(value) if value is not None else None


asset_by_hostname = {}
for asset in assets:
    if isinstance(asset, dict):
        host = asset_hostname(asset)
        if host:
            asset_by_hostname[host] = asset


def normalize_timestamp(value: Any) -> str:
    if value is None:
        return ""

    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    except ValueError:
        return str(value)


def timestamp_sort_key(value: str) -> tuple:
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (0, parsed.timestamp())
    except ValueError:
        return (1, value)


def hostname_from_event(event: dict) -> str:
    value = first_value(
        event,
        "hostname",
        "host",
        "event_summary.hostname",
        "asset.hostname",
    )
    return str(value or "unknown-host")


def category_from_event(event: dict) -> str:
    value = first_value(
        event,
        "event_category",
        "category",
        "event_summary.event_category",
        "event_summary.category",
    )
    return str(value or "unknown")


def event_timestamp(event: dict) -> str:
    value = first_value(
        event,
        "timestamp",
        "event_summary.timestamp",
        "event_time",
        "@timestamp",
    )
    return normalize_timestamp(value)


def short_description(event: dict) -> str:
    value = first_value(
        event,
        "description",
        "event_summary.description",
        "message",
        "event_summary.message",
        "action",
        "event_summary.action",
    )

    if value:
        text = str(value).strip()
    else:
        parts = []
        for label, paths in (
            ("user", ("user", "username", "account", "user_name")),
            ("source", ("src_ip", "source_ip", "src_host")),
            ("destination", ("dst_ip", "dest_ip", "dst_host", "destination")),
            ("process", ("process_name", "process.name")),
            ("command", ("command_line", "process.command_line")),
        ):
            item = first_value(event, *paths)
            if item is not None:
                parts.append(f"{label}={item}")

        text = ", ".join(parts) if parts else "Referenced security event"

    text = re.sub(r"\s+", " ", text)
    return text[:240]


def extract_scalars(value: Any) -> list[str]:
    result = []

    if isinstance(value, str):
        result.append(value)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        result.append(str(value))
    elif isinstance(value, list):
        for item in value:
            result.extend(extract_scalars(item))

    return result


IOC_KEYS = {
    "ip",
    "ip_address",
    "src_ip",
    "source_ip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "domain",
    "hostname",
    "dst_host",
    "dest_host",
    "destination",
    "user",
    "username",
    "user_name",
    "account",
    "account_name",
    "process_name",
    "process",
}


def collect_iocs(event: dict) -> list[str]:
    found = set()

    def walk(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                normalized = child_key.lower().replace("-", "_")
                if normalized in IOC_KEYS:
                    for scalar in extract_scalars(child_value):
                        scalar = scalar.strip()
                        if scalar:
                            found.add(scalar)
                walk(child_value, normalized)
        elif isinstance(value, list):
            for item in value:
                walk(item, key)

    walk(event)

    return sorted(found, key=lambda value: (value.lower(), value))


def ticket_iocs(ticket: dict) -> list[str]:
    result = set()
    value = ticket.get("ioc_hits")

    if isinstance(value, list):
        for hit in value:
            if isinstance(hit, str):
                result.add(hit)
            elif isinstance(hit, dict):
                for key in (
                    "value",
                    "indicator",
                    "ip",
                    "domain",
                    "hostname",
                ):
                    candidate = hit.get(key)
                    if candidate is not None:
                        result.add(str(candidate))

    elif isinstance(value, dict):
        for candidate in value.values():
            if isinstance(candidate, str):
                result.add(candidate)

    return sorted(result)


def ticket_event_refs(ticket: dict) -> list[str]:
    result = []

    candidates = [
        ticket.get("event_ref"),
        ticket.get("event_refs"),
        ticket.get("evidence_refs"),
    ]

    def add(value: Any) -> None:
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, list):
            for item in value:
                add(item)
        elif isinstance(value, dict):
            for key in ("event_ref", "event_id", "ref", "id"):
                if key in value:
                    add(value[key])

    for candidate in candidates:
        add(candidate)

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(result))


def ticket_host(ticket: dict, referenced_events: list[dict]) -> str:
    value = first_value(
        ticket,
        "hostname",
        "host",
        "asset.hostname",
        "asset_record.hostname",
    )
    if value:
        return str(value)

    if referenced_events:
        return hostname_from_event(referenced_events[0])

    return "unknown-host"


def ticket_rule_title(ticket: dict) -> str:
    value = first_value(
        ticket,
        "rule_title",
        "rule_name",
        "rule.name",
        "rule_id",
        "detection.rule_name",
        "detection.name",
    )
    return str(value or "security detection")


def ticket_techniques(ticket: dict) -> list[str]:
    result = set()

    value = ticket.get("attack_techniques")
    if isinstance(value, str):
        result.add(value)
    elif isinstance(value, list):
        result.update(str(item) for item in value)

    rule = ticket.get("rule")
    if isinstance(rule, dict):
        for key in ("attack_techniques", "techniques"):
            value = rule.get(key)
            if isinstance(value, str):
                result.add(value)
            elif isinstance(value, list):
                result.update(str(item) for item in value)

    return sorted(result)


def load_tickets() -> list[dict]:
    result = []

    if not tickets_dir.is_dir():
        raise SystemExit(f"error: missing {tickets_dir}")

    batch_pattern = re.compile(r"batch([1-7])_.*\.json$")

    for path in sorted(tickets_dir.glob("*.json")):
        if not batch_pattern.match(path.name):
            continue

        document = load_json(path)

        if isinstance(document, list):
            candidates = document
        elif isinstance(document, dict):
            candidates = []
            for key in ("tickets", "alerts", "items"):
                if isinstance(document.get(key), list):
                    candidates.extend(document[key])
            if not candidates and "ticket_id" in document:
                candidates = [document]
        else:
            candidates = []

        for ticket in candidates:
            if not isinstance(ticket, dict):
                continue

            classification = str(
                ticket.get("classification", "")
            ).lower()

            action = str(
                ticket.get("recommended_action", "")
            ).lower()

            if (
                classification == "true_positive"
                and action in {"escalate_tier2", "monitor"}
            ):
                result.append(ticket)

    # Deterministic deduplication. A ticket may appear in multiple batch files
    # after correlation processing.
    unique = {}
    for ticket in result:
        ticket_id = str(ticket.get("ticket_id", ""))
        if ticket_id:
            unique[ticket_id] = ticket

    return [
        unique[key]
        for key in sorted(unique)
    ]


def containment_for(ticket: dict, referenced_events: list[dict]) -> str:
    """
    Fixed containment table. More specific indicators take precedence.
    """
    text = json.dumps(ticket, ensure_ascii=False).lower()
    event_text = json.dumps(referenced_events, ensure_ascii=False).lower()
    combined = f"{text} {event_text}"

    rule = ticket_rule_title(ticket).lower()

    if (
        "credential" in rule
        or "credential" in combined
        or "account compromise" in combined
    ):
        return "disable_account"

    if (
        "c2" in combined
        or "command_and_control" in combined
        or "command-and-control" in combined
        or "malicious" in combined
        and (
            "dst_ip" in combined
            or "destination_ip" in combined
            or "dst_host" in combined
            or "destination" in combined
        )
    ):
        return "isolate_host"

    if (
        "egress" in rule
        or "outbound" in rule
        or "medical_segment" in rule
        or "destination" in rule
    ):
        return "block_ip_at_egress"

    if "brute_force" in rule or "brute force" in rule:
        return "block_source_ip"

    if (
        "privileged" in rule
        or "shift_violation" in rule
        or "privilege" in rule
    ):
        return "disable_account"

    if "interpreter" in rule:
        return "isolate_host"

    return "isolate_host"


tickets = load_tickets()

assembled = []

for ticket in tickets:
    refs = ticket_event_refs(ticket)

    referenced_events = []
    for ref in refs:
        event = event_by_ref.get(ref)
        if event is not None:
            referenced_events.append(event)

    # If a ticket references no resolvable event, do not invent a timeline.
    # The locked methodology requires event-backed tickets.
    timeline = []

    for event in referenced_events:
        timeline.append(
            {
                "timestamp": event_timestamp(event),
                "hostname": hostname_from_event(event),
                "event_category": category_from_event(event),
                "description": short_description(event),
            }
        )

    timeline.sort(
        key=lambda item: (
            timestamp_sort_key(item["timestamp"]),
            item["hostname"],
            item["description"],
        )
    )

    host = ticket_host(ticket, referenced_events)
    rule_title = ticket_rule_title(ticket)

    # Build affected assets from every hostname represented by the ticket's
    # event references, plus the ticket's explicit target host.
    affected_hosts = {host}
    affected_hosts.update(
        hostname_from_event(event)
        for event in referenced_events
    )

    affected_assets = []

    for affected_host in sorted(affected_hosts):
        asset = asset_by_hostname.get(affected_host)

        if asset is None:
            affected_assets.append(
                {
                    "hostname": affected_host,
                    "criticality": "unknown",
                    "data_classification": "unknown",
                    "network_zone": "unknown",
                }
            )
            continue

        affected_assets.append(
            {
                "hostname": affected_host,
                "criticality": str(
                    first_value(
                        asset,
                        "criticality",
                        "priority",
                        "asset_criticality",
                    ) or "unknown"
                ),
                "data_classification": str(
                    first_value(
                        asset,
                        "data_classification",
                        "data_class",
                        "classification",
                    ) or "unknown"
                ),
                "network_zone": str(
                    first_value(
                        asset,
                        "network_zone",
                        "zone",
                        "network.segment",
                    ) or "unknown"
                ),
            }
        )

    iocs = set(ticket_iocs(ticket))

    for event in referenced_events:
        iocs.update(collect_iocs(event))

    techniques = set(ticket_techniques(ticket))

    # Include techniques from contributing source-rule records when tickets
    # retain their rule object.
    for event in referenced_events:
        value = first_value(
            event,
            "attack_techniques",
            "rule.attack_techniques",
            "rule.techniques",
        )
        if isinstance(value, str):
            techniques.add(value)
        elif isinstance(value, list):
            techniques.update(str(item) for item in value)

    summary = (
        f"{rule_title} activity on {host} requires incident review."
    )

    ticket_hash = hashlib.sha256(
        str(ticket["ticket_id"]).encode("utf-8")
    ).hexdigest()

    incident_id = f"INC-{ticket_hash[:12].upper()}"

    assembled.append(
        {
            "incident_id": incident_id,
            "source_ticket_id": str(ticket["ticket_id"]),
            "summary": summary,
            "timeline": timeline,
            "affected_assets": affected_assets,
            "iocs": sorted(iocs, key=lambda value: (value.lower(), value)),
            "attack_techniques": sorted(techniques),
            "recommended_containment": containment_for(
                ticket,
                referenced_events,
            ),
            "_correlation_hosts": sorted(affected_hosts),
            "_correlation_iocs": sorted(iocs),
            "_ticket_time": (
                timeline[0]["timestamp"]
                if timeline
                else normalize_timestamp(ticket.get("created_at"))
            ),
            "_rule_title": rule_title,
        }
    )


# Establish related incidents by shared hostname or IOC.
for incident in assembled:
    related = []

    for other in assembled:
        if incident["incident_id"] == other["incident_id"]:
            continue

        shared_host = bool(
            set(incident["_correlation_hosts"])
            & set(other["_correlation_hosts"])
        )

        shared_ioc = bool(
            set(incident["_correlation_iocs"])
            & set(other["_correlation_iocs"])
        )

        if shared_host or shared_ioc:
            related.append(other["incident_id"])

    incident["related_incidents"] = sorted(set(related))


# Deterministic final ordering.
assembled.sort(
    key=lambda incident: (
        timestamp_sort_key(incident["_ticket_time"]),
        incident["_correlation_hosts"][0]
        if incident["_correlation_hosts"]
        else "",
        incident["incident_id"],
    )
)

# Remove internal assembly fields.
for incident in assembled:
    for key in (
        "_correlation_hosts",
        "_correlation_iocs",
        "_ticket_time",
        "_rule_title",
    ):
        del incident[key]

temporary = output_file.with_suffix(output_file.suffix + ".tmp")

with temporary.open("w", encoding="utf-8") as handle:
    json.dump(
        assembled,
        handle,
        indent=2,
        ensure_ascii=False,
    )
    handle.write("\n")

temporary.replace(output_file)

print("incidents assembled")

for incident in assembled:
    host = (
        incident["affected_assets"][0]["hostname"]
        if incident["affected_assets"]
        else "unknown-host"
    )
    rule_title = incident["summary"].split(" activity on ", 1)[0]
    print(
        f"  {incident['incident_id']}  "
        f"{host:<14} "
        f"{rule_title:<30} "
        f"{incident['recommended_containment']}"
    )

print(f"total incidents         : {len(assembled)}")
print("incidents.json written")
PY

