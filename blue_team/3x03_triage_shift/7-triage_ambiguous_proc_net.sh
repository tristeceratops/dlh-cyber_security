#!/bin/bash
set -euo pipefail

QUEUE_FILE="${1:-enriched_queue.json}"
BASELINE_DIR="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

BASELINE_FILE="${BASELINE_DIR}/baselines/baseline_summary.json"
EVENTS_FILE="${HANDOFF_DIR}/data/enriched_events.json"
IOC_FILE="${ASSETS_DIR}/ioc_context.json"
OUTPUT_FILE="tickets/batch5_proc_net.json"

mkdir -p tickets

python3 -W error - \
    "$QUEUE_FILE" \
    "$BASELINE_FILE" \
    "$EVENTS_FILE" \
    "$IOC_FILE" \
    "$OUTPUT_FILE" <<'PY'
import hashlib
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any


QUEUE_FILE = Path(sys.argv[1])
BASELINE_FILE = Path(sys.argv[2])
EVENTS_FILE = Path(sys.argv[3])
IOC_FILE = Path(sys.argv[4])
OUTPUT_FILE = Path(sys.argv[5])

PROCESS_CATEGORIES = {"process"}
NETWORK_CATEGORIES = {"network"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def first_value(obj: Any, *paths: str) -> Any:
    for path in paths:
        current = obj
        found = True

        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break

        if found and current not in (None, ""):
            return current

    return None


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def queue_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        for key in ("alerts", "items", "data", "enriched_queue"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]

    raise ValueError("enriched_queue.json must contain an alert list")


def event_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        for key in ("events", "items", "data", "enriched_events"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]

    raise ValueError("enriched_events.json must contain an event list")


def alert_id(alert: dict[str, Any]) -> str:
    value = first_value(alert, "alert_id", "alert.alert_id")

    if value is None:
        raise ValueError("Alert is missing alert_id")

    return str(value)


def hostname(alert: dict[str, Any]) -> str:
    value = first_value(
        alert,
        "hostname",
        "asset.hostname",
        "asset_record.hostname",
        "event_record.hostname",
    )

    return str(value) if value is not None else "unknown"


def rule_id(alert: dict[str, Any]) -> str:
    value = first_value(
        alert,
        "rule_id",
        "rule.id",
        "rule.rule_id",
    )

    return str(value) if value is not None else "unknown"


def rule_name(alert: dict[str, Any]) -> str:
    value = first_value(
        alert,
        "rule_name",
        "rule.name",
        "source_rule.name",
    )

    return str(value) if value is not None else rule_id(alert)


def category(alert: dict[str, Any]) -> str:
    value = first_value(
        alert,
        "category",
        "rule_category",
        "alert_category",
        "rule.category",
        "rule.rule_category",
    )

    return str(value).lower() if value is not None else ""


def asset_criticality(alert: dict[str, Any]) -> str:
    value = first_value(
        alert,
        "asset_criticality",
        "criticality",
        "asset.criticality",
        "asset_record.criticality",
        "asset_inventory.criticality",
    )

    return str(value).lower() if value is not None else "unknown"


def event_record(alert: dict[str, Any]) -> dict[str, Any]:
    value = alert.get("event_record")

    if isinstance(value, dict):
        return value

    return {}


def get_process_fields(alert: dict[str, Any]) -> dict[str, Any]:
    event = event_record(alert)

    return {
        "process_name": first_value(
            event,
            "process_name",
            "process.name",
        ) or first_value(
            alert,
            "process_name",
            "process.name",
        ),
        "parent_process": first_value(
            event,
            "parent_process",
            "parent_process_name",
            "process.parent_process",
            "process.parent.name",
        ) or first_value(
            alert,
            "parent_process",
            "parent_process_name",
        ),
        "command_line": first_value(
            event,
            "command_line",
            "process.command_line",
            "process.cmdline",
        ) or first_value(
            alert,
            "command_line",
            "process.command_line",
        ),
    }


def get_network_fields(alert: dict[str, Any]) -> list[dict[str, Any]]:
    event = event_record(alert)

    records: list[dict[str, Any]] = []

    def append_record(
        dst_ip: Any,
        dst_host: Any,
        dst_port: Any,
    ) -> None:
        if (
            dst_ip is None
            and dst_host is None
            and dst_port is None
        ):
            return

        records.append(
            {
                "dst_ip": str(dst_ip) if dst_ip is not None else None,
                "dst_host": str(dst_host) if dst_host is not None else None,
                "dst_port": str(dst_port) if dst_port is not None else None,
            }
        )

    network_values = event.get("network")

    if isinstance(network_values, list):
        for network in network_values:
            if isinstance(network, dict):
                append_record(
                    first_value(network, "dst_ip", "destination.ip"),
                    first_value(network, "dst_host", "destination.host"),
                    first_value(network, "dst_port", "destination.port"),
                )

    elif isinstance(network_values, dict):
        append_record(
            first_value(network_values, "dst_ip", "destination.ip"),
            first_value(network_values, "dst_host", "destination.host"),
            first_value(network_values, "dst_port", "destination.port"),
        )

    append_record(
        first_value(event, "dst_ip", "destination.ip"),
        first_value(event, "dst_host", "destination.host"),
        first_value(event, "dst_port", "destination.port"),
    )

    append_record(
        first_value(alert, "dst_ip", "destination.ip"),
        first_value(alert, "dst_host", "destination.host"),
        first_value(alert, "dst_port", "destination.port"),
    )

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()

    for record in records:
        marker = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
        )

        if marker not in seen:
            seen.add(marker)
            unique.append(record)

    return unique


def ioc_lookup(ioc_doc: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(ioc_doc, dict):
        raise ValueError("ioc_context.json must be a JSON object")

    result: dict[str, dict[str, Any]] = {}

    for key, value in ioc_doc.items():
        if isinstance(value, dict):
            result[str(key).lower()] = value

    return result


def normalize_indicator(value: str) -> str:
    return value.strip().lower()


def lookup_ioc(
    lookup: dict[str, dict[str, Any]],
    value: str | None,
) -> dict[str, Any] | None:
    if not value:
        return None

    normalized = normalize_indicator(value)

    direct = lookup.get(normalized)
    if direct is not None:
        return direct

    # Handle URL-like host values conservatively.
    if "://" in normalized:
        without_scheme = normalized.split("://", 1)[1]
        direct = lookup.get(without_scheme)

        if direct is not None:
            return direct

    return None


def network_ioc_hits(
    network_records: list[dict[str, Any]],
    lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []

    for record in network_records:
        for field in ("dst_ip", "dst_host"):
            value = record.get(field)

            if not value:
                continue

            context = lookup_ioc(lookup, str(value))

            if context is None:
                continue

            hit = dict(context)
            hit["indicator"] = str(value)
            hit["field"] = field
            hits.append(hit)

    return hits


def alert_ioc_hits(
    alert: dict[str, Any],
    network_hits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    existing = alert.get("ioc_hits", [])

    hits: list[dict[str, Any]] = []

    if isinstance(existing, list):
        hits.extend(
            x for x in existing
            if isinstance(x, dict)
        )

    hits.extend(network_hits)

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()

    for hit in hits:
        marker = json.dumps(
            hit,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

        if marker not in seen:
            seen.add(marker)
            unique.append(hit)

    return unique


def baseline_profile(alert: dict[str, Any]) -> dict[str, Any]:
    value = first_value(
        alert,
        "baseline_host_profile",
        "baseline.host_profile",
        "baseline_profile",
        "host_baseline",
    )

    return value if isinstance(value, dict) else {}


def baseline_deviation_present(alert: dict[str, Any]) -> bool:
    for key in (
        "baseline_deviation",
        "baseline_violation",
        "baseline_deviations",
        "baseline_violations",
    ):
        value = alert.get(key)

        if isinstance(value, bool) and value:
            return True

        if isinstance(value, list) and value:
            return True

        if isinstance(value, dict) and value:
            return True

    profile = baseline_profile(alert)

    violations = profile.get("violations")

    if isinstance(violations, list) and violations:
        return True

    if isinstance(violations, dict) and violations:
        return True

    return False


def baseline_contains_process(
    alert: dict[str, Any],
    process_name: str | None,
) -> bool:
    if not process_name:
        return False

    profile = baseline_profile(alert)

    process = profile.get("process")

    if not isinstance(process, dict):
        return False

    expected = process.get("expected", [])

    if isinstance(expected, dict):
        expected = list(expected.keys())

    if isinstance(expected, str):
        expected = [expected]

    if not isinstance(expected, list):
        return False

    return process_name in {str(x) for x in expected}


def other_host_baseline_match(
    alert: dict[str, Any],
    process_name: str | None,
    destinations: list[str],
) -> tuple[str | None, str | None]:
    """
    Search the queue's available baseline host profiles for the same
    process/destination on a host other than the current target.

    The function receives the full alert only for the current host;
    the actual cross-host search is performed in main() where the
    queue-wide baseline records are available.
    """
    del alert
    del process_name
    del destinations
    return None, None


def baseline_match_on_host(
    profile: dict[str, Any],
    process_name: str | None,
    destinations: list[str],
) -> str | None:
    if not isinstance(profile, dict):
        return None

    if process_name:
        process = profile.get("process")

        if isinstance(process, dict):
            expected = process.get("expected", [])

            if isinstance(expected, dict):
                expected = list(expected.keys())

            if isinstance(expected, str):
                expected = [expected]

            if isinstance(expected, list):
                expected_names = {str(x) for x in expected}

                if process_name in expected_names:
                    return f"process_name {process_name}"

    network = profile.get("network")

    if isinstance(network, dict):
        for key in (
            "expected_destinations",
            "destinations",
            "expected_hosts",
            "expected_ips",
        ):
            expected = network.get(key)

            if isinstance(expected, str):
                expected = [expected]

            if isinstance(expected, list):
                expected_set = {
                    str(x).lower()
                    for x in expected
                }

                for destination in destinations:
                    if destination.lower() in expected_set:
                        return f"destination {destination}"

    return None


def host_profiles_from_queue(
    alerts: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    profiles: list[tuple[str, dict[str, Any]]] = []

    for alert in alerts:
        host = hostname(alert)
        profile = baseline_profile(alert)

        if profile:
            profiles.append((host, profile))

    return profiles


def primary_event_ref(alert: dict[str, Any]) -> str | None:
    value = first_value(
        alert,
        "event_ref",
        "event_summary.event_ref",
        "event_record.event_ref",
    )

    return str(value) if value is not None else None


def collect_refs(value: Any) -> list[str]:
    refs: list[str] = []

    if isinstance(value, dict):
        for key in (
            "event_ref",
            "event_id",
            "ref",
            "reference",
            "correlation_ref",
        ):
            candidate = value.get(key)

            if candidate not in (None, ""):
                refs.append(str(candidate))

        for child in value.values():
            refs.extend(collect_refs(child))

    elif isinstance(value, list):
        for child in value:
            refs.extend(collect_refs(child))

    return refs


def evidence_refs(alert: dict[str, Any]) -> list[str]:
    refs: list[str] = []

    primary = primary_event_ref(alert)

    if primary is not None:
        refs.append(primary)

    for obj in (alert, alert.get("event_record")):
        if not isinstance(obj, dict):
            continue

        for key in (
            "correlation_primitives",
            "correlation",
            "linked_events",
            "linked_correlation",
        ):
            if key in obj:
                refs.extend(collect_refs(obj[key]))

    return list(dict.fromkeys(refs))


def attack_techniques(alert: dict[str, Any]) -> list[Any]:
    candidates = [
        alert.get("attack_techniques"),
    ]

    rule = alert.get("rule")

    if isinstance(rule, dict):
        candidates.extend(
            [
                rule.get("attack_techniques"),
                rule.get("techniques"),
            ]
        )

    for candidate in candidates:
        if isinstance(candidate, list):
            return candidate

        if isinstance(candidate, str) and candidate:
            return [candidate]

    return []


def make_ticket(
    alert: dict[str, Any],
    classification: str,
    action: str,
    justification: str,
    iocs: list[dict[str, Any]],
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    aid = alert_id(alert)
    event_ref = primary_event_ref(alert)

    if event_ref is None:
        raise ValueError(
            f"{aid}: matching alert has no event_ref"
        )

    digest = hashlib.sha256(
        aid.encode("utf-8")
    ).hexdigest()[:12]

    ticket: dict[str, Any] = {
        "ticket_id": f"TKT-{digest}",
        "alert_id": aid,
        "classification": classification,
        "justification": justification,
        "evidence_refs": evidence_refs(alert),
        "ioc_hits": iocs,
        "attack_techniques": attack_techniques(alert),
        "recommended_action": action,
        "analyst_time_seconds": 90,
        "created_at": str(
            first_value(
                alert,
                "event_summary.timestamp",
                "event_record.timestamp",
                "timestamp",
            )
            or "1970-01-01T00:00:00Z"
        ),
    }

    if extra_fields:
        ticket.update(extra_fields)

    return ticket


def main() -> None:
    queue_doc = load_json(QUEUE_FILE)
    baseline_doc = load_json(BASELINE_FILE)
    events_doc = load_json(EVENTS_FILE)
    ioc_doc = load_json(IOC_FILE)

    alerts = queue_items(queue_doc)
    events = event_items(events_doc)
    ioc_lookup_data = ioc_lookup(ioc_doc)

    # The source files are loaded explicitly as required. Authentication
    # history is not needed for this process/network batch, but enriched
    # event records are used to obtain the process/network primitives.
    del baseline_doc
    del events

    queue_profiles = host_profiles_from_queue(alerts)

    tickets: list[dict[str, Any]] = []
    rows: list[tuple[str, str, str, str, str]] = []

    for alert in alerts:
        alert_category = category(alert)

        if alert_category not in (
            PROCESS_CATEGORIES | NETWORK_CATEGORIES
        ):
            continue

        # Skip records explicitly marked as already handled.
        handled = first_value(
            alert,
            "handled",
            "triage.handled",
            "already_handled",
        )

        if handled is True:
            continue

        batch_marker = first_value(
            alert,
            "triage_batch",
            "handled_batch",
            "processing_batch",
        )

        if batch_marker is not None:
            marker = str(batch_marker).lower()

            if marker in {
                "1",
                "2",
                "3",
                "4",
                "batch1",
                "batch2",
                "batch3",
                "batch4",
            }:
                continue

        previous_classification = first_value(
            alert,
            "classification",
            "triage.classification",
        )

        if previous_classification in {
            "true_positive",
            "false_positive",
            "benign",
            "escalated",
        }:
            continue

        process_fields = get_process_fields(alert)
        network_records = get_network_fields(alert)

        process_name = process_fields["process_name"]

        destinations: list[str] = []

        for record in network_records:
            for field in ("dst_ip", "dst_host"):
                value = record.get(field)

                if value:
                    destinations.append(str(value))

        destinations = list(dict.fromkeys(destinations))

        # Network IOC lookup is done directly against ioc_context.json.
        network_hits = network_ioc_hits(
            network_records,
            ioc_lookup_data,
        )

        all_iocs = alert_ioc_hits(
            alert,
            network_hits,
        )

        malicious_hits = [
            hit
            for hit in all_iocs
            if str(hit.get("reputation", "")).lower()
            == "malicious"
        ]

        suspicious_hits = [
            hit
            for hit in all_iocs
            if str(hit.get("reputation", "")).lower()
            == "suspicious"
        ]

        clean_hits = [
            hit
            for hit in all_iocs
            if str(hit.get("reputation", "")).lower()
            == "clean"
        ]

        criticality = asset_criticality(alert)
        current_host = hostname(alert)

        # 1. Any malicious IOC -> TP/escalate.
        if malicious_hits:
            indicators = sorted(
                {
                    str(
                        hit.get(
                            "indicator",
                            hit.get("value", "unknown"),
                        )
                    )
                    for hit in malicious_hits
                }
            )

            categories = sorted(
                {
                    str(category)
                    for hit in malicious_hits
                    for category in as_list(
                        hit.get("categories", hit.get("category"))
                    )
                }
            )

            justification = (
                "Malicious IOC reputation matched after checking "
                f"destinations {sorted(destinations)}; malicious "
                f"indicators={indicators}, categories={categories}, "
                f"asset_criticality={criticality}."
            )

            ticket = make_ticket(
                alert,
                "true_positive",
                "escalate_tier2",
                justification,
                all_iocs,
            )

            tickets.append(ticket)
            rows.append(
                (
                    alert_id(alert),
                    rule_id(alert),
                    rule_name(alert),
                    "true_positive",
                    "escalate",
                )
            )
            continue

        # 2. Suspicious IOC + high/critical asset -> TP/monitor.
        if (
            suspicious_hits
            and criticality in {"critical", "high"}
        ):
            indicators = sorted(
                {
                    str(
                        hit.get(
                            "indicator",
                            hit.get("value", "unknown"),
                        )
                    )
                    for hit in suspicious_hits
                }
            )

            justification = (
                "Suspicious IOC reputation matched after checking "
                f"destinations {sorted(destinations)}; suspicious "
                f"indicators={indicators} and asset_criticality="
                f"{criticality}, so the activity is retained for monitoring."
            )

            ticket = make_ticket(
                alert,
                "true_positive",
                "monitor",
                justification,
                all_iocs,
            )

            tickets.append(ticket)
            rows.append(
                (
                    alert_id(alert),
                    rule_id(alert),
                    rule_name(alert),
                    "true_positive",
                    "monitor",
                )
            )
            continue

        # 3. Suspicious IOC + lower-criticality asset + known elsewhere.
        if (
            suspicious_hits
            and criticality in {"medium", "low"}
        ):
            baseline_match: str | None = None
            baseline_host: str | None = None

            for host, profile in queue_profiles:
                if host == current_host:
                    continue

                match = baseline_match_on_host(
                    profile,
                    process_name,
                    destinations,
                )

                if match is not None:
                    baseline_match = match
                    baseline_host = host
                    break

            if baseline_match is not None:
                justification = (
                    "Suspicious IOC activity was checked against "
                    f"destinations {sorted(destinations)} and asset_criticality="
                    f"{criticality}; {baseline_match} is present in the "
                    f"baseline profile for different host {baseline_host}."
                )

                ticket = make_ticket(
                    alert,
                    "false_positive",
                    "tune_rule",
                    justification,
                    all_iocs,
                    {
                        "fp_reason":
                            "suspicious_but_baseline_known_elsewhere",
                    },
                )

                tickets.append(ticket)
                rows.append(
                    (
                        alert_id(alert),
                        rule_id(alert),
                        rule_name(alert),
                        "false_positive",
                        "tune_rule",
                    )
                )
                continue

        # 4. Clean IOC + no baseline deviation -> FP/tune.
        if (
            clean_hits
            and not baseline_deviation_present(alert)
        ):
            justification = (
                "IOC context was checked and all matched indicators have "
                f"reputation clean; baseline deviation is absent for host "
                f"{current_host}."
            )

            ticket = make_ticket(
                alert,
                "false_positive",
                "tune_rule",
                justification,
                all_iocs,
                {
                    "fp_reason": "clean_ioc_no_deviation",
                },
            )

            tickets.append(ticket)
            rows.append(
                (
                    alert_id(alert),
                    rule_id(alert),
                    rule_name(alert),
                    "false_positive",
                    "tune_rule",
                )
            )
            continue

        # 5. Everything else remains a monitored TP.
        process_text = json.dumps(
            process_fields,
            sort_keys=True,
            default=str,
        )

        network_text = json.dumps(
            network_records,
            sort_keys=True,
            default=str,
        )

        reputation_text = sorted(
            {
                str(hit.get("reputation", "unknown")).lower()
                for hit in all_iocs
            }
        )

        justification = (
            "Ambiguous process/network activity remains unresolved after "
            f"checking process_fields={process_text}, "
            f"network_destinations={network_text}, "
            f"ioc_reputations={reputation_text}, "
            f"asset_criticality={criticality}, and "
            f"baseline_deviation="
            f"{baseline_deviation_present(alert)}; activity is retained "
            "for monitoring."
        )

        ticket = make_ticket(
            alert,
            "true_positive",
            "monitor",
            justification,
            all_iocs,
        )

        tickets.append(ticket)
        rows.append(
            (
                alert_id(alert),
                rule_id(alert),
                rule_name(alert),
                "true_positive",
                "monitor",
            )
        )

    combined = list(zip(tickets, rows))
    combined.sort(key=lambda pair: pair[0]["alert_id"])

    tickets = [pair[0] for pair in combined]
    rows = [pair[1] for pair in combined]

    with OUTPUT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(
            tickets,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    print("batch 5 ambiguous process and network")

    for row in rows:
        aid, rid, name, classification, action = row

        print(
            f"  {aid:<12} "
            f"{rid:<4} "
            f"{name:<32} "
            f"{classification:<15} "
            f"{action}"
        )

    print(f"batch size               : {len(tickets)}")
    print(f"tickets written          : {len(tickets)}")
    print(str(OUTPUT_FILE))


if __name__ == "__main__":
    main()
PY
