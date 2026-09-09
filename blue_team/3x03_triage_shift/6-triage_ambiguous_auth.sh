#!/bin/bash
set -euo pipefail

QUEUE_FILE="${1:-enriched_queue.json}"
BASELINE_DIR="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_FILE="${BASELINE_DIR}/baselines/baseline_summary.json"
EVENTS_FILE="${HANDOFF_DIR}/data/enriched_events.json"
OUTPUT_FILE="tickets/batch4_auth.json"

mkdir -p tickets

python3 -W error - \
    "$QUEUE_FILE" \
    "$BASELINE_FILE" \
    "$EVENTS_FILE" \
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
OUTPUT_FILE = Path(sys.argv[4])


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
        raise ValueError("authentication alert is missing alert_id")
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


def user_name(alert: dict[str, Any]) -> str | None:
    value = first_value(
        alert,
        "target_user",
        "username",
        "user",
        "user_name",
        "account",
        "event_record.target_user",
        "event_record.username",
        "event_record.user",
    )
    return str(value) if value is not None else None


def source_ip(alert: dict[str, Any]) -> str | None:
    value = first_value(
        alert,
        "source_ip",
        "src_ip",
        "source.ip",
        "network.source_ip",
        "event_record.source_ip",
        "event_record.src_ip",
    )
    return str(value) if value is not None else None


def priority_band(alert: dict[str, Any]) -> str:
    return str(alert.get("priority_band", "")).lower()


def is_authentication_alert(alert: dict[str, Any]) -> bool:
    category = first_value(
        alert,
        "category",
        "rule.category",
        "rule_category",
        "alert_category",
    )

    if category is not None:
        return str(category).lower() == "auth"

    rule_id = first_value(
        alert,
        "rule_id",
        "rule.id",
        "rule.rule_id",
    )

    rule_name = first_value(
        alert,
        "rule_name",
        "rule.name",
    )

    auth_names = {
        "ssh_brute_force",
        "windows_offhours_priv_logon",
        "privileged_shift_violation",
    }

    if rule_name is not None:
        return str(rule_name).lower() in auth_names

    if rule_id is not None:
        return str(rule_id) in {"001", "002", "013"}

    return False


def ioc_hits(alert: dict[str, Any]) -> list[dict[str, Any]]:
    hits = alert.get("ioc_hits", [])

    if not isinstance(hits, list):
        return []

    return [x for x in hits if isinstance(x, dict)]


def has_ioc_hit(alert: dict[str, Any]) -> bool:
    return bool(ioc_hits(alert))


def baseline_host_profile(alert: dict[str, Any]) -> dict[str, Any]:
    value = first_value(
        alert,
        "baseline_host_profile",
        "baseline.host_profile",
        "baseline_profile",
        "host_baseline",
    )

    return value if isinstance(value, dict) else {}


def baseline_user_record(
    baseline: dict[str, Any],
    username: str,
) -> dict[str, Any]:
    containers = (
        baseline.get("users"),
        baseline.get("known_accounts"),
        baseline.get("user_profiles"),
        baseline.get("login_patterns"),
        baseline.get("per_user"),
    )

    for container in containers:
        if not isinstance(container, dict):
            continue

        record = container.get(username)

        if isinstance(record, dict):
            return record

    return {}


def baseline_user_history(
    baseline_doc: Any,
    alert: dict[str, Any],
    username: str,
) -> dict[str, Any]:
    """
    Resolve the user's historical login record from baseline_summary.json.

    Supports both global per-user records and host-specific records.
    """
    hostname_value = hostname(alert)

    candidates: list[dict[str, Any]] = []

    if isinstance(baseline_doc, dict):
        global_users = (
            baseline_doc.get("users"),
            baseline_doc.get("known_accounts"),
            baseline_doc.get("user_profiles"),
            baseline_doc.get("login_patterns"),
            baseline_doc.get("per_user"),
        )

        for container in global_users:
            if isinstance(container, dict):
                record = container.get(username)
                if isinstance(record, dict):
                    candidates.append(record)

        hosts = baseline_doc.get("hosts")

        if isinstance(hosts, dict):
            host_record = hosts.get(hostname_value)

            if isinstance(host_record, dict):
                record = baseline_user_record(
                    host_record,
                    username,
                )
                if record:
                    candidates.insert(0, record)

    if candidates:
        merged: dict[str, Any] = {}

        for record in reversed(candidates):
            merged.update(record)

        return merged

    return baseline_user_record(
        baseline_doc if isinstance(baseline_doc, dict) else {},
        username,
    )


def history_source_ips(history: dict[str, Any]) -> set[str]:
    values = first_value(
        history,
        "source_ips",
        "source_ip",
        "ips",
        "login_source_ips",
        "historical_source_ips",
    )

    if isinstance(values, str):
        return {values}

    if isinstance(values, list):
        return {str(x) for x in values}

    return set()


def history_hosts(history: dict[str, Any]) -> set[str]:
    values = first_value(
        history,
        "host_set",
        "hosts",
        "hostnames",
        "login_hosts",
    )

    if isinstance(values, str):
        return {values}

    if isinstance(values, list):
        return {str(x) for x in values}

    return set()


def history_login_times(history: dict[str, Any]) -> list[Any]:
    values = first_value(
        history,
        "login_times",
        "times",
        "historical_login_times",
    )

    if isinstance(values, list):
        return values

    if values is None:
        return []

    return [values]


def extract_event_user(event: dict[str, Any]) -> str | None:
    value = first_value(
        event,
        "target_user",
        "username",
        "user",
        "user_name",
        "account",
        "authentication.user",
        "auth.user",
    )
    return str(value) if value is not None else None


def is_auth_event(event: dict[str, Any]) -> bool:
    category = first_value(
        event,
        "category",
        "event_category",
        "rule.category",
        "event_type",
    )

    if category is not None:
        category_text = str(category).lower()
        if category_text in {"auth", "authentication", "login"}:
            return True

    event_type = first_value(
        event,
        "event_type",
        "type",
        "action",
    )

    if event_type is not None:
        text = str(event_type).lower()
        if any(
            token in text
            for token in ("login", "logon", "authentication", "auth")
        ):
            return True

    return (
        first_value(event, "source_ip", "src_ip", "source.ip") is not None
        and extract_event_user(event) is not None
    )


def event_timestamp(event: dict[str, Any]) -> str:
    value = first_value(
        event,
        "timestamp",
        "event_summary.timestamp",
        "event_time",
        "time",
    )
    return str(value) if value is not None else ""


def last_twenty_auth_events(
    events: list[dict[str, Any]],
    username: str,
) -> list[dict[str, Any]]:
    matching = [
        event
        for event in events
        if is_auth_event(event)
        and extract_event_user(event) == username
    ]

    # Stable chronological ordering where timestamps exist.
    matching.sort(key=event_timestamp)

    return matching[-20:]


def event_failure_count(alert: dict[str, Any]) -> int:
    value = first_value(
        alert,
        "failure_count",
        "failed_count",
        "failures",
        "auth_failure_count",
        "event_record.failure_count",
        "event_record.failed_count",
    )

    if value is None:
        return 0

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def baseline_max_failures(alert: dict[str, Any]) -> int | None:
    profile = baseline_host_profile(alert)

    candidates = [
        first_value(
            profile,
            "auth.max_failures_1h_window",
            "authentication.max_failures_1h_window",
            "max_failures_1h_window",
        ),
        first_value(
            alert,
            "max_failures_1h_window",
            "baseline.max_failures_1h_window",
            "auth.max_failures_1h_window",
        ),
    ]

    for candidate in candidates:
        if candidate is not None:
            try:
                return int(candidate)
            except (TypeError, ValueError):
                continue

    return None


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


def evidence_refs(
    alert: dict[str, Any],
    history_events: list[dict[str, Any]],
) -> list[str]:
    refs: list[str] = []

    primary = primary_event_ref(alert)

    if primary is not None:
        refs.append(primary)

    for field in (
        "correlation_primitives",
        "correlation",
        "linked_events",
    ):
        if field in alert:
            refs.extend(collect_refs(alert[field]))

    for event in history_events:
        ref = first_value(
            event,
            "event_ref",
            "event_id",
            "ref",
        )

        if ref is not None:
            refs.append(str(ref))

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
    fp_reason: str | None,
    history_events: list[dict[str, Any]],
) -> dict[str, Any]:
    aid = alert_id(alert)
    event_ref = primary_event_ref(alert)

    if event_ref is None:
        raise ValueError(
            f"{aid}: authentication ticket requires an event_ref"
        )

    digest = hashlib.sha256(
        aid.encode("utf-8")
    ).hexdigest()[:12]

    ticket = {
        "ticket_id": f"TKT-{digest}",
        "alert_id": aid,
        "classification": classification,
        "justification": justification,
        "evidence_refs": evidence_refs(
            alert,
            history_events,
        ),
        "ioc_hits": ioc_hits(alert),
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

    if fp_reason is not None:
        ticket["fp_reason"] = fp_reason

    return ticket


def main() -> None:
    queue_doc = load_json(QUEUE_FILE)
    baseline_doc = load_json(BASELINE_FILE)
    events_doc = load_json(EVENTS_FILE)

    alerts = queue_items(queue_doc)
    events = event_items(events_doc)

    tickets: list[dict[str, Any]] = []
    output_rows: list[tuple[str, str, str, str]] = []

    for alert in alerts:
        if not is_authentication_alert(alert):
            continue

        aid = alert_id(alert)

        # Batches 1-3 are represented by an explicit handling marker when
        # present. This script also skips alerts already classified by the
        # previous ticket outputs if those markers were propagated.
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
                "batch1",
                "batch2",
                "batch3",
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

        username = user_name(alert)

        if username is None:
            continue

        history = baseline_user_history(
            baseline_doc,
            alert,
            username,
        )

        # Fetch the historical sequence even when the eventual decision
        # is driven by another signature.
        recent_events = last_twenty_auth_events(
            events,
            username,
        )

        historical_ips = history_source_ips(history)
        historical_hosts = history_hosts(history)
        current_ip = source_ip(alert)
        current_host = hostname(alert)
        band = priority_band(alert)

        unknown_ip = (
            current_ip is not None
            and current_ip not in historical_ips
        )

        never_on_host = current_host not in historical_hosts

        max_failures = baseline_max_failures(alert)
        failures = event_failure_count(alert)

        # Decision 1.
        if (
            unknown_ip
            and band in {"critical", "high"}
            and never_on_host
        ):
            justification = (
                f"Unknown source IP {current_ip} was checked against "
                f"historical source_ips {sorted(historical_ips)}; user "
                f"{username} has no history on host {current_host} in "
                f"host_set {sorted(historical_hosts)}, and asset priority "
                f"is {band}."
            )

            ticket = make_ticket(
                alert,
                "true_positive",
                "escalate_tier2",
                justification,
                None,
                recent_events,
            )

            tickets.append(ticket)
            output_rows.append(
                (
                    aid,
                    rule_id_for_output(alert),
                    rule_name_for_output(alert),
                    "true_positive",
                    "escalate",
                )
            )
            continue

        # Decision 2.
        if (
            unknown_ip
            and band in {"medium", "low"}
            and not has_ioc_hit(alert)
        ):
            justification = (
                f"Unknown source IP {current_ip} was checked against "
                f"historical source_ips {sorted(historical_ips)}; asset "
                f"priority is {band} and ioc_hits is empty, matching the "
                f"unknown-IP low-asset false positive signature."
            )

            ticket = make_ticket(
                alert,
                "false_positive",
                "tune_rule",
                justification,
                "unknown_ip_low_asset",
                recent_events,
            )

            tickets.append(ticket)
            output_rows.append(
                (
                    aid,
                    rule_id_for_output(alert),
                    rule_name_for_output(alert),
                    "false_positive",
                    "tune_rule",
                )
            )
            continue

        # Decision 3.
        if (
            current_ip is not None
            and current_ip in historical_ips
            and max_failures is not None
            and max_failures < failures <= max_failures * 2
        ):
            justification = (
                f"Known source IP {current_ip} is present in historical "
                f"source_ips {sorted(historical_ips)}, while failure_count "
                f"{failures} is between max_failures_1h_window "
                f"{max_failures} and {max_failures * 2}."
            )

            ticket = make_ticket(
                alert,
                "false_positive",
                "tune_rule",
                justification,
                "baseline_edge_burst",
                recent_events,
            )

            tickets.append(ticket)
            output_rows.append(
                (
                    aid,
                    rule_id_for_output(alert),
                    rule_name_for_output(alert),
                    "false_positive",
                    "tune_rule",
                )
            )
            continue

        # Decision 4: unresolved ambiguity.
        checked_fields = (
            f"user={username}; "
            f"source_ip={current_ip}; "
            f"historical_source_ips={sorted(historical_ips)}; "
            f"host={current_host}; "
            f"historical_host_set={sorted(historical_hosts)}; "
            f"priority_band={band}; "
            f"failure_count={failures}; "
            f"max_failures_1h_window={max_failures}; "
            f"ioc_hits={len(ioc_hits(alert))}; "
            f"historical_auth_events_checked={len(recent_events)}"
        )

        justification = (
            "Ambiguous authentication activity remains unresolved after "
            f"checking {checked_fields}; the available evidence does not "
            "meet a clear false-positive signature, so the alert is "
            "retained for monitoring."
        )

        ticket = make_ticket(
            alert,
            "true_positive",
            "monitor",
            justification,
            None,
            recent_events,
        )

        tickets.append(ticket)
        output_rows.append(
            (
                aid,
                rule_id_for_output(alert),
                rule_name_for_output(alert),
                "true_positive",
                "monitor",
            )
        )

    # Deterministic ordering.
    combined = list(zip(tickets, output_rows))
    combined.sort(key=lambda pair: pair[0]["alert_id"])

    tickets = [pair[0] for pair in combined]
    output_rows = [pair[1] for pair in combined]

    with OUTPUT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(
            tickets,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    print("batch 4 ambiguous authentication")

    for row in output_rows:
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


def rule_id_for_output(alert: dict[str, Any]) -> str:
    value = first_value(
        alert,
        "rule_id",
        "rule.id",
        "rule.rule_id",
    )
    return str(value) if value is not None else "unknown"


def rule_name_for_output(alert: dict[str, Any]) -> str:
    value = first_value(
        alert,
        "rule_name",
        "rule.name",
        "source_rule.name",
    )
    return str(value) if value is not None else rule_id_for_output(alert)


if __name__ == "__main__":
    main()
PY
