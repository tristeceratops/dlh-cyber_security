#!/bin/bash
set -euo pipefail

QUEUE_FILE="${1:-enriched_queue.json}"
OUTPUT_FILE="tickets/batch2_clearcut_fp.json"

mkdir -p tickets

python3 -W error - "$QUEUE_FILE" "$OUTPUT_FILE" <<'PY'
import hashlib
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any


QUEUE_FILE = Path(sys.argv[1])
OUTPUT_FILE = Path(sys.argv[2])

AUTH_PROCESS_RULE_PREFIXES = ("001", "002", "003", "004", "005", "006")


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


def alert_id(item: dict[str, Any]) -> str:
    value = first_value(item, "alert_id", "alert.alert_id")
    if value is None:
        raise ValueError("Alert is missing alert_id")
    return str(value)


def hostname(item: dict[str, Any]) -> str:
    value = first_value(
        item,
        "hostname",
        "asset.hostname",
        "asset_record.hostname",
        "event_record.hostname",
    )
    return str(value) if value is not None else "unknown"


def rule_id(item: dict[str, Any]) -> str:
    value = first_value(
        item,
        "rule_id",
        "rule.id",
        "rule.rule_id",
        "alert.rule_id",
    )
    return str(value) if value is not None else "unknown"


def rule_name(item: dict[str, Any]) -> str:
    value = first_value(
        item,
        "rule_name",
        "rule.name",
        "alert.rule_name",
        "source_rule.name",
    )
    return str(value) if value is not None else rule_id(item)


def rule_category(item: dict[str, Any]) -> str:
    value = first_value(
        item,
        "category",
        "rule_category",
        "alert_category",
        "rule.category",
        "rule.rule_category",
        "source_rule.category",
    )
    return str(value).lower() if value is not None else ""


def source_ip(item: dict[str, Any]) -> str | None:
    value = first_value(
        item,
        "source_ip",
        "src_ip",
        "source.ip",
        "network.source_ip",
        "event_record.source_ip",
        "event_record.src_ip",
    )
    return str(value) if value is not None else None


def target_user(item: dict[str, Any]) -> str | None:
    value = first_value(
        item,
        "target_user",
        "user",
        "username",
        "user_name",
        "event_record.target_user",
        "event_record.username",
        "event_record.user",
    )
    return str(value) if value is not None else None


def asset_record(item: dict[str, Any]) -> dict[str, Any]:
    for path in ("asset_inventory", "asset", "asset_record"):
        value = item.get(path)
        if isinstance(value, dict):
            return value

    return {}


def management_subnets(item: dict[str, Any]) -> list[str]:
    asset = asset_record(item)

    value = first_value(
        asset,
        "management_subnets",
        "owner.management_subnets",
        "owner_metadata.management_subnets",
        "metadata.management_subnets",
    )

    if isinstance(value, str):
        return [value]

    if isinstance(value, list):
        return [str(x) for x in value]

    return []


def service_account_prefix(item: dict[str, Any]) -> str | None:
    asset = asset_record(item)

    value = first_value(
        asset,
        "owner.service_account_prefix",
        "owner_metadata.service_account_prefix",
        "service_account_prefix",
        "metadata.service_account_prefix",
    )

    return str(value) if value is not None else None


def process_name(item: dict[str, Any]) -> str | None:
    value = first_value(
        item,
        "process_name",
        "process.name",
        "event_record.process_name",
        "event_record.process.name",
        "event_summary.process_name",
    )

    return str(value) if value is not None else None


def expected_processes(item: dict[str, Any]) -> list[str]:
    profile = first_value(
        item,
        "baseline_host_profile",
        "baseline.host_profile",
        "baseline_profile",
        "host_baseline",
    )

    if not isinstance(profile, dict):
        return []

    process = profile.get("process")

    if not isinstance(process, dict):
        return []

    expected = process.get("expected", [])

    if isinstance(expected, dict):
        expected = list(expected.keys())

    if isinstance(expected, str):
        expected = [expected]

    if not isinstance(expected, list):
        return []

    return [str(x) for x in expected]


def ioc_hits(item: dict[str, Any]) -> list[dict[str, Any]]:
    value = item.get("ioc_hits", [])

    if not isinstance(value, list):
        return []

    return [x for x in value if isinstance(x, dict)]


def baseline_deviation_present(item: dict[str, Any]) -> bool:
    """
    Detect an explicit baseline deviation/violation in the enriched record.
    A baseline_match process signature is intentionally handled separately.
    """
    for key in (
        "baseline_deviation",
        "baseline_violation",
        "baseline_deviations",
        "baseline_violations",
    ):
        value = item.get(key)

        if isinstance(value, bool):
            if value:
                return True

        elif isinstance(value, list):
            if value:
                return True

        elif isinstance(value, dict):
            if value:
                return True

    profile = first_value(
        item,
        "baseline_host_profile",
        "baseline.host_profile",
        "baseline_profile",
        "host_baseline",
    )

    if not isinstance(profile, dict):
        return False

    violations = profile.get("violations")

    if isinstance(violations, list) and violations:
        return True

    if isinstance(violations, dict) and violations:
        return True

    return False


def ip_in_management_subnet(
    address: str | None,
    subnets: list[str],
) -> bool:
    if not address:
        return False

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    for subnet in subnets:
        try:
            if ip in ipaddress.ip_network(subnet, strict=False):
                return True
        except ValueError:
            continue

    return False


def primary_event_ref(item: dict[str, Any]) -> str | None:
    value = first_value(
        item,
        "event_ref",
        "event_summary.event_ref",
        "event_record.event_ref",
    )

    return str(value) if value is not None else None


def collect_correlation_refs(value: Any) -> list[str]:
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
            refs.extend(collect_correlation_refs(child))

    elif isinstance(value, list):
        for child in value:
            refs.extend(collect_correlation_refs(child))

    return refs


def evidence_refs(item: dict[str, Any]) -> list[str]:
    refs: list[str] = []

    primary = primary_event_ref(item)

    if primary is not None:
        refs.append(primary)

    for obj in (item, item.get("event_record")):
        if not isinstance(obj, dict):
            continue

        for key in (
            "correlation_primitives",
            "correlation",
            "linked_events",
            "linked_correlation",
        ):
            if key in obj:
                refs.extend(collect_correlation_refs(obj[key]))

    return list(dict.fromkeys(refs))


def attack_techniques(item: dict[str, Any]) -> list[Any]:
    candidates = [
        item.get("attack_techniques"),
    ]

    rule = item.get("rule")

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


def find_signature(item: dict[str, Any]) -> tuple[str, str] | None:
    """
    Return (fp_reason, exact signature description).

    Priority is deterministic when an alert satisfies more than one
    signature.
    """

    user = target_user(item)
    prefix = service_account_prefix(item)
    category = rule_category(item)
    rid = rule_id(item)

    # Signature 1: service account + authentication/process rule.
    if (
        user
        and prefix
        and user.startswith(prefix)
        and (
            category in {"auth", "process"}
            or rid.startswith(AUTH_PROCESS_RULE_PREFIXES)
        )
    ):
        return (
            "service_account_activity",
            f"target user {user} matches service_account_prefix {prefix}",
        )

    # Signature 2: management subnet + network rule.
    src = source_ip(item)

    if (
        src
        and category == "network"
        and ip_in_management_subnet(src, management_subnets(item))
    ):
        matching_subnet = next(
            subnet
            for subnet in management_subnets(item)
            if ip_in_management_subnet(src, [subnet])
        )

        return (
            "management_subnet",
            f"source IP {src} is in management subnet {matching_subnet}",
        )

    # Signature 3: process is explicitly expected by host baseline.
    process = process_name(item)

    if process and process in expected_processes(item):
        return (
            "baseline_match",
            f"process_name {process} appears in baseline_host_profile.process.expected",
        )

    # Signature 4: every IOC is clean and there is no baseline deviation.
    hits = ioc_hits(item)

    all_clean = bool(hits) and all(
        str(hit.get("reputation", "")).lower() == "clean"
        for hit in hits
    )

    if all_clean and not baseline_deviation_present(item):
        return (
            "clean_ioc_no_deviation",
            "all IOC hits have reputation clean and baseline deviation is absent",
        )

    return None


def make_ticket(
    item: dict[str, Any],
    fp_reason: str,
    signature: str,
) -> dict[str, Any]:
    aid = alert_id(item)
    event_ref = primary_event_ref(item)

    if event_ref is None:
        raise ValueError(
            f"{aid}: matching false positive has no event_ref"
        )

    ticket_hash = hashlib.sha256(
        aid.encode("utf-8")
    ).hexdigest()[:12]

    return {
        "ticket_id": f"TKT-{ticket_hash}",
        "alert_id": aid,
        "classification": "false_positive",
        "justification": (
            f"False positive signature matched: {signature}."
        ),
        "evidence_refs": evidence_refs(item),
        "ioc_hits": ioc_hits(item),
        "attack_techniques": attack_techniques(item),
        "recommended_action": "tune_rule",
        "fp_reason": fp_reason,
        "analyst_time_seconds": 30,
        "created_at": str(
            first_value(
                item,
                "event_summary.timestamp",
                "event_record.timestamp",
                "timestamp",
            )
            or "1970-01-01T00:00:00Z"
        ),
    }


def main() -> None:
    data = load_json(QUEUE_FILE)
    items = queue_items(data)

    selected: list[tuple[dict[str, Any], str, str]] = []

    for item in items:
        match = find_signature(item)

        if match is None:
            continue

        fp_reason, signature = match
        selected.append((item, fp_reason, signature))

    # Deterministic ordering.
    selected.sort(key=lambda entry: alert_id(entry[0]))

    tickets = [
        make_ticket(item, fp_reason, signature)
        for item, fp_reason, signature in selected
    ]

    with OUTPUT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(
            tickets,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    print("batch 2 clear-cut false positives")

    for (item, fp_reason, _), ticket in zip(selected, tickets):
        print(
            f"  {alert_id(item):<12} "
            f"{rule_id(item):<4} "
            f"{rule_name(item):<30} "
            f"CLOSE  "
            f"{fp_reason}"
        )

    print(f"batch size               : {len(tickets)}")
    print(f"tickets written          : {len(tickets)}")
    print(str(OUTPUT_FILE))


if __name__ == "__main__":
    main()
PY

