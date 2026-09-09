#!/bin/bash
set -euo pipefail

QUEUE_FILE="${1:-enriched_queue.json}"
OUTPUT_FILE="tickets/batch1_clearcut_tp.json"

mkdir -p tickets

python3 -W error - "$QUEUE_FILE" "$OUTPUT_FILE" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


QUEUE_FILE = Path(sys.argv[1])
OUTPUT_FILE = Path(sys.argv[2])

VALID_CATEGORIES = {"auth", "process", "network", "file", "correlation"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def first_value(obj: Any, *paths: str) -> Any:
    """Return the first non-empty value found using dotted paths."""
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
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        for key in ("alerts", "items", "data", "enriched_queue"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    raise ValueError("enriched_queue.json must contain an alert list")


def get_alert_id(item: dict[str, Any]) -> str:
    value = first_value(
        item,
        "alert_id",
        "alert.alert_id",
    )
    if value is None:
        raise ValueError("Alert is missing alert_id")
    return str(value)


def get_hostname(item: dict[str, Any]) -> str:
    value = first_value(
        item,
        "hostname",
        "asset.hostname",
        "asset_record.hostname",
        "event_record.hostname",
        "event_summary.hostname",
    )
    return str(value) if value is not None else "unknown"


def get_rule_id(item: dict[str, Any]) -> str:
    value = first_value(
        item,
        "rule_id",
        "rule.id",
        "rule.rule_id",
        "alert.rule_id",
    )
    return str(value) if value is not None else "unknown"


def get_rule_category(item: dict[str, Any]) -> str | None:
    value = first_value(
        item,
        "category",
        "alert_category",
        "rule_category",
        "rule.category",
        "rule.rule_category",
        "alert.category",
        "alert.rule.category",
    )

    if value is None:
        return None

    return str(value).lower()


def get_ioc_hits(item: dict[str, Any]) -> list[dict[str, Any]]:
    hits = item.get("ioc_hits", [])

    if not isinstance(hits, list):
        return []

    return [hit for hit in hits if isinstance(hit, dict)]


def malicious_iocs(item: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        hit
        for hit in get_ioc_hits(item)
        if str(hit.get("reputation", "")).lower() == "malicious"
    ]


def scalar_difference(observed: Any, expected: Any) -> bool:
    if isinstance(observed, (dict, list)) or isinstance(expected, (dict, list)):
        return False
    return observed != expected


def baseline_violations(
    profile: Any,
    category: str,
) -> list[tuple[str, Any, Any]]:
    """
    Return (field, observed, expected) tuples representing violations.

    The function supports explicit violation records as well as common
    category/profile layouts used by the enriched queue.
    """
    if not isinstance(profile, dict):
        return []

    violations: list[tuple[str, Any, Any]] = []

    # Explicit violations.
    explicit = profile.get("violations", [])
    if isinstance(explicit, list):
        for violation in explicit:
            if not isinstance(violation, dict):
                continue

            violation_category = first_value(
                violation,
                "category",
                "rule_category",
            )

            if (
                violation_category is not None
                and str(violation_category).lower() != category
            ):
                continue

            field = first_value(
                violation,
                "field",
                "name",
                "baseline_field",
            )

            observed = first_value(
                violation,
                "observed",
                "actual",
                "value",
            )

            expected = first_value(
                violation,
                "expected",
                "baseline",
                "normal",
            )

            if field is not None:
                violations.append(
                    (
                        str(field),
                        observed,
                        expected,
                    )
                )

    # Category-specific profile.
    category_profile = None

    for container_name in (
        "categories",
        "by_category",
        "category_profiles",
        "slices",
    ):
        container = profile.get(container_name)

        if isinstance(container, dict):
            category_profile = container.get(category)

            if category_profile is None:
                category_profile = container.get(category.lower())

            if category_profile is not None:
                break

    if isinstance(category_profile, dict):
        # Explicit violations nested below the category.
        nested = category_profile.get("violations", [])

        if isinstance(nested, list):
            for violation in nested:
                if not isinstance(violation, dict):
                    continue

                field = first_value(
                    violation,
                    "field",
                    "name",
                    "baseline_field",
                )

                observed = first_value(
                    violation,
                    "observed",
                    "actual",
                    "value",
                )

                expected = first_value(
                    violation,
                    "expected",
                    "baseline",
                    "normal",
                )

                if field is not None:
                    violations.append(
                        (
                            str(field),
                            observed,
                            expected,
                        )
                    )

        # Field-level observed/expected comparisons.
        for field, values in category_profile.items():
            if field in {"violations", "metadata", "description"}:
                continue

            if not isinstance(values, dict):
                continue

            observed = first_value(
                values,
                "observed",
                "actual",
                "current",
            )

            expected = first_value(
                values,
                "expected",
                "baseline",
                "normal",
            )

            if observed is not None and expected is not None:
                if scalar_difference(observed, expected):
                    violations.append(
                        (
                            str(field),
                            observed,
                            expected,
                        )
                    )

    # De-duplicate while retaining deterministic order.
    unique: list[tuple[str, Any, Any]] = []
    seen: set[str] = set()

    for field, observed, expected in violations:
        marker = json.dumps(
            [field, observed, expected],
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

        if marker not in seen:
            seen.add(marker)
            unique.append((field, observed, expected))

    return unique


def get_baseline_profile(item: dict[str, Any]) -> Any:
    return first_value(
        item,
        "baseline_host_profile",
        "baseline.host_profile",
        "baseline_profile",
        "host_baseline",
    )


def get_primary_event_ref(item: dict[str, Any]) -> str | None:
    value = first_value(
        item,
        "event_ref",
        "alert.event_ref",
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


def get_evidence_refs(item: dict[str, Any]) -> list[str]:
    refs: list[str] = []

    primary = get_primary_event_ref(item)
    if primary is not None:
        refs.append(primary)

    # Include linked correlation primitives from the enriched alert.
    for field in (
        "correlation_primitives",
        "correlation",
        "linked_events",
        "linked_correlation",
    ):
        if field in item:
            refs.extend(collect_correlation_refs(item[field]))

    # Include primitives attached to the linked event record.
    event_record = item.get("event_record")

    if isinstance(event_record, dict):
        for field in (
            "correlation_primitives",
            "correlation",
            "linked_events",
            "linked_correlation",
        ):
            if field in event_record:
                refs.extend(collect_correlation_refs(event_record[field]))

    # Deterministic de-duplication.
    return list(dict.fromkeys(refs))


def get_attack_techniques(item: dict[str, Any]) -> list[Any]:
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


def ioc_categories(hits: list[dict[str, Any]]) -> list[str]:
    categories: list[str] = []

    for hit in hits:
        category_value = hit.get("categories", hit.get("category"))

        if isinstance(category_value, list):
            values = category_value
        elif category_value not in (None, ""):
            values = [category_value]
        else:
            values = ["unknown"]

        for value in values:
            text = str(value)
            if text not in categories:
                categories.append(text)

    return sorted(categories)


def ioc_display(hits: list[dict[str, Any]]) -> str:
    values: list[str] = []

    for hit in hits:
        value = first_value(
            hit,
            "indicator",
            "ioc",
            "value",
            "ip",
            "domain",
        )

        if value is not None:
            values.append(str(value))

    return ", ".join(sorted(set(values))) or "malicious IOC"


def make_justification(
    malicious_hits: list[dict[str, Any]],
    violations: list[tuple[str, Any, Any]],
) -> str:
    categories = ioc_categories(malicious_hits)
    category_text = ", ".join(categories)

    ioc_text = ioc_display(malicious_hits)

    field_parts: list[str] = []

    for field, observed, expected in violations:
        if expected is not None:
            field_parts.append(
                f"{field} was violated: observed value "
                f"{json.dumps(observed, sort_keys=True, default=str)} "
                f"versus baseline "
                f"{json.dumps(expected, sort_keys=True, default=str)}"
            )
        else:
            field_parts.append(
                f"{field} was violated by observed value "
                f"{json.dumps(observed, sort_keys=True, default=str)}"
            )

    baseline_text = "; ".join(field_parts)

    return (
        f"Malicious IOC category {category_text} matched "
        f"{ioc_text}; baseline field {baseline_text}."
    )


def make_ticket(item: dict[str, Any], violations: list[tuple[str, Any, Any]]) -> dict[str, Any]:
    alert_id = get_alert_id(item)
    malicious_hits = malicious_iocs(item)

    ticket_id = "TKT-" + hashlib.sha256(
        alert_id.encode("utf-8")
    ).hexdigest()[:12]

    event_ref = get_primary_event_ref(item)
    if event_ref is None:
        raise ValueError(
            f"{alert_id}: every ticket must reference an event_ref"
        )

    timestamp = first_value(
        item,
        "event_summary.timestamp",
        "event_record.timestamp",
        "timestamp",
    )

    # Use source event time rather than wall-clock time so repeated runs
    # generate identical output.
    created_at = str(timestamp) if timestamp is not None else "1970-01-01T00:00:00Z"

    return {
        "ticket_id": ticket_id,
        "alert_id": alert_id,
        "classification": "true_positive",
        "justification": make_justification(
            malicious_hits,
            violations,
        ),
        "evidence_refs": get_evidence_refs(item),
        "ioc_hits": malicious_hits,
        "attack_techniques": get_attack_techniques(item),
        "recommended_action": "escalate_tier2",
        "analyst_time_seconds": 60,
        "created_at": created_at,
    }


def main() -> None:
    queue = load_json(QUEUE_FILE)
    items = queue_items(queue)

    selected: list[dict[str, Any]] = []

    for item in items:
        if str(item.get("priority_band", "")).lower() != "critical":
            continue

        malicious_hits = malicious_iocs(item)
        if not malicious_hits:
            continue

        category = get_rule_category(item)
        if category not in VALID_CATEGORIES:
            continue

        profile = get_baseline_profile(item)
        violations = baseline_violations(profile, category)

        if not violations:
            continue

        selected.append(
            {
                "item": item,
                "violations": violations,
            }
        )

    selected.sort(key=lambda entry: get_alert_id(entry["item"]))

    tickets = [
        make_ticket(entry["item"], entry["violations"])
        for entry in selected
    ]

    # Deterministic JSON output.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(
            tickets,
            handle,
            indent=2,
            sort_keys=False,
            ensure_ascii=False,
        )
        handle.write("\n")

    print("batch 1 clear-cut true positives")

    for entry, ticket in zip(selected, tickets):
        item = entry["item"]
        alert_id = get_alert_id(item)
        rule_id = get_rule_id(item)
        hostname = get_hostname(item)
        malicious_hits = malicious_iocs(item)

        reputation = (
            str(malicious_hits[0].get("reputation", "unknown"))
            .upper()
        )

        print(
            f"  {alert_id:<12} "
            f"{rule_id:<30} "
            f"{hostname:<18} "
            f"{reputation:<10} "
            f"ESCALATE"
        )

    print(f"batch size               : {len(tickets)}")
    print(f"tickets written          : {len(tickets)}")
    print(str(OUTPUT_FILE))


if __name__ == "__main__":
    main()
PY

