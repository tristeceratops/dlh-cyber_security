#!/bin/bash
set -euo pipefail

: "${CATALOG_DIR:=$HOME/3x02_package/detection_catalog}"

QUEUE_FILE="${CATALOG_DIR}/alerts/alert_queue.json"
SCHEMA_FILE="${CATALOG_DIR}/alerts/alert_queue_schema.json"
OUTPUT_FILE="queue_assessment.json"

python3 -W error - "$QUEUE_FILE" "$SCHEMA_FILE" "$OUTPUT_FILE" <<'PY'
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


QUEUE_FILE = Path(sys.argv[1])
SCHEMA_FILE = Path(sys.argv[2])
OUTPUT_FILE = Path(sys.argv[3])


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def path_string(path: str) -> str:
    return path or "$"


def validate_schema(
    value: Any,
    schema: Dict[str, Any],
    path: str = "$",
) -> List[str]:
    """Small stdlib-only JSON Schema validator for common draft features."""
    errors: List[str] = []

    if not isinstance(schema, dict):
        return [f"{path}: schema node is not an object"]

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} is not in enum")

    schema_type = schema.get("type")
    if schema_type is not None:
        valid_type = {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float))
            and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "null": value is None,
        }.get(schema_type, True)
        if not valid_type:
            return errors + [f"{path}: expected {schema_type}"]

    if "oneOf" in schema:
        matches = sum(
            not validate_schema(value, sub, path)
            for sub in schema["oneOf"]
        )
        if matches != 1:
            errors.append(f"{path}: oneOf matched {matches} schemas")

    if "anyOf" in schema:
        if not any(not validate_schema(value, sub, path) for sub in schema["anyOf"]):
            errors.append(f"{path}: anyOf matched no schemas")

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}: missing required property {key!r}")

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, subschema in properties.items():
                if key in value:
                    errors.extend(
                        validate_schema(
                            value[key],
                            subschema,
                            f"{path}.{key}",
                        )
                    )

        additional = schema.get("additionalProperties", True)
        if additional is False and isinstance(properties, dict):
            for key in value:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key!r}")
        elif isinstance(additional, dict) and isinstance(properties, dict):
            for key, item in value.items():
                if key not in properties:
                    errors.extend(
                        validate_schema(
                            item,
                            additional,
                            f"{path}.{key}",
                        )
                    )

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(
                    validate_schema(
                        item,
                        item_schema,
                        f"{path}[{index}]",
                    )
                )

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength")
        pattern = schema.get("pattern")
        if pattern is not None:
            try:
                if re.search(pattern, value) is None:
                    errors.append(f"{path}: does not match pattern {pattern!r}")
            except re.error as exc:
                errors.append(f"{path}: invalid schema pattern: {exc}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum")

    return errors


def first_present(obj: Dict[str, Any], paths: List[str], default: Any = None) -> Any:
    for path in paths:
        current: Any = obj
        found = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found:
            return current
    return default


def alerts_from_queue(queue: Any) -> List[Dict[str, Any]]:
    if isinstance(queue, list):
        return [item for item in queue if isinstance(item, dict)]
    if isinstance(queue, dict):
        for key in ("alerts", "queue", "items", "data"):
            candidate = queue.get(key)
            if isinstance(candidate, list):
                return [item for item in candidate if isinstance(item, dict)]
    raise ValueError("alert_queue.json does not contain a supported alert list")


def alert_id(alert: Dict[str, Any]) -> str:
    return str(first_present(alert, ["alert_id", "id"], ""))


def priority_score(alert: Dict[str, Any]) -> Optional[float]:
    value = first_present(alert, ["priority_score", "priority.score", "score"])
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def priority_band(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 20:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    if score >= 1:
        return "low"
    return None


def rule_id(alert: Dict[str, Any]) -> str:
    value = first_present(alert, ["rule_id", "rule.id", "rule.rule_id"])
    return str(value) if value is not None else "unknown"


def hostname(alert: Dict[str, Any]) -> str:
    value = first_present(
        alert,
        [
            "hostname",
            "target.hostname",
            "target_host",
            "target.host",
            "host.hostname",
            "event_summary.hostname",
        ],
    )
    return str(value) if value is not None else "unknown"


TACTIC_ID_TO_NAME = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}


def tactic_from_tag(tag: Any) -> Optional[str]:
    text = str(tag).strip()
    if not text:
        return None

    upper = text.upper()
    for prefix in ("ATT&CK_TACTIC:", "ATTACK_TACTIC:", "TACTIC:", "ATTACK.TACTIC:"):
        if upper.startswith(prefix):
            name = text[len(prefix):].strip()
            return name or None

    match = re.search(r"\bTA\d{4}\b", upper)
    if match:
        return TACTIC_ID_TO_NAME.get(match.group(0), match.group(0))

    normalized = re.sub(r"[_-]+", " ", text).strip().lower()
    for name in TACTIC_ID_TO_NAME.values():
        if normalized == name.lower():
            return name

    return None


def attack_tactics(alert: Dict[str, Any]) -> List[str]:
    tags = first_present(
        alert,
        [
            "rule.tags",
            "tags",
            "rule.attack_tags",
            "attack_tags",
        ],
        [],
    )
    if not isinstance(tags, list):
        return []

    tactics = {tactic_from_tag(tag) for tag in tags}
    return sorted(tactic for tactic in tactics if tactic)


def timestamp(alert: Dict[str, Any]) -> Optional[str]:
    value = first_present(
        alert,
        [
            "event_summary.timestamp",
            "event_summary.time",
            "timestamp",
        ],
    )
    return str(value) if value is not None else None


def timestamp_sort_key(value: str) -> Tuple[int, str]:
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (0, parsed.astimezone(timezone.utc).isoformat())
    except ValueError:
        return (1, value)


def display_score(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return str(value)


def main() -> int:
    queue = load_json(QUEUE_FILE)
    schema = load_json(SCHEMA_FILE)

    raw_alerts: Any
    if isinstance(queue, dict) and isinstance(schema, dict):
        schema_for_queue = schema
        if schema.get("type") == "object":
            schema_errors = validate_schema(queue, schema_for_queue)
            if schema_errors:
                # Continue with per-alert validation so the assessment remains useful.
                pass
        raw_alerts = alerts_from_queue(queue)
    else:
        raise ValueError("queue and schema must both be JSON objects or supported structures")

    validation_errors: List[Dict[str, Any]] = []
    for index, alert in enumerate(raw_alerts):
        errors = validate_schema(alert, schema.get("items", schema))
        if errors:
            validation_errors.append(
                {
                    "alert_id": alert_id(alert) or None,
                    "index": index,
                    "errors": errors,
                }
            )

    queue_size = len(raw_alerts)
    priorities = Counter()
    rules = Counter()
    hosts = Counter()
    tactics = Counter()
    host_scores: Dict[str, float] = defaultdict(float)
    timestamps: List[str] = []

    for alert in raw_alerts:
        band = priority_band(priority_score(alert))
        if band is not None:
            priorities[band] += 1

        rules[rule_id(alert)] += 1
        host = hostname(alert)
        hosts[host] += 1

        score = priority_score(alert)
        if score is not None:
            host_scores[host] += score

        for tactic in attack_tactics(alert):
            tactics[tactic] += 1

        ts = timestamp(alert)
        if ts:
            timestamps.append(ts)

    by_rule = dict(
        sorted(
            rules.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )
    by_hostname = dict(
        sorted(
            hosts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )
    by_attack_tactic = dict(
        sorted(
            tactics.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )

    sorted_timestamps = sorted(timestamps, key=timestamp_sort_key)
    time_span = {
        "first": sorted_timestamps[0] if sorted_timestamps else None,
        "last": sorted_timestamps[-1] if sorted_timestamps else None,
    }

    top_targets = [
        {
            "hostname": host,
            "cumulative_priority_score": int(score)
            if score.is_integer()
            else score,
        }
        for host, score in sorted(
            host_scores.items(),
            key=lambda item: (-item[1], item[0]),
        )[:3]
    ]

    assessment = {
        "queue_size": queue_size,
        "validation_errors": validation_errors,
        "by_priority_band": {
            "critical": priorities.get("critical", 0),
            "high": priorities.get("high", 0),
            "medium": priorities.get("medium", 0),
            "low": priorities.get("low", 0),
        },
        "by_rule": by_rule,
        "by_hostname": by_hostname,
        "by_attack_tactic": by_attack_tactic,
        "time_span": time_span,
        "top_targets": top_targets,
    }

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(assessment, handle, indent=2, sort_keys=False)
        handle.write("\n")

    today = datetime.now(timezone.utc).date().isoformat()
    print(f"=== SHIFT BRIEFING {today} ===")
    print(f"queue size           : {queue_size} alerts")
    print(f"validation errors    : {len(validation_errors)}")
    print(
        "time span            : "
        f"{time_span['first'] or 'n/a'} -> {time_span['last'] or 'n/a'}"
    )
    print("priority bands")
    for band in ("critical", "high", "medium", "low"):
        print(f"  {band:<9}: {priorities.get(band, 0)}")

    print("top rules (5)")
    for rule, count in list(by_rule.items())[:5]:
        print(f"  {rule:<32} {count}")

    print("top hosts (3 by cumulative score)")
    for target in top_targets:
        print(
            f"  {target['hostname']:<16} "
            f"score {display_score(float(target['cumulative_priority_score']))}"
        )

    print(f"attack tactics covered : {len(by_attack_tactic)}")
    print(f"{OUTPUT_FILE} written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

PY

