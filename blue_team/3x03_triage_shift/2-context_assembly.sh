#!/bin/bash
set -euo pipefail

: "${CATALOG_DIR:=$HOME/3x02_package/detection_catalog}"
: "${HANDOFF_DIR:=$HOME/3x00_handoff/evidence_handoff}"
: "${BASELINE_PKG:=$HOME/3x01_package/baseline_package}"
: "${ASSETS_DIR:=$HOME/3x03_assets}"

QUEUE_FILE="$CATALOG_DIR/alerts/alert_queue.json"
ASSET_FILE="$HANDOFF_DIR/context/asset_inventory.json"
EVENT_FILE="$HANDOFF_DIR/data/enriched_events.json"
BASELINE_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
IOC_FILE="$ASSETS_DIR/ioc_context.json"
OUTPUT_FILE="enriched_queue.json"

mkdir -p tickets

python3 -W error - "$QUEUE_FILE" "$ASSET_FILE" "$EVENT_FILE" "$BASELINE_FILE" "$IOC_FILE" "$OUTPUT_FILE" <<'PY'
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def load(path: str) -> Any:
    with Path(path).open(encoding="utf-8") as f:
        return json.load(f)


def list_records(data: Any, keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in keys:
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
    return []


def index_records(data: Any, ids: Tuple[str, ...]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                out[str(key)] = value
    for record in list_records(data, ("alerts", "events", "assets", "items", "records", "data")):
        for key in ids:
            if record.get(key) is not None:
                out[str(record[key])] = record
                break
    return out


def first(obj: Dict[str, Any], paths: Tuple[str, ...]) -> Any:
    for path in paths:
        cur: Any = obj
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                break
            cur = cur[part]
        else:
            return cur
    return None


def host(alert: Dict[str, Any]) -> Optional[str]:
    value = first(alert, ("hostname", "target.hostname", "target_host",
                          "target.host", "host.hostname", "event_summary.hostname"))
    return str(value).strip().lower() if value is not None else None


def score(alert: Dict[str, Any]) -> float:
    value = first(alert, ("priority_score", "priority.score", "score"))
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("alert missing numeric priority_score")
    return float(value)


def band(value: float) -> str:
    if value >= 20:
        return "critical"
    if value >= 10:
        return "high"
    if value >= 5:
        return "medium"
    if value >= 1:
        return "low"
    raise ValueError("priority_score must be >= 1")


def event_ref(alert: Dict[str, Any]) -> Optional[str]:
    value = first(alert, ("event_ref", "event_summary.event_ref", "event.event_ref"))
    return str(value) if value is not None else None


def hostname_index(data: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                name = first(value, ("hostname", "host", "asset_id", "name"))
                out[str(name or key).strip().lower()] = value
    for record in list_records(data, ("assets", "items", "records", "data")):
        name = first(record, ("hostname", "host", "asset_id", "name"))
        if name is not None:
            out[str(name).strip().lower()] = record
    return out


def baseline_index(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        for key in ("hosts", "host_profiles", "baselines", "profiles"):
            if isinstance(data.get(key), dict):
                return {str(k).strip().lower(): v for k, v in data[key].items()}
        return {str(k).strip().lower(): v for k, v in data.items()}
    out: Dict[str, Any] = {}
    for record in list_records(data, ("baselines", "profiles", "items", "data")):
        name = first(record, ("hostname", "host", "asset_id", "name"))
        if name is not None:
            out[str(name).strip().lower()] = record
    return out


def strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: List[str] = []
        for item in value:
            result.extend(strings(item))
        return result
    if isinstance(value, dict):
        result = []
        for item in value.values():
            result.extend(strings(item))
        return result
    return []


IP_RE = re.compile(r"(?<![A-Za-z0-9_.:-])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.:-])")
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9.-])")


def ioc_candidates(alert: Dict[str, Any], event: Any) -> List[str]:
    values = strings(alert) + strings(event)
    found = set()
    for text in values:
        for value in IP_RE.findall(text):
            try:
                ipaddress.ip_address(value)
                found.add(value.lower())
            except ValueError:
                pass
        for value in DOMAIN_RE.findall(text):
            found.add(value.lower().rstrip("."))
    return sorted(found)


def ioc_index(data: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(data, dict):
        return {}
    return {str(k).lower().rstrip("."): v for k, v in data.items() if isinstance(v, dict)}


def baseline_slice(profile: Any, alert: Dict[str, Any]) -> Any:
    if not isinstance(profile, dict):
        return profile
    category = first(alert, ("category", "alert_category", "rule.category", "rule_category"))
    if category is None:
        return profile
    category = str(category)
    for key in ("categories", "by_category", "category_profiles", "slices"):
        container = profile.get(key)
        if isinstance(container, dict):
            for name, value in container.items():
                if str(name).lower() == category.lower():
                    return {key: {name: value}}
    return profile


queue = load(sys.argv[1])
assets = hostname_index(load(sys.argv[2]))
events = index_records(load(sys.argv[3]), ("event_ref", "event_id", "id", "ref"))
baselines = baseline_index(load(sys.argv[4]))
iocs = ioc_index(load(sys.argv[5]))

alerts = queue if isinstance(queue, list) else list_records(queue, ("alerts", "queue", "items", "data"))
if not alerts:
    raise ValueError("alert_queue.json contains no alerts")

result: List[Dict[str, Any]] = []
assets_joined = 0
missing_assets = 0
ioc_alerts = 0
reps = {"malicious": 0, "suspicious": 0, "unknown": 0}
baseline_joined = 0

for alert in alerts:
    if not isinstance(alert, dict):
        raise ValueError("alert queue contains a non-object alert")

    h = host(alert)
    asset = assets.get(h) if h else None
    assets_joined += asset is not None
    missing_assets += asset is None

    ref = event_ref(alert)
    event = events.get(ref) if ref else None
    if ref and event is None:
        raise ValueError("missing event_record for event_ref=" + repr(ref))

    profile = baselines.get(h) if h else None
    baseline_joined += profile is not None

    hits = []
    for key in ioc_candidates(alert, event):
        if key in iocs:
            entry = dict(iocs[key])
            entry["ioc"] = key
            entry["ioc_flag"] = entry.get("reputation") != "clean"
            hits.append(entry)
            if entry.get("reputation") in reps:
                reps[entry["reputation"]] += 1
    ioc_alerts += bool(hits)

    enriched = dict(alert)
    enriched["asset"] = asset
    enriched["baseline_host_profile"] = baseline_slice(profile, alert)
    enriched["event_record"] = event
    enriched["ioc_hits"] = hits
    enriched["priority_band"] = band(score(alert))
    result.append(enriched)

with Path(sys.argv[6]).open("w", encoding="utf-8", newline="\n") as f:
    json.dump(result, f, indent=2)
    f.write("\n")

print("alerts processed          :", len(alerts))
print("assets joined             :", assets_joined)
print("missing asset records     :", missing_assets)
print("alerts with IOC hits      :", ioc_alerts)
print("  malicious               :", reps["malicious"])
print("  suspicious              :", reps["suspicious"])
print("  unknown                 :", reps["unknown"])
print("baseline profiles joined  :", baseline_joined)
print(f"enriched_queue.json written ({Path(sys.argv[6]).stat().st_size / 1024:.0f} KB)")
PY

