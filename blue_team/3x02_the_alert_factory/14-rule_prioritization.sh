#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:?ASSETS_DIR is not set}"

RISK_REGISTER="$ASSETS_DIR/risk_register.json"
RULE_QUALITY="rule_quality.json"
ATTACK_COVERAGE="attack_coverage.json"
OUTPUT="rule_prioritization.json"

for file in "$RISK_REGISTER" "$RULE_QUALITY" "$ATTACK_COVERAGE"; do
    [[ -f "$file" ]] || {
        echo "ERROR: missing input: $file" >&2
        exit 1
    }
done

python3 - "$RISK_REGISTER" "$RULE_QUALITY" "$ATTACK_COVERAGE" "$OUTPUT" <<'PY'
import json
import re
import sys
from pathlib import Path

risk_file, quality_file, coverage_file, output_file = sys.argv[1:]

TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.I)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def as_list(data, keys):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value

    return []


def extract_techniques(value):
    """
    Recursively extract ATT&CK techniques from strings/lists/dicts.
    Handles:
      attack.t1059
      T1059
      t1059.001
    """
    found = set()

    if isinstance(value, str):
        for match in TECHNIQUE_RE.findall(value):
            found.add(match.lower())

        for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", value, re.I):
            found.add(match.lower())

    elif isinstance(value, list):
        for item in value:
            found.update(extract_techniques(item))

    elif isinstance(value, dict):
        for item in value.values():
            found.update(extract_techniques(item))

    return found


def get_rule_id(rule):
    return (
        rule.get("rule_id")
        or rule.get("id")
        or rule.get("rule")
        or ""
    )


def get_rule_title(rule):
    return (
        rule.get("rule_title")
        or rule.get("title")
        or rule.get("rule")
        or get_rule_id(rule)
    )


def get_level(rule):
    return rule.get("level", "unknown")


def get_f1(rule):
    try:
        return float(rule.get("f1", 0))
    except (TypeError, ValueError):
        return 0.0


def scenario_name(scenario):
    return (
        scenario.get("scenario")
        or scenario.get("name")
        or scenario.get("title")
        or scenario.get("id")
        or "unknown"
    )


def scenario_likelihood(scenario):
    value = scenario.get("likelihood", 0)

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def scenario_impact(scenario):
    value = scenario.get("impact", 0)

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


risk_data = load_json(risk_file)
quality_data = load_json(quality_file)
coverage_data = load_json(coverage_file)

risk_scenarios = as_list(
    risk_data,
    ["scenarios", "threat_scenarios", "risks", "risk_scenarios"]
)

quality_rules = as_list(
    quality_data,
    ["rules", "rule_quality", "results"]
)

coverage_rules = as_list(
    coverage_data,
    ["rules", "coverage", "attack_coverage", "results"]
)


# Build technique coverage from attack_coverage.json.
coverage_by_rule = {}

for item in coverage_rules:
    rule_id = get_rule_id(item)

    if not rule_id:
        continue

    coverage_by_rule[str(rule_id)] = extract_techniques(item)


# If attack_coverage.json identifies rules by filename/title rather than ID,
# also index those fields.
coverage_by_name = {}

for item in coverage_rules:
    techniques = extract_techniques(item)

    for key in ("rule", "rule_file", "filename", "title", "rule_title"):
        value = item.get(key)

        if value:
            coverage_by_name[str(value)] = techniques


results = []

for rule in quality_rules:
    rule_id = str(get_rule_id(rule))
    title = get_rule_title(rule)
    level = get_level(rule)
    f1 = get_f1(rule)

    techniques = set()

    # Preferred source: attack_coverage.json
    techniques.update(
        coverage_by_rule.get(rule_id, set())
    )

    # Try matching by rule filename/title.
    for key in ("rule", "rule_file", "filename", "title", "rule_title"):
        value = rule.get(key)

        if value in coverage_by_name:
            techniques.update(coverage_by_name[value])

    # Also accept technique fields directly in rule_quality.json.
    techniques.update(
        extract_techniques(rule)
    )

    risk_score = 0.0
    covering_scenarios = []

    for scenario in risk_scenarios:
        scenario_techniques = extract_techniques(scenario)

        if techniques & scenario_techniques:
            likelihood = scenario_likelihood(scenario)
            impact = scenario_impact(scenario)

            risk_score += likelihood * impact
            covering_scenarios.append(scenario_name(scenario))

    # Required zero-F1 floor.
    if f1 == 0:
        priority_score = risk_score * 0.1
    else:
        priority_score = risk_score * f1

    results.append({
        "rule_id": rule_id,
        "rule_title": title,
        "risk_score": round(risk_score, 2),
        "f1": round(f1, 4),
        "priority_score": round(priority_score, 2),
        "covering_scenarios": covering_scenarios,
        "level": level
    })


# Highest priority first.
results.sort(
    key=lambda x: (
        -x["priority_score"],
        x["rule_id"]
    )
)

Path(output_file).write_text(
    json.dumps(results, indent=2) + "\n",
    encoding="utf-8"
)

print("top 10 rules by priority_score")

rank = 1

for item in results:
    if item["priority_score"] <= 0:
        continue

    if rank > 10:
        break

    rule_id = item["rule_id"]

    # Prefer the numeric catalog prefix when present.
    match = re.match(r"(\d+)", rule_id)
    number = match.group(1) if match else rule_id

    title = item["rule_title"]

    # Expected output uses the catalog-friendly short name.
    title = re.sub(r"^\d+[_-]", "", title)
    title = title.replace(".yml", "")

    print(
        f"{rank:2}  "
        f"{item['priority_score']:5.1f}  "
        f"{number:>3} {title}"
    )

    rank += 1


orphans = [
    item for item in results
    if item["priority_score"] == 0
]

print(f"orphan rules (no risk scenario covers) : {len(orphans)}")

if orphans:
    print("ORPHAN")

    for item in orphans:
        rule_id = item["rule_id"]
        title = re.sub(r"^\d+[_-]", "", item["rule_title"])
        print(f"  {rule_id} {title}")

print("rule_prioritization.json written")
PY
