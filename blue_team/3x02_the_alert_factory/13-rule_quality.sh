#!/bin/bash
set -euo pipefail

BASELINE_DIR="${BASELINE_PKG:?BASELINE_PKG is not set}"
BASELINES="$BASELINE_DIR/baselines"
ANOMALIES="$BASELINE_DIR/anomalies/ranked_anomalies.json"
LABELED="$BASELINE_DIR/taxonomy/labeled_events.json"
SUMMARY="$BASELINES/baseline_summary.json"

RULE_DIR="rules/sigma"
TUNED_DIR="rules/sigma/tuned"
RUNNER="./3-sigma_runner.sh"
FP_FILE="fp_baseline.json"
OUTPUT="rule_quality.json"

for file in "$ANOMALIES" "$LABELED" "$SUMMARY" "$FP_FILE"; do
    [[ -f "$file" ]] || {
        echo "ERROR: missing file: $file" >&2
        exit 1
    }
done

[[ -x "$RUNNER" ]] || {
    echo "ERROR: runner not executable: $RUNNER" >&2
    exit 1
}

read -r EVAL_START EVAL_END < <(
    python3 - "$SUMMARY" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

def first(*keys):
    for key in keys:
        value = data.get(key)
        if value:
            return value
    return None

start = first(
    "evaluation_window_start",
    "evaluation_start",
    "eval_window_start",
    "window_start"
)

end = first(
    "evaluation_window_end",
    "evaluation_end",
    "eval_window_end",
    "window_end"
)

if not start or not end:
    raise SystemExit(
        "evaluation window not found in baseline_summary.json"
    )

print(start, end)
PY
)

WINDOW="${EVAL_START},${EVAL_END}"

mapfile -t RULES < <(
    {
        find "$RULE_DIR" -maxdepth 1 -type f -name '*.yml'
        [[ -d "$TUNED_DIR" ]] &&
            find "$TUNED_DIR" -type f -name '*.yml'
    } 2>/dev/null | sort
)

echo "evaluating ${#RULES[@]} rules against labeled ground truth"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

python3 - "$ANOMALIES" "$LABELED" "$FP_FILE" "$TMP" <<'PY'
import json
import sys

anomaly_file, labeled_file, fp_file, output = sys.argv[1:]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def event_ref(obj):
    if not isinstance(obj, dict):
        return None

    for key in (
        "event_ref",
        "eventRef",
        "event_id",
        "eventId",
        "id",
    ):
        value = obj.get(key)
        if value is not None:
            return str(value)

    return None


def is_true_positive(obj):
    if not isinstance(obj, dict):
        return False

    # Explicit boolean indicators.
    for key in (
        "true_positive",
        "truePositive",
        "malicious",
        "is_malicious",
    ):
        if obj.get(key) is True:
            return True

    # Common label fields.
    for key in ("label", "classification", "verdict", "status"):
        value = obj.get(key)

        if isinstance(value, str):
            value = value.lower().replace("-", "_").replace(" ", "_")

            if value in {
                "malicious",
                "true_positive",
                "truepositive",
                "confirmed_malicious",
                "confirmed",
                "attack",
            }:
                return True

    return False


anomalies = load(anomaly_file)
labeled = load(labeled_file)

refs = set()

# ranked_anomalies.json represents the confirmed anomaly set.
for obj in walk(anomalies):
    ref = event_ref(obj)

    if ref is not None:
        # Only accept objects that actually look like anomaly records.
        if any(
            key in obj
            for key in (
                "rank",
                "score",
                "anomaly_score",
                "reason",
                "anomaly",
                "category",
            )
        ):
            refs.add(ref)

# labeled_events.json provides explicit malicious/TP labels.
for obj in walk(labeled):
    ref = event_ref(obj)

    if ref is not None and is_true_positive(obj):
        refs.add(ref)

# Store one JSON object containing the normalized ground truth.
result = {
    "true_positive_event_refs": sorted(refs)
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(result, f)

print(len(refs), file=sys.stderr)
PY

# Temporary file currently contains the ground-truth object.
GT_COUNT=$(
    python3 - "$TMP" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

print(len(data["true_positive_event_refs"]))
PY
)

# Save ground truth in a shell variable as JSON.
GROUND_TRUTH=$(
    cat "$TMP"
)

for rule in "${RULES[@]}"; do

    result=$(
        "$RUNNER" "$rule" --window "$WINDOW" 2>/dev/null
    )

    python3 - "$rule" "$result" "$FP_FILE" "$ANOMALIES" "$LABELED" "$GROUND_TRUTH" "$EVAL_START" "$EVAL_END" "$TMP" <<'PY'
import json
import sys
import yaml

(
    rule_file,
    runner_result,
    fp_file,
    anomaly_file,
    labeled_file,
    ground_truth,
    eval_start,
    eval_end,
    output
) = sys.argv[1:]

with open(rule_file, encoding="utf-8") as f:
    rule = yaml.safe_load(f)

result = json.loads(runner_result)

matches = result.get("matches", [])

matched_refs = {
    str(x["event_ref"])
    for x in matches
    if x.get("event_ref") not in (None, "")
}

with open(fp_file, encoding="utf-8") as f:
    fp_data = json.load(f)

# Support either a list or {"rules": [...]}.
if isinstance(fp_data, dict):
    fp_entries = (
        fp_data.get("rules")
        or fp_data.get("findings")
        or fp_data.get("entries")
        or []
    )
else:
    fp_entries = fp_data

baseline_fp = 0

for entry in fp_entries:
    if entry.get("rule_id") == rule["id"]:
        baseline_fp = int(entry.get("fp_count", 0))
        break

ground_truth = json.loads(ground_truth)
tp_refs = set(
    str(x) for x in ground_truth["true_positive_event_refs"]
)

tp_count = len(matched_refs & tp_refs)

evaluation_fp = len(matched_refs - tp_refs)

fp_count = evaluation_fp + baseline_fp

# Determine the event category covered by this rule.
logsource = rule.get("logsource", {})
category = logsource.get("category")

if not category:
    service = logsource.get("service")

    if service == "auth":
        category = "authentication"
    else:
        category = service

# For process_creation rules, use the labeled/anomaly event category.
# This gives FN the same-category ground truth denominator.
def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def ref(obj):
    if not isinstance(obj, dict):
        return None

    for key in ("event_ref", "eventRef", "event_id", "eventId", "id"):
        if obj.get(key) is not None:
            return str(obj[key])

    return None


def get_category(obj):
    if not isinstance(obj, dict):
        return None

    for key in (
        "event_category",
        "category",
        "eventCategory",
    ):
        value = obj.get(key)
        if value:
            return str(value)

    return None


all_ground_truth = {}

for path in (anomaly_file, labeled_file):
    data = load(path)

    for obj in walk(data):
        event_ref = ref(obj)

        if event_ref is None:
            continue

        if event_ref not in tp_refs:
            continue

        event_category = get_category(obj)

        if event_category:
            all_ground_truth[event_ref] = event_category


same_category_refs = set()

if category:
    for event_ref, event_category in all_ground_truth.items():
        if event_category == category:
            same_category_refs.add(event_ref)

# If the source data does not expose categories, use all ground truth.
if not same_category_refs:
    same_category_refs = tp_refs.copy()

fn_count = len(same_category_refs - matched_refs)

precision = (
    tp_count / (tp_count + fp_count)
    if tp_count + fp_count
    else 0.0
)

recall = (
    tp_count / (tp_count + fn_count)
    if tp_count + fn_count
    else 0.0
)

f1 = (
    2 * precision * recall / (precision + recall)
    if precision + recall
    else 0.0
)

entry = {
    "rule_id": rule["id"],
    "rule_title": rule["title"],
    "level": rule["level"],
    "tp_count": tp_count,
    "fp_count": fp_count,
    "fn_count": fn_count,
    "precision": round(precision, 4),
    "recall": round(recall, 4),
    "f1": round(f1, 4),
    "evaluation_window_start": eval_start,
    "evaluation_window_end": eval_end,
}

with open(output, "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")
PY

done

python3 - "$TMP" <<'PY'
import json
import sys
from pathlib import Path

tmp = sys.argv[1]

# The first JSON object in TMP is ground truth.
lines = Path(tmp).read_text().splitlines()

ground_truth = json.loads(lines[0])

entries = [
    json.loads(line)
    for line in lines[1:]
    if line.strip()
]

entries.sort(key=lambda x: x["f1"], reverse=True)

Path("rule_quality.json").write_text(
    json.dumps(entries, indent=2) + "\n",
    encoding="utf-8"
)

def display(entry):
    title = entry["rule_title"]

    if len(title) > 34:
        title = title[:34]

    marker = ""

    if entry["f1"] < 0.3:
        marker = "  [WEAK]"
    elif entry["f1"] >= 0.7:
        marker = "  [STRONG]"

    print(
        f"  {title:<34} "
        f"f1={entry['f1']:.2f}  "
        f"p={entry['precision']:.2f} "
        f"r={entry['recall']:.2f}"
        f"{marker}"
    )

print("strongest")

for entry in entries[:5]:
    display(entry)

print("weakest")

for entry in entries[-5:]:
    display(entry)
PY

echo "rule_quality.json written"
