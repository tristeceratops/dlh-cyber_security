#!/bin/bash
set -euo pipefail

BASELINE_DIR="${BASELINE_PKG:?BASELINE_PKG is not set}/baselines"
SUMMARY_FILE="$BASELINE_DIR/baseline_summary.json"
RULE_DIR="rules/sigma"
RUNNER="./3-sigma_runner.sh"
OUTPUT="fp_baseline.json"

[[ -f "$SUMMARY_FILE" ]] || {
    echo "ERROR: baseline summary not found: $SUMMARY_FILE" >&2
    exit 1
}

[[ -x "$RUNNER" ]] || {
    echo "ERROR: runner not executable: $RUNNER" >&2
    exit 1
}

read -r START END < <(
    python3 - "$SUMMARY_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

start = (
    data.get("baseline_window_start")
    or data.get("window_start")
    or data.get("start")
)

end = (
    data.get("baseline_window_end")
    or data.get("window_end")
    or data.get("end")
)

if not start or not end:
    raise SystemExit("baseline window not found in baseline_summary.json")

print(start, end)
PY
)

WINDOW="${START},${END}"

mapfile -t RULES < <(find "$RULE_DIR" -type f -name '*.yml' | sort)

echo "evaluating ${#RULES[@]} rules against baseline window $START -> $END"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

for rule in "${RULES[@]}"; do
    result=$("$RUNNER" "$rule" --window "$WINDOW" 2>/dev/null)

    fp_count=$(
        python3 - "$result" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
print(data["match_count"])
PY
    )

    python3 - "$rule" "$fp_count" "$START" "$END" "$TMP" <<'PY'
import json
import os
import sys
from datetime import datetime

rule_file, fp_count, start, end, output = sys.argv[1:]

with open(rule_file, encoding="utf-8") as f:
    rule = __import__("yaml").safe_load(f)

start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))

days = (end_dt - start_dt).total_seconds() / 86400

entry = {
    "rule_id": rule["id"],
    "rule_title": rule["title"],
    "level": rule["level"],
    "fp_count": int(fp_count),
    "baseline_window_start": start,
    "baseline_window_end": end,
    "fp_rate_per_day": round(int(fp_count) / days, 2)
}

with open(output, "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")
PY
done

python3 - "$TMP" "$OUTPUT" <<'PY'
import json
import sys
from pathlib import Path

tmp, output = sys.argv[1:]

entries = []

for line in Path(tmp).read_text().splitlines():
    if line.strip():
        entries.append(json.loads(line))

entries.sort(key=lambda x: x["fp_count"], reverse=True)

Path(output).write_text(
    json.dumps(entries, indent=2) + "\n",
    encoding="utf-8"
)

for entry in entries:
    title = entry["rule_title"]

    if len(title) > 34:
        title = title[:34]

    marker = " [TUNE]" if entry["fp_count"] > 10 else ""

    print(
        f"  {title:<34} "
        f"fp={entry['fp_count']:>3}{marker}"
    )
PY

echo "fp_baseline.json written"
