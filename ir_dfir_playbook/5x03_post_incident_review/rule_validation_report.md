
#!/usr/bin/env bash
set -Eeuo pipefail

RULE1="${RULE1:-sigma_powershell_encoded_command.yml}"
RULE2="${RULE2:-sigma_powershell_msbuild_lolbin.yml}"
INCIDENT="${INCIDENT:-incident_sysmon.jsonl}"
CLEAN="${CLEAN:-clean_sysmon.jsonl}"

usage() {
    printf 'Usage: %s [rule1.yml] [rule2.yml] [incident.jsonl] [clean.jsonl]\n' "$0"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

RULE1="${1:-$RULE1}"
RULE2="${2:-$RULE2}"
INCIDENT="${3:-$INCIDENT}"
CLEAN="${4:-$CLEAN}"

for file in "$RULE1" "$RULE2" "$INCIDENT" "$CLEAN"; do
    if [[ ! -f "$file" || ! -r "$file" ]]; then
        printf 'ERROR: File missing or unreadable: %s\n' "$file" >&2
        usage >&2
        exit 2
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    printf 'ERROR: python3 is required.\n' >&2
    exit 2
fi

if ! python3 -c 'import yaml' >/dev/null 2>&1; then
    printf 'ERROR: PyYAML is required. Install it with: python3 -m pip install PyYAML\n' >&2
    exit 2
fi

export RULE1 RULE2 INCIDENT CLEAN

python3 <<'PYTHON'
import ast
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required.", file=sys.stderr)
    sys.exit(2)


RULES = [
    ("PowerShell encoded-command detection", os.environ["RULE1"]),
    ("PowerShell / script host spawning LOLBin", os.environ["RULE2"]),
]

SAMPLES = [
    ("incident", os.environ["INCIDENT"]),
    ("clean", os.environ["CLEAN"]),
]

ALIASES = {
    "Image": ("image", "Image"),
    "ParentImage": ("parent_image", "ParentImage"),
    "CommandLine": ("cmdline", "CommandLine", "command_line"),
    "ProcessCommandLine": ("cmdline", "ProcessCommandLine"),
    "User": ("user", "User"),
    "Computer": ("host", "Computer", "computer"),
    "Hostname": ("host", "Hostname"),
    "EventID": ("event_id", "EventID"),
    "ParentProcessId": ("ppid", "ParentProcessId"),
    "ProcessId": ("pid", "ProcessId"),
    "DestinationIp": ("dst_ip", "DestinationIp"),
    "DestinationPort": ("dst_port", "DestinationPort"),
    "TargetFilename": ("target", "TargetFilename"),
}


def get_field(event, field):
    candidates = ALIASES.get(field, (field, field.lower()))
    for candidate in candidates:
        if candidate in event:
            return event[candidate]
    return None


def endswith_match(actual, expected):
    if actual is None:
        return False
    return str(actual).lower().endswith(str(expected).lower())


def scalar_match(actual, expected, modifier=None):
    if isinstance(actual, list):
        return any(scalar_match(x, expected, modifier) for x in actual)

    if isinstance(expected, list):
        if modifier == "all":
            return all(scalar_match(actual, x) for x in expected)
        return any(scalar_match(actual, x) for x in expected)

    if modifier == "endswith":
        return endswith_match(actual, expected)

    if modifier == "startswith":
        return actual is not None and str(actual).lower().startswith(str(expected).lower())

    if modifier == "contains":
        return actual is not None and str(expected).lower() in str(actual).lower()

    if modifier == "re":
        try:
            return actual is not None and re.search(str(expected), str(actual), re.IGNORECASE) is not None
        except re.error:
            return False

    if modifier == "exists":
        expected_bool = str(expected).lower() == "true"
        return (actual is not None) == expected_bool

    if actual is None:
        return False

    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual == expected

    return str(actual).casefold() == str(expected).casefold()


def selection_matches(selection, event):
    if not isinstance(selection, dict):
        raise ValueError("Detection selections must be YAML mappings.")

    for key, expected in selection.items():
        parts = key.split("|")
        field = parts[0]
        modifiers = parts[1:]

        modifier = None
        for item in modifiers:
            if item in ("endswith", "startswith", "contains", "re", "exists"):
                modifier = item
                break

        actual = get_field(event, field)

        if not scalar_match(actual, expected, modifier):
            return False

    return True


def condition_matches(condition, matched_names):
    condition = condition.strip()

    def replace_one_of(match):
        pattern = match.group(1).strip().strip("'\"")
        names = [
            name for name in matched_names.keys()
            if fnmatch.fnmatchcase(name, pattern)
        ]
        return str(any(matched_names[name] for name in names))

    def replace_all_of(match):
        pattern = match.group(1).strip().strip("'\"")
        names = [
            name for name in matched_names.keys()
            if fnmatch.fnmatchcase(name, pattern)
        ]
        return str(bool(names) and all(matched_names[name] for name in names))

    condition = re.sub(
        r"\b1\s+of\s+([A-Za-z0-9_*?]+)",
        replace_one_of,
        condition,
        flags=re.IGNORECASE,
    )
    condition = re.sub(
        r"\ball\s+of\s+([A-Za-z0-9_*?]+)",
        replace_all_of,
        condition,
        flags=re.IGNORECASE,
    )

    for name in sorted(matched_names, key=len, reverse=True):
        condition = re.sub(
            rf"\b{re.escape(name)}\b",
            str(matched_names[name]),
            condition,
        )

    condition = re.sub(r"\bAND\b", "and", condition, flags=re.IGNORECASE)
    condition = re.sub(r"\bOR\b", "or", condition, flags=re.IGNORECASE)
    condition = re.sub(r"\bNOT\b", "not", condition, flags=re.IGNORECASE)

    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError as exc:
        raise ValueError(
            f"Unsupported Sigma condition: {condition}"
        ) from exc

    allowed = (
        ast.Expression, ast.BoolOp, ast.UnaryOp, ast.And,
        ast.Or, ast.Not, ast.Constant,
    )
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise ValueError(
                f"Unsupported syntax in Sigma condition: {type(node).__name__}"
            )

    return bool(eval(compile(tree, "<sigma-condition>", "eval"), {"__builtins__": {}}, {}))


def load_rule(path):
    with open(path, "r", encoding="utf-8") as handle:
        rule = yaml.safe_load(handle)

    if not isinstance(rule, dict):
        raise ValueError(f"{path}: YAML root must be a mapping.")

    for key in ("title", "id", "logsource", "detection"):
        if key not in rule:
            raise ValueError(f"{path}: missing required Sigma field '{key}'.")

    if not isinstance(rule["detection"], dict):
        raise ValueError(f"{path}: detection must be a mapping.")

    condition = rule["detection"].get("condition")
    if not isinstance(condition, str):
        raise ValueError(f"{path}: detection.condition must be a string.")

    selections = {
        name: selection
        for name, selection in rule["detection"].items()
        if name != "condition"
    }

    if not selections:
        raise ValueError(f"{path}: no detection selections found.")

    return rule, selections, condition


def event_matches_rule(event, rule, selections, condition):
    category = str(rule.get("logsource", {}).get("category", "")).lower()

    if category == "process_creation":
        event_type = str(event.get("event_type", "")).lower()
        event_id = str(event.get("event_id", ""))

        if event_type:
            if event_type != "process_create":
                return False
        elif event_id and event_id != "1":
            return False

    results = {
        name: selection_matches(selection, event)
        for name, selection in selections.items()
    }

    return condition_matches(condition, results)


def read_jsonl(path):
    events = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}:{line_number}: invalid JSON: {exc}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"{path}:{line_number}: each JSONL record must be an object."
                )

            event["_source_line"] = line_number
            events.append(event)

    return events


def describe_event(event, rule_title):
    return {
        "rule": rule_title,
        "ts": event.get("ts", "unknown"),
        "host": event.get("host", "unknown"),
        "user": event.get("user", "unknown"),
        "image": event.get("image", "unknown"),
        "parent_image": event.get("parent_image", "unknown"),
        "cmdline": event.get("cmdline", ""),
        "event_type": event.get("event_type", "unknown"),
        "line": event.get("_source_line", "?"),
    }


def main():
    loaded_rules = []

    for label, path in RULES:
        rule, selections, condition = load_rule(path)
        loaded_rules.append((label, path, rule, selections, condition))
        print(f"RULE: {rule['title']}")
        print(f"  File: {path}")
        print(f"  ID: {rule['id']}")
        print("  Matcher: compatible local Sigma-subset evaluator")
        print()

    sample_events = {}
    for sample_name, path in SAMPLES:
        events = read_jsonl(path)
        sample_events[sample_name] = events
        print(f"SAMPLE: {sample_name}")
        print(f"  File: {path}")
        print(f"  Total events: {len(events)}")
        print()

    all_clean_matches = []

    print("MATCH RESULTS")
    print("=" * 72)

    for label, path, rule, selections, condition in loaded_rules:
        print(f"\nRule: {rule['title']} [{path}]")

        for sample_name, sample_path in SAMPLES:
            events = sample_events[sample_name]
            matches = [
                event for event in events
                if event_matches_rule(event, rule, selections, condition)
            ]

            total = len(events)
            rate = (100.0 * len(matches) / total) if total else 0.0

            print(f"  Sample: {sample_name}")
            print(f"    Total events: {total}")
            print(f"    Events matched: {len(matches)}")
            print(f"    Match rate: {rate:.2f}%")

            if sample_name == "clean":
                if matches:
                    print("    Clean-sample match details:")
                    for event in matches:
                        details = describe_event(event, rule["title"])
                        print(
                            "      - "
                            f"{details['ts']} | host={details['host']} | "
                            f"user={details['user']} | "
                            f"parent={details['parent_image']} | "
                            f"image={details['image']}"
                        )
                        print(f"        cmdline={details['cmdline']}")
                        print(
                            "        Possible FP pattern: "
                            "review legitimate developer, build, or scripting activity."
                        )
                        all_clean_matches.append(details)
                else:
                    print("    Clean-sample match details: none")

    print("\nCLEAN BASELINE FALSE-POSITIVE SUMMARY")
    print("=" * 72)

    if not all_clean_matches:
        print("No events matched either rule in the supplied clean baseline.")
    else:
        print(f"Total rule-event matches in clean baseline: {len(all_clean_matches)}")
        print("Review the individual matches above; one event may match both rules.")

    print("\nVALIDATION NOTES")
    print("-" * 72)
    print("This script evaluates a compatible subset of Sigma detection syntax.")
    print("It is not a replacement for full sigma-cli backend conversion or validation.")
    print("The reported match rate uses all JSONL events as the denominator.")
    print("Detection is evaluated only against the fields present in the supplied logs.")
    print("A clean-sample match is a candidate false positive, not proof of benign activity.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
PYTHON
