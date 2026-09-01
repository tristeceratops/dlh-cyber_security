#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATASET="${HANDOFF_DIR}/data/enriched_events.json"

usage() {
    cat <<'EOF'
query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message
EOF
}

die() {
    printf 'error: %s\n' "$1" >&2
    exit 2
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

case "$1" in
    help|-h|--help)
        usage
        exit 0
        ;;
esac

VERB="$1"
shift

[[ -f "$DATASET" ]] || die "dataset not found: $DATASET"

python3 -W error - "$VERB" "$DATASET" "$@" <<'PY'
import json
import sys
from collections import Counter
from datetime import datetime, timezone


def error(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def parse_arguments(argv):
    if len(argv) < 2:
        error("missing arguments")

    verb = argv[0]
    dataset = argv[1]
    args = argv[2:]

    allowed = {
        "--source",
        "--host",
        "--from",
        "--to",
        "--category",
        "--field",
        "--limit",
        "--bucket",
    }

    values = {}
    i = 0

    while i < len(args):
        option = args[i]

        if option not in allowed:
            error(f"unknown option: {option}")

        if i + 1 >= len(args):
            error(f"{option} requires a value")

        if option in values:
            error(f"{option} specified more than once")

        values[option] = args[i + 1]
        i += 2

    return verb, dataset, values


def load_records(path):
    records = []

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                error(
                    f"invalid JSON on line {line_number}: {exc.msg}"
                )

            if not isinstance(record, dict):
                error(
                    f"record on line {line_number} is not a JSON object"
                )

            records.append(record)

    return records


def parse_time(value):
    if not isinstance(value, str):
        return None

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None

    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)

    return result


# CLI field names map to the actual enriched dataset schema.
FIELD_ALIASES = {
    "source": "source_type",
    "host": "hostname",
    "category": "event_category",
}


def canonical_field(field):
    return FIELD_ALIASES.get(field, field)


def get_field(record, field):
    field = canonical_field(field)

    value = record

    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]

    return value


def matches(record, filters):
    simple_filters = (
        ("--source", "source"),
        ("--host", "host"),
        ("--category", "category"),
    )

    for option, field in simple_filters:
        if option in filters:
            if get_field(record, field) != filters[option]:
                return False

    timestamp = get_field(record, "timestamp")

    if "--from" in filters:
        start = parse_time(filters["--from"])

        if start is None:
            error("--from must be a valid ISO-8601 timestamp")

        record_time = parse_time(timestamp)

        if record_time is None or record_time < start:
            return False

    if "--to" in filters:
        end = parse_time(filters["--to"])

        if end is None:
            error("--to must be a valid ISO-8601 timestamp")

        record_time = parse_time(timestamp)

        if record_time is None or record_time > end:
            return False

    return True


def value_as_text(value):
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        )

    return str(value)


def matching_records(records, filters):
    return [
        record
        for record in records
        if matches(record, filters)
    ]


def command_filter(records, filters):
    for record in matching_records(records, filters):
        print(
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
            )
        )


def command_count(records, filters):
    print(len(matching_records(records, filters)))


def command_distinct(records, filters):
    if "--field" not in filters:
        error("distinct requires --field")

    field = filters["--field"]

    values = {
        value_as_text(get_field(record, field))
        for record in matching_records(records, filters)
        if get_field(record, field) is not None
    }

    for value in sorted(values):
        print(value)


def command_top(records, filters):
    if "--field" not in filters:
        error("top requires --field")

    if "--limit" not in filters:
        error("top requires --limit")

    field = filters["--field"]

    try:
        limit = int(filters["--limit"])
    except ValueError:
        error("--limit must be an integer")

    if limit < 0:
        error("--limit must be non-negative")

    counts = Counter(
        value_as_text(get_field(record, field))
        for record in matching_records(records, filters)
        if get_field(record, field) is not None
    )

    # Deterministic ordering:
    # highest count first, then value ascending.
    for value, count in sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0]),
    )[:limit]:
        print(f"{value}\t{count}")


def command_window(records, filters):
    if "--field" not in filters:
        error("window requires --field")

    if "--bucket" not in filters:
        error("window requires --bucket")

    field = filters["--field"]
    bucket = filters["--bucket"]

    if bucket not in {"hour", "day"}:
        error("window --bucket must be hour or day")

    counts = Counter()

    for record in matching_records(records, filters):
        timestamp = parse_time(get_field(record, field))

        if timestamp is None:
            continue

        if bucket == "hour":
            key = timestamp.strftime("%Y-%m-%dT%H:00:00Z")
        else:
            key = timestamp.strftime("%Y-%m-%d")

        counts[key] += 1

    for key in sorted(counts):
        print(f"{key}\t{counts[key]}")


def main():
    verb, dataset, filters = parse_arguments(sys.argv[1:])
    records = load_records(dataset)

    commands = {
        "filter": command_filter,
        "top": command_top,
        "distinct": command_distinct,
        "count": command_count,
        "window": command_window,
    }

    if verb not in commands:
        error(f"unknown verb: {verb}")

    commands[verb](records, filters)


if __name__ == "__main__":
    main()
PY

