#!/bin/bash
set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-"$HOME/evidence_pack_primary"}"
LINUX_DIR="${LINUX_DIR:-"$EVIDENCE_PACK/linux"}"
TELEMETRY_FILE="${TELEMETRY_FILE:-"$EVIDENCE_PACK/student_telemetry/linux_events.json"}"
OUTPUT="${OUTPUT:-linux_events.json}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required" >&2
    exit 1
fi

for file in auth.log audit.log syslog; do
    if [[ ! -f "$LINUX_DIR/$file" ]]; then
        echo "error: missing $LINUX_DIR/$file" >&2
        exit 1
    fi
done

if [[ ! -f "$TELEMETRY_FILE" ]]; then
    echo "error: missing $TELEMETRY_FILE" >&2
    exit 1
fi

OUTPUT_DIR=$(dirname -- "$OUTPUT")
mkdir -p "$OUTPUT_DIR"

TEMP_OUTPUT=$(mktemp "${OUTPUT}.tmp.XXXXXX")
trap 'rm -f "$TEMP_OUTPUT"' EXIT

LINUX_DIR="$LINUX_DIR" \
TELEMETRY_FILE="$TELEMETRY_FILE" \
OUTPUT="$TEMP_OUTPUT" \
python3 <<'PY'
import json
import os
import re
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

linux_dir = Path(os.environ["LINUX_DIR"])
telemetry_file = Path(os.environ["TELEMETRY_FILE"])
output_file = Path(os.environ["OUTPUT"])

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)\s+"
    r"(?P<program>[^:\s\[]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

AUDIT_RE = re.compile(
    r"^type=(?P<audit_type>\S+)\s+"
    r"msg=audit\((?P<audit_ts>\d+\.\d+):(?P<audit_serial>\d+)\):\s*"
    r"(?P<body>.*)$"
)

KV_RE = re.compile(
    r'(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)='
    r'(?P<value>"(?:\\.|[^"])*"|\S+)'
)

USER_KEYS = (
    "user",
    "acct",
    "account",
    "auid",
    "uid",
    "euid",
    "suid",
    "fsuid",
    "loginuid",
    "subject",
    "target",
    "owner",
)


def iso_utc(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_kv(text):
    fields = OrderedDict()

    for match in KV_RE.finditer(text):
        key = match.group("key")
        value = match.group("value")

        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = value[1:-1]

        fields[key] = value

    return fields


def first_user(fields):
    for key in USER_KEYS:
        if key not in fields:
            continue

        value = fields[key]

        if value not in ("", "0", "4294967295", 0, 4294967295):
            return value

    return None


def parse_syslog_line(line, year):
    match = SYSLOG_RE.match(line)

    if match is None:
        return {
            "timestamp_raw": "1970-01-01T00:00:00Z",
            "hostname": None,
            "program": None,
            "raw_message": line,
            "parsed_fields": {
                "timestamp_original": None,
                "unparsed": True,
            },
            "source_origin": "evidence_pack",
        }

    timestamp_original = match.group("timestamp")
    month_name, day_text, clock = timestamp_original.split(maxsplit=2)
    month = MONTHS.get(month_name)

    if month is None:
        return {
            "timestamp_raw": "1970-01-01T00:00:00Z",
            "hostname": match.group("hostname"),
            "program": match.group("program"),
            "raw_message": line,
            "parsed_fields": {
                "timestamp_original": timestamp_original,
                "unparsed": True,
                "invalid_month": month_name,
            },
            "source_origin": "evidence_pack",
        }

    try:
        hour, minute, second = (
            int(value) for value in clock.split(":")
        )

        dt = datetime(
            year,
            month,
            int(day_text),
            hour,
            minute,
            second,
            tzinfo=timezone.utc,
        )
    except ValueError:
        return {
            "timestamp_raw": "1970-01-01T00:00:00Z",
            "hostname": match.group("hostname"),
            "program": match.group("program"),
            "raw_message": line,
            "parsed_fields": {
                "timestamp_original": timestamp_original,
                "unparsed": True,
            },
            "source_origin": "evidence_pack",
        }

    message = match.group("message")
    parsed = parse_kv(message)
    parsed["timestamp_original"] = timestamp_original
    parsed["message"] = message

    record = {
        "timestamp_raw": iso_utc(dt),
        "hostname": match.group("hostname"),
        "program": match.group("program"),
        "raw_message": line,
        "parsed_fields": parsed,
        "source_origin": "evidence_pack",
    }

    if match.group("pid") is not None:
        record["pid"] = int(match.group("pid"))

    user = first_user(parsed)

    if user is not None:
        record["user"] = user

    return record

def audit_timestamp_to_iso(timestamp):
    return iso_utc(
        datetime.fromtimestamp(
            float(timestamp),
            tz=timezone.utc,
        )
    )


def parse_audit_group(lines):
    first = AUDIT_RE.match(lines[0])

    if first is None:
        return {
            "timestamp_raw": "1970-01-01T00:00:00Z",
            "hostname": None,
            "audit_type": None,
            "raw_message": "\n".join(lines),
            "parsed_fields": {
                "timestamp_original": None,
                "unparsed": True,
            },
            "source_origin": "evidence_pack",
        }

    audit_timestamp = first.group("audit_ts")
    audit_serial = first.group("audit_serial")
    audit_type = first.group("audit_type")

    parsed = OrderedDict()

    for line in lines:
        match = AUDIT_RE.match(line)

        if match is None:
            continue

        for key, value in parse_kv(match.group("body")).items():
            parsed[key] = value

    parsed["timestamp_original"] = audit_timestamp
    parsed["audit_serial"] = audit_serial
    parsed["audit_group_id"] = f"{audit_timestamp}:{audit_serial}"
    parsed["line_count"] = len(lines)

    record = {
        "timestamp_raw": audit_timestamp_to_iso(audit_timestamp),
        "hostname": parsed.get("hostname"),
        "audit_type": audit_type,
        "raw_message": "\n".join(lines),
        "parsed_fields": parsed,
        "source_origin": "evidence_pack",
    }

    if "pid" in parsed:
        try:
            record["pid"] = int(parsed["pid"])
        except (TypeError, ValueError):
            record["pid"] = parsed["pid"]

    user = first_user(parsed)
    if user is not None:
        record["user"] = user

    return record


def audit_groups(path):
    current_id = None
    current_lines = []

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            match = AUDIT_RE.match(line)

            if match is None:
                if current_lines:
                    current_lines.append(line)
                else:
                    current_lines = [line]
                continue

            group_id = (
                f"{match.group('audit_ts')}:{match.group('audit_serial')}"
            )

            if current_id is not None and group_id != current_id:
                yield current_lines

            current_id = group_id
            current_lines = [line]

    if current_lines:
        yield current_lines


def infer_year(audit_path):
    with audit_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        for line in handle:
            match = AUDIT_RE.match(line.rstrip("\n"))

            if match:
                dt = datetime.fromtimestamp(
                    float(match.group("audit_ts")),
                    tz=timezone.utc,
                )
                return dt.year

    return datetime.now(timezone.utc).year


def normalize_telemetry(record):
    result = dict(record)

    original_timestamp = result.get(
        "timestamp_raw",
        result.get("timestamp"),
    )

    if original_timestamp is None:
        raise ValueError("student telemetry record has no timestamp")

    if isinstance(original_timestamp, str):
        timestamp = original_timestamp

        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"

        dt = datetime.fromisoformat(timestamp)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        result["timestamp_raw"] = iso_utc(dt)

    elif isinstance(original_timestamp, (int, float)):
        result["timestamp_raw"] = iso_utc(
            datetime.fromtimestamp(
                original_timestamp,
                tz=timezone.utc,
            )
        )
    else:
        raise ValueError("unsupported telemetry timestamp")

    result.pop("timestamp", None)

    result["source_origin"] = result.get(
        "source_origin",
        "student_telemetry",
    )

    if "hostname" not in result:
        result["hostname"] = None

    if "raw_message" not in result:
        result["raw_message"] = json.dumps(
            record,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    if "parsed_fields" not in result:
        parsed_fields = {}

        for key, value in record.items():
            if key not in {
                "timestamp",
                "timestamp_raw",
                "hostname",
                "raw_message",
                "parsed_fields",
                "source_origin",
            }:
                parsed_fields[key] = value

        result["parsed_fields"] = parsed_fields

    return result

auth_path = linux_dir / "auth.log"
audit_path = linux_dir / "audit.log"
syslog_path = linux_dir / "syslog"

year = infer_year(audit_path)

with output_file.open("w", encoding="utf-8") as output:
    auth_lines = 0

    with auth_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            auth_lines += 1

            output.write(
                json.dumps(
                    parse_syslog_line(line, year),
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )

    print(
        f"parsing auth.log      ... {auth_lines:5d} lines"
        f"  -> {auth_lines:5d} records"
    )

    with audit_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        audit_lines = sum(1 for _ in handle)

    audit_records = 0

    for group in audit_groups(audit_path):
        output.write(
            json.dumps(
                parse_audit_group(group),
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        )
        audit_records += 1

    print(
        f"parsing audit.log     ... {audit_lines:5d} lines"
        f"  -> {audit_records:5d} records (grouped)"
    )

    syslog_lines = 0

    with syslog_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            syslog_lines += 1

            output.write(
                json.dumps(
                    parse_syslog_line(line, year),
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )

    print(
        f"parsing syslog        ... {syslog_lines:5d} lines"
        f"  -> {syslog_lines:5d} records"
    )

    telemetry_records = 0

    with telemetry_file.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
                normalized = normalize_telemetry(record)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(
                    f"invalid student telemetry record at line "
                    f"{line_number}: {exc}"
                ) from exc

            output.write(
                json.dumps(
                    normalized,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )
            telemetry_records += 1

    print(
        f"appending student telemetry ... "
        f"{telemetry_records:5d} records"
    )

with output_file.open(
    "r",
    encoding="utf-8",
) as handle:
    total = 0

    for line_number, line in enumerate(handle, 1):
        if not line.strip():
            raise ValueError(
                f"blank output line at {line_number}"
            )

        record = json.loads(line)

        if not isinstance(record, dict):
            raise ValueError(
                f"line {line_number} is not a JSON object"
            )

        required = (
            "timestamp_raw",
            "hostname",
            "raw_message",
            "parsed_fields",
            "source_origin",
        )

        missing = [
            key for key in required
            if key not in record
        ]

        if missing:
            raise ValueError(
                f"line {line_number} missing fields: "
                + ", ".join(missing)
            )

        timestamp = record["timestamp_raw"]

        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T"
            r"\d{2}:\d{2}:\d{2}Z",
            timestamp,
        ):
            raise ValueError(
                f"line {line_number} has invalid UTC "
                f"timestamp: {timestamp}"
            )

        total += 1

print(f"linux_events.json: written ({total} records)")
PY

mv -- "$TEMP_OUTPUT" "$OUTPUT"
trap - EXIT
