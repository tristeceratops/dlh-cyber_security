#!/bin/bash
set -euo pipefail

WINDOWS_FILE="windows_events.json"
LINUX_FILE="linux_events.json"
SCHEMA_FILE="event_schema.json"

NORMALIZED_FILE="normalized_events.json"
QUARANTINE_FILE="quarantine.json"

for file in "$WINDOWS_FILE" "$LINUX_FILE" "$SCHEMA_FILE"; do
    if [[ ! -f "$file" ]]; then
        echo "error: missing $file" >&2
        exit 1
    fi
done

python3 <<'PY'
import json
from datetime import datetime, timezone


WINDOWS_FILE = "windows_events.json"
LINUX_FILE = "linux_events.json"
SCHEMA_FILE = "event_schema.json"

NORMALIZED_FILE = "normalized_events.json"
QUARANTINE_FILE = "quarantine.json"


# ------------------------------------------------------------
# Load schema
# ------------------------------------------------------------

with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
    schema = json.load(f)

fields = schema["fields"]

schema_required = {
    field["name"]
    for field in fields
    if field["required"]
}


# ------------------------------------------------------------
# Timestamp
# ------------------------------------------------------------

def normalize_timestamp(value):
    if value is None:
        raise ValueError("missing timestamp_raw")

    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(
            value,
            tz=timezone.utc
        )
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    value = str(value).strip()

    # ISO 8601 with Z
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    # ISO 8601 timezone such as +0000
    if len(value) >= 5:
        suffix = value[-5:]
        if (
            suffix[0] in "+-"
            and suffix[1:].isdigit()
            and ":" not in suffix
        ):
            value = value[:-2] + ":" + value[-2:]

    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"unparseable timestamp_raw: {value}"
        ) from exc

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def event_data(record):
    value = record.get("event_data")
    return value if isinstance(value, dict) else {}


def parsed_fields(record):
    value = record.get("parsed_fields")
    return value if isinstance(value, dict) else {}


def get_windows_user(record):
    data = event_data(record)

    return (
        data.get("User")
        or data.get("TargetUserName")
        or data.get("SubjectUserName")
    )


def get_linux_user(record):
    data = parsed_fields(record)

    # The 3.sh parser may already have promoted a user.
    if record.get("user") not in (None, "", "0)"):
        return record["user"]

    # Explicit parsed fields.
    for key in ("acct", "user", "USER"):
        if data.get(key):
            value = data[key]

            if value not in (
                "0",
                "0)",
                "4294967295",
            ):
                return value

    # auth.log messages sometimes contain:
    # "for user username"
    message = data.get("message", "")

    marker = "for user "
    if marker in message:
        value = message.split(marker, 1)[1]
        value = value.split()[0]
        value = value.rstrip(".,;:)")

        if value:
            return value

    # sudo messages:
    # "a.thompson : TTY=..."
    if record.get("program") == "sudo":
        if ":" in message:
            value = message.split(":", 1)[0].strip()
            if value:
                return value

    return None


def get_windows_process(record):
    data = event_data(record)

    value = data.get("Image")

    if value:
        # Keep the process name rather than the complete Windows path.
        return value.replace("\\", "/").rsplit("/", 1)[-1]

    return None


def get_linux_process(record):
    data = parsed_fields(record)

    value = data.get("comm")

    if value:
        return str(value).strip('"')

    return record.get("program")


def get_windows_src_ip(record):
    data = event_data(record)

    return (
        data.get("SourceIp")
        or data.get("IpAddress")
    )


def get_windows_dst_ip(record):
    data = event_data(record)

    return data.get("DestinationIp")


def get_linux_src_ip(record):
    data = parsed_fields(record)

    return (
        data.get("addr")
        or data.get("SRC")
        or data.get("src_ip")
    )


def get_linux_dst_ip(record):
    data = parsed_fields(record)

    return (
        data.get("DST")
        or data.get("dst_ip")
    )


def integer_or_none(value):
    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------
# Derived fields
# ------------------------------------------------------------

def windows_category(record):
    event_id = record.get("event_id")
    channel = record.get("channel", "")

    if channel == "Security":
        if event_id in (4624, 4625, 4634, 4647):
            return "authentication"

        if event_id == 4672:
            return "privilege"

        return "security"

    if "PowerShell" in channel:
        return "powershell"

    if "Sysmon" in channel:
        if event_id == 1:
            return "process"
        if event_id == 3:
            return "network"
        return "sysmon"

    return "windows"


def linux_category(record):
    program = record.get("program")
    data = parsed_fields(record)

    audit_type = data.get("audit_type")

    if audit_type:
        if str(audit_type).startswith("USER_"):
            return "authentication"

        if audit_type in (
            "SYSCALL",
            "EXECVE",
        ):
            return "process"

        return "audit"

    if program in (
        "sudo",
        "su",
        "login",
        "sshd",
        "polkitd",
        "systemd-logind",
    ):
        return "authentication"

    if program in (
        "CRON",
        "cron",
    ):
        return "process"

    return "linux"


def derive_severity(source_type, record):
    """
    The schema requires severity, but Windows/Linux have no native
    severity field in the supplied normalized inputs.

    Therefore assign a deterministic default rather than quarantining.
    """

    # Network severity is handled if network records are ever added.
    if source_type == "network":
        alert = record.get("alert", {})
        if isinstance(alert, dict) and alert.get("severity") is not None:
            return integer_or_none(alert["severity"])

    # Informational default for sources without native severity.
    return 0


# ------------------------------------------------------------
# Windows normalization
# ------------------------------------------------------------

def normalize_windows(record):

    normalized = {
        "timestamp": normalize_timestamp(
            record.get("timestamp_raw")
        ),

        "hostname": record.get("hostname"),

        "source_type": "windows_json",

        "event_category": windows_category(record),

        "severity": derive_severity(
            "windows_json",
            record
        ),

        "user": get_windows_user(record),

        "process_name": get_windows_process(record),

        "src_ip": get_windows_src_ip(record),

        "dst_ip": get_windows_dst_ip(record),

        "raw_message": record.get("raw_message"),

        "src_port": integer_or_none(
            event_data(record).get("SourcePort")
            or event_data(record).get("IpPort")
        ),

        "dst_port": integer_or_none(
            event_data(record).get("DestinationPort")
        ),
    }

    validate_required(normalized)

    return normalized


# ------------------------------------------------------------
# Linux normalization
# ------------------------------------------------------------

def normalize_linux(record):

    data = parsed_fields(record)

    normalized = {
        "timestamp": normalize_timestamp(
            record.get("timestamp_raw")
        ),

        "hostname": record.get("hostname"),

        "source_type": "linux_text",

        "event_category": linux_category(record),

        "severity": derive_severity(
            "linux_text",
            record
        ),

        "user": get_linux_user(record),

        "process_name": get_linux_process(record),

        "src_ip": get_linux_src_ip(record),

        "dst_ip": get_linux_dst_ip(record),

        "raw_message": record.get("raw_message"),

        "src_port": integer_or_none(
            data.get("SPT")
        ),

        "dst_port": integer_or_none(
            data.get("DPT")
        ),
    }

    validate_required(normalized)

    return normalized


# ------------------------------------------------------------
# Required-field validation
# ------------------------------------------------------------

def validate_required(record):

    missing = []

    for field in schema_required:

        if field not in record:
            missing.append(field)
            continue

        if record[field] is None:
            missing.append(field)

        elif isinstance(record[field], str) and not record[field].strip():
            missing.append(field)

    if missing:
        raise ValueError(
            "missing required fields: "
            + ", ".join(sorted(missing))
        )


# ------------------------------------------------------------
# File processing
# ------------------------------------------------------------

counts = {
    "windows_json": {
        "normalized": 0,
        "quarantined": 0,
    },
    "linux_text": {
        "normalized": 0,
        "quarantined": 0,
    },
}


def process_file(
    filename,
    source_type,
    normalize_function,
    normalized_output,
    quarantine_output,
):

    with open(
        filename,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as handle:

        for line_number, line in enumerate(handle, 1):

            line = line.strip()

            if not line:
                continue

            record = None

            try:
                record = json.loads(line)

                if not isinstance(record, dict):
                    raise ValueError(
                        "record is not a JSON object"
                    )

                normalized = normalize_function(record)

                normalized_output.write(
                    json.dumps(
                        normalized,
                        separators=(",", ":"),
                        ensure_ascii=False
                    ) + "\n"
                )

                counts[source_type]["normalized"] += 1

            except Exception as exc:

                quarantine_record = {
                    "source_type": source_type,
                    "quarantine_reason": str(exc),
                    "record": (
                        record
                        if record is not None
                        else line
                    ),
                }

                quarantine_output.write(
                    json.dumps(
                        quarantine_record,
                        separators=(",", ":"),
                        ensure_ascii=False
                    ) + "\n"
                )

                counts[source_type]["quarantined"] += 1


# ------------------------------------------------------------
# Run
# ------------------------------------------------------------

with open(
    NORMALIZED_FILE,
    "w",
    encoding="utf-8"
) as normalized_output, open(
    QUARANTINE_FILE,
    "w",
    encoding="utf-8"
) as quarantine_output:

    process_file(
        WINDOWS_FILE,
        "windows_json",
        normalize_windows,
        normalized_output,
        quarantine_output,
    )

    process_file(
        LINUX_FILE,
        "linux_text",
        normalize_linux,
        normalized_output,
        quarantine_output,
    )


# ------------------------------------------------------------
# Counts
# ------------------------------------------------------------

windows = counts["windows_json"]
linux = counts["linux_text"]

total_normalized = (
    windows["normalized"]
    + linux["normalized"]
)

total_quarantined = (
    windows["quarantined"]
    + linux["quarantined"]
)

print(
    f"windows_json     : normalized {windows['normalized']:5d}"
    f" quarantined {windows['quarantined']:5d}"
)

print(
    f"linux_text       : normalized {linux['normalized']:5d}"
    f" quarantined {linux['quarantined']:5d}"
)

print(
    f"total            : normalized {total_normalized:5d}"
    f" quarantined {total_quarantined:5d}"
)

print("normalized_events.json written")
print("quarantine.json  written")
PY

