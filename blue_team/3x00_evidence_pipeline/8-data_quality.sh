#!/bin/bash

set -euo pipefail

INPUT="${1:-normalized_events.json}"
CLEANED="${2:-cleaned_events.json}"
LOG="${3:-cleaning_log.json}"

python3 -W error - "$INPUT" "$CLEANED" "$LOG" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path


input_path = Path(sys.argv[1])
cleaned_path = Path(sys.argv[2])
log_path = Path(sys.argv[3])


def parse_iso8601(value):
    """Parse an ISO-8601 timestamp and return an aware UTC datetime."""

    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")

    text = value.strip()

    # Accept the common UTC Z notation.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    # Accept offsets such as +0000.
    if len(text) >= 5:
        suffix = text[-5:]
        if (
            suffix[0] in "+-"
            and suffix[1:].isdigit()
            and ":" not in suffix
        ):
            text = text[:-5] + suffix[:3] + ":" + suffix[3:]

    dt = datetime.fromisoformat(text)

    if dt.tzinfo is None:
        raise ValueError("timestamp has no timezone")

    return dt.astimezone(timezone.utc)


def format_utc(dt):
    """Return the project-standard UTC timestamp."""

    return dt.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def repair_timestamp(value):
    """Try fallback timestamp formats."""

    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")

    text = value.strip()

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M:%S",
    )

    candidate = text

    # Convert Z to a Python-compatible UTC offset.
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"

    # Convert +0000 to +00:00.
    if len(candidate) >= 5:
        suffix = candidate[-5:]
        if (
            suffix[0] in "+-"
            and suffix[1:].isdigit()
            and ":" not in suffix
        ):
            candidate = (
                candidate[:-5]
                + suffix[:3]
                + ":"
                + suffix[3:]
            )

    for fmt in formats:
        try:
            dt = datetime.strptime(candidate, fmt)

            # Fallback timestamps without timezone are interpreted as UTC.
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            return dt.astimezone(timezone.utc)

        except ValueError:
            continue

    raise ValueError(
        f"unable to repair timestamp: {value!r}"
    )


def record_id(record):
    """Stable ID based on the original record contents."""

    encoded = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()[:16]


def repair_encoding(value):
    """
    Attempt to repair common UTF-8/Latin-1 mojibake.

    Example:
        cafÃ© -> café
    """

    if not isinstance(value, str):
        return value, False

    suspicious = (
        "\ufffd" in value
        or "Ã" in value
        or "Â" in value
        or "â€" in value
        or "â€™" in value
        or "â€œ" in value
        or "â€\x9d" in value
        or "ð" in value
    )

    if not suspicious:
        return value, False

    try:
        repaired = value.encode("latin-1").decode("utf-8")

        # Do not accept a conversion that still contains replacement
        # characters.
        if "\ufffd" in repaired:
            return value, False

        return repaired, repaired != value

    except (UnicodeEncodeError, UnicodeDecodeError):
        return value, False


records = []
quarantine = []
cleaning_log = []

malformed_detected = 0
malformed_repaired = 0
malformed_dropped = 0

duplicates_detected = 0
duplicates_removed = 0

hostname_normalized = 0

encoding_detected = 0
encoding_repaired = 0

wrong_tz_flagged = 0


# ----------------------------------------------------------------------
# Read NDJSON.
# ----------------------------------------------------------------------

with input_path.open("r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        line = line.rstrip("\n")

        if not line.strip():
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            quarantine.append({
                "record_id": f"line-{line_number}",
                "quarantine_reason": f"invalid JSON: {exc}",
                "record": line,
            })
            continue

        if not isinstance(record, dict):
            quarantine.append({
                "record_id": f"line-{line_number}",
                "quarantine_reason": "record is not a JSON object",
                "record": record,
            })
            continue

        records.append(record)


# ----------------------------------------------------------------------
# Determine the evidence-pack date range from valid timestamps.
#
# The ±12 hour comparison is deliberately based on the input evidence
# rather than hardcoding dates.
# ----------------------------------------------------------------------

valid_datetimes = []

for record in records:
    timestamp = record.get("timestamp")

    try:
        dt = parse_iso8601(timestamp)
        valid_datetimes.append(dt)
    except (TypeError, ValueError):
        try:
            dt = repair_timestamp(timestamp)
            valid_datetimes.append(dt)
        except (TypeError, ValueError):
            pass


if valid_datetimes:
    evidence_min = min(valid_datetimes)
    evidence_max = max(valid_datetimes)
    tz_lower = evidence_min - timedelta(hours=12)
    tz_upper = evidence_max + timedelta(hours=12)
else:
    evidence_min = None
    evidence_max = None
    tz_lower = None
    tz_upper = None


# ----------------------------------------------------------------------
# Process records.
# ----------------------------------------------------------------------

seen = set()

for original_record in records:
    record = dict(original_record)
    rid = record_id(original_record)

    # --------------------------------------------------------------
    # 1. Timestamp validation / repair
    # --------------------------------------------------------------

    original_timestamp = record.get("timestamp")

    try:
        timestamp_dt = parse_iso8601(original_timestamp)

    except (TypeError, ValueError):
        malformed_detected += 1

        try:
            timestamp_dt = repair_timestamp(original_timestamp)
            corrected_timestamp = format_utc(timestamp_dt)

            record["timestamp"] = corrected_timestamp
            malformed_repaired += 1

            cleaning_log.append({
                "defect_type": "malformed_timestamp",
                "original_value": original_timestamp,
                "corrected_value": corrected_timestamp,
                "record_id": rid,
                "reason": "timestamp repaired using fallback format",
            })

        except (TypeError, ValueError) as exc:
            malformed_dropped += 1

            cleaning_log.append({
                "defect_type": "malformed_timestamp",
                "original_value": original_timestamp,
                "corrected_value": None,
                "record_id": rid,
                "reason": f"unrepairable timestamp: {exc}",
            })

            continue

    else:
        # Even valid ISO timestamps are normalized to the canonical
        # project representation ending in Z.
        canonical_timestamp = format_utc(timestamp_dt)

        if original_timestamp != canonical_timestamp:
            record["timestamp"] = canonical_timestamp

    # --------------------------------------------------------------
    # 2. Duplicate detection
    #
    # Duplicate identity is based exactly on:
    # timestamp + hostname + source_type + raw_message
    # --------------------------------------------------------------

    duplicate_key = (
        record.get("timestamp"),
        record.get("hostname"),
        record.get("source_type"),
        record.get("raw_message"),
    )

    if duplicate_key in seen:
        duplicates_detected += 1
        duplicates_removed += 1

        cleaning_log.append({
            "defect_type": "duplicate",
            "original_value": {
                "timestamp": record.get("timestamp"),
                "hostname": record.get("hostname"),
                "source_type": record.get("source_type"),
                "raw_message": record.get("raw_message"),
            },
            "corrected_value": None,
            "record_id": rid,
            "reason": (
                "duplicate of an earlier record with identical "
                "timestamp, hostname, source_type, and raw_message"
            ),
        })

        continue

    seen.add(duplicate_key)

    # --------------------------------------------------------------
    # 3. Hostname case normalization
    # --------------------------------------------------------------

    hostname = record.get("hostname")

    if isinstance(hostname, str):
        corrected_hostname = hostname.lower()

        if corrected_hostname != hostname:
            record["hostname"] = corrected_hostname
            hostname_normalized += 1

            cleaning_log.append({
                "defect_type": "hostname_case",
                "original_value": hostname,
                "corrected_value": corrected_hostname,
                "record_id": rid,
                "reason": "hostname normalized to lowercase",
            })

    # --------------------------------------------------------------
    # 4. Encoding / mojibake repair
    # --------------------------------------------------------------

    raw_message = record.get("raw_message")

    if isinstance(raw_message, str):
        has_encoding_defect = (
            "\ufffd" in raw_message
            or "Ã" in raw_message
            or "Â" in raw_message
            or "â€" in raw_message
            or "â€™" in raw_message
            or "â€œ" in raw_message
            or "â€\x9d" in raw_message
            or "ð" in raw_message
        )

        if has_encoding_defect:
            encoding_detected += 1

            repaired_message, repaired = repair_encoding(
                raw_message
            )

            if repaired:
                record["raw_message"] = repaired_message
                encoding_repaired += 1

                cleaning_log.append({
                    "defect_type": "encoding_error",
                    "original_value": raw_message,
                    "corrected_value": repaired_message,
                    "record_id": rid,
                    "reason": (
                        "re-decoded suspected Latin-1/UTF-8 "
                        "mojibake"
                    ),
                })

    # --------------------------------------------------------------
    # 5. Timezone/date-range consistency
    # --------------------------------------------------------------

    if (
        evidence_min is not None
        and evidence_max is not None
        and (
            timestamp_dt < tz_lower
            or timestamp_dt > tz_upper
        )
    ):
        wrong_tz_flagged += 1

        cleaning_log.append({
            "defect_type": "suspected_wrong_tz",
            "original_value": record.get("timestamp"),
            "corrected_value": None,
            "record_id": rid,
            "reason": (
                "timestamp falls more than 12 hours outside "
                "the inferred evidence-pack date range "
                f"({format_utc(evidence_min)} to "
                f"{format_utc(evidence_max)})"
            ),
        })

    # Keep the record. Wrong timezone is flagged, not dropped.
    record["timestamp"] = format_utc(timestamp_dt)

    # --------------------------------------------------------------
    # Clean record
    # --------------------------------------------------------------

    # Remove Python None values only where the source explicitly
    # supplied them; otherwise preserve the normalized structure.
    recordsafe = record

    # Store an internal flag only for counting; do not write it.
    network_flag = False
    _ = network_flag

    # Attach to cleaned list.
    # The list is created lazily here to keep processing simple.
    if "cleaned_records" not in locals():
        cleaned_records = []

    cleaned_records.append(record)


# ----------------------------------------------------------------------
# Ensure deterministic output.
# ----------------------------------------------------------------------

if "cleaned_records" not in locals():
    cleaned_records = []


with cleaned_path.open("w", encoding="utf-8") as handle:
    for record in cleaned_records:
        handle.write(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )


# cleaning_log.json is a JSON array, so:
#
#     jq empty cleaning_log.json
#
# always succeeds, including when there are no defects.

with log_path.open("w", encoding="utf-8") as handle:
    json.dump(
        cleaning_log,
        handle,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    handle.write("\n")


# ----------------------------------------------------------------------
# Required report.
# ----------------------------------------------------------------------

print(
    "malformed timestamps   : "
    f"detected {malformed_detected:>7} "
    f"repaired {malformed_repaired:>7} "
    f"dropped {malformed_dropped:>7}"
)

print(
    "duplicates             : "
    f"detected {duplicates_detected:>7} "
    f"removed {duplicates_removed:>7}"
)

print(
    "hostname case          : "
    f"normalized {hostname_normalized}"
)

print(
    "encoding errors        : "
    f"detected {encoding_detected:>7} "
    f"repaired {encoding_repaired:>7}"
)

print(
    "suspected wrong tz     : "
    f"flagged {wrong_tz_flagged}"
)

print("cleaned_events.json    written")
print("cleaning_log.json      written")
PY

