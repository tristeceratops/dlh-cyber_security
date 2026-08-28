#!/bin/bash

set -euo pipefail

DIR="$HOME/evidence_pack_primary"
FOLDERS=("windows" "linux" "network")

total_file=0
total_size=0

JSON_PATH="source_inventory.json"


# ------------------------------------------------------------
# Find an evidence year from actual event timestamps.
# Used only for syslog/auth.log, whose native format has no year.
# ------------------------------------------------------------

get_evidence_year() {

    local year=""

    year=$(
        jq -R -r '
            fromjson?
            | select(type == "object")
            | .timestamp_raw?
            | select(type == "string")
        ' "$DIR"/windows/*.json 2>/dev/null |
        sed -n 's/^\([0-9]\{4\}\)-.*/\1/p' |
        head -n 1
    ) || true

    if [[ -z "$year" ]]; then
        year=$(
            jq -R -r '
                fromjson?
                | select(type == "object")
                | .timestamp?
                | select(type == "string")
            ' "$DIR"/network/suricata_eve.json 2>/dev/null |
            sed -n 's/^\([0-9]\{4\}\)-.*/\1/p' |
            head -n 1
        ) || true
    fi

    if [[ -z "$year" ]]; then
        year=$(
            jq -R -r '
                fromjson?
                | select(type == "object")
                | .start_time?
                | select(type == "string")
            ' "$DIR"/network/pcap_summary.json 2>/dev/null |
            sed -n 's|.*/\([0-9]\{4\}\).*|\1|p' |
            head -n 1
        ) || true
    fi

    printf '%s\n' "$year"
}


EVIDENCE_YEAR="$(get_evidence_year)"


# ------------------------------------------------------------
# Convert ISO-8601 timestamp to epoch.
# Supports Z, offsets and fractional seconds.
# ------------------------------------------------------------

iso_to_epoch() {

    local timestamp="$1"

    python3 - "$timestamp" <<'PY'
import sys
from datetime import datetime, timezone

value = sys.argv[1]

try:
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)

    if dt.tzinfo is None:
        raise ValueError

    print(dt.timestamp())
except (ValueError, OverflowError):
    sys.exit(1)
PY
}


# ------------------------------------------------------------
# Convert epoch to ISO-8601 UTC.
# ------------------------------------------------------------

epoch_to_iso() {

    local timestamp="$1"

    python3 - "$timestamp" <<'PY'
import sys
from datetime import datetime, timezone

try:
    value = float(sys.argv[1])
    print(
        datetime.fromtimestamp(
            value,
            timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
except (ValueError, OverflowError, OSError):
    sys.exit(1)
PY
}


get_first_last_timestamp() {

    local file="$1"
    local first=""
    local last=""

    # --------------------------------------------------------
    # Windows JSONL:
    # timestamp_raw = 2026-03-18T00:05:19Z
    # --------------------------------------------------------

    if [[ "$file" == */windows/*.json ]]; then

        IFS='|' read -r first last < <(
            jq -R -r '
                fromjson?
                | select(type == "object")
                | .timestamp_raw?
                | select(type == "string")
            ' "$file" |
            while IFS= read -r timestamp
            do
                if epoch=$(iso_to_epoch "$timestamp" 2>/dev/null); then
                    printf '%s|%s\n' "$epoch" "$timestamp"
                fi
            done |
            awk -F'|' '
                NR == 1 {
                    min = $1
                    max = $1
                    first = $2
                    last = $2
                    next
                }

                $1 < min {
                    min = $1
                    first = $2
                }

                $1 > max {
                    max = $1
                    last = $2
                }

                END {
                    if (NR > 0)
                        printf "%s|%s\n", first, last
                }
            '
        )

    # --------------------------------------------------------
    # Suricata JSONL:
    # timestamp = 2026-03-18T00:00:31.026524+0000
    # --------------------------------------------------------

    elif [[ "$file" == */network/suricata_eve.json ]]; then

        IFS='|' read -r first last < <(
            jq -R -r '
                fromjson?
                | select(type == "object")
                | .timestamp?
                | select(type == "string")
            ' "$file" |
            while IFS= read -r timestamp
            do
                if epoch=$(iso_to_epoch "$timestamp" 2>/dev/null); then
                    printf '%s|%s\n' "$epoch" "$timestamp"
                fi
            done |
            awk -F'|' '
                NR == 1 {
                    min = $1
                    max = $1
                    first = $2
                    last = $2
                    next
                }

                $1 < min {
                    min = $1
                    first = $2
                }

                $1 > max {
                    max = $1
                    last = $2
                }

                END {
                    if (NR > 0)
                        printf "%s|%s\n", first, last
                }
            '
        )

    # --------------------------------------------------------
    # PCAP summary JSONL:
    # start_time/end_time = 03/20/2026 11:16:56 PM
    # --------------------------------------------------------

    elif [[ "$file" == */network/pcap_summary.json ]]; then

        IFS='|' read -r first last < <(
            jq -R -r '
                fromjson?
                | select(type == "object")
                | select(
                    (.start_time? | type) == "string"
                    and
                    (.end_time? | type) == "string"
                )
                | [.start_time, .end_time]
                | @tsv
            ' "$file" |
            while IFS=$'\t' read -r start_time end_time
            do
                if start_epoch=$(date -d "$start_time" +%s 2>/dev/null) &&
                   end_epoch=$(date -d "$end_time" +%s 2>/dev/null)
                then
                    printf '%s|%s\n' "$start_epoch" "$end_epoch"
                fi
            done |
            awk -F'|' '
                NR == 1 {
                    min = $1
                    max = $2
                    next
                }

                $1 < min {
                    min = $1
                }

                $2 > max {
                    max = $2
                }

                END {
                    if (NR > 0)
                        printf "%.0f|%.0f\n", min, max
                }
            ' |
            while IFS='|' read -r first_epoch last_epoch
            do
                if first=$(epoch_to_iso "$first_epoch" 2>/dev/null) &&
                   last=$(epoch_to_iso "$last_epoch" 2>/dev/null)
                then
                    printf '%s|%s\n' "$first" "$last"
                fi
            done
        )

    # --------------------------------------------------------
    # Firewall CSV:
    # timestamp = 1773792002
    # --------------------------------------------------------

    elif [[ "$file" == */network/*.csv ]]; then

        IFS='|' read -r first last < <(
            awk -F',' '
                NR > 1 && $1 ~ /^[0-9]+(\.[0-9]+)?$/ {
                    if (!found) {
                        min = $1
                        max = $1
                        found = 1
                        next
                    }

                    if ($1 < min)
                        min = $1

                    if ($1 > max)
                        max = $1
                }

                END {
                    if (found)
                        printf "%.0f|%.0f\n", min, max
                }
            ' "$file" |
            while IFS='|' read -r first_epoch last_epoch
            do
                if first=$(epoch_to_iso "$first_epoch" 2>/dev/null) &&
                   last=$(epoch_to_iso "$last_epoch" 2>/dev/null)
                then
                    printf '%s|%s\n' "$first" "$last"
                fi
            done
        )

    # --------------------------------------------------------
    # Linux audit.log:
    # audit(1774442959.133:10)
    # --------------------------------------------------------

    elif [[ "$file" == */linux/audit.log ]]; then

        IFS='|' read -r first last < <(
            awk '
                match($0, /audit\(([0-9]+(\.[0-9]+)?):/, m) {

                    timestamp = m[1] + 0

                    if (!found) {
                        min = timestamp
                        max = timestamp
                        found = 1
                        next
                    }

                    if (timestamp < min)
                        min = timestamp

                    if (timestamp > max)
                        max = timestamp
                }

                END {
                    if (found)
                        printf "%.3f|%.3f\n", min, max
                }
            ' "$file" |
            while IFS='|' read -r first_epoch last_epoch
            do
                if first=$(epoch_to_iso "$first_epoch" 2>/dev/null) &&
                   last=$(epoch_to_iso "$last_epoch" 2>/dev/null)
                then
                    printf '%s|%s\n' "$first" "$last"
                fi
            done
        )

    # --------------------------------------------------------
    # Linux syslog/auth.log:
    # Mar 18 00:00:38 hostname process[pid]: ...
    #
    # The native timestamp has no year.
    # EVIDENCE_YEAR is taken from another artifact's event data.
    # If no evidence-derived year is available, timestamps remain null.
    # --------------------------------------------------------

    elif [[ "$file" == */linux/*.log ||
            "$file" == */linux/syslog ]]; then

        if [[ -n "$EVIDENCE_YEAR" ]]; then

            IFS='|' read -r first last < <(
                awk -v year="$EVIDENCE_YEAR" '
                    function month_number(month) {
                        months["Jan"] = "01"
                        months["Feb"] = "02"
                        months["Mar"] = "03"
                        months["Apr"] = "04"
                        months["May"] = "05"
                        months["Jun"] = "06"
                        months["Jul"] = "07"
                        months["Aug"] = "08"
                        months["Sep"] = "09"
                        months["Oct"] = "10"
                        months["Nov"] = "11"
                        months["Dec"] = "12"

                        return months[month]
                    }

                    /^[A-Z][a-z][a-z] [0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2} / {

                        month = month_number($1)

                        if (month == "")
                            next

                        day = sprintf("%02d", $2)

                        split($3, time, ":")

                        if (time[1] !~ /^[0-9]+$/ ||
                            time[2] !~ /^[0-9]+$/ ||
                            time[3] !~ /^[0-9]+$/)
                            next

                        if (time[1] > 23 ||
                            time[2] > 59 ||
                            time[3] > 59)
                            next

                        timestamp = year month day \
                                   sprintf("%02d", time[1]) \
                                   sprintf("%02d", time[2]) \
                                   sprintf("%02d", time[3])

                        if (!found) {
                            min = timestamp
                            max = timestamp
                            found = 1
                        }
                        else {
                            if (timestamp < min)
                                min = timestamp

                            if (timestamp > max)
                                max = timestamp
                        }
                    }

                    END {
                        if (found)
                            printf "%s|%s\n", min, max
                    }
                ' "$file"
            )

            if [[ -n "$first" ]]; then
                first="${first:0:4}-${first:4:2}-${first:6:2}T${first:8:2}:${first:10:2}:${first:12:2}Z"
            fi

            if [[ -n "$last" ]]; then
                last="${last:0:4}-${last:4:2}-${last:6:2}T${last:8:2}:${last:10:2}:${last:12:2}Z"
            fi
        fi
    fi

    printf '%s|%s\n' "$first" "$last"
}


get_record_count() {

    local file="$1"

    if [[ "$file" == *.json ]]; then

        jq -R -c '
            fromjson?
            | select(type == "object")
        ' "$file" |
        wc -l

    else

        wc -l < "$file"
    fi
}


printf '[\n' > "$JSON_PATH"
first_record=1


for folder in "${FOLDERS[@]}"
do

    mapfile -t files < <(
        find "$DIR/$folder" -maxdepth 1 -type f
    )

    for file in "${files[@]}"
    do
        relative_path=${file#"$DIR"/}

        sourcetype="$folder"

        if [[ $file == *.json ]]; then
            sourcetype="${sourcetype}_json"
        elif [[ $file == *.csv ]]; then
            sourcetype="${sourcetype}_csv"
        else
            sourcetype="${sourcetype}_text"
        fi

        size_bytes="$(stat -c %s "$file")"

        shahash="$(shasum -a 256 "$file" | awk '{print $1}')"

        record_count="$(get_record_count "$file")"

        if [[ $file == *.json ]]; then
            count_field="record_count"
        else
            count_field="line_count"
        fi

        IFS='|' read -r first_timestamp last_timestamp \
            < <(get_first_last_timestamp "$file")

        if [[ "$first_record" -eq 0 ]]; then
            printf ',\n' >> "$JSON_PATH"
        fi

        first_record=0

        jq -n \
            --arg path "$relative_path" \
            --arg source_type "$sourcetype" \
            --argjson size_bytes "$size_bytes" \
            --arg sha256 "$shahash" \
            --arg count_field "$count_field" \
            --argjson count "$record_count" \
            --arg first_event_time "$first_timestamp" \
            --arg last_event_time "$last_timestamp" \
            '{
                path: $path,
                source_type: $source_type,
                size_bytes: $size_bytes,
                sha256: $sha256
            }
            + {($count_field): $count}
            + {
                first_event_time:
                    (if $first_event_time == ""
                     then null
                     else $first_event_time
                     end),
                last_event_time:
                    (if $last_event_time == ""
                     then null
                     else $last_event_time
                     end)
            }' \
            >> "$JSON_PATH"
    done

    count=$(find "$DIR/$folder" -maxdepth 1 -type f | wc -l)

    size=$(find "$DIR/$folder" -maxdepth 1 -type f -printf '%s\n' |
        awk '{sum += $1} END {print sum + 0}')

    total_size=$((total_size + size))
    total_file=$((total_file + count))

    size=$(numfmt --to=iec --format="%.1f" --suffix=B "$size")

    printf "%-7s : %d files  |  %6s\n" \
        "$folder" "$count" "$size"
done


printf '\n]\n' >> "$JSON_PATH"


total_size=$(numfmt --to=iec --format="%.1f" --suffix=B "$total_size")

printf "%-7s : %d files  |  %6s\n" \
    "total" "$total_file" "$total_size"

printf 'manifest written to %s\n' "$JSON_PATH"

