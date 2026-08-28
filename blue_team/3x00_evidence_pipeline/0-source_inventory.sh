#!/bin/bash

set -euo pipefail

DIR="$HOME/evidence_pack_primary"
FOLDERS=("windows" "linux" "network")

total_file=0
total_size=0

JSON_PATH="source_inventory.json"

get_first_last_timestamp() {

    local file="$1"
    local first=""
    local last=""

    # Windows JSONL: timestamp_raw = 2026-03-18T00:05:19Z
    if [[ "$file" == */windows/*.json ]]; then

        IFS='|' read -r first last < <(
            jq -r '.timestamp_raw // empty' "$file" |
            awk '
                NR == 1 {
                    min = $0
                    max = $0
                    next
                }

                $0 < min {
                    min = $0
                }

                $0 > max {
                    max = $0
                }

                END {
                    if (NR > 0)
                        printf "%s|%s\n", min, max
                }
            '
        )

    # Suricata JSONL: timestamp = 2026-03-18T00:00:31.026524+0000
    elif [[ "$file" == */network/suricata_eve.json ]]; then

        IFS='|' read -r first last < <(
            jq -r '.timestamp // empty' "$file" |
            awk '
                NR == 1 {
                    min = $0
                    max = $0
                    next
                }

                $0 < min {
                    min = $0
                }

                $0 > max {
                    max = $0
                }

                END {
                    if (NR > 0)
                        printf "%s|%s\n", min, max
                }
            '
        )

    # PCAP summary JSONL:
    # start_time/end_time = 03/20/2026 11:16:56 PM
    elif [[ "$file" == */network/pcap_summary.json ]]; then

        IFS='|' read -r first last < <(
            jq -r 'select(.start_time != null) |
                   [.start_time, .end_time] |
                   @tsv' "$file" |
            while IFS=$'\t' read -r start_time end_time
            do
                start_epoch=$(date -d "$start_time" +%s)
                end_epoch=$(date -d "$end_time" +%s)

                printf '%s|%s\n' "$start_epoch" "$end_epoch"
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
                        printf "%s|%s\n", min, max
                }
            ' |
            awk -F'|' '
                {
                    first = strftime("%Y-%m-%dT%H:%M:%SZ", $1, 1)
                    last  = strftime("%Y-%m-%dT%H:%M:%SZ", $2, 1)

                    printf "%s|%s\n", first, last
                }
            '
        )

    # Firewall CSV: timestamp = 1773792002
    elif [[ "$file" == */network/*.csv ]]; then

        IFS='|' read -r first last < <(
            awk -F',' '
                NR > 1 && $1 != "" {
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
                        printf "%s|%s\n", min, max
                }
            ' "$file"
        )

    # Linux audit.log: audit(1774442959.133:10)
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
            ' "$file"
        )

    # Linux syslog/auth.log: Mar 18 00:00:38 hostname process[pid]: ...
    elif [[ "$file" == */linux/*.log ||
            "$file" == */linux/syslog ]]; then

        local year

        year=$(stat -c %y "$file" | cut -d'-' -f1)

        IFS='|' read -r first last < <(
            awk -v year="$year" '
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

                NF >= 3 {

                    month = month_number($1)
                    day   = sprintf("%02d", $2)

                    split($3, time, ":")

                    hour   = sprintf("%02d", time[1])
                    minute = sprintf("%02d", time[2])
                    second = sprintf("%02d", time[3])

                    timestamp = year month day hour minute second

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

    printf '%s|%s\n' "$first" "$last"
}


printf '[\n' > "$JSON_PATH"
first_record=1


for folder in "${FOLDERS[@]}"
do

    mapfile -t files < <(find "$DIR/$folder" -maxdepth 1 -type f)

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

        record_count=0

        if [[ $file == *.json ]]; then
            record_count=$(wc -l < "$file")
            count_field="record_count"
        else
            record_count=$(cat "$file" | wc -l)
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
                first_event_time: $first_event_time,
                last_event_time: $last_event_time
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

