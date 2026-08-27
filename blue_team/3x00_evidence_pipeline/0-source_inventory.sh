#!/bin/bash

DIR="$HOME/evidence_pack_primary"
FOLDERS=("windows" "linux" "network")

total_file=0
total_size=0

JSON_PATH="source_inventory.json"

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
            sourcetype="${sourcetype}_txt"
        fi
        size="$(stat -c %s "$file")B"
        shahash="$(shasum "$file" | awk '{print $1}')"
        record_count=0
        if [[ $file == *.json ]]; then
            record_count="$(jq 'length' $file | wc -l)"
        else
            record_count="$(cat $file | wc -l)"
        fi
        printf "path: %s --- sourcetype: %s --- size: %s --- hash: %s --- line/record count: %s\n" "$relative_path" "$sourcetype" "$size" "$shahash" "$record_count"
    done

    count=$(find "$DIR/$folder" -maxdepth 1 -type f | wc -l)
    size=$(ls -l $DIR/$folder | awk '{sum+= $5} END {print sum}')
    total_size=$((total_size + size))
    size=$(numfmt --to=iec --suffix=B $size)
    printf "%-8s %2s %8s %2s %8s\n" "$folder" ":" "$count files" '|' "$size"
    total_file=$((total_file + count))
done

total_size=$(numfmt --to=iec --suffix=B $total_size)
printf "%-8s %2s %8s %2s %8s\n" "Total" ":"  "$total_file files" '|' "$total_size"
