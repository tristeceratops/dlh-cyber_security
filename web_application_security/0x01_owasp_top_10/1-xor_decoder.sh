#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo './1-xor_decoder.sh [xor to decode]'
    exit 1
fi

encoded="${1#\{xor\}}"

if ! decoded=$(printf '%s' "$encoded" | base64 -d 2>/dev/null); then
    echo "Invalid Base64 input" >&2
    exit 1
fi

key=95
i=0

while [ "$i" -lt "${#decoded}" ]; do
    byte=$(printf '%d' "'${decoded:$i:1}")
    printf "\\$(printf '%03o' "$((byte ^ key))")"
    i=$((i + 1))
done

echo
