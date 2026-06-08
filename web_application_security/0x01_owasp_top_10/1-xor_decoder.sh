#!/bin/bash

encoded="${1#\{xor\}}"
decoded=$(printf '%s' "$encoded" | base64 -d)

key=95
i=0

while [ "$i" -lt "${#decoded}" ]
do
    byte=$(printf '%d' "'${decoded:$i:1}")
    printf "\\$(printf '%03o' "$((byte ^ key))")"
    i=$((i + 1))
done

printf '\n'
