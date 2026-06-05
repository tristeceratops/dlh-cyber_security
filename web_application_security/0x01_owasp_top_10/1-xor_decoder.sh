#!/bin/bash

encoded="${1#\{xor\}}"
decoded=$(echo -n "$encoded" | base64 -d)

key=0x5f

for ((i=0; i<${#decoded}; i++)); do
    byte=$(printf '%d' "'${decoded:i:1}")
    printf "\\$(printf '%03o' $((byte ^ key)))"
done
