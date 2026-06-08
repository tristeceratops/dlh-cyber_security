#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo './1-xor_decoder.sh [xor to decode]'
    exit 1
fi

encoded="${1#\{xor\}}"

echo "$encoded" | base64 -d | perl -pe 's/(.)/chr(ord($1) ^ 0x5F)/ge'
