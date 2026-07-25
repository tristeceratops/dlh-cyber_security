#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file> <expected_sha256_hash>"
    exit 1
fi

FILE="$1"
EXPECTED_HASH="$2"

if [ ! -f "$FILE" ]; then
    echo "Error: File '$FILE' not found."
    exit 1
fi

ACTUAL_HASH=$(sha256sum "$FILE" | awk '{print $1}')

if [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $EXPECTED_HASH got $ACTUAL_HASH"
    exit 1
fi
