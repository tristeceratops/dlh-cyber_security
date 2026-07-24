#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <input_file> <output_file> <cbc|gcm>"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"
MODE="$3"

if [ ! -f "$INPUT" ]; then
    echo "Error: Input file '$INPUT' does not exist."
    exit 1
fi

case "$MODE" in
    cbc)
        openssl enc -aes-256-cbc \
            -salt \
            -pbkdf2 \
            -in "$INPUT" \
            -out "$OUTPUT"
        ;;
    gcm)
        openssl enc -aes-256-gcm \
            -salt \
            -pbkdf2 \
            -in "$INPUT" \
            -out "$OUTPUT"
        ;;
    *)
        echo "Error: Mode must be 'cbc' or 'gcm'."
        exit 1
        ;;
esac

if [ $? -eq 0 ]; then
    echo "Encryption successful: $OUTPUT"
else
    echo "Encryption failed."
    exit 1
fi
