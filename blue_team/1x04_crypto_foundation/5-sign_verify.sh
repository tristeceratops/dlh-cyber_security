#!/bin/bash

# Script: 5-sign_verify.sh
# Usage:
#   Sign:   ./5-sign_verify.sh sign <file> <private_key>
#   Verify: ./5-sign_verify.sh verify <file> <signature> <public_key>

MODE="$1"

if [ "$MODE" = "sign" ]; then

    if [ "$#" -ne 3 ]; then
        echo "Usage: $0 sign <file> <private_key>"
        exit 1
    fi

    FILE="$2"
    PRIVATE_KEY="$3"
    SIGNATURE="${FILE}.sig"

    openssl dgst -sha256 \
        -sign "$PRIVATE_KEY" \
        -out "$SIGNATURE" \
        "$FILE"

    if [ $? -eq 0 ]; then
        echo "Signature created: $SIGNATURE"
        exit 0
    else
        echo "Signature creation failed"
        exit 1
    fi


elif [ "$MODE" = "verify" ]; then

    if [ "$#" -ne 4 ]; then
        echo "Usage: $0 verify <file> <signature> <public_key>"
        exit 1
    fi

    FILE="$2"
    SIGNATURE="$3"
    PUBLIC_KEY="$4"

    openssl dgst -sha256 \
        -verify "$PUBLIC_KEY" \
        -signature "$SIGNATURE" \
        "$FILE"

    if [ $? -eq 0 ]; then
        echo "INTEGRITY OK - Signature verified"
        exit 0
    else
        echo "INTEGRITY FAILED - Signature verification failed"
        exit 1
    fi


else
    echo "Invalid mode. Use: sign or verify"
    exit 1
fi
