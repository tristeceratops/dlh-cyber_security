#!/bin/bash

# Check arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 \"Your Name\" \"your@email.com\""
    exit 1
fi

USERNAME="$1"
EMAIL="$2"

# Set global Git config
git config --global user.name "$USERNAME"
git config --global user.email "$EMAIL"

# Cache credentials for 4 hours (14400 seconds)
git config --global credential.helper "cache --timeout=14400"

echo "Git configuration updated:"
echo "  Username: $USERNAME"
echo "  Email: $EMAIL"
echo "  Credential cache: 4 hours"
