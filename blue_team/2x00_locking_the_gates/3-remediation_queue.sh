#!/bin/bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <cis_profile.json> <lynis_findings.json>" >&2
    exit 1
fi
