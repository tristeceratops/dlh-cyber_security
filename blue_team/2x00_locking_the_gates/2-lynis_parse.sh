#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <lynis-report.dat>" >&2
    exit 1
fi

REPORT="$1"
OUTPUT="lynis_findings.json"

if [ ! -f "$REPORT" ]; then
    echo "Error: '$REPORT' does not exist." >&2
    exit 1
fi

hardening_index=$(grep '^hardening_index=' "$REPORT" | cut -d= -f2)
hardening_index=${hardening_index:-0}

jq -Rn \
    --argjson hardening_index "$hardening_index" '
{
    hardening_index: $hardening_index,
    findings: [
        inputs
        | select(
            startswith("warning[]=") or
            startswith("suggestion[]=") or
            startswith("manual_check[]=")
        )
        | capture("^(?<severity>warning|suggestion|manual_check)\\[\\]=(?<rest>.*)$")
        | .severity as $severity
        | .rest
        | split("|")
        | {
            severity: $severity,
            test_id: .[0],
            message: .[1]
        }
    ]
}
' < "$REPORT" > "$OUTPUT"

echo "Lynis report parsed successfully."
echo "Hardening index: $hardening_index"
echo "Findings extracted: $(jq '.findings | length' "$OUTPUT")"
echo "Report saved to: $OUTPUT"
