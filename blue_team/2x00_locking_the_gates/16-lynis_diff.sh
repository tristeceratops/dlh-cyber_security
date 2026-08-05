#!/bin/bash

set -euo pipefail

BEFORE_FILE="lynis_findings.json"
AFTER_FILE="lynis_post_findings.json"
REPORT="hardening_improvement.json"

LYNIS_REPORT="/var/log/lynis-report.dat"

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


echo "[*] Preparing Lynis comparison..."


if [[ ! -f "$BEFORE_FILE" ]]; then

    echo "Error: missing $BEFORE_FILE"
    echo "Run baseline Lynis collection first."
    exit 1

fi



#############################################
# Generate post-hardening Lynis data
#############################################

if [[ ! -f "$AFTER_FILE" ]]; then

    echo "[*] Running Lynis post-hardening scan..."

    if ! command -v lynis >/dev/null 2>&1; then

        echo "Installing Lynis..."

        apt-get update
        apt-get install -y lynis

    fi


    lynis audit system --quiet


    if [[ ! -f "$LYNIS_REPORT" ]]; then

        echo "Error: Lynis report not generated"
        exit 1

    fi


    echo "[*] Parsing Lynis findings..."


    SCORE=$(grep "hardening_index" "$LYNIS_REPORT" \
        | awk -F= '{print $2}' \
        | tr -d ' ')


    if [[ -z "$SCORE" ]]; then
        SCORE=0
    fi


    jq -n \
    --argjson score "$SCORE" \
    --jsonargs \
    '
    {
        score:$score,
        findings:[]
    }
    ' > "$AFTER_FILE"


    while read -r finding; do

        jq \
        --arg id "$finding" \
        '.findings += [$id]' \
        "$AFTER_FILE" > /tmp/after.json

        mv /tmp/after.json "$AFTER_FILE"

    done < <(
        grep "^hardening_hint" "$LYNIS_REPORT" 2>/dev/null \
        | awk -F= '{print $1}'
    )


fi



#############################################
# Extract scores
#############################################

BEFORE_SCORE=$(jq -r '.score // .before_score // 0' "$BEFORE_FILE")

AFTER_SCORE=$(jq -r '.score // .after_score // 0' "$AFTER_FILE")


DELTA=$((AFTER_SCORE - BEFORE_SCORE))


if [[ "$DELTA" -ge 0 ]]; then
    DELTA_DISPLAY="+$DELTA"
else
    DELTA_DISPLAY="$DELTA"
fi



#############################################
# Compare findings
#############################################

BEFORE_FINDINGS=$(mktemp)
AFTER_FINDINGS=$(mktemp)

cleanup()
{
    rm -f "$BEFORE_FINDINGS" "$AFTER_FINDINGS"
}

trap cleanup EXIT


jq -r '.findings[]?' "$BEFORE_FILE" \
    | sort \
    > "$BEFORE_FINDINGS"


jq -r '.findings[]?' "$AFTER_FILE" \
    | sort \
    > "$AFTER_FINDINGS"



RESOLVED=$(comm -23 "$BEFORE_FINDINGS" "$AFTER_FINDINGS")

REMAINING=$(comm -12 "$BEFORE_FINDINGS" "$AFTER_FINDINGS")

NEW=$(comm -13 "$BEFORE_FINDINGS" "$AFTER_FINDINGS")


RESOLVED_COUNT=$(grep -c . <<<"$RESOLVED" || true)
REMAINING_COUNT=$(grep -c . <<<"$REMAINING" || true)
NEW_COUNT=$(grep -c . <<<"$NEW" || true)



#############################################
# Residual risk summary
#############################################

RISK=""

if [[ "$REMAINING_COUNT" -eq 0 ]]; then

    RISK="No remaining Lynis findings detected"

elif [[ "$REMAINING_COUNT" -lt 10 ]]; then

    RISK="Low residual risk - limited findings remain"

elif [[ "$REMAINING_COUNT" -lt 30 ]]; then

    RISK="Moderate residual risk - review remaining findings"

else

    RISK="High residual risk - significant findings remain"

fi



#############################################
# JSON report
#############################################

jq -n \
--argjson before "$BEFORE_SCORE" \
--argjson after "$AFTER_SCORE" \
--argjson delta "$DELTA" \
--argjson resolved_count "$RESOLVED_COUNT" \
--argjson remaining_count "$REMAINING_COUNT" \
--argjson new_count "$NEW_COUNT" \
--arg risk "$RISK" \
--argjson resolved "$(jq -R -s 'split("\n") | map(select(length>0))' <<<"$RESOLVED")" \
--argjson remaining "$(jq -R -s 'split("\n") | map(select(length>0))' <<<"$REMAINING")" \
--argjson new "$(jq -R -s 'split("\n") | map(select(length>0))' <<<"$NEW")" \
'
{
    before_score:$before,
    after_score:$after,
    delta:$delta,

    resolved_findings:$resolved,
    remaining_findings:$remaining,
    new_findings:$new,

    resolved_count:$resolved_count,
    remaining_count:$remaining_count,
    new_count:$new_count,

    residual_risk_summary:$risk
}
' > "$REPORT"



#############################################
# Output
#############################################

echo
echo "Before: $BEFORE_SCORE"
echo "After: $AFTER_SCORE"
echo "Delta: $DELTA_DISPLAY"
echo "Findings resolved: $RESOLVED_COUNT"
echo "Findings remaining: $REMAINING_COUNT"
echo "New findings: $NEW_COUNT"
echo "Report saved to: $REPORT"
