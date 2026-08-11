#!/bin/bash

set -euo pipefail

GROUND_TRUTH="linux_attack_log.json"
OUTPUT="linux_detection_matrix.json"
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"

if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root"
    exit 1
fi

command -v jq >/dev/null 2>&1 || {
    echo "Error: jq is required"
    exit 1
}

jq empty "$GROUND_TRUTH" >/dev/null 2>&1 || {
    echo "Error: invalid $GROUND_TRUTH"
    exit 1
}

COUNT=$(jq '.events | length' "$GROUND_TRUTH")

echo "[*] Loading ground truth ($COUNT actions)..."
echo "[*] Searching telemetry..."

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo '[]' > "$TMP"

CAPTURED=0

key_for() {
    case "$1" in
        1) echo "identity" ;;
        2) echo "sudoers" ;;
        3) echo "process_exec" ;;
        4) echo "network_connect" ;;
        5) echo "cron_persist" ;;
        6) echo "identity" ;;
        *) echo "" ;;
    esac
}

fields_for() {
    case "$1" in
        1) echo "user" ;;
        2) echo "path,operation,key" ;;
        3) echo "command_line,exe" ;;
        4) echo "destination,syscall" ;;
        5) echo "path,operation,key" ;;
        6) echo "path,operation" ;;
        *) echo "" ;;
    esac
}

printf "%-35s %-12s %-18s %-10s %s\n" \
    "Action" "Source" "Key" "Detail" "Status"
echo "--------------------------------------------------------------------------"

while IFS= read -r event; do

    ACTION_NUM=$(jq -r '.action' <<< "$event")
    DESCRIPTION=$(jq -r '.description' <<< "$event")
    START=$(jq -r '.timestamp' <<< "$event")

    END_TIME=$(date -u -d "$START + 30 seconds" '+%Y-%m-%dT%H:%M:%SZ')

    KEY=$(key_for "$ACTION_NUM")
    FIELDS=$(fields_for "$ACTION_NUM")

    AUDIT_START=$(date -d "$START" '+%m/%d/%Y %H:%M:%S')
    AUDIT_END=$(date -d "$END_TIME" '+%m/%d/%Y %H:%M:%S')

    SOURCE="none"
    DETAIL="None"

    # --------------------------------------------------
    # Auditd
    # --------------------------------------------------

    case "$ACTION_NUM" in

        1)
            DATA=$(ausearch \
                -ts "$AUDIT_START" \
                -te "$AUDIT_END" \
                -m USER_ACCT,ADD_USER,USER_START \
                2>/dev/null || true)
            ;;

        2)
            DATA=$(ausearch \
                -k sudoers \
                -ts "$AUDIT_START" \
                -te "$AUDIT_END" \
                2>/dev/null || true)
            ;;

        3)
            DATA=$(ausearch \
                -k process_exec \
                -ts "$AUDIT_START" \
                -te "$AUDIT_END" \
                2>/dev/null || true)
            ;;

        4)
            DATA=$(ausearch \
                -k network_connect \
                -ts "$AUDIT_START" \
                -te "$AUDIT_END" \
                2>/dev/null || true)
            ;;

        5)
            DATA=$(ausearch \
                -k cron_persist \
                -ts "$AUDIT_START" \
                -te "$AUDIT_END" \
                2>/dev/null || true)
            ;;

        6)
            DATA=$(ausearch \
                -ts "$AUDIT_START" \
                -te "$AUDIT_END" \
                -m SYSCALL,PATH \
                2>/dev/null || true)
            ;;

        *)
            DATA=""
            ;;
    esac

    if [[ -n "$DATA" ]]; then
        SOURCE="auditd"
        DETAIL="Full"

    elif [[ -f "$AUTH_LOG" ]] && \
         grep -Ei \
         'useradd|userdel|sudo|sudoers|cron|shadow|connect|127\.0\.0\.1|4444' \
         "$AUTH_LOG" >/dev/null 2>&1; then

        SOURCE="auth.log"
        DETAIL="Partial"
        FIELDS="user"

    elif [[ -f "$SYSLOG" ]] && \
         grep -Ei \
         'sudo|cron|shadow|connect|127\.0\.0\.1|4444|error' \
         "$SYSLOG" >/dev/null 2>&1; then

        SOURCE="syslog"
        DETAIL="Partial"
        FIELDS="message"
    fi

    if [[ "$SOURCE" != "none" ]]; then
        STATUS="CAPTURED"
        CAPTURED=$((CAPTURED + 1))
    else
        STATUS="MISSED"
    fi

    printf "%-35s %-12s %-18s %-10s [%s]\n" \
        "$DESCRIPTION" \
        "$SOURCE" \
        "$KEY" \
        "$DETAIL" \
        "$STATUS"

    # Build JSON without a jq filter containing the keyword "end".
    jq \
        --arg action "$DESCRIPTION" \
        --arg source "$SOURCE" \
        --arg key "$KEY" \
        --arg detail "$DETAIL" \
        --arg status "$STATUS" \
        --arg start "$START" \
        --arg end_time "$END_TIME" \
        --arg fields "$FIELDS" \
        '. += [{
            action: $action,
            source: $source,
            key: $key,
            detail: $detail,
            status: $status,
            start: $start,
            end_time: $end_time,
            key_fields: $fields
        }]' \
        "$TMP" > "$TMP.new"

    mv "$TMP.new" "$TMP"

done < <(jq -c '.events[]' "$GROUND_TRUTH")

MULTI_SOURCE=$(jq '
    group_by(.action)
    | map([.[].source] | unique | length)
    | map(select(. > 1))
    | length
' "$TMP")

PERCENT=$(awk \
    -v captured="$CAPTURED" \
    -v total="$COUNT" \
    'BEGIN {
        if (total > 0)
            printf "%.0f", captured * 100 / total
        else
            print 0
    }')

jq \
    --argjson actions "$COUNT" \
    --argjson captured "$CAPTURED" \
    --argjson multi "$MULTI_SOURCE" \
    '{
        actions: $actions,
        captured: $captured,
        capture_percent: (
            if $actions > 0
            then ($captured * 100 / $actions)
            else 0
            end
        ),
        multi_source: $multi,
        events: .
    }' \
    "$TMP" > "$OUTPUT"

echo "Actions: $COUNT | Captured: $CAPTURED/$COUNT (${PERCENT}%) | Multi-source: $MULTI_SOURCE"
echo "Report saved to: $OUTPUT"
