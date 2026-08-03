#!/bin/bash

set -euo pipefail

RUN_LOG="hardening_run.json"
IMPROVEMENT_LOG="hardening_improvement.json"

SCRIPTS=(
"0-baseline_snapshot.sh"
"2-lynis_parse.sh"
"4-ssh_hardening.sh"
"5-sysctl_hardening.sh"
"6-filesystem_hardening.sh"
"7-service_minimization.sh"
"8-pam_hardening.sh"
"9-apparmor_config.sh"
"10-auditd_config.sh"
"11-audit_coverage_test.sh"
"12-log_config.sh"
"13-firewall_baseline.sh"
"15-validation.sh"
)

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

echo "[*] Performing pre-checks for required scripts..."

for script in "${SCRIPTS[@]}"; do
    if [[ ! -f "$script" ]]; then
        echo "$script exists: NO"
        exit 1
    fi

    chmod +x "$script"
done

echo "Pre-checks: PASS"
echo "Steps scheduled: ${#SCRIPTS[@]}"

##############################################
# Capture pre hardening Lynis score
##############################################

BEFORE_SCORE=0

if command -v lynis >/dev/null 2>&1; then

    TMP=$(mktemp)

    lynis audit system \
        --quick \
        --quiet \
        >"$TMP" 2>/dev/null || true

    BEFORE_SCORE=$(grep -oP 'Hardening index *: *\K[0-9]+' "$TMP" | tail -1)

    BEFORE_SCORE=${BEFORE_SCORE:-0}

    rm -f "$TMP"

fi

##############################################
# JSON start
##############################################

echo "[" > "$RUN_LOG"

FAILED=0
COMPLETED=0
FIRST=true

##############################################
# Execute workflow
##############################################

for script in "${SCRIPTS[@]}"; do

    START=$(date +%s)

    if bash "./$script"; then
        EXITCODE=0
    else
        EXITCODE=$?
    fi

    END=$(date +%s)
    DURATION=$((END-START))

    if [[ "$FIRST" == true ]]; then
        FIRST=false
    else
        echo "," >> "$RUN_LOG"
    fi

    cat >> "$RUN_LOG" <<EOF
{
  "script":"$script",
  "exit_code":$EXITCODE,
  "duration_seconds":$DURATION
}
EOF

    if [[ $EXITCODE -ne 0 ]]; then

        FAILED=1

        echo "]" >> "$RUN_LOG"

        echo
        echo "Step failed: $script"
        echo "Execution stopped."

        exit $EXITCODE

    fi

    COMPLETED=$((COMPLETED+1))

done

echo "]" >> "$RUN_LOG"

##############################################
# Capture post Lynis score
##############################################

AFTER_SCORE=0

if command -v lynis >/dev/null 2>&1; then

    TMP=$(mktemp)

    lynis audit system \
        --quick \
        --quiet \
        >"$TMP" 2>/dev/null || true

    AFTER_SCORE=$(grep -oP 'Hardening index *: *\K[0-9]+' "$TMP" | tail -1)

    AFTER_SCORE=${AFTER_SCORE:-0}

    rm -f "$TMP"

fi

DELTA=$((AFTER_SCORE-BEFORE_SCORE))

cat > "$IMPROVEMENT_LOG" <<EOF
{
  "before_score": $BEFORE_SCORE,
  "after_score": $AFTER_SCORE,
  "delta": $DELTA
}
EOF

##############################################
# JSON END
##############################################

echo
echo "Steps completed: $COMPLETED"
echo "Steps failed: 0"
echo "Before Lynis score: $BEFORE_SCORE"
echo "After Lynis score: $AFTER_SCORE"

if [[ $DELTA -ge 0 ]]; then
    echo "Delta: +$DELTA"
else
    echo "Delta: $DELTA"
fi

echo "Run log saved to: $RUN_LOG"
echo "Improvement saved to: $IMPROVEMENT_LOG"
