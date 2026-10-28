
#!/bin/bash
# recovery_validation.sh
#
# Exit codes:
#   0 = every validation passed
#   1 = one or more validations failed or could not be completed
#
# Required configuration:
#   HOSTS_FILE                  One authorized hostname per line
#   SSH_USER                    Authorized remote account
#   BEACON_CHECK_CMD            EDR/telemetry adapter
#   C2_CHECK_CMD                Firewall/proxy telemetry adapter
#   EDR_CHECK_CMD               EDR console adapter
#   SIEM_SIGMA_CHECK_CMD        SIEM rule + synthetic-event adapter
#   EVIDENCE_BASELINE           sha256sum-format evidence baseline
#
# Adapter contract:
#   Exit 0 only when the full requested check succeeds.
#   Nonzero means failure or inconclusive.
#   Adapters must query actual telemetry, not static success responses.

set -uo pipefail
umask 077

HOSTS_FILE="${HOSTS_FILE:-./affected_hosts.txt}"
SSH_USER="${SSH_USER:-ir-validator}"
EVIDENCE_BASELINE="${EVIDENCE_BASELINE:-./evidence-baseline.sha256}"

C2_DOMAIN="staging.office365-cdn[.]net"
C2_IP="45.152.66.114"

EPIC_API_URL="${EPIC_API_URL:-https://epic-api.example.invalid/health}"
LIS_API_URL="${LIS_API_URL:-https://lis-api.example.invalid/health}"
SCHEDULING_API_URL="${SCHEDULING_API_URL:-https://scheduling-api.example.invalid/health}"

failures=0

pass() {
    printf '[PASS] %s\n' "$1"
}

fail() {
    printf '[FAIL] %s\n' "$1"
    failures=$((failures + 1))
}

require_file() {
    [[ -f "$1" && -r "$1" ]]
}

require_adapter() {
    [[ -n "${1:-}" && -x "${1:-}" ]]
}

# The adapter must check process creation/termination telemetry and lineage
# across every affected host, covering the preceding 24 hours.
check_beacon() {
    require_adapter "${BEACON_CHECK_CMD:-}" &&
        "$BEACON_CHECK_CMD" \
            --hosts-file "$HOSTS_FILE" \
            --lookback-hours 24 \
            --process svchost32.exe \
            --include-related-process-tree
}

# The adapter must inspect actual firewall, proxy, or network telemetry
# for both the domain and IP, including successful outbound connections.
check_c2() {
    require_adapter "${C2_CHECK_CMD:-}" &&
        "$C2_CHECK_CMD" \
            --hosts-file "$HOSTS_FILE" \
            --domain "$C2_DOMAIN" \
            --ip "$C2_IP" \
            --lookback-hours 24
}

# Query every host over SSH. Any inaccessible host or failed command
# makes the check inconclusive and therefore a failure.
check_staging_scripts() {
    require_file "$HOSTS_FILE" || return 1
    command -v ssh >/dev/null 2>&1 || return 1

    local host
    local result=0

    while IFS= read -r host || [[ -n "$host" ]]; do
        [[ -z "$host" || "$host" == \#* ]] && continue

        # Prevent malformed host entries from becoming SSH options.
        [[ "$host" =~ ^[a-zA-Z0-9._-]+$ ]] || {
            result=1
            continue
        }

        # Remote command reports failure if either directory contains
        # a matching file. This searches filenames; content-based malware
        # classification remains a separate EDR/forensic task.
        if ! ssh \
            -o BatchMode=yes \
            -o ConnectTimeout=10 \
            -o StrictHostKeyChecking=yes \
            "${SSH_USER}@${host}" \
            'powershell.exe -NoProfile -NonInteractive -Command "
              $ErrorActionPreference = '\''Stop'\''
              $roots = @('\''C:\Windows\System32'\'',
                         '\''C:\ProgramData'\'')
              $found = @(
                foreach ($root in $roots) {
                  if (Test-Path -LiteralPath $root) {
                    Get-ChildItem -LiteralPath $root -File -Recurse `
                      -ErrorAction SilentlyContinue |
                      Where-Object { $_.Extension -in @('\''.bat'\'',
                                                       '\''.ps1'\'') }
                  }
                }
              )
              if ($found.Count -gt 0) {
                $found | Select-Object -ExpandProperty FullName
                exit 1
              }
              exit 0
            "' >/dev/null 2>&1; then
            result=1
        fi
    done < "$HOSTS_FILE"

    return "$result"
}

# Require an HTTP 200 response from each clinical endpoint.
check_endpoint() {
    local url="$1"
    local status

    status="$(curl --silent --show-error \
        --connect-timeout 5 --max-time 15 \
        --output /dev/null --write-out '%{http_code}' \
        "$url" 2>/dev/null)" || return 1

    [[ "$status" == "200" ]]
}

check_services() {
    check_endpoint "$EPIC_API_URL" &&
    check_endpoint "$LIS_API_URL" &&
    check_endpoint "$SCHEDULING_API_URL"
}

# Adapter must confirm that every host in the inventory has checked in
# to the EDR console within the preceding five minutes.
check_edr() {
    require_adapter "${EDR_CHECK_CMD:-}" &&
        "$EDR_CHECK_CMD" \
            --hosts-file "$HOSTS_FILE" \
            --max-age-minutes 5 \
            --require-all
}

# Adapter must confirm the named Sigma rule is enabled in the intended
# SIEM and that an authorized synthetic test produced the expected hit.
check_detection() {
    require_adapter "${SIEM_SIGMA_CHECK_CMD:-}" &&
        "$SIEM_SIGMA_CHECK_CMD" \
            --rule sigma_cobalt_strike_beacon.yml \
            --require-active \
            --run-synthetic-test \
            --require-expected-hit
}

# Validate all artifacts against the preserved SHA-256 baseline.
# The baseline itself must be stored in a trusted, protected location.
check_evidence_hashes() {
    require_file "$EVIDENCE_BASELINE" || return 1
    command -v sha256sum >/dev/null 2>&1 || return 1

    sha256sum --check --status "$EVIDENCE_BASELINE"
}

main() {
    if ! require_file "$HOSTS_FILE"; then
        fail "inventory: affected-host inventory is missing or unreadable"
        printf 'RECOVERY VALIDATION FAILED\n'
        return 1
    fi

    local host_count
    host_count="$(
        grep -Ev '^[[:space:]]*(#|$)' "$HOSTS_FILE" | wc -l
    )"

    if [[ "$host_count" -ne 5 ]]; then
        fail "inventory: expected 5 affected hosts; found $host_count"
    fi

    if check_beacon; then
        pass "beacon: no svchost32.exe or related process tree in last 24h across all affected hosts"
    else
        fail "beacon: telemetry missing, inconclusive, or matching process tree found"
    fi

    if check_c2; then
        pass "c2: no outbound connections to staging.office365-cdn[.]net or 45.152.66.114"
    else
        fail "c2: outbound connections found or telemetry unavailable"
    fi

    if check_staging_scripts; then
        pass "ransomware staging: no .bat or .ps1 staging scripts found in Windows\System32 or ProgramData"
    else
        fail "ransomware staging: scripts found or one or more hosts could not be checked"
    fi

    if check_services; then
        pass "services: epic-api 200, lis-api 200, scheduling-api 200"
    else
        fail "services: one or more clinical endpoints did not return HTTP 200"
    fi

    if check_edr; then
        pass "edr: all 5 hosts reporting to EDR console in last 5 minutes"
    else
        fail "edr: one or more hosts are stale, missing, or unverifiable"
    fi

    if check_detection; then
        pass "detection: sigma_cobalt_strike_beacon.yml active; synthetic test event returned expected hit"
    else
        fail "detection: Sigma rule inactive or synthetic test failed"
    fi

    if check_evidence_hashes; then
        local total
        total="$(grep -Ec '^[[:xdigit:]]{64}[[:space:]]' "$EVIDENCE_BASELINE" || true)"
        pass "evidence hashes: ${total}/${total} artifacts match original SHA-256 baseline"
    else
        fail "evidence hashes: baseline missing or at least one artifact hash mismatched"
    fi

    if [[ "$failures" -eq 0 ]]; then
        printf 'ALL CHECKS PASSED\n'
        return 0
    fi

    printf 'RECOVERY VALIDATION FAILED: %s check(s) failed\n' "$failures"
    return 1
}

main "$@"
exit $?
