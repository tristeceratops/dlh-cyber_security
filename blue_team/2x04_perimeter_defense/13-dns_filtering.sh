#!/bin/bash

set -euo pipefail

# get /home/analyst/MedDefense_Lab/dns/blocklist.txt and /home/analyst/MedDefense_Lab/allowlist.txt

BASE="/home/analyst/MedDefense_Lab"
BLOCKLIST="$BASE/dns/blocklist.txt"
ALLOWLIST="$BASE/dns/allowlist.txt"
UPSTREAM="/etc/dnsmasq.d/meddefense-upstream.conf"
BLOCKCONF="/etc/dnsmasq.d/meddefense-blocklist.conf"
MAINCONF="/etc/dnsmasq.d/meddefense.conf"
LOGFILE="/var/log/dnsmasq.log"
JSON="$BASE/dns/dns_filtering.json"

die() {
    echo "[!] $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f "$BLOCKLIST" ]] || die "missing $BLOCKLIST"
[[ -f "$ALLOWLIST" ]] || die "missing $ALLOWLIST"
[[ -f "$UPSTREAM" ]] || die "missing $UPSTREAM"

# ---------------------------------------------------------------------------
# Measure before changing anything
# ---------------------------------------------------------------------------

BEFORE_SERVICE=$(systemctl is-active dnsmasq 2>/dev/null || true)
BEFORE_CONFIG=$(sha256sum "$BLOCKCONF" 2>/dev/null | awk '{print $1}' || echo "absent")

# ---------------------------------------------------------------------------
# Install dnsmasq if necessary
# ---------------------------------------------------------------------------

echo -n "[*] Ensuring dnsmasq is installed...     "
# idempotent
if ! command -v dnsmasq >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y dnsmasq >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y dnsmasq >/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y dnsmasq >/dev/null
    else
        die "unsupported distribution"
    fi
fi

echo "dnsmasq $(dnsmasq --version | awk 'NR==1 {print $2}')"

# ---------------------------------------------------------------------------
# Render dnsmasq configuration
# ---------------------------------------------------------------------------

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    { gsub(/\r/, ""); print "address=/" $0 "/0.0.0.0" }
' "$BLOCKLIST" | sort -u > "$TMP"

COUNT=$(wc -l < "$TMP")

echo "[*] Rendering blocklist...               ($COUNT domains)"

cat > "$MAINCONF" <<EOF
# Managed by 13-dns_filtering.sh
listen-address=127.0.0.1
bind-interfaces
no-resolv
log-queries
log-facility=$LOGFILE
EOF

# Only replace the blocklist when it actually changed.
if [[ ! -f "$BLOCKCONF" ]] || ! cmp -s "$TMP" "$BLOCKCONF"; then
    install -m 0644 "$TMP" "$BLOCKCONF"
    CHANGED=1
else
    CHANGED=0
fi

touch "$LOGFILE"
dnsmasq --test >/dev/null

# ---------------------------------------------------------------------------
# Start/restart
# ---------------------------------------------------------------------------

echo -n "[*] Restarting dnsmasq.service...        "

if (( CHANGED )) || [[ "$BEFORE_SERVICE" != "active" ]]; then
    systemctl restart dnsmasq.service
fi

systemctl is-active --quiet dnsmasq.service || die "dnsmasq is not active"
echo "active"

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

ALLOW=$(awk '!/^[[:space:]]*#/ && NF {print $1; exit}' "$ALLOWLIST")
BLOCK=$(awk '!/^[[:space:]]*#/ && NF {print $1; exit}' "$BLOCKLIST")

# Use a known external name only when it is absent from both supplied lists.
UNKNOWN="ubuntu.com"

if grep -Fxi "$UNKNOWN" "$BLOCKLIST" "$ALLOWLIST" >/dev/null 2>&1; then
    UNKNOWN="example.com"
fi

[[ -n "$ALLOW" ]] || die "allowlist is empty"
[[ -n "$BLOCK" ]] || die "blocklist is empty"

dig_a() {
    dig +short +time=3 +tries=1 @127.0.0.1 "$1" A 2>/dev/null |
        head -n1
}

ALLOW_ANSWER=$(dig_a "$ALLOW")
BLOCK_ANSWER=$(dig_a "$BLOCK")
UNKNOWN_ANSWER=$(dig_a "$UNKNOWN")

ALLOW_OK=FAIL
BLOCK_OK=FAIL
UNKNOWN_OK=FAIL

[[ -n "$ALLOW_ANSWER" && "$ALLOW_ANSWER" != "0.0.0.0" ]] && ALLOW_OK=PASS
[[ "$BLOCK_ANSWER" == "0.0.0.0" ]] && BLOCK_OK=PASS
[[ -n "$UNKNOWN_ANSWER" && "$UNKNOWN_ANSWER" != "0.0.0.0" ]] && UNKNOWN_OK=PASS

echo "[*] Validation queries..."

printf '  dig @127.0.0.1 %s\n' "$ALLOW"
printf '      -> %-20s expected allow      %s\n' "${ALLOW_ANSWER:-NO ANSWER}" "$ALLOW_OK"

printf '  dig @127.0.0.1 %s\n' "$BLOCK"
printf '      -> %-20s expected sinkhole   %s\n' "${BLOCK_ANSWER:-NO ANSWER}" "$BLOCK_OK"

printf '  dig @127.0.0.1 %s\n' "$UNKNOWN"
printf '      -> %-20s expected allow      %s\n' "${UNKNOWN_ANSWER:-NO ANSWER}" "$UNKNOWN_OK"

# ---------------------------------------------------------------------------
# JSON evidence
# ---------------------------------------------------------------------------

AFTER_CONFIG=$(sha256sum "$BLOCKCONF" | awk '{print $1}')

#instead of jq
python3 - "$JSON" <<PY
import json

data = {
    "task": "13-dns_filtering",
    "blocklist": {
        "path": "$BLOCKLIST",
        "domains": $COUNT
    },
    "configuration": {
        "upstream": "$UPSTREAM",
        "blocklist": "$BLOCKCONF",
        "log": "$LOGFILE"
    },
    "before": {
        "service": "$BEFORE_SERVICE",
        "blocklist_sha256": "$BEFORE_CONFIG"
    },
    "after": {
        "service": "active",
        "blocklist_sha256": "$AFTER_CONFIG"
    },
    "validation": {
        "allowed": {
            "domain": "$ALLOW",
            "answer": "$ALLOW_ANSWER",
            "result": "$ALLOW_OK"
        },
        "blocked": {
            "domain": "$BLOCK",
            "answer": "$BLOCK_ANSWER",
            "result": "$BLOCK_OK"
        },
        "unknown": {
            "domain": "$UNKNOWN",
            "answer": "$UNKNOWN_ANSWER",
            "result": "$UNKNOWN_OK"
        }
    }
}

with open("$JSON", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\\n")
PY

echo "[*] Findings written to $JSON"

[[ "$ALLOW_OK" == PASS &&
   "$BLOCK_OK" == PASS &&
   "$UNKNOWN_OK" == PASS ]]

