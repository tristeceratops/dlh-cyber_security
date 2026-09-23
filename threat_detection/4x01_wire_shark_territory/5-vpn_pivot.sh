#!/bin/bash

# 5-vpn_pivot.sh
#
# Analyze an external VPN connection and correlate it with lateral movement.
#
# Usage:
#   ./5-vpn_pivot.sh full_timeline.pcap
#
# Requirements:
#   - tshark
#   - whois
#
# All packet observations are derived from the supplied PCAP.
# No packet counts, timestamps, durations, or destinations are hardcoded.

set -o pipefail

PCAP="${1:-full_timeline.pcap}"

VPN_ENDPOINT="10.10.0.1"
RDP_PORT="3389"

if [[ ! -f "$PCAP" ]]; then
    echo "ERROR: PCAP not found: $PCAP"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "ERROR: tshark is not installed."
    exit 1
fi

if ! command -v whois >/dev/null 2>&1; then
    echo "ERROR: whois is not installed."
    exit 1
fi

echo "=== INPUT ==="
echo "PCAP: $PCAP"
echo

echo "=== FILTERS / COMMANDS USED ==="
echo "VPN candidate: tcp.port == 443"
echo "VPN endpoint correlation: ip.addr == $VPN_ENDPOINT && tcp.port == 443"
echo "RDP correlation: tcp.dstport == $RDP_PORT"
echo "VPN close check: ip.addr == $VPN_ENDPOINT && tcp.port == 443 && tcp.flags.fin == 1"
echo "VPN reset check: ip.addr == $VPN_ENDPOINT && tcp.port == 443 && tcp.flags.reset == 1"
echo

# ----------------------------------------------------------------------
# 1. Identify external HTTPS/VPN candidates
# ----------------------------------------------------------------------

echo "=== VPN CONNECTION CANDIDATES ==="

tshark -r "$PCAP" \
    -Y 'tcp.port == 443' \
    -T fields \
    -e frame.time \
    -e frame.time_epoch \
    -e ip.src \
    -e tcp.srcport \
    -e ip.dst \
    -e tcp.dstport \
    -e tls.handshake.type \
    -e tls.handshake.extensions_server_name

echo

# ----------------------------------------------------------------------
# Find external source talking to the known VPN endpoint.
# ----------------------------------------------------------------------

VPN_SOURCE=$(
    tshark -r "$PCAP" \
        -Y "ip.dst == $VPN_ENDPOINT && tcp.dstport == 443" \
        -T fields \
        -e ip.src 2>/dev/null |
    awk '
        $1 !~ /^10\./ &&
        $1 !~ /^192[.]168[.]/ &&
        $1 !~ /^172[.]([1][6-9]|2[0-9]|3[0-1])[.]/ {
            print $1
        }
    ' |
    sort -u |
    head -n 1
)

if [[ -z "$VPN_SOURCE" ]]; then
    echo "No external source communicating with $VPN_ENDPOINT:443 was identified."
    exit 1
fi

VPN_FILTER="ip.addr == $VPN_ENDPOINT && ip.addr == $VPN_SOURCE && tcp.port == 443"

# ----------------------------------------------------------------------
# First observed VPN packet
# ----------------------------------------------------------------------

VPN_FIRST_LINE=$(
    tshark -r "$PCAP" \
        -Y "$VPN_FILTER" \
        -T fields \
        -e frame.time \
        -e frame.time_epoch \
        -e ip.src \
        -e tcp.srcport \
        -e ip.dst \
        -e tcp.dstport 2>/dev/null |
    head -n 1
)

VPN_TIMESTAMP=$(awk '{print $1}' <<< "$VPN_FIRST_LINE")
VPN_EPOCH=$(awk '{print $2}' <<< "$VPN_FIRST_LINE")
VPN_SRC_PORT=$(awk '{print $4}' <<< "$VPN_FIRST_LINE")

# ----------------------------------------------------------------------
# TLS SNI
# ----------------------------------------------------------------------

VPN_SNI=$(
    tshark -r "$PCAP" \
        -Y "$VPN_FILTER && tls.handshake.extensions_server_name" \
        -T fields \
        -e tls.handshake.extensions_server_name 2>/dev/null |
    head -n 1
)

echo "=== VPN CONNECTION IDENTIFIED ==="
echo "Timestamp: $VPN_TIMESTAMP"
echo "Source: $VPN_SOURCE:$VPN_SRC_PORT"
echo "Destination: $VPN_ENDPOINT:443"

if [[ -n "$VPN_SNI" ]]; then
    echo "Protocol: TLS/HTTPS session, SNI=$VPN_SNI"
else
    echo "Protocol: TLS/HTTPS session"
fi

echo

# ----------------------------------------------------------------------
# Authentication metadata
# ----------------------------------------------------------------------

echo "=== VPN AUTHENTICATION METADATA ==="

echo "Available authentication-related fields:"
tshark -G fields 2>/dev/null |
    awk -F '\t' '
        $2 ~ /(^|[.])(user|username|login|account|auth|identity|credential)/ {
            print $2
        }
    ' |
    sort -u |
    head -n 50

echo
echo "Authentication-related packet metadata observed on the VPN flow:"

tshark -r "$PCAP" \
    -Y "$VPN_FILTER" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tls.handshake.type \
    -e tls.handshake.extensions_server_name

echo

# ----------------------------------------------------------------------
# 2. WHOIS / GeoIP
# ----------------------------------------------------------------------

echo "=== GEOLOCATION ==="
echo "IP: $VPN_SOURCE"

WHOIS_OUTPUT=$(whois "$VPN_SOURCE" 2>/dev/null)

COUNTRY=$(printf '%s\n' "$WHOIS_OUTPUT" |
    awk -F: '
        tolower($1) ~ /^country[[:space:]]*$/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
            print $2
            exit
        }
    ')

ASN=$(printf '%s\n' "$WHOIS_OUTPUT" |
    awk '
        /origin:/ {
            print $2
            exit
        }
    ')

ORGANIZATION=$(printf '%s\n' "$WHOIS_OUTPUT" |
    awk -F: '
        tolower($1) ~ /^(org-name|orgname)$/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
            print $2
            exit
        }
    ')

NETWORK=$(printf '%s\n' "$WHOIS_OUTPUT" |
    awk -F: '
        tolower($1) ~ /^netname[[:space:]]*$/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
            print $2
            exit
        }
    ')

echo "Country: ${COUNTRY:-Not available}"
echo "ASN: ${ASN:-Not available}"
echo "Organization: ${ORGANIZATION:-Not available}"
echo "Network: ${NETWORK:-Not available}"

echo
echo "WHOIS evidence:"
printf '%s\n' "$WHOIS_OUTPUT" |
    grep -Ei 'inetnum|netname|descr|country|origin:|route:|org-name|orgname' |
    head -n 20

echo
echo "Assessment: Geographic location is evidence about the registered network,"
echo "not proof of the physical location or identity of the user."

echo

# ----------------------------------------------------------------------
# 3. Correlate with first RDP movement
# ----------------------------------------------------------------------

echo "=== TIMELINE CORRELATION ==="

FIRST_RDP=$(
    tshark -r "$PCAP" \
        -Y "tcp.dstport == $RDP_PORT" \
        -T fields \
        -e frame.time \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport 2>/dev/null |
    head -n 1
)

if [[ -z "$FIRST_RDP" ]]; then
    echo "No RDP traffic observed with filter: tcp.dstport == $RDP_PORT"
else
    RDP_TIMESTAMP=$(awk '{print $1}' <<< "$FIRST_RDP")
    RDP_EPOCH=$(awk '{print $2}' <<< "$FIRST_RDP")

    echo "VPN connection: $VPN_TIMESTAMP"
    echo "First RDP movement: $RDP_TIMESTAMP"

    if [[ -n "$VPN_EPOCH" && -n "$RDP_EPOCH" ]]; then
        GAP=$(awk -v vpn="$VPN_EPOCH" -v rdp="$RDP_EPOCH" \
            'BEGIN { printf "%.3f", rdp - vpn }')

        GAP_MINUTES=$(awk -v gap="$GAP" \
            'BEGIN { printf "%.2f", gap / 60 }')

        if awk -v vpn="$VPN_EPOCH" -v rdp="$RDP_EPOCH" \
            'BEGIN { exit !(vpn < rdp) }'; then
            echo "Order: VPN connection occurs before first observed RDP session."
            echo "Gap: ${GAP} seconds (${GAP_MINUTES} minutes)"
        else
            echo "Order: VPN connection does not precede the first observed RDP session."
            echo "Time difference: ${GAP} seconds (${GAP_MINUTES} minutes)"
        fi
    fi
fi

echo

# ----------------------------------------------------------------------
# 4. Session duration
# ----------------------------------------------------------------------

echo "=== VPN SESSION DURATION ==="

VPN_LAST_LINE=$(
    tshark -r "$PCAP" \
        -Y "$VPN_FILTER" \
        -T fields \
        -e frame.time \
        -e frame.time_epoch 2>/dev/null |
    tail -n 1
)

VPN_LAST_TIMESTAMP=$(awk '{print $1}' <<< "$VPN_LAST_LINE")
VPN_LAST_EPOCH=$(awk '{print $2}' <<< "$VPN_LAST_LINE")

echo "Connection start: $VPN_TIMESTAMP"
echo "Last observed packet: $VPN_LAST_TIMESTAMP"

if [[ -n "$VPN_EPOCH" && -n "$VPN_LAST_EPOCH" ]]; then
    DURATION=$(awk -v start="$VPN_EPOCH" -v end="$VPN_LAST_EPOCH" \
        'BEGIN { printf "%.3f", end - start }')

    DURATION_MINUTES=$(awk -v duration="$DURATION" \
        'BEGIN { printf "%.2f", duration / 60 }')

    echo "Observed duration: ${DURATION} seconds (${DURATION_MINUTES} minutes)"
fi

echo
echo "TCP close evidence:"

tshark -r "$PCAP" \
    -Y "$VPN_FILTER && tcp.flags.fin == 1" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e tcp.srcport \
    -e ip.dst \
    -e tcp.dstport

echo
echo "TCP reset evidence:"

tshark -r "$PCAP" \
    -Y "$VPN_FILTER && tcp.flags.reset == 1" \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e tcp.srcport \
    -e ip.dst \
    -e tcp.dstport

echo

# ----------------------------------------------------------------------
# 5. Assigned internal IP
# ----------------------------------------------------------------------

echo "=== ASSIGNED INTERNAL IP ==="

echo "Internal addresses observed in traffic associated with the VPN source:"

tshark -r "$PCAP" \
    -Y "ip.addr == $VPN_SOURCE" \
    -T fields \
    -e ip.src \
    -e ip.dst |
awk '
    $1 ~ /^10[.]/ {print $1}
    $2 ~ /^10[.]/ {print $2}
' |
sort -u

echo
echo "Potential VPN-assigned/internal addresses must be validated against"
echo "VPN-specific metadata; ordinary internal traffic alone does not prove assignment."

echo

# ----------------------------------------------------------------------
# 6. Evidence / limitations
# ----------------------------------------------------------------------

echo "=== WHAT THE PCAP PROVES ==="

echo "- An external source communicated with the internal VPN endpoint."
echo "- The VPN flow's timestamps, addresses, ports and TLS metadata are observable."
echo "- The TLS SNI, when present, identifies the advertised server name."
echo "- The temporal relationship with RDP traffic can be measured."
echo "- TCP FIN/RST packets can establish observed connection termination evidence."
echo

echo "=== WHAT THE PCAP CANNOT PROVE BY ITSELF ==="

echo "- The password entered by the user, when authentication is encrypted."
echo "- The physical location of the person using the external IP."
echo "- The identity of the person operating the source system."
echo "- That VPN activity directly caused the subsequent RDP activity."
echo "- That the last observed packet represents the true application-level logout."
echo "- That an internal IP was assigned by the VPN unless assignment metadata is visible."
echo

echo "=== PIVOT ASSESSMENT ==="

if [[ -n "${FIRST_RDP:-}" && -n "$VPN_EPOCH" && -n "${RDP_EPOCH:-}" ]]; then
    if awk -v vpn="$VPN_EPOCH" -v rdp="$RDP_EPOCH" \
        'BEGIN { exit !(vpn < rdp) }'; then
        echo "The observed VPN session precedes the first observed RDP session."
        echo "This establishes a temporal relationship consistent with a possible"
        echo "external-to-internal pivot, but packet timing alone does not prove causation."
    else
        echo "The observed VPN session does not precede the first observed RDP session."
    fi
else
    echo "Insufficient observed timestamps to establish the VPN-to-RDP sequence."
fi
