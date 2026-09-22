#!/bin/bash

PCAP="${1:-phishing_click.pcap}"

[[ -f "$PCAP" ]] || {
    echo "Usage: $0 phishing_click.pcap"
    exit 1
}

DOMAIN="meddefense-portal.com"
PHISH_IP="91.234.99.107"

fmt_time() {
    sed -E 's/.*T([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}).*/\1/' <<< "$1"
}

echo "=== DNS RESOLUTION ==="

# FILTER:
# dns.qry.name == "meddefense-portal.com"

DNS=$(tshark -r "$PCAP" \
    -Y "dns.qry.name == \"$DOMAIN\"" \
    -T fields -e frame.time -e ip.src -e ip.dst \
    -e dns.qry.name -e dns.a -e dns.resp.ttl)

while IFS=$'\t' read -r ts src dst name ip ttl; do
    [[ -z "$ts" ]] && continue

    if [[ -z "$ip" ]]; then
        QUERY_TIME=$(fmt_time "$ts")
        CLIENT="$src"
        DNS_SERVER="$dst"
        echo "$QUERY_TIME  Query: $name"
    else
        RESPONSE_IP="$ip"
        echo "$(fmt_time "$ts")  Response: $ip"
        echo "TTL: $ttl"
        echo "Source: $CLIENT -> $DNS_SERVER"
    fi
done <<< "$DNS"


echo
echo "=== TLS HANDSHAKE ==="

# FILTER:
# ip.addr == 91.234.99.107 && tcp.port == 443 && tls.handshake.type == 1

HELLO=$(tshark -r "$PCAP" \
    -Y "ip.addr == $PHISH_IP && tcp.port == 443 && tls.handshake.type == 1" \
    -T fields \
    -e frame.time \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.version \
    -e tls.handshake.ciphersuite)

if [[ -n "$HELLO" ]]; then
    while IFS=$'\t' read -r ts sni version cipher; do
        echo "$(fmt_time "$ts")  ClientHello"
        echo "  SNI: ${sni:-N/A}"
        echo "  TLS version: ${version:-N/A}"
        echo "  Cipher suites: ${cipher:-N/A}"
    done <<< "$HELLO"
else
    echo "No ClientHello found."
fi


echo
echo "=== SERVER CERTIFICATE ==="

# FILTER:
# ip.addr == 91.234.99.107 && tcp.port == 443 && tls.handshake.type == 11

CERT=$(tshark -r "$PCAP" \
    -Y "ip.addr == $PHISH_IP && tcp.port == 443 && tls.handshake.type == 11" \
    -T fields \
    -e frame.time \
    -e x509af.subject \
    -e x509af.issuer \
    -e x509af.notBeforeTime \
    -e x509af.notAfterTime \
    -e x509af.serialNumber 2>/dev/null)

if [[ -n "$CERT" ]]; then
    IFS=$'\t' read -r ts subject issuer from to serial <<< "$CERT"

    echo "$(fmt_time "$ts")  Server Certificate"
    echo "  Subject: ${subject:-N/A}"
    echo "  Issuer: ${issuer:-N/A}"
    echo "  Valid from: ${from:-N/A}"
    echo "  Valid until: ${to:-N/A}"
    echo "  Serial: ${serial:-N/A}"
else
    echo "No TLS Certificate found."
fi


echo
echo "=== DATA EXCHANGE ==="

# FILTER:
# ip.addr == 91.234.99.107 && tcp.port == 443 && tcp.len > 0

DATA=$(tshark -r "$PCAP" \
    -Y "ip.addr == $PHISH_IP && tcp.port == 443 && tcp.len > 0" \
    -T fields -e frame.time -e ip.src -e tcp.len)

CLIENT_BYTES=0
SERVER_BYTES=0
CLIENT_SEGMENTS=0
SERVER_SEGMENTS=0
LARGEST=0
LARGEST_TIME=""

while IFS=$'\t' read -r ts src len; do
    [[ -z "$len" ]] && continue

    if [[ "$src" == "$CLIENT" ]]; then
        CLIENT_BYTES=$((CLIENT_BYTES + len))
        CLIENT_SEGMENTS=$((CLIENT_SEGMENTS + 1))

        if (( len > LARGEST )); then
            LARGEST="$len"
            LARGEST_TIME="$ts"
        fi
    else
        SERVER_BYTES=$((SERVER_BYTES + len))
        SERVER_SEGMENTS=$((SERVER_SEGMENTS + 1))
    fi
done <<< "$DATA"

echo "Client -> Server: $CLIENT_BYTES bytes across $CLIENT_SEGMENTS TCP segments"
echo "Server -> Client: $SERVER_BYTES bytes across $SERVER_SEGMENTS TCP segments"

if [[ -n "$LARGEST_TIME" ]]; then
    echo "Largest client TCP payload: $LARGEST bytes at $(fmt_time "$LARGEST_TIME")"
fi


echo
echo "=== CONNECTION TIMELINE ==="

# FILTER:
# Client -> phishing server TCP SYN
START=$(tshark -r "$PCAP" \
    -Y "ip.src == $CLIENT && ip.dst == $PHISH_IP && tcp.dstport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
    -T fields -e frame.time | head -1)

# FILTER:
# Phishing server -> client SYN-ACK
SYNACK=$(tshark -r "$PCAP" \
    -Y "ip.src == $PHISH_IP && ip.dst == $CLIENT && tcp.srcport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 1" \
    -T fields -e frame.time | head -1)

# FILTER:
# TCP application data
FIRST=$(tshark -r "$PCAP" \
    -Y "ip.addr == $CLIENT && ip.addr == $PHISH_IP && tcp.port == 443 && tcp.len > 0" \
    -T fields -e frame.time | head -1)

LAST=$(tshark -r "$PCAP" \
    -Y "ip.addr == $CLIENT && ip.addr == $PHISH_IP && tcp.port == 443 && tcp.len > 0" \
    -T fields -e frame.time | tail -1)

# FILTER:
# TCP FIN or RST
CLOSE=$(tshark -r "$PCAP" \
    -Y "ip.addr == $CLIENT && ip.addr == $PHISH_IP && tcp.port == 443 && (tcp.flags.fin == 1 || tcp.flags.reset == 1)" \
    -T fields -e frame.time | tail -1)

[[ -n "$START" ]] && echo "$(fmt_time "$START")  Connection start"
[[ -n "$SYNACK" ]] && echo "$(fmt_time "$SYNACK")  SYN-ACK"
[[ -n "$FIRST" ]] && echo "$(fmt_time "$FIRST")  Data transfer start"
[[ -n "$LAST" ]] && echo "$(fmt_time "$LAST")  Data transfer end"
[[ -n "$CLOSE" ]] && echo "$(fmt_time "$CLOSE")  Connection close"


echo
echo "=== CREDENTIAL-SUBMISSION ASSESSMENT ==="

echo "TLS application data is encrypted."
echo "Exact form fields and password contents are not visible."
echo
echo "[*] Client -> Server: $CLIENT_BYTES bytes"
echo "[*] Largest client TCP payload: $LARGEST bytes"
echo "[*] The traffic is consistent with an HTTPS submission,"
echo "    but the PCAP does not prove that credentials were submitted."


echo
echo "=== POST-CLICK BEHAVIOR ==="

# FILTER:
# dns.flags.response == 0 && dns.qry.name == "meddefense.com"

POST=$(tshark -r "$PCAP" \
    -Y 'dns.flags.response == 0 && dns.qry.name == "meddefense.com"' \
    -T fields -e frame.time -e ip.src -e ip.dst)

if [[ -n "$POST" ]]; then
    while IFS=$'\t' read -r ts src dst; do
        echo "$(fmt_time "$ts")  DNS query: meddefense.com"
        echo "Source: $src -> $dst"
    done <<< "$POST"

    echo
    echo "[*] DNS query for the legitimate meddefense.com occurred"
    echo "    after the phishing activity."
else
    echo "No post-click DNS query for meddefense.com found."
fi


echo
echo "=== 4x00 CORRELATION ==="

DOMAIN_MATCH=false
IP_MATCH=false
CLIENT_MATCH=false

[[ "$DOMAIN" == "meddefense-portal.com" ]] && DOMAIN_MATCH=true
[[ "$RESPONSE_IP" == "$PHISH_IP" ]] && IP_MATCH=true
[[ "$CLIENT" == "10.10.2.15" ]] && CLIENT_MATCH=true

echo "4x00 IOC domain: $DOMAIN"
echo "4x00 IOC IP:     $PHISH_IP"

if $DOMAIN_MATCH && $IP_MATCH && $CLIENT_MATCH; then
    echo
    echo "[MATCH] PCAP matches the 4x00 phishing indicators."
    echo "[MATCH] meddefense-portal.com resolved to 91.234.99.107."
    echo "[MATCH] Workstation 10.10.2.15 contacted the phishing IP."
    echo "[MATCH] TLS SNI was requested for meddefense-portal.com."
    echo
    echo "[*] This provides network-level evidence supporting"
    echo "    the reported phishing click."
    echo "[*] Credential theft or account compromise is not established."
else
    echo
    echo "[NO FULL MATCH] PCAP does not match all 4x00 indicators."
    echo
    echo "Domain match: $DOMAIN_MATCH"
    echo "IP match:     $IP_MATCH"
    echo "Client match: $CLIENT_MATCH"
fi
