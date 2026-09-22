#!/bin/bash
# 0-baseline_analysis.sh
# Usage: ./0-baseline_analysis.sh normal_baseline_clinical.pcap
#
# All PCAP analysis is performed with tshark.
# Filters and commands are printed for reproducibility.
# Timestamps are included with findings where applicable.

set -euo pipefail

PCAP="${1:?Usage: $0 <pcap-file>}"

[[ -f "$PCAP" ]] || { echo "ERROR: PCAP not found: $PCAP" >&2; exit 1; }
command -v tshark >/dev/null || { echo "ERROR: tshark is required." >&2; exit 1; }

run() {
    echo "# tshark $*"
    tshark "$@"
}

echo "=== PROTOCOL DISTRIBUTION ==="
echo '# Filter: ip.proto / ipv6.nxt'
run -r "$PCAP" -T fields -e ip.proto -e ipv6.nxt |
awk '
{
    p=($1 != "" ? $1 : $2)
    if (p=="6") tcp++
    else if (p=="17") udp++
    else if (p=="1" || p=="58") icmp++
    else other++
}
END {
    total=tcp+udp+icmp+other
    printf "TCP:   %.2f%% (%d packets)\n", 100*tcp/total,tcp
    printf "UDP:   %.2f%% (%d packets)\n", 100*udp/total,udp
    printf "ICMP:  %.2f%% (%d packets)\n", 100*icmp/total,icmp
    printf "Other: %.2f%% (%d packets)\n", 100*other/total,other
}'

echo
echo "=== APPLICATION BREAKDOWN ==="

for service in \
    "HTTPS|tcp.port == 443" \
    "DNS|dns" \
    "Kerberos|tcp.port == 88 || udp.port == 88" \
    "LDAP|tcp.port == 389 || udp.port == 389" \
    "SMB|tcp.port == 445" \
    "NTP|udp.port == 123" \
    "Printing|tcp.port == 9100"
do
    name="${service%%|*}"
    filter="${service#*|}"

    echo "# $name: $filter"

    run -r "$PCAP" -Y "$filter" -T fields -e frame.number |
        wc -l |
        awk -v n="$name" '{printf "%-15s %d packets\n", n ":", $1}'
done

echo
echo "=== TOP 10 SOURCE IPS BY BYTES ==="
echo '# tshark fields: frame.time_epoch ip.src frame.len'
run -r "$PCAP" -T fields \
    -e frame.time_epoch -e ip.src -e frame.len |
awk -F '\t' '$2 { bytes[$2]+=$3; first[$2]=first[$2]?$first[$2]:$1; last[$2]=$1 }
END { for (ip in bytes) print bytes[ip],ip,first[ip],last[ip] }' |
sort -nr | head -10 |
awk '{printf "%2d. %-15s %.2f MB  first=%s last=%s\n",NR,$2,$1/1048576,$3,$4}'

echo
echo "=== TOP 10 DESTINATIONS BY CONNECTION TUPLES ==="
echo '# Connection = unique source IP + destination IP + destination port'
run -r "$PCAP" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport |
awk -F '\t' '
$2 && $3 {
    port=($4 ? $4 : $5)
    key=$2 "|" $3 "|" port
    if (!seen[key]++) {
        count[$3]++
        first[$3]=first[$3]?$first[$3]:$1
        last[$3]=$1
    }
}
END { for (ip in count) print count[ip],ip,first[ip],last[ip] }' |
sort -nr | head -10 |
awk '{printf "%2d. %-15s %d connections  first=%s last=%s\n",NR,$2,$1,$3,$4}'

echo
echo "=== DNS QUERY PROFILE ==="
DNS_FILTER='dns.flags.response == 0 && dns.qry.name'
echo "# Filter: $DNS_FILTER"

run -r "$PCAP" -Y "$DNS_FILTER" -T fields \
    -e frame.time_epoch -e dns.qry.name -e dns.qry.type |
tee /tmp/baseline_dns.tsv >/dev/null

echo "Top 20 domains:"
awk -F '\t' '$2 {count[$2]++} END {for (d in count) print count[d],d}' \
    /tmp/baseline_dns.tsv |
sort -nr | head -20

echo
echo "Query types:"
awk -F '\t' '$3 {count[$3]++} END {for (t in count) print t,count[t]}' \
    /tmp/baseline_dns.tsv | sort -k2nr

echo
echo "TXT queries:"
awk -F '\t' '$3 == 16 {print}' /tmp/baseline_dns.tsv

echo
echo "=== TCP CONNECTION DURATION ==="
echo '# tshark fields: frame.time_epoch tcp.stream'
run -r "$PCAP" -Y "tcp.stream" -T fields \
    -e frame.time_epoch -e tcp.stream |
awk -F '\t' '
{
    if (!( $2 in first )) first[$2]=$1
    last[$2]=$1
}
END {
    for (s in first) {
        d=last[s]-first[s]
        if (d < 1) short++
        else if (d <= 30) medium++
        else long++
    }
    printf "Short (<1s):   %d\n",short
    printf "Medium (1-30s): %d\n",medium
    printf "Long (>30s):   %d\n",long
}'

echo
echo "=== TLS ==="

for filter in \
    "SNI|tls.handshake.extensions_server_name" \
    "TLS versions|tls.handshake.version" \
    "Certificate issuers|x509ce.issuer"
do
    name="${filter%%|*}"
    field="${filter#*|}"

    echo
    echo "$name:"
    echo "# Filter: $field"

    run -r "$PCAP" -Y "$field" -T fields \
        -e frame.time_epoch -e "$field" |
        sort -u
done

echo
echo "=== TRAFFIC PER MINUTE ==="
echo '# tshark fields: frame.time_epoch frame.len'
run -r "$PCAP" -T fields -e frame.time_epoch -e frame.len |
awk '
NR==1 {start=$1}
{
    minute=int(($1-start)/60)
    packets[minute]++
    bytes[minute]+=$2
}
END {
    for (m in packets)
        printf "%02d min: %d packets, %d bytes\n",m,packets[m],bytes[m]
}' | sort -n

echo
echo "=== BASELINE SIGNATURES ==="
echo "Normal DNS rate: calculated from DNS query timestamps above."
echo "Normal TXT rate: calculated from TXT queries above."
echo "Normal packet volume: see per-minute traffic above."
echo "Known-good services: see application breakdown and destination list above."
echo "External connection rhythm: see destination timestamps above."

echo
echo "=== BASELINE SAVED ==="
echo "The terminal output is the reproducible baseline."
