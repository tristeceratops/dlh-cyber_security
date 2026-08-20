#!/bin/bash
set -euo pipefail

PCAP="${1:-/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap}"
JSON="pcap_findings.json"

[[ -f "$PCAP" ]] || { echo "[!] PCAP not found: $PCAP" >&2; exit 1; }

bytes() {
    awk -v n="$1" 'BEGIN {
        if (n >= 1048576) printf "%.1f MB", n/1048576
        else if (n >= 1024) printf "%.0f KB", n/1024
        else printf "%d B", n
    }'
}

num() {
    printf "%s" "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

count() {
    awk 'NF { n++ } END { print n+0 }'
}

# PCAP stats
read -r START END PACKETS < <(
    tshark -r "$PCAP" -T fields -e frame.time_epoch |
    awk 'NR==1{s=$1}{e=$1;n++}END{printf "%.6f %.6f %d\n",s,e,n}'
)
DURATION=$(awk -v a="$START" -v b="$END" 'BEGIN{printf "%.2f",b-a}')

printf '[*] PCAP: %s\n' "$PCAP"
printf '[*] Duration: %s s     Packets: %s\n' "$DURATION" "$(num "$PACKETS")"

# Tshark extractions
## tshark -q -z conv,tcp
TCP=$(tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null)
## tshark -q -z conv,udp
UDP=$(tshark -r "$PCAP" -q -z conv,udp 2>/dev/null)
## tshark -Y dns.flags.response==0 -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type
DNS=$(tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields \
    -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null)
## tshark -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri
HTTP=$(tshark -r "$PCAP" -Y http.request -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e http.host \
    -e http.request.method -e http.request.uri 2>/dev/null)
## tshark -Y tls.handshake.type==1 -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
TLS=$(tshark -r "$PCAP" -Y 'tls.handshake.type==1' -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst \
    -e tls.handshake.extensions_server_name 2>/dev/null)
## tshark -Y "http.content_type or smb2.filename" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename
FILES=$(tshark -r "$PCAP" -Y 'http.content_type or smb2.filename' -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst \
    -e http.file_data -e smb2.filename 2>/dev/null)

TC=$(printf '%s\n' "$TCP" | awk '/<->/{n++}END{print n+0}')
UC=$(printf '%s\n' "$UDP" | awk '/<->/{n++}END{print n+0}')
DC=$(printf '%s\n' "$DNS" | count)
HC=$(printf '%s\n' "$HTTP" | count)
TLSC=$(printf '%s\n' "$TLS" | count)
FC=$(printf '%s\n' "$FILES" | count)

printf '[*] Extracting TCP conversations...      (%s)\n' "$TC"
printf '[*] Extracting UDP conversations...      (%s)\n' "$UC"
printf '[*] Extracting DNS queries...            (%s)\n' "$DC"
printf '[*] Extracting HTTP requests...          (%s)\n' "$HC"
printf '[*] Extracting TLS SNI...                (%s)\n' "$TLSC"
printf '[*] Extracting file transfers...         (%s)\n' "$FC"

# Protocol distribution
## tshark -q -z io,phs
read -r TP UP IP OP TOTAL < <(
    tshark -r "$PCAP" -T fields -e _ws.col.Protocol 2>/dev/null |
    awk '
        {p=tolower($1)
         if(p=="tcp")t++
         else if(p=="udp")u++
         else if(p=="icmp"||p=="icmpv6")i++
         else o++}
        END{printf "%d %d %d %d %d\n",t,u,i,o,t+u+i+o}'
)

pct() { awk -v n="$1" -v t="$TOTAL" 'BEGIN{printf "%.0f",t?n*100/t:0}'; }

TCP_P=$(pct "$TP")
UDP_P=$(pct "$UP")
ICMP_P=$(pct "$IP")
OTHER_P=$(pct "$OP")

printf '[*] Protocol distribution...             (tcp %s%%, udp %s%%, icmp %s%%, other %s%%)\n' \
    "$TCP_P" "$UDP_P" "$ICMP_P" "$OTHER_P"

# Top conversations
TOP=$(
    {
        printf '%s\n' "$TCP" | awk '/<->/ {
            gsub(/,/,"")
            if($10~/^[0-9]+$/&&$11~/^[0-9]+$/)
                print $10,$11,"tcp",$1,$3
        }'
        printf '%s\n' "$UDP" | awk '/<->/ {
            gsub(/,/,"")
            if($10~/^[0-9]+$/&&$11~/^[0-9]+$/)
                print $10,$11,"udp",$1,$3
        }'
    } | sort -nr | head -5
)

echo
# top 10
echo "Top conversations:"
while read -r pkts b proto src dst; do
    [[ -n "$pkts" ]] || continue
    printf '  %-31s %-4s %6s pkts  %8s\n' \
        "$src <-> $dst" "$proto" "$(num "$pkts")" "$(bytes "$b")"
done <<< "$TOP"

# Long DNS labels
LONG_DNS=$(printf '%s\n' "$DNS" | awk -F'\t' '
    NF>=3 {
        q=$3; sub(/\.$/,"",q); split(q,a,".")
        if(length(a[1])>50) print $3 "\t" length(a[1])
    }' | sort -u)

echo
echo "Long DNS labels (> 50 chars):"
if [[ -n "$LONG_DNS" ]]; then
    while IFS=$'\t' read -r q len; do
        printf '  %-65s (%d chars)\n' "$q" "$len"
    done <<< "$LONG_DNS"
else
    echo "  (none)"
fi

# JSON insteaed of jq
python3 - "$PCAP" "$DURATION" "$PACKETS" \
    "$TCP" "$UDP" "$DNS" "$HTTP" "$TLS" "$FILES" \
    "$TCP_P" "$UDP_P" "$ICMP_P" "$OTHER_P" "$LONG_DNS" <<'PY'
import json, sys

(
    pcap, duration, packets, tcp, udp, dns, http, tls, files,
    tcp_p, udp_p, icmp_p, other_p, long_dns
) = sys.argv[1:]

def rows(s):
    return [x.split("\t") for x in s.splitlines() if x.strip()]

def fields(s, names):
    return [dict(zip(names, r)) for r in rows(s)]

def conv(s, proto):
    out = []
    for r in s.splitlines():
        if "<->" not in r: continue
        p = r.split()
        try:
            out.append({
                "src": p[0], "dst": p[2], "protocol": proto,
                "packets": int(p[9]), "bytes": int(p[10].replace(",",""))
            })
        except (ValueError, IndexError):
            pass
    return out

def dns_long(s):
    return [
        {"query": r[0], "leftmost_label_length": int(r[1])}
        for r in rows(s) if len(r) >= 2
    ]

data = {
    "pcap": pcap,
    "duration_seconds": float(duration),
    "packets": int(packets),
    "tcp_conversations": conv(tcp, "tcp"),
    "udp_conversations": conv(udp, "udp"),
    "dns_queries": fields(dns, ["timestamp","src","query","type"]),
    "http_requests": fields(http, ["timestamp","src","dst","host","method","uri"]),
    "tls_sni": fields(tls, ["timestamp","src","dst","sni"]),
    "file_transfers": fields(files, ["timestamp","src","dst","http_file_data","smb2_filename"]),
    "protocol_distribution": {
        "tcp_percent": int(tcp_p),
        "udp_percent": int(udp_p),
        "icmp_percent": int(icmp_p),
        "other_percent": int(other_p)
    },
    "long_dns_labels": dns_long(long_dns)
}

with open("pcap_findings.json", "w") as f:
    json.dump(data, f, indent=2)

print("[*] Findings written to pcap_findings.json")
PY

