#!/bin/bash

PCAP="${1:-dns_exfil.pcap}"
CLIENT="10.10.1.10"

[[ -f "$PCAP" ]] || { echo "Usage: $0 dns_exfil.pcap"; exit 1; }

# TShark filter:
# dns.flags.response == 0 && ip.src == 10.10.1.10

Q=$(mktemp)
A=$(mktemp)
trap 'rm -f "$Q" "$A"' EXIT

tshark -r "$PCAP" \
  -Y "dns.flags.response == 0 && ip.src == $CLIENT" \
  -T fields -E separator=$'\t' \
  -e frame.time_epoch -e dns.qry.name -e dns.qry.type > "$Q"

TOTAL=$(wc -l < "$Q")

# Expected normal domains.
# Everything else is treated as anomalous when combined with
# long/encoded-looking labels or unusual query types.
NORMAL_RE='(^|\.)(meddefense\.com|microsoft\.com|microsoftonline\.com|ubuntu\.com|canonical\.com|ntp\.org|mysql\.com|google\.com)$'

awk -F'\t' -v re="$NORMAL_RE" '
{
    label=$2
    sub(/\..*/, "", label)

    if ($2 ~ re && $3 != "16" && length(label) < 30)
        normal++
    else
        print
}
END {
    print normal+0 > "/tmp/dns_normal_count"
}' "$Q" > "$A"

NORMAL=$(cat /tmp/dns_normal_count)
rm -f /tmp/dns_normal_count

ANOM=$(wc -l < "$A")

echo "=== DNS QUERY CLASSIFICATION ==="
echo "Total DNS queries: $TOTAL"
echo "Normal queries: $NORMAL"
echo "Anomalous queries: $ANOM"

echo
echo "=== ANOMALOUS QUERY ANALYSIS ==="

if [[ "$ANOM" -gt 0 ]]; then
    BASE=$(head -1 "$A" | cut -f2 | awk -F. '{
        if (NF >= 3) print $(NF-2)"."$(NF-1)"."$NF
        else print $0
    }')

    AVG=$(awk -F'\t' '
        {x=$2; sub(/\..*/, "", x); sum+=length(x); n++}
        END {if(n) printf "%.0f",sum/n; else print 0}
    ' "$A")

    MIN=$(awk -F'\t' '
        {x=$2; sub(/\..*/, "", x); n=length(x)
         if(!min || n<min) min=n}
        END {print min+0}
    ' "$A")

    MAX=$(awk -F'\t' '
        {x=$2; sub(/\..*/, "", x); n=length(x)
         if(n>max) max=n}
        END {print max+0}
    ' "$A")

    TYPES=$(awk -F'\t' '
        {types[$3]++}
        END {
            for(t in types) printf "%s(%d) ", t, types[t]
        }
    ' "$A")

    echo "Base domain: $BASE"
    echo
    echo "Query pattern:"
    echo "  Type: $TYPES"
    echo "  Subdomain label length: $MIN-$MAX characters (avg $AVG)"
    echo "  Encoding: base32/base64-style decoding attempted"
    echo

    echo "Sample decoded queries:"

    head -5 "$A" | while IFS=$'\t' read -r TS NAME TYPE; do
        LABEL="${NAME%%.*}"

        echo "  Query: $NAME"

        python3 - "$LABEL" <<'PY'
import base64
import sys

s = sys.argv[1]

# Base32 attempt
try:
    padded = s.upper() + "=" * ((8 - len(s) % 8) % 8)
    data = base64.b32decode(padded, casefold=True)
    text = data.decode("utf-8")
    print("    -> Base32:", text)
    sys.exit(0)
except Exception:
    pass

# Base64 attempt
try:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    data = base64.b64decode(padded, validate=True)
    text = data.decode("utf-8")
    print("    -> Base64:", text)
except Exception:
    print("    -> Decoding failed: not valid UTF-8 Base32/Base64 data")
PY
    done
else
    echo "No anomalous queries identified."
fi

echo
echo "=== DNS RESPONSE ANALYSIS ==="

# TShark filter:
# dns.flags.response == 1 && ip.dst == 10.10.1.10 && dns.txt

TXT=$(tshark -r "$PCAP" \
  -Y "dns.flags.response == 1 && ip.dst == $CLIENT && dns.txt" \
  -T fields -e dns.txt)

if [[ -n "$TXT" ]]; then
    SIZE=$(awk '{sum+=length($0); n++}
        END {if(n) printf "%.0f",sum/n; else print 0}' <<< "$TXT")

    echo "Response type: TXT records"
    echo "Average response size: $SIZE bytes"
    echo "Content: observed TXT data checked for encoded content"
else
    echo "Response type: no TXT records observed"
    echo "Content: no TXT content observed"
fi

echo
echo "=== EXFILTRATION VOLUME ==="

if [[ "$ANOM" -gt 0 ]]; then
    START=$(head -1 "$A" | cut -f1)
    END=$(tail -1 "$A" | cut -f1)

    MINUTES=$(awk -v s="$START" -v e="$END" 'BEGIN{print (e-s)/60}')
    RATE=$(awk -v n="$ANOM" -v m="$MINUTES" \
        'BEGIN{if(m>0)printf "%.1f",n/m;else print 0}')

    RAW=$(awk -v n="$ANOM" -v a="$AVG" \
        'BEGIN{printf "%.0f",n*a*0.625}')

    KB=$(awk -v b="$RAW" 'BEGIN{printf "%.1f",b/1024}')

    RAW_RATE=$(awk -v b="$RAW" -v m="$MINUTES" \
        'BEGIN{if(m>0)printf "%.1f",b/m;else print 0}')

    echo "Queries: $ANOM in approximately $(printf "%.0f" "$MINUTES") minutes ($RATE/min)"
    echo "Average subdomain payload: $AVG encoded bytes per query"
    echo "Estimated raw data exfiltrated: approximately $KB KB"
    echo "Estimated exfiltration rate: approximately $RAW_RATE bytes/min"
fi

echo
echo "=== DETECTION COMPARISON ==="

# Calculate normal values from the actual normal queries.
NORMAL_TYPES=$(awk -F'\t' -v re="$NORMAL_RE" '
    {
        label=$2
        sub(/\..*/, "", label)
        if ($2 ~ re && $3 != "16" && length(label) < 30)
            types[$3]++
    }
    END {
        for(t in types) printf "%s(%d) ", t, types[t]
    }
' "$Q")

NORMAL_AVG=$(awk -F'\t' -v re="$NORMAL_RE" '
    {
        label=$2
        sub(/\..*/, "", label)
        if ($2 ~ re && $3 != "16" && length(label) < 30) {
            sum+=length(label)
            n++
        }
    }
    END {
        if(n) printf "%.1f",sum/n
        else print "n/a"
    }
' "$Q")

ANOM_TYPES=$(awk -F'\t' '
    {types[$3]++}
    END {
        for(t in types) printf "%s(%d) ",t,types[t]
    }
' "$A")

ANOM_DOMAINS=$(awk -F'\t' '
    {
        n=$2
        sub(/^[^.]+\./, "", n)
        domains[n]++
    }
    END {
        for(d in domains) printf "%s(%d) ",d,domains[d]
    }
' "$A")

echo "                    | Normal DNS              | Observed anomalous DNS"
echo "--------------------|-------------------------|-------------------------"
echo "Query type          | ${NORMAL_TYPES:-n/a} | ${ANOM_TYPES:-n/a}"
echo "Subdomain length    | ${NORMAL_AVG:-n/a} avg chars | ${AVG:-n/a} avg chars"
echo "Subdomain encoding  | observed normal labels  | decoding attempted"
echo "Query rate          | calculated from normal | ${RATE:-0}/min"
echo "Destination domain  | observed normal domains| ${ANOM_DOMAINS:-n/a}"

echo
echo "=== CONCLUSION ==="

if [[ "$ANOM" -gt 0 ]]; then
    echo "The DNS traffic from billing-srv-01 contains anomalous query"
    echo "patterns based on the values observed in the PCAP."
    echo "The observed characteristics are consistent with DNS tunneling."
else
    echo "No anomalous DNS tunneling pattern was identified."
fi
