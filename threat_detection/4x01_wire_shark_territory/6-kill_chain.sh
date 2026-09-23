#!/bin/bash
set -uo pipefail

PCAP_CLICK="phishing_click.pcap"
PCAP_C2="c2_beaconing.pcap"
PCAP_EXFIL="dns_exfil.pcap"
PCAP_LATERAL="lateral_movement.pcap"
PCAP_FULL="full_timeline.pcap"
CTX="../4x00_phishing_dissection/11-ioc_extraction.md"

for f in "$PCAP_CLICK" "$PCAP_C2" "$PCAP_EXFIL" "$PCAP_LATERAL" "$PCAP_FULL" "$CTX"; do
    [[ -f "$f" ]] || { echo "ERROR: missing $f" >&2; exit 1; }
done

count() {
    tshark -r "$1" -Y "$2" 2>/dev/null | wc -l
}

fields() {
    tshark -r "$1" -Y "$2" -T fields -E separator='|' \
        -e frame.number -e frame.time -e frame.time_epoch \
        -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
        -e tcp.flags -e dns.qry.name \
        -e tls.handshake.extensions_server_name 2>/dev/null || true
}

echo "================================================================"
echo "   COMPLETE KILL CHAIN RECONSTRUCTION"
echo "   Incident: Phishing -> Network Compromise -> DNS Exfiltration"
echo "================================================================"

# ================================================================
# PHASE 1
# ================================================================
echo
echo "PHASE 1: INITIAL ACCESS"
echo "MITRE: T1566.002 - Phishing: Spearphishing Link"
echo "Evidence: 4x00 phishing investigation context"
echo "Status: CONTEXT, NOT PCAP EVIDENCE"
echo "Email: E2"
echo "Sender: noreply@meddefense-portal.com"
echo "Recipient: dmarsh@meddefense.com"
echo "Sending IP: 91.234.99.107"
echo "Authentication: SPF fail / DKIM none / DMARC fail"
echo "Defense tested: email authentication / anti-phishing policy"
echo "Inference: E2 is the reported initial-access phishing message."

# ================================================================
# PHASE 2
# ================================================================
CLICK_DNS='dns.qry.name == "meddefense-portal.com"'
CLICK_TLS='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tcp.dstport == 443'
CLICK_SNI='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tls.handshake.extensions_server_name == "meddefense-portal.com"'
CLICK_REC='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tls.record.length'

echo
echo "PHASE 2: CREDENTIAL-HARVESTING SESSION"
echo "MITRE: T1056.003 - Input Capture: Web Portal Capture"
echo "PCAP: $PCAP_CLICK"

echo "DNS filter: $CLICK_DNS"
fields "$PCAP_CLICK" "$CLICK_DNS" | head -2

echo "TLS filter: $CLICK_TLS"
echo "TLS packets: $(count "$PCAP_CLICK" "$CLICK_TLS")"

echo "TLS/SNI filter: $CLICK_SNI"
fields "$PCAP_CLICK" "$CLICK_SNI" | head -3

MAX_TLS=$(
    tshark -r "$PCAP_CLICK" -Y "$CLICK_REC" \
        -T fields -e tls.record.length 2>/dev/null |
    awk 'NF && $1 ~ /^[0-9]+$/ {if($1>m)m=$1} END{print m+0}'
)

MAX_TIME=$(
    tshark -r "$PCAP_CLICK" -Y "$CLICK_REC" \
        -T fields -E separator='|' \
        -e frame.time -e tls.record.length 2>/dev/null |
    awk -F'|' -v m="$MAX_TLS" '$2==m{print $1;exit}'
)

echo "TLS record filter: $CLICK_REC"
echo "Largest observed TLS record: ${MAX_TLS} bytes"
[[ -n "$MAX_TIME" ]] && echo "Largest-record timestamp: $MAX_TIME"
echo "Confirmed: WS-NURSE-04 contacted 91.234.99.107."
echo "Inference: encrypted traffic is consistent with portal interaction."
echo "Unconfirmed: plaintext credentials and successful submission."
echo "Defense tested: user click / TLS encryption."

# ================================================================
# PHASE 3
# ================================================================
C2_TCP='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tcp.dstport == 443'
C2_SNI='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tls.handshake.extensions_server_name == "meddefense-portal.com"'
C2_SYN='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tcp.dstport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 0'

echo
echo "PHASE 3: BEACONING"
echo "MITRE: T1071.001 - Application Layer Protocol: Web Protocols"
echo "PCAP: $PCAP_C2"

echo "TCP/443 filter: $C2_TCP"
echo "Observed TCP/443 packets: $(count "$PCAP_C2" "$C2_TCP")"

echo "SYN filter: $C2_SYN"
SYN_COUNT=$(count "$PCAP_C2" "$C2_SYN")
echo "Observed SYN connection starts: $SYN_COUNT"

echo "TLS/SNI filter: $C2_SNI"
fields "$PCAP_C2" "$C2_SNI" | head -24

C2_TIMES=$(
    tshark -r "$PCAP_C2" -Y "$C2_SNI" \
        -T fields -e frame.time_epoch 2>/dev/null || true
)

if [[ -n "$C2_TIMES" ]]; then
    echo "$C2_TIMES" |
        awk '
        NR==1 {first=$1;prev=$1}
        NR>1 {
            d=$1-prev
            sum+=d;n++
            if(min==""||d<min)min=d
            if(d>max)max=d
            prev=$1
        }
        END {
            if(n)
                printf "Observed interval: average %.1fs, minimum %.1fs, maximum %.1fs\n",
                       sum/n,min,max
            else
                print "Only one matching session timestamp observed."
        }'
fi

echo "Confirmed: repeated TCP/443 communications with the same external host."
echo "Inference: repeated timing and SNI are consistent with automated beaconing."
echo "Defense tested: encrypted outbound traffic / beaconing visibility."

# ================================================================
# PHASE 4
# ================================================================
VPN='ip.src == "154.118.42.89" && ip.dst == "10.10.0.1" && tcp.dstport == 443'

echo
echo "PHASE 4: EXTERNAL ACCESS / VPN PIVOT"
echo "MITRE: T1133 - External Remote Services"
echo "PCAP: $PCAP_FULL"
echo "Filter: $VPN"

VPN_COUNT=$(count "$PCAP_FULL" "$VPN")
echo "Observed VPN TCP/443 packets: $VPN_COUNT"
fields "$PCAP_FULL" "$VPN" | head -8

echo "Confirmed: 154.118.42.89 generated TCP/443 activity toward 10.10.0.1."
echo "Unconfirmed: VPN authentication, account identity, and MFA result."
echo "Defense tested: VPN authentication / remote-access controls."

# ================================================================
# PHASE 5
# ================================================================
RDP='ip.src == "10.10.2.15" && ip.dst == "10.10.1.10" && tcp.dstport == 3389'

echo
echo "PHASE 5: LATERAL MOVEMENT"
echo "MITRE: T1021.001 - Remote Services: RDP"
echo "PCAP: $PCAP_LATERAL"
echo "Filter: $RDP"

RDP_COUNT=$(count "$PCAP_LATERAL" "$RDP")
echo "Observed TCP/3389 packets: $RDP_COUNT"
fields "$PCAP_LATERAL" "$RDP" | head -6

echo "RDP dissector filter: rdp"
echo "Protocol-decoded RDP packets: $(count "$PCAP_LATERAL" 'rdp')"

echo "Confirmed: TCP/3389 activity from WS-NURSE-04 toward billing-srv-01."
echo "Inference: traffic is consistent with RDP."
echo "Unconfirmed: authenticated account and successful interactive logon."
echo "Defense tested: RDP access controls."

# ================================================================
# PHASE 6
# ================================================================
SMB='tcp.port == 445'
RESET='tcp.port == 445 && tcp.flags.reset == 1'

echo
echo "PHASE 6: SMB / INTERNAL DISCOVERY"
echo "MITRE: T1021.002 - Remote Services: SMB/Windows Admin Shares"
echo "Additional context: T1135 - Network Share Discovery"
echo "PCAP: $PCAP_LATERAL"

SMB_COUNT=$(count "$PCAP_LATERAL" "$SMB")
RESET_COUNT=$(count "$PCAP_LATERAL" "$RESET")

echo "TCP/445 filter: $SMB"
echo "Observed TCP/445 packets: $SMB_COUNT"
fields "$PCAP_LATERAL" "$SMB" | head -18

echo "Reset filter: $RESET"
echo "Observed TCP/445 reset packets: $RESET_COUNT"
fields "$PCAP_LATERAL" "$RESET" | head -6

echo "SMB dissector filter: smb || smb2"
echo "Protocol-decoded SMB packets: $(count "$PCAP_LATERAL" 'smb || smb2')"

echo "Confirmed: TCP/445 activity and reset events were observed."
echo "Unconfirmed: share enumeration, directory listing, file access, SMB authentication."
echo "Defense tested: internal SMB/access controls."

# ================================================================
# PHASE 7
# ================================================================
TXT='dns.qry.type == 16 && dns.qry.name'
EXFIL='dns.qry.type == 16 && dns.qry.name contains "data-sync.meddefense-portal.com"'

echo
echo "PHASE 7: DNS EXFILTRATION"
echo "MITRE: T1048.003 - Exfiltration Over Alternative Protocol: DNS"
echo "PCAP: $PCAP_EXFIL"

TXT_COUNT=$(count "$PCAP_EXFIL" "$TXT")
EXFIL_COUNT=$(count "$PCAP_EXFIL" "$EXFIL")

echo "TXT-query filter: $TXT"
echo "Observed TXT packets: $TXT_COUNT"
echo "Exfil-domain filter: $EXFIL"
echo "Observed exfil-domain packets: $EXFIL_COUNT"

EXFIL_ROWS=$(
    tshark -r "$PCAP_EXFIL" -Y "$EXFIL" \
        -T fields -E separator='|' \
        -e frame.number -e frame.time -e frame.time_epoch \
        -e ip.src -e ip.dst -e dns.qry.name 2>/dev/null || true
)

echo "First matching query:"
echo "$EXFIL_ROWS" |
    awk -F'|' '$4=="10.10.1.10"{print;exit}'

echo "Last matching query:"
echo "$EXFIL_ROWS" |
    awk -F'|' '$4=="10.10.1.10"{last=$0}END{print last}'

echo "Encoded-label statistics:"
echo "$EXFIL_ROWS" |
    awk -F'|' '
    $4=="10.10.1.10" {
        n=$6
        sub(/\.data-sync\.meddefense-portal\.com$/,"",n)
        l=length(n)
        if(l){sum+=l;count++;if(l>max)max=l}
    }
    END {
        if(count)
            printf "Average label length: %.1f chars\nMaximum label length: %d chars\n",
                   sum/count,max
        else
            print "No label-length data available."
    }'

echo "Confirmed: repeated DNS queries occurred beneath data-sync.meddefense-portal.com."
echo "Inference: long encoded-looking labels are consistent with DNS tunneling/exfiltration."
echo "Unconfirmed: exact plaintext dataset, successful receipt, and byte volume."
echo "Defense tested: DNS monitoring / egress inspection."

# ================================================================
# DWELL TIME
# ================================================================
FIRST=$(
    tshark -r "$PCAP_CLICK" -Y "$CLICK_DNS" \
        -T fields -e frame.time_epoch 2>/dev/null | head -1
)

LAST=$(
    tshark -r "$PCAP_EXFIL" -Y "$EXFIL" \
        -T fields -e frame.time_epoch -e ip.src 2>/dev/null |
    awk '$2=="10.10.1.10"{last=$1}END{print last}'
)

FIRST_TIME=$(
    tshark -r "$PCAP_CLICK" -Y "$CLICK_DNS" \
        -T fields -e frame.time 2>/dev/null | head -1
)

LAST_TIME=$(
    tshark -r "$PCAP_EXFIL" -Y "$EXFIL" \
        -T fields -E separator='|' \
        -e frame.time -e ip.src 2>/dev/null |
    awk -F'|' '$2=="10.10.1.10"{last=$1}END{print last}'
)

echo
echo "================================================================"
echo "DWELL TIME"
echo "================================================================"

if [[ -n "$FIRST" && -n "$LAST" ]]; then
    awk -v a="$FIRST" -v b="$LAST" '
    BEGIN {
        d=int(b-a+0.5)
        days=int(d/86400);d%=86400
        h=int(d/3600);d%=3600
        m=int(d/60);s=d%60
        printf "First known access-related activity: %s\n", ENVIRON["FIRST_TIME"]
        printf "Last observed exfiltration activity: %s\n", ENVIRON["LAST_TIME"]
        printf "Observed dwell time: %dd %02dh %02dm %02ds\n",days,h,m,s
    }'
else
    echo "Dwell time could not be calculated."
fi

# ================================================================
# MASTER TIMELINE
# ================================================================
echo
echo "================================================================"
echo "MASTER TIMELINE"
echo "================================================================"
printf "%-16s %-9s %-22s %-31s %-15s %-15s %s\n" \
"EPOCH" "PHASE" "PCAP" "TIMESTAMP" "SOURCE" "DESTINATION" "EVIDENCE"

TMP=$(mktemp)

# Phase 1: email context is deliberately not given a fake packet timestamp.
printf "%s\n" \
"CONTEXT|PHASE 1|4x00 phishing context|Email E2|dmarsh@meddefense.com|noreply@meddefense-portal.com|SPF fail / DMARC fail" \
>> "$TMP"

# Phase 2
tshark -r "$PCAP_CLICK" -Y "$CLICK_DNS" \
    -T fields -E separator='|' \
    -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
    -e dns.qry.name 2>/dev/null |
head -2 |
awk -F'|' '{print $1"|PHASE 2|phishing_click.pcap|" $2 "|" $3 "|" $4 "|DNS " $5}' >> "$TMP"

tshark -r "$PCAP_CLICK" -Y "$CLICK_SNI" \
    -T fields -E separator='|' \
    -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
    -e tls.handshake.extensions_server_name 2>/dev/null |
head -1 |
awk -F'|' '{print $1"|PHASE 2|phishing_click.pcap|" $2 "|" $3 "|" $4 "|TLS SNI " $5}' >> "$TMP"

# Phase 3
tshark -r "$PCAP_C2" -Y "$C2_SNI" \
    -T fields -E separator='|' \
    -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
    -e tls.handshake.extensions_server_name 2>/dev/null |
head -24 |
awk -F'|' '{print $1"|PHASE 3|c2_beaconing.pcap|" $2 "|" $3 "|" $4 "|HTTPS/SNI " $5}' >> "$TMP"

# Phase 4
tshark -r "$PCAP_FULL" -Y "$VPN" \
    -T fields -E separator='|' \
    -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
    -e tcp.dstport -e tcp.flags 2>/dev/null |
head -8 |
awk -F'|' '{print $1"|PHASE 4|full_timeline.pcap|" $2 "|" $3 "|" $4 "|TCP/" $5 " flags=" $6}' >> "$TMP"

# Phase 5
tshark -r "$PCAP_LATERAL" -Y "$RDP" \
    -T fields -E separator='|' \
    -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
    -e tcp.dstport -e tcp.flags 2>/dev/null |
head -1 |
awk -F'|' '{print $1"|PHASE 5|lateral_movement.pcap|" $2 "|" $3 "|" $4 "|TCP/3389 flags=" $6}' >> "$TMP"

# Phase 6
tshark -r "$PCAP_LATERAL" -Y "$RESET" \
    -T fields -E separator='|' \
    -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
    -e tcp.dstport -e tcp.flags 2>/dev/null |
head -4 |
awk -F'|' '{print $1"|PHASE 6|lateral_movement.pcap|" $2 "|" $3 "|" $4 "|TCP/445 RESET flags=" $6}' >> "$TMP"

# Phase 7 - query direction only
tshark -r "$PCAP_EXFIL" -Y "$EXFIL" \
    -T fields -E separator='|' \
    -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
    -e dns.qry.name 2>/dev/null |
awk -F'|' '$3=="10.10.1.10"{print $1"|PHASE 7|dns_exfil.pcap|" $2 "|" $3 "|" $4 "|TXT " $5}' |
head -24 >> "$TMP"

sort -t'|' -k1,1n "$TMP" |
while IFS='|' read -r epoch phase pcap timestamp src dst evidence; do
    if [[ "$epoch" == "CONTEXT" ]]; then
        printf "%-16s %-9s %-22s %-31s %-15s %-15s %s\n" \
            "-" "$phase" "$pcap" "$timestamp" "$src" "$dst" "$evidence"
    else
        printf "%-16s %-9s %-22s %-31s %-15s %-15s %s\n" \
            "$epoch" "$phase" "$pcap" "$timestamp" "$src" "$dst" "$evidence"
    fi
done

rm -f "$TMP"

# ================================================================
# PIVOT POINTS
# ================================================================
echo
echo "================================================================"
echo "CRITICAL PIVOT POINTS"
echo "================================================================"
echo "1. Email authentication: SPF/DMARC failure was present in E2."
echo "2. User click: WS-NURSE-04 resolved the phishing domain."
echo "3. TLS session: workstation contacted 91.234.99.107 over TCP/443."
echo "4. Beaconing: repeated communications to the same external host."
echo "5. VPN: external TCP/443 activity reached 10.10.0.1."
echo "6. RDP: WS-NURSE-04 generated TCP/3389 traffic to billing-srv-01."
echo "7. SMB: TCP/445 activity and resets were observable."
echo "8. DNS exfiltration: repeated encoded-looking DNS labels were observed."
echo "These are analytical intervention opportunities, not proof of control failure."

# ================================================================
# IMPACT
# ================================================================
echo
echo "================================================================"
echo "IMPACT ASSESSMENT"
echo "================================================================"
echo "Confirmed systems with packet activity:"
echo "  WS-NURSE-04       10.10.2.15"
echo "  billing-srv-01    10.10.1.10"
echo "  VPN endpoint      10.10.0.1"
echo "  DNS server        10.10.1.1"
echo "  Phishing/C2 host  91.234.99.107"
echo "  External source   154.118.42.89"

echo
echo "Confirmed access/movement evidence:"
echo "  - phishing-domain DNS resolution"
echo "  - TLS communication with phishing infrastructure"
echo "  - repeated external TCP/443 communication"
echo "  - external TCP/443 activity toward VPN endpoint"
echo "  - WS-NURSE-04 -> billing-srv-01 TCP/3389"
echo "  - internal TCP/445 activity"
echo "  - repeated TXT DNS queries under exfiltration domain"

echo
echo "Likely data-transfer behavior:"
echo "  $EXFIL_COUNT packets matched the data-sync.meddefense-portal.com domain."
echo "  Long encoded-looking labels were observed."
echo "  Exact data content and successful receipt are unconfirmed."

echo
echo "Resisted / incomplete access evidence:"
echo "  - TCP/445 reset events"
echo "  - no protocol-decoded SMB evidence"
echo "  - no protocol-decoded RDP evidence"
echo "  - no proof of successful VPN authentication"

echo
echo "UNCONFIRMED:"
echo "  - plaintext credentials"
echo "  - successful credential submission"
echo "  - VPN authentication/account/MFA"
echo "  - successful RDP logon"
echo "  - SMB enumeration or file access"
echo "  - exact exfiltrated dataset"
echo "  - exact exfiltration byte volume"
echo "  - malware execution or persistence"

echo
echo "================================================================"
echo "CONFIRMED EVIDENCE vs ANALYTICAL INFERENCE"
echo "================================================================"
echo "CONFIRMED: packet fields, timestamps, IPs, ports, DNS names,"
echo "           TLS metadata, TCP flags and observed packet counts."
echo "INFERENCE: phishing, credential harvesting, beaconing, lateral"
echo "           movement, discovery and DNS exfiltration interpretation."
echo "UNCONFIRMED: authentication results, credentials, file access,"
echo "             exact data stolen and endpoint execution/persistence."
echo "================================================================"
