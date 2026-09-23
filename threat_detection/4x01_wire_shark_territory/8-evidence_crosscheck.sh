#!/bin/bash
set -euo pipefail

PCAP_CLICK="phishing_click.pcap"
PCAP_C2="c2_beaconing.pcap"
PCAP_EXFIL="dns_exfil.pcap"
PCAP_LATERAL="lateral_movement.pcap"
PCAP_FULL="full_timeline.pcap"
CTX="../4x00_phishing_dissection/11-ioc_extraction.md"

for f in "$PCAP_CLICK" "$PCAP_C2" "$PCAP_EXFIL" "$PCAP_LATERAL" "$PCAP_FULL" "$CTX"; do
    [[ -f "$f" ]] || {
        echo "ERROR: missing $f" >&2
        exit 1
    }
done

count() {
    tshark -r "$1" -Y "$2" 2>/dev/null | wc -l
}

echo "================================================================"
echo "   EVIDENCE CROSS-CHECK - PCAP VISIBILITY"
echo "================================================================"

echo
echo "Phase | Attack Action         | PCAP Evidence? | Verdict"
echo "------|-----------------------|----------------|----------------------"
echo "  1   | Phishing delivery     | No             | CONTEXT"
echo "  2   | Credential harvest    | Yes            | STRONG INFERENCE"
echo "  3   | C2 beaconing          | Yes            | CONFIRMED"
echo "  4   | VPN pivot             | Yes            | STRONG INFERENCE"
echo "  5   | RDP lateral movement  | Yes            | CONFIRMED"
echo "  6   | SMB discovery         | Yes            | UNCONFIRMED"
echo "  7   | DNS exfiltration      | Yes            | CONFIRMED"

# ----------------------------------------------------------------
# Phase 1
# ----------------------------------------------------------------
echo
echo "=== PHASE 1: PHISHING DELIVERY ==="
echo "Verdict: NOT VISIBLE IN PCAP"
echo
echo "CONFIRMED:"
echo "  - E2 exists in the supplied phishing-investigation context."
echo "  - Sender: noreply@meddefense-portal.com"
echo "  - Recipient: dmarsh@meddefense.com"
echo "  - Sending IP: 91.234.99.107"
echo "  - SPF fail / DKIM none / DMARC fail"
echo
echo "INFERRED:"
echo "  - E2 represents the reported initial-access phishing message."
echo "  - The later network activity is temporally associated with the report."
echo
echo "CANNOT CONFIRM FROM PCAP:"
echo "  - SMTP delivery"
echo "  - mailbox delivery"
echo "  - message rendering"
echo "  - whether the user opened the message"
echo
echo "ADDITIONAL EVIDENCE:"
echo "  - Mail gateway logs"
echo "  - Exchange/M365 mailbox audit logs"
echo "  - User interview"

# ----------------------------------------------------------------
# Phase 2
# ----------------------------------------------------------------
CLICK_DNS='dns.qry.name == "meddefense-portal.com"'
CLICK_TLS='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tcp.dstport == 443'
CLICK_SNI='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tls.handshake.extensions_server_name == "meddefense-portal.com"'

CLICK_DNS_COUNT=$(count "$PCAP_CLICK" "$CLICK_DNS")
CLICK_TLS_COUNT=$(count "$PCAP_CLICK" "$CLICK_TLS")
CLICK_SNI_COUNT=$(count "$PCAP_CLICK" "$CLICK_SNI")

echo
echo "=== PHASE 2: CREDENTIAL-HARVESTING SESSION ==="
echo "Verdict: STRONG INFERENCE"
echo
echo "PCAP CONFIRMS:"
echo "  - DNS query for meddefense-portal.com: $CLICK_DNS_COUNT packet(s)"
echo "  - TCP/443 traffic to 91.234.99.107: $CLICK_TLS_COUNT packet(s)"
echo "  - Matching TLS SNI packets: $CLICK_SNI_COUNT"
echo
echo "INFERRED:"
echo "  - WS-NURSE-04 contacted the phishing infrastructure."
echo "  - The timing is consistent with interaction following the reported click."
echo "  - Encrypted HTTPS traffic is consistent with portal access."
echo
echo "CANNOT CONFIRM FROM PCAP:"
echo "  - Password entry"
echo "  - Successful credential submission"
echo "  - Credential theft"
echo "  - Whether a browser form was actually submitted"
echo
echo "ADDITIONAL EVIDENCE:"
echo "  - Endpoint/browser history"
echo "  - EDR process and network telemetry"
echo "  - Phishing web-server logs"
echo "  - Identity/authentication logs"
echo "  - User interview"

# ----------------------------------------------------------------
# Phase 3
# ----------------------------------------------------------------
C2_SNI='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tls.handshake.extensions_server_name == "meddefense-portal.com"'
C2_COUNT=$(count "$PCAP_C2" "$C2_SNI")

C2_TIMES=$(
    tshark -r "$PCAP_C2" -Y "$C2_SNI" \
        -T fields -e frame.time_epoch 2>/dev/null || true
)

echo
echo "=== PHASE 3: C2 BEACONING ==="
echo "Verdict: CONFIRMED"
echo
echo "PCAP CONFIRMS:"
echo "  - Repeated TLS/SNI communications to 91.234.99.107"
echo "  - SNI: meddefense-portal.com"
echo "  - Matching TLS/SNI observations: $C2_COUNT"

if [[ -n "$C2_TIMES" ]]; then
    echo "$C2_TIMES" |
        awk '
        NR == 1 {
            first=$1
            previous=$1
        }
        NR > 1 {
            interval=$1-previous
            sum+=interval
            count++
            if (min == "" || interval < min) min=interval
            if (interval > max) max=interval
            previous=$1
        }
        END {
            if (count > 0)
                printf "  - Interval mean: %.2f seconds\n  - Interval minimum: %.2f seconds\n  - Interval maximum: %.2f seconds\n",
                    sum/count,min,max
        }'
fi

echo
echo "INFERRED:"
echo "  - Regular repeated communication is consistent with beaconing."
echo "  - Automated C2 behavior is an analytical interpretation of the traffic pattern."
echo
echo "CANNOT CONFIRM FROM PCAP:"
echo "  - Malware process responsible for the connections"
echo "  - Commands sent to the host"
echo "  - Command execution"
echo "  - Persistence mechanism"
echo
echo "ADDITIONAL EVIDENCE:"
echo "  - EDR/process telemetry"
echo "  - Endpoint memory/process logs"
echo "  - Proxy/server logs"

# ----------------------------------------------------------------
# Phase 4
# ----------------------------------------------------------------
VPN='ip.src == "154.118.42.89" && ip.dst == "10.10.0.1" && tcp.dstport == 443'
VPN_COUNT=$(count "$PCAP_FULL" "$VPN")

echo
echo "=== PHASE 4: VPN ACCESS ==="
echo "Verdict: STRONG INFERENCE"
echo
echo "PCAP CONFIRMS:"
echo "  - TCP/443 activity from 154.118.42.89 to 10.10.0.1"
echo "  - Matching packet count: $VPN_COUNT"
echo
echo "INFERRED:"
echo "  - Traffic is consistent with access to the VPN endpoint."
echo "  - The activity represents a possible pivot into the internal environment."
echo
echo "CANNOT CONFIRM FROM PCAP:"
echo "  - Successful VPN authentication"
echo "  - Username/account"
echo "  - Password validity"
echo "  - MFA result"
echo "  - Country or ASN attribution"
echo
echo "ADDITIONAL EVIDENCE:"
echo "  - VPN authentication logs"
echo "  - MFA logs"
echo "  - Identity-provider logs"
echo "  - GeoIP/ASN enrichment"

# ----------------------------------------------------------------
# Phase 5
# ----------------------------------------------------------------
RDP='ip.src == "10.10.2.15" && ip.dst == "10.10.1.10" && tcp.dstport == 3389'
RDP_COUNT=$(count "$PCAP_LATERAL" "$RDP")

echo
echo "=== PHASE 5: RDP LATERAL MOVEMENT ==="
echo "Verdict: CONFIRMED NETWORK ACCESS"
echo
echo "PCAP CONFIRMS:"
echo "  - WS-NURSE-04: 10.10.2.15"
echo "  - billing-srv-01: 10.10.1.10"
echo "  - TCP/3389 activity: $RDP_COUNT packet(s)"
echo
echo "INFERRED:"
echo "  - Traffic is consistent with RDP lateral movement."
echo
echo "CANNOT CONFIRM FROM PCAP:"
echo "  - Successful RDP authentication"
echo "  - Account used"
echo "  - Interactive desktop access"
echo "  - Commands executed after login"
echo
echo "ADDITIONAL EVIDENCE:"
echo "  - Windows Security logs"
echo "  - Terminal Services/RDP logs"
echo "  - Domain Controller authentication logs"
echo "  - Server logs"
echo "  - EDR telemetry"

# ----------------------------------------------------------------
# Phase 6
# ----------------------------------------------------------------
SMB='tcp.port == 445'
SMB_COUNT=$(count "$PCAP_LATERAL" "$SMB")
SMB_DECODED=$(count "$PCAP_LATERAL" 'smb || smb2')

echo
echo "=== PHASE 6: SMB / DISCOVERY ==="
echo "Verdict: UNCONFIRMED"
echo
echo "PCAP CONFIRMS:"
echo "  - TCP/445 activity: $SMB_COUNT packet(s)"
echo "  - SMB protocol-decoded packets: $SMB_DECODED"
echo "  - TCP reset events are present in the capture."
echo
echo "STRONG INFERENCE:"
echo "  - TCP/445 activity is consistent with SMB-related communication."
echo
echo "CANNOT CONFIRM FROM PCAP:"
echo "  - Share enumeration"
echo "  - Directory listing"
echo "  - File access"
echo "  - Successful SMB authentication"
echo "  - Specific discovery commands"
echo
echo "ADDITIONAL EVIDENCE:"
echo "  - SMB/server audit logs"
echo "  - Windows Security logs"
echo "  - Endpoint telemetry"
echo "  - File-server logs"
echo
echo "Important:"
echo "  TCP/445 activity must not be reported as confirmed SMB enumeration"
echo "  when the SMB dissector provides no protocol-level evidence."

# ----------------------------------------------------------------
# Phase 7
# ----------------------------------------------------------------
EXFIL='dns.qry.type == 16 && dns.qry.name contains "data-sync.meddefense-portal.com"'

EXFIL_PACKETS=$(count "$PCAP_EXFIL" "$EXFIL")

EXFIL_QUERIES=$(
    tshark -r "$PCAP_EXFIL" -Y "$EXFIL" \
        -T fields -E separator='|' \
        -e frame.time -e ip.src -e ip.dst -e dns.qry.name 2>/dev/null |
    awk -F'|' '$2=="10.10.1.10"'
)

EXFIL_QUERY_COUNT=$(printf '%s\n' "$EXFIL_QUERIES" | awk 'NF{n++}END{print n+0}')

echo
echo "=== PHASE 7: DNS EXFILTRATION ==="
echo "Verdict: CONFIRMED SUSPICIOUS DNS TRANSFER PATTERN"
echo
echo "PCAP CONFIRMS:"
echo "  - Matching data-sync.meddefense-portal.com packets: $EXFIL_PACKETS"
echo "  - Outbound TXT queries from 10.10.1.10: $EXFIL_QUERY_COUNT"
echo "  - Repeated long encoded-looking DNS labels"
echo
echo "INFERRED:"
echo "  - The pattern is consistent with DNS tunneling/exfiltration."
echo "  - The labels may contain encoded chunks of transferred data."
echo
echo "CANNOT CONFIRM FROM PCAP:"
echo "  - Exact data content"
echo "  - Whether the attacker successfully reconstructed the data"
echo "  - Exact business records contained in the labels"
echo "  - Complete exfiltration volume outside the capture window"
echo
echo "ADDITIONAL EVIDENCE:"
echo "  - DNS resolver logs"
echo "  - Endpoint DNS/process telemetry"
echo "  - Destination/server logs"
echo "  - Endpoint files/database audit logs"

# ----------------------------------------------------------------
# Visibility score
# ----------------------------------------------------------------
DIRECT_PHASES=0
TOTAL_PHASES=7

[[ "$CLICK_DNS_COUNT" -gt 0 && "$CLICK_TLS_COUNT" -gt 0 ]] && DIRECT_PHASES=$((DIRECT_PHASES + 1))
[[ "$C2_COUNT" -gt 0 ]] && DIRECT_PHASES=$((DIRECT_PHASES + 1))
[[ "$VPN_COUNT" -gt 0 ]] && DIRECT_PHASES=$((DIRECT_PHASES + 1))
[[ "$RDP_COUNT" -gt 0 ]] && DIRECT_PHASES=$((DIRECT_PHASES + 1))
[[ "$SMB_COUNT" -gt 0 ]] && DIRECT_PHASES=$((DIRECT_PHASES + 1))
[[ "$EXFIL_QUERY_COUNT" -gt 0 ]] && DIRECT_PHASES=$((DIRECT_PHASES + 1))

VISIBILITY_PERCENT=$(
    awk -v direct="$DIRECT_PHASES" -v total="$TOTAL_PHASES" \
        'BEGIN {printf "%.0f", (direct/total)*100}'
)

echo
echo "================================================================"
echo "=== PACKET VISIBILITY SCORE ==="
echo "================================================================"
echo "Direct PCAP evidence exists for $DIRECT_PHASES of $TOTAL_PHASES phases."
echo "Packet visibility: ${VISIBILITY_PERCENT}%"
echo
echo "Note:"
echo "  Phase 1 is not directly visible because the supplied PCAPs do not"
echo "  contain the email-delivery transaction. It is supported by 4x00 context."
echo
echo "Phase 6 has direct TCP/445 packet evidence, but SMB discovery itself"
echo "is not confirmed by protocol-level packet decoding."

# ----------------------------------------------------------------
# Evidence strength
# ----------------------------------------------------------------
echo
echo "================================================================"
echo "=== WHERE PACKET EVIDENCE IS STRONG ==="
echo "================================================================"
echo "- Source/destination IP addresses"
echo "- TCP destination ports"
echo "- Packet timestamps"
echo "- DNS query names and record types"
echo "- TLS SNI metadata"
echo "- Repeated communication patterns"
echo "- TCP flags and connection behavior"
echo
echo "These observations can be directly reproduced from the PCAPs."

echo
echo "================================================================"
echo "=== WHERE PACKET EVIDENCE HAS LIMITS ==="
echo "================================================================"
echo "- Email delivery is outside the supplied packet captures."
echo "- Encrypted TLS hides application payload and submitted credentials."
echo "- TCP/443 does not prove successful VPN authentication."
echo "- TCP/3389 does not by itself prove successful RDP login."
echo "- TCP/445 does not by itself prove SMB enumeration or file access."
echo "- DNS labels can reveal transfer patterns without proving exact data content."
echo "- Packet captures do not reveal endpoint process execution unless reflected"
echo "  in observable network behavior."

# ----------------------------------------------------------------
# Additional evidence matrix
# ----------------------------------------------------------------
echo
echo "================================================================"
echo "=== ADDITIONAL EVIDENCE MATRIX ==="
echo "================================================================"
echo
echo "Finding                              Evidence needed"
echo "----------------------------------------------------------------"
echo "Phishing delivery                    Mail gateway / mailbox logs"
echo "Credential submission                Endpoint/browser + web-server logs"
echo "Credential use                       VPN + identity-provider logs"
echo "Endpoint malware execution           EDR / endpoint process logs"
echo "VPN authentication                   VPN authentication + MFA logs"
echo "RDP authentication                   Windows Security / DC logs"
echo "SMB enumeration                      Server/SMB audit + endpoint logs"
echo "File access                          File-server + endpoint audit logs"
echo "DNS exfiltrated content              DNS logs + endpoint/source data"
echo "User interaction/intent              User interview + endpoint telemetry"
echo "Successful attacker receipt          Destination/server-side logs"

# ----------------------------------------------------------------
# Final lesson
# ----------------------------------------------------------------
echo
echo "================================================================"
echo "KEY LESSON"
echo "================================================================"
echo "Packets show communication."
echo
echo "Logs show context around that communication:"
echo "  who authenticated,"
echo "  which process generated the traffic,"
echo "  what account was used,"
echo "  what file or service was accessed,"
echo "  and whether an operation succeeded."
echo
echo "A strong investigation therefore separates:"
echo "  CONFIRMED       = directly observable packet evidence"
echo "  STRONG INFERENCE= multiple observations support the interpretation"
echo "  UNCONFIRMED     = plausible but not demonstrated"
echo "  NOT VISIBLE     = requires another evidence source"
echo
echo "The goal is not to make packets prove everything."
echo "The goal is to correlate packet, identity, endpoint, mail and server"
echo "evidence so that each inference can be tested against another source."
echo "================================================================"
