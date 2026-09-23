#!/bin/bash
set -euo pipefail

OUT="11-network_forensics_report.md"

CLICK="phishing_click.pcap"
C2="c2_beaconing.pcap"
EXFIL="dns_exfil.pcap"
LATERAL="lateral_movement.pcap"
FULL="full_timeline.pcap"

CTX="../4x00_phishing_dissection/11-ioc_extraction.md"

echo "Generating $OUT..."

for f in "$CLICK" "$C2" "$EXFIL" "$LATERAL" "$FULL" "$CTX"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Missing file: $f" >&2
        exit 1
    fi
done

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

run_tshark() {
    tshark "$@" 2>/dev/null || true
}

capture_window() {
    local file="$1"

    run_tshark -r "$file" -T fields \
        -e frame.time -e frame.time_epoch |
        awk '
        NR == 1 {
            first=$1
            first_epoch=$2
        }
        {
            last=$1
            last_epoch=$2
        }
        END {
            if (NR > 0)
                printf "%s|%s|%s|%s\n",
                    first,last,first_epoch,last_epoch
        }'
}

count_filter() {
    local file="$1"
    local filter="$2"

    run_tshark -r "$file" -Y "$filter" |
        awk 'END {print NR+0}'
}

first_fields() {
    local file="$1"
    local filter="$2"

    run_tshark -r "$file" -Y "$filter" -T fields \
        -E separator='|' \
        -e frame.number \
        -e frame.time \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport \
        -e dns.qry.name |
        awk 'NR == 1 {print; exit}'
}

last_fields() {
    local file="$1"
    local filter="$2"

    run_tshark -r "$file" -Y "$filter" -T fields \
        -E separator='|' \
        -e frame.number \
        -e frame.time \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport \
        -e dns.qry.name |
        awk '{last=$0} END {if (last != "") print last}'
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

# ------------------------------------------------------------
# Capture windows
# ------------------------------------------------------------

CLICK_WINDOW=$(capture_window "$CLICK")
C2_WINDOW=$(capture_window "$C2")
EXFIL_WINDOW=$(capture_window "$EXFIL")
LATERAL_WINDOW=$(capture_window "$LATERAL")
FULL_WINDOW=$(capture_window "$FULL")

CLICK_START=$(printf '%s' "$CLICK_WINDOW" | cut -d'|' -f1)
CLICK_END=$(printf '%s' "$CLICK_WINDOW" | cut -d'|' -f2)

C2_START=$(printf '%s' "$C2_WINDOW" | cut -d'|' -f1)
C2_END=$(printf '%s' "$C2_WINDOW" | cut -d'|' -f2)

EXFIL_START=$(printf '%s' "$EXFIL_WINDOW" | cut -d'|' -f1)
EXFIL_END=$(printf '%s' "$EXFIL_WINDOW" | cut -d'|' -f2)

LATERAL_START=$(printf '%s' "$LATERAL_WINDOW" | cut -d'|' -f1)
LATERAL_END=$(printf '%s' "$LATERAL_WINDOW" | cut -d'|' -f2)

FULL_START=$(printf '%s' "$FULL_WINDOW" | cut -d'|' -f1)
FULL_END=$(printf '%s' "$FULL_WINDOW" | cut -d'|' -f2)

# ------------------------------------------------------------
# Phase 2: phishing-domain DNS
# ------------------------------------------------------------

PHISH_DNS='dns.qry.name == "meddefense-portal.com"'

PHISH_ROW=$(first_fields "$CLICK" "$PHISH_DNS")

PHISH_FRAME=$(printf '%s' "$PHISH_ROW" | cut -d'|' -f1)
PHISH_TIME=$(printf '%s' "$PHISH_ROW" | cut -d'|' -f2)
PHISH_SRC=$(printf '%s' "$PHISH_ROW" | cut -d'|' -f4)
PHISH_DST=$(printf '%s' "$PHISH_ROW" | cut -d'|' -f5)

# ------------------------------------------------------------
# Phase 2: TLS/SNI
# ------------------------------------------------------------

SNI_FILTER='ip.src == "10.10.2.15" && ip.dst == "91.234.99.107" && tls.handshake.extensions_server_name == "meddefense-portal.com"'

SNI_ROW=$(first_fields "$CLICK" "$SNI_FILTER")
SNI_TIME=$(printf '%s' "$SNI_ROW" | cut -d'|' -f2)

# ------------------------------------------------------------
# Phase 3: C2
# ------------------------------------------------------------

C2_ROW_FIRST=$(first_fields "$C2" "$SNI_FILTER")
C2_ROW_LAST=$(last_fields "$C2" "$SNI_FILTER")

C2_COUNT=$(count_filter "$C2" "$SNI_FILTER")

C2_FIRST_FRAME=$(printf '%s' "$C2_ROW_FIRST" | cut -d'|' -f1)
C2_FIRST_TIME=$(printf '%s' "$C2_ROW_FIRST" | cut -d'|' -f2)
C2_FIRST_SRC=$(printf '%s' "$C2_ROW_FIRST" | cut -d'|' -f4)
C2_FIRST_DST=$(printf '%s' "$C2_ROW_FIRST" | cut -d'|' -f5)

C2_LAST_TIME=$(printf '%s' "$C2_ROW_LAST" | cut -d'|' -f2)

C2_TIMING=$(
    run_tshark -r "$C2" -Y "$SNI_FILTER" \
        -T fields -e frame.time_epoch |
        awk '
        NR == 1 {
            previous=$1
            next
        }
        {
            interval=$1-previous
            sum+=interval
            sumsq+=(interval*interval)
            n++
            previous=$1
        }
        END {
            if (n > 0) {
                mean=sum/n
                variance=(sumsq/n)-(mean*mean)
                if (variance < 0)
                    variance=0
                printf "%.2f|%.2f\n",mean,sqrt(variance)
            } else {
                print "0.00|0.00"
            }
        }'
)

C2_MEAN=$(printf '%s' "$C2_TIMING" | cut -d'|' -f1)
C2_STDDEV=$(printf '%s' "$C2_TIMING" | cut -d'|' -f2)

# ------------------------------------------------------------
# Phase 4: VPN
#
# Use broad TCP/443 capture and classify endpoints in awk.
# This avoids the unreliable exact directional filter observed
# in the supplied capture.
# ------------------------------------------------------------

VPN_ROWS="$tmpdir/vpn.txt"

run_tshark -r "$FULL" -Y 'tcp.port == 443' \
    -T fields -E separator='|' \
    -e frame.number \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport |
    awk -F'|' '
    ($3=="154.118.42.89" && $4=="10.10.0.1") ||
    ($3=="10.10.0.1" && $4=="154.118.42.89") {
        print
    }' > "$VPN_ROWS"

VPN_COUNT=$(awk 'END {print NR+0}' "$VPN_ROWS")
VPN_FIRST=$(awk 'NR==1 {print}' "$VPN_ROWS")

VPN_FRAME=$(printf '%s' "$VPN_FIRST" | cut -d'|' -f1)
VPN_TIME=$(printf '%s' "$VPN_FIRST" | cut -d'|' -f2)
VPN_SRC=$(printf '%s' "$VPN_FIRST" | cut -d'|' -f3)
VPN_DST=$(printf '%s' "$VPN_FIRST" | cut -d'|' -f4)

# ------------------------------------------------------------
# Phase 5: RDP
#
# Extract all TCP/3389 packets, then classify in awk.
# ------------------------------------------------------------

RDP_ROWS="$tmpdir/rdp.txt"

run_tshark -r "$LATERAL" -Y 'tcp.port == 3389' \
    -T fields -E separator='|' \
    -e frame.number \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport |
    awk -F'|' '
    $3=="10.10.2.15" && $4=="10.10.1.10" {
        print
    }' > "$RDP_ROWS"

RDP_COUNT=$(awk 'END {print NR+0}' "$RDP_ROWS")
RDP_FIRST=$(awk 'NR==1 {print}' "$RDP_ROWS")

RDP_FRAME=$(printf '%s' "$RDP_FIRST" | cut -d'|' -f1)
RDP_TIME=$(printf '%s' "$RDP_FIRST" | cut -d'|' -f2)
RDP_SRC=$(printf '%s' "$RDP_FIRST" | cut -d'|' -f3)
RDP_DST=$(printf '%s' "$RDP_FIRST" | cut -d'|' -f4)

# ------------------------------------------------------------
# Phase 6: SMB
# ------------------------------------------------------------

SMB_COUNT=$(count_filter "$LATERAL" 'tcp.port == 445')
SMB_RESET_COUNT=$(count_filter "$LATERAL 'tcp.port == 445 && tcp.flags.reset == 1')

SMB_FIRST=$(first_fields "$LATERAL" 'tcp.port == 445')

SMB_FRAME=$(printf '%s' "$SMB_FIRST" | cut -d'|' -f1)
SMB_TIME=$(printf '%s' "$SMB_FIRST" | cut -d'|' -f2)
SMB_SRC=$(printf '%s' "$SMB_FIRST" | cut -d'|' -f4)
SMB_DST=$(printf '%s' "$SMB_FIRST" | cut -d'|' -f5)

# ------------------------------------------------------------
# Phase 7: DNS exfiltration
# ------------------------------------------------------------

EXFIL_FILTER='dns.qry.type == 16 && dns.qry.name contains "data-sync.meddefense-portal.com"'

EXFIL_ROWS="$tmpdir/exfil.txt"

run_tshark -r "$EXFIL" -Y "$EXFIL_FILTER" \
    -T fields -E separator='|' \
    -e frame.number \
    -e frame.time \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e dns.qry.name |
    awk -F'|' '$4=="10.10.1.10" {print}' > "$EXFIL_ROWS"

EXFIL_COUNT=$(awk 'END {print NR+0}' "$EXFIL_ROWS")

EXFIL_FIRST=$(awk 'NR==1 {print}' "$EXFIL_ROWS")
EXFIL_LAST=$(awk '{last=$0} END {if (last!="") print last}' "$EXFIL_ROWS")

EXFIL_FIRST_FRAME=$(printf '%s' "$EXFIL_FIRST" | cut -d'|' -f1)
EXFIL_FIRST_TIME=$(printf '%s' "$EXFIL_FIRST" | cut -d'|' -f2)
EXFIL_FIRST_EPOCH=$(printf '%s' "$EXFIL_FIRST" | cut -d'|' -f3)
EXFIL_FIRST_SRC=$(printf '%s' "$EXFIL_FIRST" | cut -d'|' -f4)
EXFIL_FIRST_DST=$(printf '%s' "$EXFIL_FIRST" | cut -d'|' -f5)
EXFIL_FIRST_NAME=$(printf '%s' "$EXFIL_FIRST" | cut -d'|' -f6)

EXFIL_LAST_FRAME=$(printf '%s' "$EXFIL_LAST" | cut -d'|' -f1)
EXFIL_LAST_TIME=$(printf '%s' "$EXFIL_LAST" | cut -d'|' -f2)
EXFIL_LAST_EPOCH=$(printf '%s' "$EXFIL_LAST" | cut -d'|' -f3)
EXFIL_LAST_NAME=$(printf '%s' "$EXFIL_LAST" | cut -d'|' -f6)

EXFIL_STATS=$(
    awk -F'|' '
    {
        name=$6
        sub(/\.data-sync\.meddefense-portal\.com$/,"",name)
        len=length(name)

        if (len > 0) {
            sum+=len
            n++

            if (len > max)
                max=len
        }
    }
    END {
        if (n > 0)
            printf "%.1f|%d\n",sum/n,max
        else
            print "0.0|0"
    }' "$EXFIL_ROWS"
)

EXFIL_AVG=$(printf '%s' "$EXFIL_STATS" | cut -d'|' -f1)
EXFIL_MAX=$(printf '%s' "$EXFIL_STATS" | cut -d'|' -f2)

# ------------------------------------------------------------
# Dwell time
# ------------------------------------------------------------

DWELL="Unavailable"

if [[ -n "$PHISH_TIME" && -n "$EXFIL_LAST_TIME" ]]; then
    FIRST_EPOCH=$(printf '%s' "$PHISH_ROW" | cut -d'|' -f3)

    if [[ -n "$FIRST_EPOCH" && -n "$EXFIL_LAST_EPOCH" ]]; then
        DWELL=$(
            awk -v start="$FIRST_EPOCH" -v end="$EXFIL_LAST_EPOCH" '
            BEGIN {
                seconds=int(end-start+0.5)

                days=int(seconds/86400)
                seconds=seconds-(days*86400)

                hours=int(seconds/3600)
                seconds=seconds-(hours*3600)

                minutes=int(seconds/60)
                seconds=seconds-(minutes*60)

                printf "%dd %02dh %02dm %02ds",
                    days,hours,minutes,seconds
            }'
        )
    fi
fi

# ------------------------------------------------------------
# SHA-256
# ------------------------------------------------------------

HASH_CLICK=$(sha256_file "$CLICK")
HASH_C2=$(sha256_file "$C2")
HASH_EXFIL=$(sha256_file "$EXFIL")
HASH_LATERAL=$(sha256_file "$LATERAL")
HASH_FULL=$(sha256_file "$FULL")

# ------------------------------------------------------------
# Generate report
# ------------------------------------------------------------

cat > "$OUT" <<EOF
# Network Forensics Investigation Report

## Executive Summary

A phishing campaign targeting MedDefense personnel was followed by network activity from WS-NURSE-04 (\`10.10.2.15\`) to phishing infrastructure at \`91.234.99.107\`. The first observed post-click network activity was a DNS lookup for \`meddefense-portal.com\` at **$PHISH_TIME** in \`phishing_click.pcap\`, followed by TLS communication to the same external infrastructure. Later captures show repeated TLS communications, VPN-related traffic, RDP access from WS-NURSE-04 to billing-srv-01, TCP/445 activity, and repeated DNS TXT queries containing long labels beneath \`data-sync.meddefense-portal.com\`. The DNS activity is consistent with data exfiltration, but the exact contents and successful receipt of the data cannot be established from packets alone. The observed interval from the first known access-related packet to the last observed outbound DNS exfiltration query was **$DWELL**.

## Investigation Scope

### PCAPs Analyzed

| PCAP | Purpose | Capture Window |
|---|---|---|
| \`phishing_click.pcap\` | Post-click DNS and TLS activity | $CLICK_START → $CLICK_END |
| \`c2_beaconing.pcap\` | Repeated TLS communications | $C2_START → $C2_END |
| \`dns_exfil.pcap\` | DNS TXT and long-label activity | $EXFIL_START → $EXFIL_END |
| \`lateral_movement.pcap\` | RDP and TCP/445 activity | $LATERAL_START → $LATERAL_END |
| \`full_timeline.pcap\` | Cross-stage network timeline | $FULL_START → $FULL_END |

### Supporting 4x00 Evidence

- \`../4x00_phishing_dissection/11-ioc_extraction.md\`
- \`../4x00_phishing_dissection/13-phishing_investigation_report.md\`

### Tools Used

- TShark
- Bash
- awk
- sha256sum

### Evidence Not Available

The following evidence was not available for direct analysis:

- endpoint/EDR logs
- Windows event logs
- Domain Controller authentication logs
- VPN authentication logs
- MFA logs
- mail gateway logs
- phishing web-server logs
- DNS resolver logs outside the supplied captures
- application/database audit logs
- user interview evidence

## Methodology

### Baseline Establishment

The supplied normal clinical baseline was used to identify expected DNS, HTTPS, Kerberos, printing and SMB behavior.

TCP/445 activity was not automatically treated as malicious because SMB traffic also occurs in the normal baseline.

### Known-IOC Search

The investigation correlated known indicators from 4x00 with the PCAPs, including:

- \`meddefense-portal.com\`
- \`91.234.99.107\`
- \`154.118.42.89\`
- \`data-sync.meddefense-portal.com\`

### DNS Analysis

DNS record types, query names, TXT frequency and label lengths were examined.

The exfiltration analysis specifically separated outbound queries from DNS responses by requiring the source to be \`10.10.1.10\`.

### TLS Metadata Analysis

TLS SNI and TCP/443 metadata were used because encrypted application payloads were not available in plaintext.

### Timing Analysis

Packet timestamps were correlated across captures to identify:

- first post-click activity
- recurring C2-like intervals
- VPN activity
- RDP activity
- DNS exfiltration duration
- overall observed dwell time

### Behavioral Analysis

Behavioral indicators included:

- repeated external connections
- regular intervals
- long DNS labels
- TXT query frequency
- clinical-workstation-to-server RDP
- TCP/445 activity

### Cross-PCAP Correlation

Hosts, IP addresses, domains, ports and timestamps were correlated across all captures.

# Findings by Attack Phase

## Phase 1 — Phishing Delivery

**MITRE ATT&CK:** T1566.002 — Phishing: Spearphishing Link  
**Confidence:** CONFIRMED BY 4x00 CONTEXT; NOT VISIBLE IN SUPPLIED PCAP

The 4x00 investigation identified E2 as the relevant phishing message.

**Email evidence:**

- Sender: \`noreply@meddefense-portal.com\`
- Recipient: \`dmarsh@meddefense.com\`
- Sending IP: \`91.234.99.107\`
- SPF: fail
- DKIM: none
- DMARC: fail
- Phishing URL: \`https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1\`

The email delivery itself is not present in the supplied PCAPs.

**Additional evidence required:** mail gateway logs, mailbox audit logs and user interview.

## Phase 2 — Phishing-Linked Web Session

**MITRE ATT&CK:** T1056.003 — Input Capture: Web Portal Capture  
**Confidence:** STRONG INFERENCE

**PCAP:** \`phishing_click.pcap\`

At frame **$PHISH_FRAME**, timestamp **$PHISH_TIME**, host **$PHISH_SRC** queried DNS server **$PHISH_DST** for:

\`meddefense-portal.com\`

TLS SNI activity to \`meddefense-portal.com\` was subsequently observed at **$SNI_TIME** from WS-NURSE-04 toward \`91.234.99.107\`.

The packets prove DNS resolution and subsequent TLS communication.

They do not prove that credentials were entered or accepted.

**Additional evidence required:** browser history, EDR telemetry, authentication logs, phishing web-server logs and user interview.

## Phase 3 — C2 Beaconing

**MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols  
**Confidence:** CONFIRMED REPEATED NETWORK BEHAVIOR; C2 INTERPRETATION

**PCAP:** \`c2_beaconing.pcap\`

First matching observation:

- Frame: **$C2_FIRST_FRAME**
- Time: **$C2_FIRST_TIME**
- Source: **$C2_FIRST_SRC**
- Destination: **$C2_FIRST_DST**

Last matching observation:

- Time: **$C2_LAST_TIME**

Observed TLS/SNI session markers: **$C2_COUNT**

Calculated interval statistics:

- Mean: **$C2_MEAN seconds**
- Standard deviation: **$C2_STDDEV seconds**

The repeated communication with the same external IP and SNI is confirmed.

The regularity is consistent with automated beaconing, but packets alone do not identify the responsible process or malware.

**Additional evidence required:** EDR, endpoint process telemetry, proxy logs and destination logs.

## Phase 4 — VPN Pivot

**MITRE ATT&CK:** T1133 — External Remote Services  
**Confidence:** STRONG INFERENCE

**PCAP:** \`full_timeline.pcap\`

Observed traffic:

- Frame: **$VPN_FRAME**
- Time: **$VPN_TIME**
- Source: **$VPN_SRC**
- Destination: **$VPN_DST**
- Matching packets: **$VPN_COUNT**

The network evidence establishes communication between \`154.118.42.89\` and the VPN endpoint.

It does not establish successful VPN authentication, account identity, MFA status, source country or ASN.

**Additional evidence required:** VPN authentication logs, MFA logs, identity-provider logs and GeoIP/ASN data.

## Phase 5 — RDP Lateral Movement

**MITRE ATT&CK:** T1021.001 — Remote Services: RDP  
**Confidence:** CONFIRMED NETWORK ACCESS

**PCAP:** \`lateral_movement.pcap\`

The first matching RDP packet was:

- Frame: **$RDP_FRAME**
- Time: **$RDP_TIME**
- Source: **$RDP_SRC**
- Destination: **$RDP_DST**

Total matching TCP/3389 packets: **$RDP_COUNT**

The packet evidence proves TCP/3389 communication from WS-NURSE-04 to billing-srv-01.

It does not prove successful RDP authentication or what actions occurred inside the session.

**Additional evidence required:** Windows Security logs, RDP/Terminal Services logs, Domain Controller logs, billing-server logs and EDR.

## Phase 6 — SMB Activity

**MITRE ATT&CK:** T1021.002 — Remote Services: SMB/Windows Admin Shares  
**Related:** T1135 — Network Share Discovery  
**Confidence:** CONFIRMED TCP/445 ACTIVITY; ENUMERATION UNCONFIRMED

**PCAP:** \`lateral_movement.pcap\`

First observed TCP/445 activity:

- Frame: **$SMB_FRAME**
- Time: **$SMB_TIME**
- Source: **$SMB_SRC**
- Destination: **$SMB_DST**

Total TCP/445 packets: **$SMB_COUNT**

TCP/445 reset packets: **$SMB_RESET_COUNT**

The capture confirms TCP/445 activity.

The SMB dissectors did not provide sufficient protocol-level evidence to confirm share enumeration, directory listing or file access.

**Additional evidence required:** SMB/server audit logs, Windows Security logs, file-server logs and endpoint telemetry.

## Phase 7 — DNS Exfiltration

**MITRE ATT&CK:** T1048.003 — Exfiltration Over Alternative Protocol  
**Confidence:** CONFIRMED SUSPICIOUS DNS TRANSFER PATTERN

**PCAP:** \`dns_exfil.pcap\`

First outbound matching query:

- Frame: **$EXFIL_FIRST_FRAME**
- Time: **$EXFIL_FIRST_TIME**
- Source: **$EXFIL_FIRST_SRC**
- Destination: **$EXFIL_FIRST_DST**
- Query: \`$EXFIL_FIRST_NAME\`

Last outbound matching query:

- Frame: **$EXFIL_LAST_FRAME**
- Time: **$EXFIL_LAST_TIME**
- Query: \`$EXFIL_LAST_NAME\`

Outbound TXT queries matching the exfiltration domain: **$EXFIL_COUNT**

Average left-most label length: **$EXFIL_AVG characters**

Maximum left-most label length: **$EXFIL_MAX characters**

The repeated TXT queries and long encoded-looking labels beneath \`data-sync.meddefense-portal.com\` are consistent with DNS tunneling/exfiltration.

The exact data content and successful attacker-side reconstruction cannot be confirmed from the supplied packets.

**Additional evidence required:** DNS resolver logs, endpoint DNS/process telemetry, database/file audit logs and destination logs.

# Network-Level IOC Table

| Type | Value | Source | Confidence | Detection Utility |
|---|---|---|---|---|
| Domain | \`meddefense-portal.com\` | 4x00 + PCAP | HIGH | DNS/TLS detection |
| IP | \`91.234.99.107\` | 4x00 + PCAP | HIGH | Egress block/alert |
| Sender | \`noreply@meddefense-portal.com\` | 4x00 E2 | HIGH | Mail filtering |
| URL | \`hxxps://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1\` | 4x00 E2 | HIGH | Mail/web detection |
| Domain | \`outlook-protection.com\` | 4x00 E3 | HIGH | Mail/web detection |
| IP | \`51.38.42.17\` | 4x00 E3 | HIGH | Network detection |
| Sender | \`security@outlook-protection.com\` | 4x00 E3 | HIGH | Mail filtering |
| Domain | \`medequip-supplies.net\` | 4x00 E5 | HIGH | Mail/web detection |
| IP | \`185.176.43.22\` | 4x00 E5 | HIGH | Network detection |
| Sender | \`invoices@medequip-supplies.net\` | 4x00 E5 | HIGH | Mail filtering |
| Domain | \`meddefense-benefits.org\` | 4x00 E7 | HIGH | Mail/web detection |
| IP | \`164.90.218.73\` | 4x00 E7 | HIGH | Network detection |
| Sender | \`hr-notifications@meddefense-benefits.org\` | 4x00 E7 | HIGH | Mail filtering |
| IP | \`154.118.42.89\` | full_timeline.pcap | HIGH | VPN correlation |
| Domain | \`data-sync.meddefense-portal.com\` | dns_exfil.pcap | HIGH | DNS tunneling detection |
| Host | \`10.10.2.15\` | PCAPs | HIGH | WS-NURSE-04 |
| Host | \`10.10.1.10\` | PCAPs | HIGH | billing-srv-01 |
| Host | \`10.10.0.1\` | full_timeline.pcap | HIGH | VPN endpoint |

# Impact Assessment

## Systems Involved

### WS-NURSE-04 — 10.10.2.15

Observed:

- phishing-domain DNS resolution
- TLS connection to phishing infrastructure
- repeated TLS/SNI communications
- TCP/3389 traffic toward billing-srv-01

### billing-srv-01 — 10.10.1.10

Observed:

- RDP traffic
- TCP/445 activity
- repeated outbound TXT DNS queries to the suspected exfiltration domain

### VPN Endpoint — 10.10.0.1

Observed network traffic from \`154.118.42.89\`.

### DNS Server — 10.10.1.1

Observed handling of phishing-domain and DNS-exfiltration-related traffic.

## Data Likely Exfiltrated

The strongest evidence is the repeated TXT DNS traffic from billing-srv-01 to:

\`data-sync.meddefense-portal.com\`

The long labels are consistent with encoded chunks of information.

The exact dataset is not recoverable from the supplied evidence and should not be assumed without server, endpoint or application logs.

## Systems Protected or Not Reached

TCP/445 reset packets demonstrate connections being reset, but they do not prove that access was explicitly denied.

The capture does not establish successful SMB share enumeration or successful RDP/VPN authentication.

## Credential Exposure

The phishing context combined with subsequent network communication strongly supports an association between the phishing interaction and WS-NURSE-04 network activity.

The actual credential contents cannot be recovered from the encrypted TLS session.

## Regulatory and Business Concerns

Because this is a healthcare environment, confirmed access or transfer involving billing, clinical or other sensitive records should trigger an appropriate privacy and regulatory assessment.

The actual affected records must be determined from server, application and endpoint evidence.

# Detection Gap Analysis

The packet investigation exposed these detection opportunities:

1. DNS lookup of phishing lookalike domains
2. TLS SNI to phishing infrastructure
3. repeated regular external connections
4. anomalous VPN source infrastructure
5. clinical workstation to server RDP
6. TCP/445 activity
7. high-frequency TXT queries with long encoded labels

The major behavioral gaps were:

- lack of regular-beacon detection
- lack of DNS label-length anomaly detection
- lack of TXT tunneling analytics
- lack of VPN GeoIP/ASN anomaly correlation
- lack of role-aware RDP detection
- insufficient SMB protocol-level visibility

# Detection Rules Recommended

| Rule | Required Data | Phase | False Positives |
|---|---|---|---|
| C2 Beaconing | Zeek/NetFlow/proxy/firewall | 3 | Updates, monitoring, backups |
| DNS Query Length Anomaly | DNS logs/Zeek/PCAP | 7 | CDNs, DKIM, SaaS |
| VPN Geo-Anomaly | VPN + MFA + GeoIP/ASN | 4 | Travelling users |
| Cross-Role RDP | Network + identity + Windows logs | 5 | IT support |
| DNS TXT Tunneling | DNS resolver/Zeek | 7 | Legitimate TXT-heavy services |
| TLS Campaign Lookalike | TLS SNI + IOC/first-seen table | 2 | Newly deployed legitimate domains |

## Recommended Logic

### C2 Beaconing

Alert when the same internal host communicates with the same external destination more than 10 times within 60 minutes and:

\`interval_stddev < interval_mean * 0.15\`

### DNS Length Anomaly

Alert when the left-most DNS label exceeds 40 characters, especially when the query is TXT and repeated against one base domain.

### VPN Geo-Anomaly

Alert when the VPN source country or ASN is outside the organization's expected geography or ASN history.

### Cross-Role RDP

Alert when a non-IT or clinical account initiates TCP/3389 toward a protected server subnet.

### DNS TXT Tunneling

Alert when a source performs more than 10 TXT queries within 120 seconds against one domain and the labels appear encoded or unusually long.

### TLS Campaign Lookalike

Alert when TLS SNI matches a known phishing IOC or a domain recorded in a campaign first-seen table.

# Recommendations

## Immediate — Next 24 Hours

1. Isolate WS-NURSE-04.
2. Preserve endpoint and volatile evidence.
3. Reset credentials associated with the suspected phishing interaction after appropriate containment.
4. Block confirmed malicious domains and IPs.
5. Review \`154.118.42.89\` in VPN logs.
6. Preserve VPN, identity, DNS, Windows, server and mail logs.
7. Search for the IOCs across available telemetry.

## Short-Term — Next 7 Days

1. Deploy behavioral C2 detection.
2. Review VPN access and authentication history.
3. Improve DNS egress visibility.
4. Search for additional affected hosts.
5. Search for additional queries to \`data-sync.meddefense-portal.com\`.
6. Review RDP activity from clinical workstations.
7. Correlate PCAP evidence with EDR and identity logs.

## Medium-Term — Next 30 Days

1. Strengthen email authentication and anti-phishing policy.
2. Implement DNS length, entropy and TXT-frequency analytics.
3. Implement role-based RDP restrictions.
4. Establish VPN geography and ASN baselines.
5. Improve endpoint/network/identity correlation.
6. Conduct a healthcare data exposure review.
7. Establish IOC first-seen and campaign tracking.

# Evidence Chain

| File | Purpose | Capture Window | SHA-256 |
|---|---|---|---|
| \`$CLICK\` | Phishing-domain DNS/TLS | $CLICK_START → $CLICK_END | \`$HASH_CLICK\` |
| \`$C2\` | Repeated TLS communications | $C2_START → $C2_END | \`$HASH_C2\` |
| \`$EXFIL\` | DNS TXT transfer activity | $EXFIL_START → $EXFIL_END | \`$HASH_EXFIL\` |
| \`$LATERAL\` | RDP/TCP-445 activity | $LATERAL_START → $LATERAL_END | \`$HASH_LATERAL\` |
| \`$FULL\` | Cross-stage timeline | $FULL_START → $FULL_END | \`$HASH_FULL\` |

### Evidence Handling

Evidence was analyzed from:

\`$(pwd)\`

The original PCAP files should be preserved read-only and separate from working copies.

SHA-256 values above provide an integrity reference for the files used to generate this report.

# Continuity with 4x00

The 4x00 investigation established the phishing campaign, E2, the phishing domains, sender infrastructure and email-authentication failures.

The network investigation extends those findings by documenting:

- DNS resolution of the phishing domain from WS-NURSE-04
- subsequent TLS communication with the phishing infrastructure
- repeated beacon-like TLS activity
- VPN-related network activity
- RDP traffic from WS-NURSE-04 to billing-srv-01
- TCP/445 activity
- DNS TXT transfer activity beneath \`data-sync.meddefense-portal.com\`

The credential-exposure assessment therefore moves from a phishing-context concern to a **strongly supported network correlation**, while remaining unconfirmed as to the actual password entered or successfully authenticated.

The DNS activity materially expands the impact assessment because it provides network evidence consistent with data transfer from billing-srv-01.

# Final Evidence Assessment

| Finding | Assessment |
|---|---|
| Phishing delivery | Confirmed by 4x00; not visible in supplied PCAP |
| Phishing-domain resolution | Confirmed |
| TLS communication to phishing infrastructure | Confirmed |
| Credential harvesting | Strong inference |
| Repeated beacon-like communications | Confirmed network behavior |
| VPN-related traffic | Strong inference |
| RDP network access | Confirmed |
| RDP authentication | Unconfirmed |
| TCP/445 activity | Confirmed |
| SMB enumeration | Unconfirmed |
| DNS tunneling/exfiltration pattern | Confirmed suspicious pattern |
| Exact exfiltrated data | Unconfirmed |
| Endpoint malware execution | Not visible in supplied PCAP |
| Exact credential use | Not visible in supplied PCAP |

## Final Lesson

Packet evidence is strongest for answering **who communicated with whom, when, over which protocol, and with what observable network characteristics**.

Packet evidence is weaker for answering **which user authenticated, what process executed, what password was entered, what application action occurred, and exactly what data was successfully received**.

Those questions require correlation with endpoint, authentication, mail, DNS, server and application logs.
EOF

echo "Done."
echo
echo "Generated: $OUT"
echo
echo "Key dynamically derived values:"
echo "  First access:       $PHISH_TIME"
echo "  C2 observations:    $C2_COUNT"
echo "  C2 mean interval:   $C2_MEAN seconds"
echo "  C2 std deviation:   $C2_STDDEV seconds"
echo "  VPN packets:        $VPN_COUNT"
echo "  RDP packets:        $RDP_COUNT"
echo "  TCP/445 packets:    $SMB_COUNT"
echo "  TCP/445 resets:     $SMB_RESET_COUNT"
echo "  DNS exfil queries:  $EXFIL_COUNT"
echo "  DNS label average:  $EXFIL_AVG characters"
echo "  DNS label maximum:  $EXFIL_MAX characters"
echo "  Observed dwell:     $DWELL"
