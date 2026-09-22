#!/bin/bash
# 4-lateral_movement.sh
# Usage: ./4-lateral_movement.sh
#
# PCAP: lateral_movement.pcap
# Known hosts:
#   WS-NURSE-04 = 10.10.2.15
#   billing-srv-01 = 10.10.1.10
#   mx01.meddefense.com = 10.10.1.20
#
# Baseline:
#   normal_baseline_clinical.pcap
#
# All PCAP analysis is performed with tshark.
# Filters and commands are printed for reproducibility.
# Timestamps are included with findings where applicable.

set -euo pipefail

PCAP="lateral_movement.pcap"
BASELINE_PCAP="normal_baseline_clinical.pcap"

START_IP="10.10.2.15"
BILLING_IP="10.10.1.10"
MX_IP="10.10.1.20"

[[ -f "$PCAP" ]] || {
    echo "ERROR: PCAP not found: $PCAP" >&2
    exit 1
}

command -v tshark >/dev/null || {
    echo "ERROR: tshark is required." >&2
    exit 1
}

run() {
    echo "# tshark $*"
    tshark "$@"
}

field_exists() {
    tshark -G fields 2>/dev/null |
        awk -F '\t' -v field="$1" '$3 == field {found=1} END {exit !found}'
}

count_filter() {
    local filter="$1"

    tshark -r "$PCAP" \
        -Y "$filter" \
        -T fields \
        -e frame.number 2>/dev/null |
        wc -l
}

echo "=== PCAP CHECK ==="
echo "PCAP: $PCAP"
echo "Packets: $(tshark -r "$PCAP" -T fields -e frame.number | wc -l)"

if [[ -f "$BASELINE_PCAP" ]]; then
    echo "Baseline PCAP: $BASELINE_PCAP"
else
    echo "Baseline PCAP: NOT FOUND"
fi

echo
echo "=== CROSS-SUBNET TRAFFIC ==="

echo
echo "--- 10.10.2.x -> 10.10.1.x ---"
echo "# Filter: ip"
echo "# Subnet classification is performed from TShark-extracted IPv4 addresses."

run -r "$PCAP" \
    -Y 'ip' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport |
awk -F '\t' '
function is_10_10_2(ip) {
    return ip ~ /^10[.]10[.]2[.][0-9]+$/
}
function is_10_10_1(ip) {
    return ip ~ /^10[.]10[.]1[.][0-9]+$/
}
is_10_10_2($2) && is_10_10_1($3) {
    print
}'

echo
echo "--- 10.10.1.x -> other 10.10.x.x internal subnets ---"
echo "# Filter: ip"
echo "# Destination is classified from TShark-extracted IPv4 addresses."

run -r "$PCAP" \
    -Y 'ip' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport |
awk -F '\t' '
$2 ~ /^10[.]10[.]1[.][0-9]+$/ &&
$3 ~ /^10[.]10[.][0-9]+[.][0-9]+$/ &&
$3 !~ /^10[.]10[.]1[.][0-9]+$/ {
    print
}'

echo
echo "--- Server-to-server traffic ---"
echo "# Filter: ip"
echo "# Both endpoints are classified from TShark-extracted 10.10.x.x addresses."

run -r "$PCAP" \
    -Y 'ip' \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport |
awk -F '\t' '
$2 ~ /^10[.]10[.][0-9]+[.][0-9]+$/ &&
$3 ~ /^10[.]10[.][0-9]+[.][0-9]+$/ &&
$2 != $3 {
    print
}'

echo
echo "=== AUTHENTICATION / REMOTE ACCESS EVENTS ==="

echo
echo "--- Protocol presence ---"

for item in \
    "Kerberos|kerberos" \
    "NTLMSSP|ntlmssp" \
    "RDP port 3389|tcp.port == 3389" \
    "RDP dissector|rdp" \
    "CredSSP/NLA|credssp" \
    "SMB|smb" \
    "SMB2|smb2"
do
    name="${item%%|*}"
    filter="${item#*|}"

    echo
    echo "$name"
    echo "# Filter: $filter"

    count=$(count_filter "$filter")

    if [[ "$count" -gt 0 ]]; then
        echo "Packets: $count"
    else
        echo "Not observed"
    fi
done

echo
echo "--- Kerberos events ---"

if count_filter 'kerberos' | grep -q '[1-9]'; then
    FILTER='kerberos'
    echo "# Filter: $FILTER"

    fields=(
        frame.time
        ip.src
        ip.dst
    )

    field_exists 'kerberos.CNameString' && fields+=(kerberos.CNameString)
    field_exists 'kerberos.SNameString' && fields+=(kerberos.SNameString)
    field_exists 'kerberos.msg_type' && fields+=(kerberos.msg_type)
    field_exists 'kerberos.error_code' && fields+=(kerberos.error_code)

    run -r "$PCAP" -Y "$FILTER" -T fields \
        "${fields[@]/#/-e}"
else
    echo "No Kerberos packets observed."
fi

echo
echo "--- NTLMSSP events ---"

if count_filter 'ntlmssp' | grep -q '[1-9]'; then
    FILTER='ntlmssp'
    echo "# Filter: $FILTER"

    fields=(
        frame.time
        ip.src
        ip.dst
    )

    field_exists 'ntlmssp.messagetype' &&
        fields+=(ntlmssp.messagetype)

    field_exists 'ntlmssp.auth.username' &&
        fields+=(ntlmssp.auth.username)

    run -r "$PCAP" -Y "$FILTER" -T fields \
        "${fields[@]/#/-e}"
else
    echo "No NTLMSSP packets observed."
fi

echo
echo "--- RDP / NLA events ---"

FILTER='tcp.port == 3389'
echo "# Filter: $FILTER"

RDP_COUNT=$(count_filter "$FILTER")
echo "RDP TCP/3389 packets: $RDP_COUNT"

if [[ "$RDP_COUNT" -gt 0 ]]; then
    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport
fi

echo
FILTER='credssp'
echo "# Filter: $FILTER"

CREDSSP_COUNT=$(count_filter "$FILTER")
echo "CredSSP packets: $CREDSSP_COUNT"

if [[ "$CREDSSP_COUNT" -gt 0 ]]; then
    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst
fi

echo
echo "--- SMB Session Setup ---"

SMB_SETUP_FILTER='smb2.cmd == 1'
echo "# Filter: $SMB_SETUP_FILTER"

if field_exists 'smb2.cmd'; then
    SMB_SETUP_COUNT=$(count_filter "$SMB_SETUP_FILTER")
    echo "SMB2 Session Setup packets: $SMB_SETUP_COUNT"

    if [[ "$SMB_SETUP_COUNT" -gt 0 ]]; then
        fields=(
            frame.time
            ip.src
            ip.dst
            smb2.cmd
        )

        field_exists 'smb2.nt_status' &&
            fields+=(smb2.nt_status)

        run -r "$PCAP" -Y "$SMB_SETUP_FILTER" -T fields \
            "${fields[@]/#/-e}"
    fi
else
    echo "smb2.cmd is not available in this TShark version."
fi

echo
echo "=== ATTACK PATH ==="

echo
echo "--- Starting system activity ---"
FILTER='ip.src == 10.10.2.15'
echo "# Filter: $FILTER"

run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e udp.dstport

echo
echo "--- WS-NURSE-04 -> billing-srv-01 ---"
FILTER='ip.src == 10.10.2.15 && ip.dst == 10.10.1.10'
echo "# Filter: $FILTER"

run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e udp.dstport

echo
echo "--- Systems contacted by billing-srv-01 ---"
FILTER='ip.src == 10.10.1.10'
echo "# Filter: $FILTER"

run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e udp.dstport |
awk -F '\t' '$3 != "" {print}' |
sort -k3,3 -k1,1

echo
echo "--- Unique destinations from billing-srv-01 ---"
FILTER='ip.src == 10.10.1.10'
echo "# Filter: $FILTER"

run -r "$PCAP" -Y "$FILTER" -T fields \
    -e ip.dst |
awk 'NF {count[$1]++} END {
    for (ip in count)
        printf "%-15s %d packets\n", ip, count[ip]
}' |
sort -k2nr

echo
echo "--- WS-NURSE-04 first internal destination ---"
FILTER='ip.src == 10.10.2.15'
echo "# Filter: $FILTER"

run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time_epoch \
    -e frame.time \
    -e ip.dst |
awk '
$3 ~ /^10[.]10[.]/ {
    if (!found) {
        print "First internal destination:"
        print "Timestamp:", $2
        print "Destination:", $3
        found=1
    }
}'

echo
echo "=== FAILED CONNECTIONS ==="

echo
echo "--- TCP RST packets ---"
FILTER='tcp.flags.reset == 1'
echo "# Filter: $FILTER"

RST_COUNT=$(count_filter "$FILTER")
echo "RST packets: $RST_COUNT"

if [[ "$RST_COUNT" -gt 0 ]]; then
    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport
fi

echo
echo "--- RST responses to SYN ---"
FILTER='tcp.flags.syn == 1 && tcp.flags.reset == 1'
echo "# Filter: $FILTER"

SYN_RST_COUNT=$(count_filter "$FILTER")
echo "SYN/RST packets: $SYN_RST_COUNT"

if [[ "$SYN_RST_COUNT" -gt 0 ]]; then
    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport
fi

echo
echo "--- SMB error/status responses ---"

if field_exists 'smb2.nt_status'; then
    FILTER='smb2.nt_status'
    echo "# Filter: $FILTER"

    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e smb2.nt_status
else
    echo "smb2.nt_status is not available in this TShark version."
fi

echo
echo "--- Kerberos errors ---"

if field_exists 'kerberos.error_code'; then
    FILTER='kerberos.error_code'
    echo "# Filter: $FILTER"

    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e kerberos.error_code
else
    echo "kerberos.error_code is not available in this TShark version."
fi

echo
echo "=== SMB ENUMERATION ==="

echo
echo "--- SMB2 command distribution ---"

if field_exists 'smb2.cmd'; then
    FILTER='smb2'
    echo "# Filter: $FILTER"

    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e smb2.cmd |
    awk -F '\t' '
    $4 != "" {
        count[$4]++
    }
    END {
        for (cmd in count)
            printf "SMB2 command %s: %d packets\n", cmd, count[cmd]
    }' |
    sort
else
    echo "smb2.cmd is not available in this TShark version."
fi

echo
echo "--- SMB filenames when visible ---"

if field_exists 'smb2.filename'; then
    FILTER='smb2.filename'
    echo "# Filter: $FILTER"

    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e smb2.filename
else
    echo "smb2.filename is not available in this TShark version."
fi

echo
echo "--- SMB tree/share connections ---"

if field_exists 'smb2.cmd'; then
    FILTER='smb2.cmd == 3'
    echo "# Filter: $FILTER"

    run -r "$PCAP" -Y "$FILTER" -T fields \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e smb2.cmd
else
    echo "smb2.cmd is not available in this TShark version."
fi

echo
echo "=== BASELINE COMPARISON ==="

if [[ -f "$BASELINE_PCAP" ]]; then

    echo
    echo "--- WS-NURSE-04 -> billing-srv-01 RDP in baseline ---"
    FILTER='ip.src == 10.10.2.15 && ip.dst == 10.10.1.10 && tcp.dstport == 3389'
    echo "# Baseline filter: $FILTER"

    BASE_RDP=$(tshark -r "$BASELINE_PCAP" \
        -Y "$FILTER" \
        -T fields \
        -e frame.number |
        wc -l)

    echo "Baseline matching packets: $BASE_RDP"

    echo
    echo "--- Current WS-NURSE-04 -> billing-srv-01 RDP ---"
    FILTER='ip.src == 10.10.2.15 && ip.dst == 10.10.1.10 && tcp.dstport == 3389'
    echo "# Current filter: $FILTER"

    CURRENT_RDP=$(tshark -r "$PCAP" \
        -Y "$FILTER" \
        -T fields \
        -e frame.number |
        wc -l)

    echo "Current matching packets: $CURRENT_RDP"

    echo
    echo "--- billing-srv-01 outbound destinations in baseline ---"
    FILTER='ip.src == 10.10.1.10'
    echo "# Baseline filter: $FILTER"

    tshark -r "$BASELINE_PCAP" \
        -Y "$FILTER" \
        -T fields \
        -e ip.dst |
    awk 'NF {count[$1]++}
    END {
        for (ip in count)
            printf "%-15s %d packets\n", ip, count[ip]
    }' |
    sort -k2nr

    echo
    echo "--- billing-srv-01 outbound destinations in current PCAP ---"
    FILTER='ip.src == 10.10.1.10'
    echo "# Current filter: $FILTER"

    run -r "$PCAP" \
        -Y "$FILTER" \
        -T fields \
        -e ip.dst |
    awk 'NF {count[$1]++}
    END {
        for (ip in count)
            printf "%-15s %d packets\n", ip, count[ip]
    }' |
    sort -k2nr

    echo
    echo "--- Baseline SMB activity from billing-srv-01 ---"
    FILTER='ip.src == 10.10.1.10 && tcp.dstport == 445'
    echo "# Baseline filter: $FILTER"

    tshark -r "$BASELINE_PCAP" \
        -Y "$FILTER" \
        -T fields \
        -e frame.number |
        wc -l

    echo
    echo "--- Current SMB activity from billing-srv-01 ---"
    FILTER='ip.src == 10.10.1.10 && tcp.dstport == 445'
    echo "# Current filter: $FILTER"

    tshark -r "$PCAP" \
        -Y "$FILTER" \
        -T fields \
        -e frame.number |
        wc -l

else
    echo "Baseline PCAP unavailable."
    echo "No baseline traffic comparison performed."
fi

echo
echo "=== TIMING ==="

FILTER='ip.src == 10.10.2.15 || ip.src == 10.10.1.10'
echo "# Filter: $FILTER"

run -r "$PCAP" \
    -Y "$FILTER" \
    -T fields \
    -e frame.time_epoch \
    -e frame.time \
    -e ip.src \
    -e ip.dst |
awk -F '\t' '
NR == 1 {
    first_epoch=$1
    first_time=$2
}
{
    last_epoch=$1
    last_time=$2
}
END {
    if (NR > 0) {
        printf "First observed packet: %s\n", first_time
        printf "Last observed packet:  %s\n", last_time
        printf "Observed duration: %.3f seconds\n", last_epoch-first_epoch
    } else {
        print "No packets matched."
    }
}'

echo
echo "=== MITRE ATT&CK EVIDENCE MAPPING ==="

echo
echo "--- T1021.001 - Remote Services: RDP ---"
echo "# Evidence filter: ip.src == 10.10.2.15 && ip.dst == 10.10.1.10 && tcp.dstport == 3389"

RDP_PATH_COUNT=$(count_filter \
    'ip.src == 10.10.2.15 && ip.dst == 10.10.1.10 && tcp.dstport == 3389')

if [[ "$RDP_PATH_COUNT" -gt 0 ]]; then
    echo "Observed: $RDP_PATH_COUNT matching packets."
    echo "Evidence supports RDP traffic between the two specified hosts."
else
    echo "Not observed between the specified hosts."
fi

echo
echo "--- T1021.002 - Remote Services: SMB/Windows Admin Shares ---"
echo "# Evidence filter: ip.src == 10.10.1.10 && tcp.dstport == 445"

SMB_PATH_COUNT=$(count_filter \
    'ip.src == 10.10.1.10 && tcp.dstport == 445')

if [[ "$SMB_PATH_COUNT" -gt 0 ]]; then
    echo "Observed: $SMB_PATH_COUNT matching packets."
    echo "Evidence supports SMB traffic from billing-srv-01."
else
    echo "No matching SMB traffic observed."
fi

echo
echo "--- T1046 - Network Service Scanning ---"
echo "# Evidence: unique destination IPs contacted by 10.10.1.10"

run -r "$PCAP" \
    -Y 'ip.src == 10.10.1.10' \
    -T fields \
    -e ip.dst |
awk 'NF {seen[$1]=1}
END {
    for (ip in seen)
        count++
    printf "Unique destinations contacted by billing-srv-01: %d\n", count
}'

echo "This count is evidence only; broad scanning is not inferred from the count alone."

echo
echo "--- T1135 - Network Share Discovery ---"
echo "# Evidence filter: smb2.cmd == 3"

if field_exists 'smb2.cmd'; then
    SHARE_COUNT=$(count_filter 'smb2.cmd == 3')
    echo "SMB2 Tree Connect packets: $SHARE_COUNT"

    if [[ "$SHARE_COUNT" -gt 0 ]]; then
        echo "SMB2 tree/share connection activity was observed."
    else
        echo "No SMB2 Tree Connect packets observed."
    fi
else
    echo "smb2.cmd unavailable; mapping cannot be evaluated from this field."
fi

echo
echo "--- T1078 - Valid Accounts ---"
echo "# Evidence: packet-visible usernames plus successful authentication status."

if count_filter 'ntlmssp' | grep -q '[1-9]' ||
   count_filter 'kerberos' | grep -q '[1-9]'; then
    echo "Authentication protocol traffic is present."
    echo "A valid-account technique is not asserted without packet-visible successful authentication."
else
    echo "No Kerberos or NTLMSSP traffic observed."
    echo "Valid Accounts cannot be established from these protocols."
fi

echo
