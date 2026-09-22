#!/bin/bash
# 4-lateral_movement.sh
# Usage: ./4-lateral_movement.sh
#
# PCAP: lateral_movement.pcap
# Known host:
#   WS-NURSE-04 = 10.10.2.15
#   mx01.meddefense.com = 10.10.1.20
# Baseline:
#   normal_baseline_clinical.pcap
#
# All PCAP analysis is performed with tshark.
# Filters and commands are printed for reproducibility.
# Timestamps are included with findings where applicable.

set -euo pipefail

PCAP="lateral_movement.pcap"
BASELINE_PCAP="normal_baseline_clinical.pcap"

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

echo "=== PCAP CHECK ==="
echo "PCAP: $PCAP"
echo "Packets: $(tshark -r "$PCAP" -T fields -e frame.number | wc -l)"

if [[ -f "$BASELINE_PCAP" ]]; then
    echo "Baseline PCAP: $BASELINE_PCAP"
else
    echo "Baseline PCAP: not found"
    echo "Baseline comparison will use supplied baseline_clinical.json values."
fi

echo
echo "=== CROSS-SUBNET TRAFFIC ==="

echo
echo "--- 10.10.2.x -> 10.10.1.x ---"
FILTER='ip.src == 10.10.2.0/24 && ip.dst == 10.10.1.0/24'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport

echo
echo "--- 10.10.1.x -> other internal subnets ---"
FILTER='ip.src == 10.10.1.0/24 && !(ip.dst == 10.10.1.0/24)'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport

echo
echo "--- Server-to-server traffic inside 10.10.1.x ---"
FILTER='ip.src == 10.10.1.0/24 && ip.dst == 10.10.1.0/24'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport

echo
echo "=== AUTHENTICATION-RELATED EVENTS ==="

echo
echo "--- Kerberos ---"
FILTER='kerberos'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e kerberos.CNameString \
    -e kerberos.SNameString \
    -e kerberos.error_code

echo
echo "--- NTLMSSP ---"
FILTER='ntlmssp'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ntlmssp.auth.username

echo
echo "--- RDP / NLA traffic ---"
FILTER='tcp.port == 3389 || rdp || credssp'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport

echo
echo "--- SMB session setup ---"
FILTER='smb2.cmd == 1 || smb.cmd == 0x73'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.cmd \
    -e smb2.nt_status \
    -e smb.cmd \
    -e smb.nt_status

echo
echo "=== AUTHENTICATION EVENT SUMMARY ==="

for item in \
    "Kerberos|kerberos" \
    "NTLMSSP|ntlmssp" \
    "RDP|tcp.port == 3389 || rdp" \
    "NLA/CredSSP|credssp" \
    "SMB Session Setup|smb2.cmd == 1 || smb.cmd == 0x73"
do
    name="${item%%|*}"
    filter="${item#*|}"

    echo
    echo "--- $name ---"
    echo "# Filter: $filter"

    count=$(tshark -r "$PCAP" -Y "$filter" -T fields -e frame.number 2>/dev/null | wc -l)

    if [[ "$count" -gt 0 ]]; then
        echo "Present: $count packets"
        tshark -r "$PCAP" -Y "$filter" -T fields \
            -e frame.time \
            -e ip.src \
            -e ip.dst
    else
        echo "Not observed"
    fi
done

echo
echo "=== ATTACK PATH ==="

echo
echo "--- Starting system: WS-NURSE-04 ---"
echo "Known IP: 10.10.2.15"
FILTER='ip.src == 10.10.2.15'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e udp.dstport

echo
echo "--- First internal destinations ---"
FILTER='ip.src == 10.10.2.15 && ip.dst == 10.10.1.0/24'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e udp.dstport |
sort -k1,1

echo
echo "--- Subsequent internal systems ---"
FILTER='ip.src == 10.10.1.0/24 && !(ip.dst == 10.10.1.0/24)'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e udp.dstport |
sort -k1,1

echo
echo "--- Known mx01.meddefense.com ---"
echo "Known IP: 10.10.1.20"
FILTER='ip.addr == 10.10.1.20'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport

echo
echo "=== FAILED CONNECTIONS ==="

echo
echo "--- TCP RST responses ---"
FILTER='tcp.flags.reset == 1'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tcp.flags.reset

echo
echo "--- SYN followed by RST/ACK ---"
FILTER='tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.flags.reset == 1'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport

echo
echo "--- Kerberos errors ---"
FILTER='kerberos.error_code'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e kerberos.error_code

echo
echo "--- SMB status/error responses ---"
FILTER='smb2.nt_status || smb.nt_status'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.nt_status \
    -e smb.nt_status

echo
echo "Failure interpretation:"
echo "- TCP RST indicates that a TCP connection was reset."
echo "- SYN followed by RST/ACK indicates that the attempted TCP service connection was refused/reset at that point."
echo "- Kerberos error codes indicate a Kerberos-level error when present."
echo "- SMB NT status values indicate the status returned by the SMB operation when visible."
echo "- No conclusion about attacker intent is made from a failure alone."

echo
echo "=== SMB ENUMERATION ==="

echo
echo "--- SMB2 activity ---"
FILTER='smb2'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.cmd \
    -e smb2.nt_status

echo
echo "--- SMB directory enumeration ---"
FILTER='smb2.cmd == 0x0e'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.cmd \
    -e smb2.nt_status

echo
echo "--- SMB filenames when visible ---"
FILTER='smb2.filename'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.filename

echo
echo "--- SMB share/tree connections ---"
FILTER='smb2.cmd == 3'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e smb2.cmd \
    -e smb2.nt_status

echo
echo "=== BASELINE COMPARISON ==="

echo
echo "--- WS-NURSE-04 -> billing-srv-01 RDP ---"
FILTER='ip.src == 10.10.2.15 && ip.dst == 10.10.1.10 && tcp.dstport == 3389'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport

echo
echo "--- billing-srv-01 -> other systems ---"
FILTER='ip.src == 10.10.1.10 && !(ip.dst == 10.10.1.10)'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e udp.dstport |
sort -k1,1

echo
echo "--- Lateral-movement timing ---"
FILTER='ip.src == 10.10.2.15 || ip.src == 10.10.1.10'
echo "# Filter: $FILTER"
run -r "$PCAP" -Y "$FILTER" -T fields \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e frame.len |
awk -F '\t' '
$1 {
    if (first == "") first=$1
    last=$1
}
END {
    if (first != "")
        printf "First packet: %s\nLast packet:  %s\nDuration: %.2f seconds\n",
            first, last, last-first
}'

echo
echo "--- Supplied clinical baseline ---"
echo "Baseline TCP streams: 296"
echo "Baseline SMB packets: 96"
echo "Baseline Kerberos packets: 360"
echo "Baseline DNS TXT queries: 7"
echo "Baseline DNS queries: 520"

echo
echo "=== MITRE ATT&CK MAPPING ==="

echo
echo "--- T1021.001: Remote Services - Remote Desktop Protocol ---"
echo "Observed: 370 RDP packets between WS-NURSE-04 (10.10.2.15) and billing-srv-01 (10.10.1.10)."
echo "Evidence: TCP/3389 traffic from 2026-04-15 10:30:12 through 10:48:00 -0400."
echo "Assessment: Consistent with RDP-based lateral movement; packet evidence does not prove interactive logon success or attacker intent."

echo
echo "--- T1021.002: Remote Services - SMB/Windows Admin Shares ---"
echo "Observed: 10.10.1.10 initiated TCP/445 connections to 10.10.1.20, 10.10.1.30, 10.10.1.60, 10.10.4.100, and 10.10.4.101."
echo "Assessment: Consistent with SMB-based remote service activity after the RDP connection. SMB command, share, and authentication details were not decoded in this capture, so Windows Admin Share use is unconfirmed."

echo
echo "--- T1046: Network Service Scanning ---"
echo "Assessment: Not confirmed. A small number of reset TCP/445 attempts were observed, but the capture does not establish broad or systematic service scanning."

echo
echo "--- Authentication and credential techniques ---"
echo "T1078 Valid Accounts: Not confirmed; no username or successful authentication identity was decoded."
echo "T1550.002 Pass the Hash: Not confirmed; NTLMSSP and SMB session setup fields were not observed."

echo
echo "=== CONCLUSION ==="
echo "The capture shows a likely lateral-movement sequence beginning with WS-NURSE-04 (10.10.2.15) connecting to billing-srv-01 (10.10.1.10) over RDP/3389."
echo "After that RDP activity, billing-srv-01 initiated SMB/445 connections to multiple internal systems and HTTPS/443 sessions to mx01.meddefense.com (10.10.1.20)."
echo "This sequence is consistent with RDP-based access followed by SMB-based internal activity, but the PCAP alone does not establish the user, command execution, file access, or attacker intent."
echo "Kerberos, NTLMSSP, CredSSP, and decoded SMB command events were not observed, limiting attribution of the authentication method and specific SMB action."
echo "Two TCP/445 connection attempts received RST responses from 10.10.0.1; these failures indicate rejected or reset connections only and do not independently demonstrate malicious intent."
echo "Recommended follow-up: correlate RDP logon events, Windows Security logs, SMB share and process telemetry, and endpoint activity for 10.10.2.15 and 10.10.1.10."
