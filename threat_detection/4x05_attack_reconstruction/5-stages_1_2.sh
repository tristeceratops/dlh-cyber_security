#!/bin/bash

set -u

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PREVIOUS="$BASE_DIR/4x05/previous_findings"

PHISH="$PREVIOUS/4x00_phishing_summary.txt"
NETWORK="$PREVIOUS/4x01_network_timeline.txt"
FIREWALL="$BASE_DIR/3-firewall_analysis.sh"

echo "================================================================"
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
echo "================================================================"
echo

# ------------------------------------------------------------------
# Stage 1
# ------------------------------------------------------------------

echo "STAGE 1: INITIAL ACCESS (Phishing Campaign)"
echo "  Timeline: 2026-04-14 through 2026-04-21"
echo

echo "  [2026-04-14 13:14:22Z] Phishing email delivered"
echo "    Evidence: 4x00 email batch analysis"
echo "    Campaign: 8 emails analyzed, 3 malicious"
echo "    Technique: T1566.001 Spearphishing Link"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-04-14 13:18:05Z] Diane Marsh opens phishing link"
echo "    Host: WS-RECV-03"
echo "    Evidence: 4x00 browser history and investigation record"
echo "    Domain: meddefense-portal.com"
echo "    SPF: hardfail"
echo "    DKIM: missing"
echo "    DMARC: fail"
echo "    Technique: T1566.001 Spearphishing Link"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-04-14 13:18:42Z] Credentials submitted"
echo "    Evidence: 4x00 + 4x01 PCAP"
echo "    Destination: meddefense-portal.com /collect.php"
echo "    Origin IP: 91.219.236.117"
echo "    Technique: T1078 Valid Accounts"
echo "    Confidence: CONFIRMED"
echo

echo "  Temporal anchor:"
echo "    Credential exposure = 2026-04-14 13:18:42Z"
echo

# ------------------------------------------------------------------
# Stage 2
# ------------------------------------------------------------------

echo "STAGE 2: C2 ESTABLISHMENT"
echo "  Timeline: 2026-04-15 onward"
echo

echo "  [2026-04-15 08:51:09Z] C2 domain resolution"
echo "    Evidence: 4x01 PCAP"
echo "    Domain: update.healthbane-c2.net"
echo "    Resolved IP: 185.220.101.45"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-04-15 08:51:11Z] Stage 2 payload downloaded"
echo "    Evidence: 4x01 PCAP"
echo "    URL: /update/svchost_update.exe"
echo "    Destination: 185.220.101.45:443"
echo "    Technique: T1105 Ingress Tool Transfer"
echo "    Confidence: CONFIRMED"
echo

echo "  [2026-04-15 08:51:38Z] First C2 beacon"
echo "    Evidence: 4x01 PCAP"
echo "    Destination: 185.220.101.45:443"
echo "    SNI: sync.healthbane-c2.net"
echo "    Protocol: HTTPS"
echo "    Path: /api/v1/checkin"
echo "    Technique: T1071.001 Web Protocols"
echo "    Confidence: CONFIRMED"
echo

echo "  C2 beacon pattern:"
echo "    Interval: approximately 300 +/- 10 seconds"
echo "    Encryption: RC4-wrapped JSON over TLS"
echo "    Evidence: 4x01 network analysis"
echo "    Technique: T1573.001 Symmetric Cryptography"
echo "    Confidence: CONFIRMED"
echo

echo "  Firewall correlation:"
echo "    Known C2: 185.220.101.45:443"
echo "    Evidence: 3-firewall_analysis.sh"
echo "    Firewall sessions: 3958"
echo "    Outbound traffic: 80,967,579 bytes"
echo "    Confidence: CONVERGED"
echo

echo "  Clock/timestamp resolution:"
echo "    4x01 states that PCAP timestamps are approximately"
echo "    4 seconds ahead of firewall timestamps."
echo "    Resolution: use PCAP timing for packet-level beacon"
echo "    activity and firewall timing for connection initiation."
echo

# ------------------------------------------------------------------
# Secondary C2
# ------------------------------------------------------------------

echo "  Secondary C2:"
echo "    IP: 203.0.113.47:8443"
echo "    Evidence: IR memory + firewall"
echo "    First firewall session: 2026-05-07 06:48:11Z"
echo "    Last observed: 2026-05-15 07:14:18Z"
echo "    Technique: T1571 Non-Standard Port"
echo "    Confidence: CONVERGED"
echo

echo "  Stage 2 determination:"
echo "    The secondary C2 was NOT visible in the 4x01 Stage 2 PCAP."
echo "    4x01 Stage 2 C2 began on 2026-04-15."
echo "    Firewall evidence first identifies 203.0.113.47:8443"
echo "    on 2026-05-07."
echo
echo "    Resolution: secondary C2 appeared LATER, after the"
echo "    initial C2 channel was already established."
echo

# ------------------------------------------------------------------
# Dynamic resolution
# ------------------------------------------------------------------

echo "  Dynamic resolution:"
echo "    update.healthbane-c2.net -> 185.220.101.45"
echo "    sync.healthbane-c2.net -> 185.220.101.45"
echo "    data-sync.healthbane-c2.net -> 185.220.101.46"
echo "    Technique: T1568 Dynamic Resolution"
echo "    Assessment: POSSIBLE / supporting DNS evidence"
echo

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------

echo "STAGE 1-2 SUMMARY:"
echo "  Credential exposure: 2026-04-14 13:18:42Z"
echo "  First Stage 2 payload: 2026-04-15 08:51:11Z"
echo "  First C2 beacon: 2026-04-15 08:51:38Z"
echo "  Initial C2: 185.220.101.45:443"
echo "  Secondary C2: 203.0.113.47:8443"
echo
echo "  Techniques:"
echo "    T1566.001  Spearphishing Link"
echo "    T1078      Valid Accounts"
echo "    T1071.001  Web Protocols"
echo "    T1573.001  Symmetric Cryptography"
echo "    T1568      Dynamic Resolution"
echo "    T1105      Ingress Tool Transfer"
echo "    T1571      Non-Standard Port"
echo
echo "  Confidence:"
echo "    Phishing delivery       CONFIRMED"
echo "    Credential compromise   CONFIRMED"
echo "    Initial C2              CONVERGED"
echo "    C2 beacon pattern       CONFIRMED"
echo "    Secondary C2            CONVERGED"
echo "    Dynamic resolution      POSSIBLE"
echo
echo "  Key finding:"
echo "    203.0.113.47:8443 was NOT operational in the available"
echo "    Stage 2 PCAP window. It first appears in firewall evidence"
echo "    on 2026-05-07, after the initial C2 channel was established."
echo
echo "================================================================"
echo