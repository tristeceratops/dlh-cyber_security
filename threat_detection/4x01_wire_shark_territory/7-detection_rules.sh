#!/bin/bash
set -euo pipefail

echo "================================================================"
echo "   DETECTION ENGINEERING PLAN"
echo "================================================================"

# ----------------------------------------------------------------
# Detection 1
# ----------------------------------------------------------------
echo
echo "[*] Detection 1: C2 Beaconing"
echo "    Type: Frequency + interval-regularity behavioral detection"
echo "    Logic:"
echo "      Group connections by src_ip -> dst_ip."
echo "      Count connections in a rolling 3600-second window."
echo "      If count > 10:"
echo "        calculate intervals between consecutive connections."
echo "        interval_mean = mean(intervals)."
echo "        interval_stddev = standard deviation(intervals)."
echo "        If interval_stddev < interval_mean * 0.15:"
echo "          THEN alert: Possible C2 beaconing"
echo
echo "    Pseudocode:"
echo "      for each src_ip, dst_ip:"
echo "        sessions = connections_in_last_3600_seconds()"
echo "        if len(sessions) > 10:"
echo "          intervals = diff(session_timestamps)"
echo "          mean = average(intervals)"
echo "          stddev = standard_deviation(intervals)"
echo "          if stddev < mean * 0.15:"
echo "            alert(src_ip, dst_ip, mean, stddev)"
echo
echo "    SIEM implementation:"
echo "      Aggregate network sessions by source/destination."
echo "      Use a rolling 60-minute window and statistical aggregation."
echo
echo "    Zeek implementation:"
echo "      Track conn.log timestamps by src/dst pair."
echo "      Calculate intervals after each new connection."
echo "      Raise notice when frequency and regularity thresholds match."
echo
echo "    Python scheduled analysis:"
echo "      Read Zeek conn.log, NetFlow or proxy records."
echo "      Group by src/dst, calculate interval statistics, emit alerts."
echo
echo "    NetFlow implementation:"
echo "      Group flow records by internal source and external destination."
echo "      Calculate connection frequency and inter-flow timing."
echo
echo "    Required data source:"
echo "      Zeek conn.log, NetFlow, firewall, proxy or SIEM network telemetry"
echo
echo "    Test scenario:"
echo "      10.10.2.15 -> 91.234.99.107 every ~300 seconds"
echo "      for 24 observed sessions."
echo
echo "    Would detect:"
echo "      Phase 3 beaconing in c2_beaconing.pcap"
echo
echo "    False positive considerations:"
echo "      Software updates, monitoring agents, backup tools,"
echo "      endpoint management and health checks may be periodic."
echo "      Use destination reputation and historical baselines to reduce noise."

# ----------------------------------------------------------------
# Detection 2
# ----------------------------------------------------------------
echo
echo "[*] Detection 2: DNS Query Length Anomaly"
echo "    Type: DNS lexical anomaly detection"
echo "    Logic:"
echo "      Extract the left-most label from dns.qry.name."
echo "      If label length > 40 characters:"
echo "        AND query type is TXT:"
echo "        AND repeated queries target the same base domain:"
echo "          THEN alert: Possible DNS tunneling"
echo
echo "    Pseudocode:"
echo "      label = leftmost_label(dns.qry.name)"
echo "      if length(label) > 40:"
echo "        if dns.qry.type == TXT:"
echo "          if repeated_same_base_domain:"
echo "            alert(src_ip, base_domain, label_length)"
echo
echo "    Why encoded labels matter:"
echo "      DNS labels normally contain hostnames and service names."
echo "      Long, high-entropy or encoded-looking labels can carry"
echo "      chunks of data inside DNS queries."
echo "      Repeated long labels beneath one domain increase tunneling suspicion."
echo
echo "    Required data source:"
echo "      DNS query logs, Zeek dns.log, resolver logs or packet capture"
echo
echo "    Test scenario:"
echo "      Query:"
echo "      obqxi2lfnz2f64tfmnxxezb2jfcd2nbyheysy3tbnvst2us.data-sync.meddefense-portal.com"
echo "      Left-most label is greater than 40 characters."
echo
echo "    Would detect:"
echo "      Phase 7 DNS exfiltration in dns_exfil.pcap"
echo
echo "    False positive considerations:"
echo "      CDNs, tracking systems, DKIM-related names, cloud services"
echo "      and legitimate machine-generated DNS names can be long."
echo "      Combine length with query type, frequency and entropy."

# ----------------------------------------------------------------
# Detection 3
# ----------------------------------------------------------------
echo
echo "[*] Detection 3: VPN Geo-Anomaly"
echo "    Type: Authentication + geolocation behavioral detection"
echo "    Logic:"
echo "      If VPN source country OR ASN is outside the organization's"
echo "      approved geography/ASN list:"
echo "        AND the account has no established history from that location:"
echo "          THEN alert: Suspicious VPN login"
echo
echo "    Pseudocode:"
echo "      country = GeoIP(vpn_source_ip).country"
echo "      asn = GeoIP(vpn_source_ip).asn"
echo "      if country not in approved_countries:"
echo "        if asn not in approved_asns:"
echo "          if no_recent_account_history(account, country, asn):"
echo "            alert(account, source_ip, country, asn)"
echo
echo "    Required data source:"
echo "      VPN authentication logs containing:"
echo "        username/account"
echo "        source IP"
echo "        timestamp"
echo "        authentication result"
echo "        MFA result"
echo "        assigned VPN session"
echo "      PLUS GeoIP/ASN enrichment."
echo
echo "    Test scenario:"
echo "      VPN source: 154.118.42.89"
echo "      Destination: 10.10.0.1:443"
echo "      Enrich source IP with country and ASN."
echo "      Compare against approved organization geography/ASN."
echo
echo "    Would detect:"
echo "      Phase 4 external VPN access."
echo
echo "    False positive considerations:"
echo "      Employees travelling, approved VPN providers,"
echo "      cloud egress addresses and corporate proxies."
echo "      Maintain an approved travel/ASN exception process."
echo
echo "    Important limitation:"
echo "      Packet data alone does not prove VPN authentication,"
echo "      account identity, country or ASN. Authentication logs are required."

# ----------------------------------------------------------------
# Detection 4
# ----------------------------------------------------------------
echo
echo "[*] Detection 4: Cross-Role RDP"
echo "    Type: Identity + network access-control detection"
echo "    Logic:"
echo "      If account_role is clinical/non-IT"
echo "      AND destination belongs to server subnet"
echo "      AND destination port == 3389:"
echo "        THEN alert: Possible lateral movement"
echo
echo "    Pseudocode:"
echo "      if role(account) in CLINICAL_OR_NON_IT:"
echo "        if destination_ip in SERVER_SUBNETS:"
echo "          if dst_port == 3389:"
echo "            alert(account, src_ip, destination_ip)"
echo
echo "    Packet-metadata option:"
echo "      Detect TCP connections to tcp/3389 from workstation VLANs"
echo "      toward protected server subnets."
echo
echo "    Authentication-log option:"
echo "      Correlate Windows Security/RDP authentication events"
echo "      with account role, source workstation and destination server."
echo
echo "    Required data source:"
echo "      Network telemetry for TCP/3389"
echo "      PLUS identity/AD role information."
echo "      Windows authentication logs provide stronger attribution."
echo
echo "    Test scenario:"
echo "      10.10.2.15 -> 10.10.1.10:3389"
echo "      WS-NURSE-04 -> billing-srv-01"
echo
echo "    Would detect:"
echo "      Phase 5 lateral movement."
echo
echo "    False positive considerations:"
echo "      Help-desk activity, approved clinical administration,"
echo "      emergency support and temporary elevated privileges."
echo "      Use documented exceptions rather than disabling the rule."

# ----------------------------------------------------------------
# Detection 5
# ----------------------------------------------------------------
echo
echo "[*] Detection 5: DNS Tunneling TXT Query Pattern"
echo "    Type: Frequency + encoding behavioral detection"
echo "    Logic:"
echo "      Count TXT queries per source IP per base domain."
echo "      If count > 10 within 120 seconds"
echo "      AND encoded-looking labels are present:"
echo "        THEN alert: Possible DNS tunneling"
echo
echo "    Pseudocode:"
echo "      for each src_ip, base_domain:"
echo "        queries = TXT_queries(last_120_seconds)"
echo "        encoded = count_encoded_or_high_entropy_labels(queries)"
echo "        if len(queries) > 10 AND encoded > 0:"
echo "          alert(src_ip, base_domain, len(queries), encoded)"
echo
echo "    Useful encoding indicators:"
echo "      Base32-like alphabet"
echo "      Base64-like alphabet"
echo "      hexadecimal strings"
echo "      high character entropy"
echo "      repeated long labels"
echo "      sequentially changing labels under one base domain"
echo
echo "    Required data source:"
echo "      DNS resolver logs, Zeek dns.log or packet capture"
echo
echo "    Test scenario:"
echo "      10.10.1.10 repeatedly queries"
echo "      data-sync.meddefense-portal.com"
echo "      using long encoded-looking labels."
echo
echo "    Would detect:"
echo "      Phase 7 DNS exfiltration."
echo
echo "    False positive considerations:"
echo "      Security products, service discovery, DKIM, SaaS applications"
echo "      and legitimate TXT-heavy applications."
echo "      Baseline known high-volume TXT domains."

# ----------------------------------------------------------------
# Detection 6
# ----------------------------------------------------------------
echo
echo "[*] Detection 6: TLS to Campaign Lookalike Domain"
echo "    Type: IOC / first-seen domain detection"
echo "    Logic:"
echo "      If TLS SNI matches a known phishing IOC:"
echo "        THEN alert immediately."
echo
echo "      OR:"
echo "      If TLS SNI matches a domain in a campaign first-seen table:"
echo "        AND domain was first observed during a phishing investigation:"
echo "          THEN alert with campaign context."
echo
echo "    Pseudocode:"
echo "      sni = tls.handshake.extensions_server_name"
echo
echo "      if sni in phishing_ioc_domains:"
echo "        alert(src_ip, sni, campaign_id)"
echo
echo "      first_seen = domain_first_seen_table[sni]"
echo "      if first_seen.campaign == PHISHING_CAMPAIGN:"
echo "        alert(src_ip, sni, first_seen.timestamp, campaign_id)"
echo
echo "    No live domain-age feed required:"
echo "      Maintain an internal IOC/first-seen table containing:"
echo "        domain"
echo "        first_seen_timestamp"
echo "        campaign/source"
echo "        confidence"
echo "        expiration timestamp"
echo
echo "    Required data source:"
echo "      TLS SNI from Zeek SSL logs, proxy logs, firewall telemetry"
echo "      or packet capture, plus IOC/first-seen enrichment."
echo
echo "    Test scenario:"
echo "      SNI: meddefense-portal.com"
echo "      Source: 10.10.2.15"
echo "      Destination: 91.234.99.107"
echo
echo "    Would detect:"
echo "      Phase 2 phishing-click TLS session."
echo
echo "    False positive considerations:"
echo "      Newly registered legitimate domains, shared hosting,"
echo "      marketing infrastructure and domains appearing in threat feeds."
echo "      Require campaign confidence and expiration controls."

# ----------------------------------------------------------------
# Detection coverage
# ----------------------------------------------------------------
echo
echo "=== DETECTION COVERAGE UPDATE ==="
echo "Before packet analysis:"
echo "  Campaign visibility depended primarily on email IOCs."
echo
echo "After detection engineering:"
echo "  Phase 1  Phishing delivery       -> email/IOC controls"
echo "  Phase 2  Phishing click          -> TLS SNI campaign IOC"
echo "  Phase 3  C2 beaconing            -> frequency + interval analysis"
echo "  Phase 4  VPN pivot               -> geo/ASN + authentication anomaly"
echo "  Phase 5  RDP lateral movement    -> cross-role server access"
echo "  Phase 6  SMB activity             -> TCP/445 behavioral monitoring"
echo "  Phase 7  DNS exfiltration        -> TXT frequency + label anomaly"
echo
echo "Remaining visibility gaps:"
echo "  Endpoint execution confirmation requires EDR/endpoint telemetry."
echo "  Successful credential use requires identity/authentication logs."
echo "  VPN account attribution requires VPN authentication logs."
echo "  Successful RDP authentication requires Windows security logs."
echo "  SMB enumeration/file access requires SMB or endpoint telemetry."
echo "  Exact exfiltrated content cannot be recovered from encrypted traffic"
echo "  without endpoint, proxy or destination-side evidence."
echo
echo "Operational principle:"
echo "  Network detections identify behavior."
echo "  Identity telemetry identifies the account."
echo "  Endpoint telemetry confirms execution and impact."
echo "  Correlation across all three produces higher-confidence alerts."
echo
echo "================================================================"
