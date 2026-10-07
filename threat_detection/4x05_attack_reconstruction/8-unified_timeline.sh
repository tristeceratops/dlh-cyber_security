#!/bin/bash

echo "================================================================"
echo "   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense"
echo "   Period: 2026-04-14 to 2026-05-18"
echo "================================================================"
echo
echo "CHRONOLOGICAL SEQUENCE:"
echo
printf "  #  Timestamp                 Event                              ATT&CK       Conf   Sources\n"
printf "  -- ------------------------  ---------------------------------  -----------  -----  ----------------\n"

printf "  01 2026-04-14 13:14:22 UTC  Phishing email delivered             T1566.001    CONF   4x00\n"
printf "  02 2026-04-14 13:18:05 UTC  Diane clicks phishing link           T1566.001    CONF   4x00,4x01\n"
printf "  03 2026-04-14 13:18:42 UTC  Credentials submitted                T1078        CONV   4x00,4x01\n"
printf "  04 2026-04-15 08:51:09 UTC  C2 domain resolved                   T1071.004    CONV   4x01\n"
printf "  05 2026-04-15 08:51:11 UTC  Stage 2 payload downloaded            T1105        CONV   4x01,4x03\n"
printf "  06 2026-04-15 08:51:38 UTC  First C2 beacon                      T1071.001    CONV   4x01,IR-FW\n"
printf "  07 2026-04-15 08:51:38 UTC  Encrypted C2 channel established      T1573.001    CONF   4x01\n"
printf "  08 2026-04-15 13:42:11 UTC  DNS tunneling test                   T1071.004    CONF   4x01\n"
printf "  09 2026-05-05 03:22 CDT     First LSASS credential dump           T1003.001    CONV   4x04,4x05\n"
printf "  10 2026-05-06 02:12 CDT     PsExec lateral movement              T1021.002    CONV   4x04,4x05\n"
printf "  11 2026-05-06 02:12 CDT     WMI remote activity                  T1047        CONF   4x04\n"
printf "  12 2026-05-06 02:12 CDT     PSRemoting remote activity            T1021.006    CONF   4x04\n"
printf "  13 2026-05-07 01:47 CDT     HealthSync scheduled task             T1053.005    CONV   4x05\n"
printf "  14 2026-05-07 01:47 CDT     Defender exclusion configured         T1562.001    CONF   4x05\n"
printf "  15 2026-05-07 01:48 CDT     Secondary C2 becomes active           T1571        CONV   4x05,IR-FW\n"
printf "  16 2026-05-09 03:40 CDT     Lateral movement to SRV-INS-DB       T1021.002    CONF   4x04\n"
printf "  17 2026-05-12 02:45 CDT     Second LSASS credential dump          T1003.001    CONV   4x04,4x05\n"
printf "  18 2026-05-13 01:56 CDT     Lateral movement to SRV-DC-01        T1021.002    CONF   4x04\n"
printf "  19 2026-05-13 01:56 CDT     Active Directory discovery             T1018        CONF   4x04\n"
printf "  20 2026-05-15 07:14:18 UTC  Last observed secondary C2 session    T1571        CONF   IR-FW\n"
printf "  21 2026-05-18 09:00 CDT     Proactive hunt initiated              ---          CONF   4x04\n"
printf "  22 2026-05-18 13:42 CDT     WS-RECV-03 isolated                   ---          CONF   IR\n"
printf "  23 2026-05-18 14:18 CDT     Memory acquisition completed           ---          CONF   IR\n"
printf "  24 2026-05-18 19:45 CDT     Disk imaging completed                 ---          CONF   IR\n"

echo
echo "HOST / CREDENTIAL CONTEXT:"
echo "  Initial access:     WS-RECV-03 / Diane Marsh (dmarsh)"
echo "  Primary C2:         WS-RECV-03 -> 185.220.101.45:443"
echo "  Secondary C2:       WS-RECV-03 -> 203.0.113.47:8443"
echo "  Lateral source:     WS-RECV-03 (10.10.3.21)"
echo "  Lateral targets:    SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01"
echo "  Credential abused:  svc_healthsync via NTLM"
echo "  Credential source:   LSASS access from debug_tool.exe"
echo
echo "  Data collection is directly evidenced against:"
echo "    SRV-HEALTH-DB / health_records"
echo "  Local staging location:"
echo "    WS-RECV-03 / C:\\Users\\Public\\Tmp"
echo
echo "CLOCK SKEW:"
echo "  4x01 PCAP timestamps are approximately 4 seconds ahead of"
echo "  firewall timestamps. Firewall timestamps are authoritative"
echo "  for connection initiation. No adjustment is required for"
echo "  ordering at the minute/hour level used here."
echo
echo "TEMPORAL METRICS:"
echo
echo "  Total dwell time:"
echo "    34 days, 0 hours, 23 minutes"
echo "    2026-04-14 13:18:05 UTC -> 2026-05-18 13:42 CDT"
echo "    Note: containment time is recorded in CDT; source timestamps"
echo "    should be normalized before automated duration calculations."
echo
echo "  Breakout time:"
echo "    Approximately 21 days, 12 hours"
echo "    Initial access -> first confirmed lateral movement."
echo
echo "  Time to persistence:"
echo "    Approximately 21 days"
echo "    Initial access -> HealthSync scheduled task."
echo
echo "  Time to data staging:"
echo "    NOT CONFIDENTLY CALCULABLE"
echo "    Disk evidence timestamps staging files as Feb 10-11, while"
echo "    the memory/firewall/lateral-movement timeline is May 2026."
echo "    The supplied evidence contains a date inconsistency."
echo
echo "  Detection to containment:"
echo "    4 hours, 42 minutes"
echo "    2026-05-18 09:00 CDT hunt -> 13:42 CDT isolation."
echo
echo "  Operational tempo:"
echo "    Activity clusters during off-hours, generally 01:00-04:00 CDT."
echo "    Major phases progress from phishing -> C2 -> credential access"
echo "    -> lateral movement -> collection/staging -> containment."
echo
echo "TIMELINE EVIDENCE SUMMARY:"
echo
echo "  Total events in timeline:             24"
echo "  Events with CONVERGED evidence:       7"
echo "  Events with SINGLE-SOURCE evidence:    17"
echo "  Convergence rate:                      29%"
echo
echo "  CONVERGED examples:"
echo "    - Credential submission: 4x00 + 4x01"
echo "    - First C2: 4x01 + firewall"
echo "    - LSASS dumping: 4x04 + 4x05"
echo "    - PsExec lateral movement: 4x04 + 4x05"
echo "    - Scheduled task: 4x04 + 4x05"
echo "    - Secondary C2: memory + firewall"
echo
echo "TIMELINE GAPS:"
echo
echo "  GAP 1: 2026-04-16 to 2026-05-04"
echo "         PCAP visibility ended after the initial C2 period."
echo "         Assessment: collection/visibility gap. Firewall evidence"
echo "         partially bridges this period but does not provide endpoint"
echo "         activity or complete command-level reconstruction."
echo
echo "  GAP 2: Between initial C2 establishment and 2026-05-05"
echo "         No endpoint telemetry is available for the intermediate"
echo "         period before the 4x04 hunt."
echo "         Assessment: attacker activity is unknown."
echo
echo "  GAP 3: 2026-05-07 to 2026-05-09"
echo "         Secondary C2 is observed, but endpoint evidence does not"
echo "         establish every action performed through that channel."
echo "         Assessment: network visibility without complete endpoint context."
echo
echo "  GAP 4: Staging dates in disk evidence"
echo "         Disk evidence reports Feb 10-11 timestamps, while the"
echo "         unified incident timeline is otherwise Apr-May 2026."
echo "         Assessment: unresolved source-date inconsistency."
echo
echo "SEQUENCING UNCERTAINTIES:"
echo
echo "  [*] Stage 2 -> Stage 4 intermediate activity cannot be completely"
echo "      sequenced because endpoint telemetry is absent before 4x04."
echo
echo "  [*] Secondary C2 first observed on 2026-05-07 06:48:11 UTC."
echo "      Memory evidence establishes the connection, while firewall"
echo "      evidence establishes network timing. Exact process activity"
echo "      over every session is not available."
echo
echo "  [*] Data-staging events cannot be confidently placed in the May"
echo "      attack sequence because disk evidence uses Feb 10-11 timestamps."
echo "      This is a significant reconstruction uncertainty."
echo
echo "  [*] Last attacker activity cannot be equated with the last known"
echo "      firewall session. Network inactivity does not prove attacker"
echo "      inactivity."
echo
echo "================================================================"