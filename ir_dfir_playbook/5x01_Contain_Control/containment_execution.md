# Containment Execution: IR-2026-0414-01

- 2026-04-14T03:16:04Z | [Network Operations actor] | Reassign WST-WS-031 (10.42.118.31) switch port to VLAN 999; apply quarantine ACL allowing IR jumpbox access only | Host isolated from user network; IR jumpbox access retained | [Record switch name, port, change ID, applied VLAN/ACL, and timestamped verification output] | [Record execution errors or deviations; use none only if verified]

- 2026-04-14T03:17:21Z | [Firewall Administrator actor] | Apply outbound deny rule for source 10.42.118.31 to destination 185.220.101.47, TCP port 443 | Outbound connection to suspected C2 destination blocked | [Record firewall rule ID, deployment status, timestamp, and matching deny-log event] | [Record failed deployment, rule-scope differences, or none if verified]

- 2026-04-14T03:17:21Z | [Incident Response Network Analyst] | Query packet capture or NetFlow for 10.42.118.31 -> 185.220.101.47:443/TCP after containment | No successful C2 sessions after the blocking action; any attempted traffic is denied | [Record telemetry source, query/filter, UTC interval, and evidence reference showing denied traffic or no successful sessions] | [Record telemetry gaps, collection delay, or other limitations]

- 2026-04-14T03:19:02Z | [Endpoint Response Analyst] | Enable endpoint network-containment flag for WST-WS-031, if supported | Endpoint console reports containment enabled | [Record EDR platform, device identifier, action timestamp, status, and console/audit-log evidence reference; if unsupported, record that result] | [Record unsupported feature, failed action, or other deviation]

- 2026-04-14T03:22:04Z | [Incident Response Analyst] | From the authorized IR jumpbox, test access to WST-WS-031; from an unauthorized user-network source, test access; review switch, ACL, firewall, and endpoint logs | IR jumpbox access succeeds; unauthorized user-network access is denied; prohibited outbound traffic is blocked | [Record source identifiers, UTC test times, commands or console actions, observed pass/fail results, and log/evidence references] | [Record any unexpected connectivity, failed test, or control discrepancy]
