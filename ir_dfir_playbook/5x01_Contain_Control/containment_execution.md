# Containment Execution: IR-2026-0414-01

- **Incident ID:** IR-2026-0414-01
- **Target host:** WST-WS-031
- **IP address:** 10.42.118.31
- **Quarantine VLAN:** 999
- **C2 destination:** 185.220.101.47:443/TCP
- **Evidence store:** `/evidence/IR-2026-0414-01/`
- **Execution status:** Pending verification against operational logs
- **Execution owner:** Network Operations and Incident Response
- **Authorizing authority:** James Chen, IR Commander — authorization must be verified
- **Reference decision:** [containment_decision.md](containment_decision.md)

## Execution log

### Step 1 — Network isolation

- **timestamp (UTC):** 2026-04-14T03:16:04Z — proposed; verify actual time
- **actor:** Network Operations — individual operator to be identified
- **command or console action:** Reassign the switch port associated with WST-WS-031 to VLAN 999. Apply the quarantine policy to block all outbound traffic and permit only authorized forensic access from the IR jumpbox. Record the switch, port, VLAN configuration, and change identifier.
- **expected result:** The workstation is isolated from normal user and production networks. Outbound command-and-control traffic and unauthorized lateral movement are blocked, while the approved jumpbox retains forensic access.
- **observed result:** Pending verification. Confirm the effective VLAN assignment and policy using switch and network-control logs.
- **deviation notes:** No deviation can be established from the supplied evidence. Record any configuration errors, policy exceptions, or unexpected connectivity.

### Step 2 — Block the identified C2 destination

- **timestamp (UTC):** 2026-04-14T03:17:21Z — proposed; verify actual time
- **actor:** Network Operations / Firewall Administrator — individual operator to be identified
- **command or console action:** Install and enable an outbound firewall deny rule blocking traffic from WST-WS-031 (`10.42.118.31`) to `185.220.101.47` on TCP port 443. Confirm the rule's scope, priority, deployment status, and logging. Maintain the broader quarantine policy; this destination-specific rule is defense in depth, not a substitute for isolation.
- **expected result:** Connections from WST-WS-031 to `185.220.101.47:443` are denied. The rule does not inadvertently block the authorized forensic management path.
- **observed result:** Pending verification. Obtain the firewall rule identifier, deployment timestamp, and matching deny logs.
- **deviation notes:** The supplied alert confirms an earlier established connection to this destination, but does not establish that the firewall rule was deployed or that subsequent traffic was denied.

### Step 3 — Verify command-and-control traffic is severed

- **timestamp (UTC):** 2026-04-14T03:17:21Z onward — verification interval to be established from telemetry
- **actor:** Incident Response Network Analyst — individual analyst to be identified
- **command or console action:** Review firewall logs and network flow telemetry for source `10.42.118.31`, destination `185.220.101.47`, and TCP port 443. Compare traffic immediately before and after the containment timestamp. Where available, preserve relevant packet captures or flow records in the incident evidence store and record capture filters, observation interval, collection point, and timestamps.
- **expected result:** No successful outbound C2 sessions are observed after containment. Any attempted connections are denied, and there is no evidence of an established session or successful data transfer to the identified destination.
- **observed result:** Pending verification. No packet capture, firewall log, or post-containment flow export was provided with the incident context.
- **deviation notes:** A netflow gap alone does not prove successful containment. Validate sensor health, collection coverage, clock synchronization, and visibility at the relevant network boundary. Distinguish denied connection attempts from successful sessions.

### Step 4 — Endpoint containment flag

- **timestamp (UTC):** 2026-04-14T03:19:02Z — proposed; verify actual time
- **actor:** Endpoint Response Analyst — individual operator to be identified
- **command or console action:** If the deployed endpoint security platform supports device isolation, enable its containment flag for WST-WS-031 using the approved endpoint console. Record the endpoint device identifier, action status, policy applied, and console audit event. Ensure that the endpoint containment policy does not conflict with the approved IR jumpbox access requirement.
- **expected result:** The endpoint platform reports successful device containment, restricting network communication according to its isolation policy while preserving approved incident-response access where supported.
- **observed result:** Pending verification. Confirm the final containment status in the endpoint console and retain the audit record.
- **deviation notes:** The supplied alert identifies WazuhEDR as the detection source but does not establish that its deployment supports device isolation or that a containment flag was set. If unsupported, record `not supported` and rely on verified network controls.

### Step 5 — Verify jumpbox-only reachability

- **timestamp (UTC):** 2026-04-14T03:22:04Z — proposed; verify actual time
- **actor:** Incident Response Analyst — individual analyst to be identified
- **command or console action:** Test connectivity from the authorized IR jumpbox and from a representative unauthorized user-network host. Verify permitted forensic management access and test relevant outbound paths. Inspect firewall, switch, and endpoint policy logs to confirm that the observed results reflect enforced controls rather than a failed test or unavailable host.
- **expected result:** The authorized IR jumpbox can reach the workstation through the approved forensic path. Unauthorized user-network hosts cannot reach it, and the workstation cannot establish prohibited outbound connections.
- **observed result:** Pending verification. Record the source host, destination, protocol, port, test timestamp, result, and relevant policy log for each test.
- **deviation notes:** A successful ping is not sufficient to prove that only the jumpbox can reach the host. ICMP may be disabled independently of other protocols. Validate the actual allowed management ports and confirm that no unauthorized network path remains.

## Completion criteria

Containment may be marked verified only when all applicable checks below have supporting evidence:

- [ ] VLAN 999 assignment confirmed in switch or network-controller logs.
- [ ] Quarantine policy confirmed to block unauthorized outbound traffic.
- [ ] Firewall deny rule for `185.220.101.47:443/TCP` confirmed active.
- [ ] Post-containment network telemetry reviewed for successful C2 communication.
- [ ] Endpoint containment flag confirmed, or platform limitation documented.
- [ ] Authorized jumpbox access tested successfully.
- [ ] Unauthorized user-network access tested and denied.
- [ ] Evidence artifacts preserved, timestamped, and SHA-256 hashed.
- [ ] Actual timestamps, actors, results, and deviations entered into `incident_timeline.md`.

## Evidence and audit requirements

Store the supporting switch, firewall, endpoint, and network telemetry exports under `/evidence/IR-2026-0414-01/`. Record each artifact's actual collection time, operator, source system, and SHA-256 hash in the incident hash manifest. Preserve raw records as well as analyst summaries.

Do not describe a control as confirmed, a connection as severed, or a containment operation as completed until the corresponding operational evidence has been reviewed. Update this execution log and the incident timeline with actual values as they become available.
