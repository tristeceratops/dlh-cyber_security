# Incident Timeline: IR-2026-0414-01

## Header

- incident_id: IR-2026-0414-01
- declared_at: 2026-04-14T02:51:04Z
- declared_by: Jean de la Villanderie, on-call SOC
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: Jean de la Villanderie

## Legend

- OBSERVATION: raw fact from an alert, log, or artifact
- DECISION: a choice made by an authorized actor, with rationale
- ACTION: an operation executed against an asset, with owner
- COMMUNICATION: a message sent or received, with audience
- EVIDENCE: a preserved artifact with hash and storage path

## Entries

- 2026-04-13T18:14:02Z | OBSERVATION | Proxy logs | User dmarsh accessed ms0365-support[.]login-verification[.]click/auth from Outlook; the page returned HTTP 200 | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:41Z | OBSERVATION | Proxy logs | User dmarsh submitted data to the suspicious authentication page; the request returned HTTP 302 | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:43Z | OBSERVATION | Proxy logs | The suspicious site served update.zip (421004 bytes) following the authentication submission | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:41Z | OBSERVATION | WazuhEDR | PowerShell started under MEDDEFENSE\dmarsh with execution policy bypass, hidden window, and an encoded command referencing the suspicious authentication URL | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:46:57Z | OBSERVATION | WazuhEDR | PowerShell spawned Microsoft-signed MSBuild.exe using C:\Users\dmarsh\AppData\Local\Temp\update.xml | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | WazuhEDR and proxy logs | MSBuild.exe established an outbound TCP connection to 185.220.101.47:443; threat intelligence identifies the remote IP as a high-risk Tor exit relay | source=alert_A-20260414-9841.json; proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | Jean de la Villanderie | Incident declared at SEV2: confirmed beaconing from clinical workstation; data exposure not confirmed yet | source=alert A-20260414-9841 + playbook PB-CRED-001 | certainty=confirmed

- 2026-04-14T03:10:00Z | DECISION | James Chen, IR Commander / SOC Lead | Selected Strategy A: isolate WST-WS-031 (`10.42.118.31`) to quarantine VLAN 999, block all outbound traffic, and allow authorized IR jumpbox access only. Rationale: sever command-and-control traffic while preserving volatile evidence and allowing controlled forensic access; the expected clinical impact is one unavailable laboratory workstation, subject to confirmation of spare workstation availability. Strategy B would destroy uncaptured volatile evidence; Strategy C would terminate process state and leave greater residual host and lateral-movement risk. Approval timestamp and authority must be verified against the actual approval record. See [containment_decision.md](containment_decision.md) | source=containment_decision.md; certainty=proposed pending approval verification

- 2026-04-14T03:14:00Z | EVIDENCE | Incident Response | Proposed evidence-preservation completion time for WST-WS-031. Confirm that required memory, process, network, and telemetry artifacts have been acquired and that hashes have been recorded and verified before treating preservation as complete. | source=/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt; certainty=unverified pending acquisition records

- 2026-04-14T03:16:00Z | ACTION | Incident Response / Network Operations | Proposed start of containment: move WST-WS-031 to VLAN 999, block all outbound traffic, and permit authorized IR jumpbox access only. Verify effective isolation and document the actual operator, execution time, and test results. | source=containment_decision.md; certainty=proposed pending execution logs