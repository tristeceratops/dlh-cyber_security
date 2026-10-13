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