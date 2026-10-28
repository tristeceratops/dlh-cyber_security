# Incident Timeline: IR-2026-0420-01

**Classification:** Incident Evidence  
**Timezone:** UTC  
**Status:** Open — append-only record

| Timestamp | Type | Actor | Description | Source | Certainty |
|---|---|---|---|---|---|
| 2026-04-20T19:43:22Z | OBSERVATION | On-call nurse, reported by Mike Torres | Nurse reports that workstation CS-WS-101 is unusually slow and desktop filenames or files appear different. Torres has not independently verified the reported changes. | Torres call transcript | Reported; not independently verified |
| 2026-04-20T19:44:20Z | OBSERVATION | Mike Torres | SIEM rule wz-edr-200214 reports service installation activity on CS-WS-104, CS-WS-107, and CS-WS-112 within a twelve-minute window. | Torres call transcript | Alert confirmed by caller; underlying activity requires investigation |
| 2026-04-20T19:52:00Z | DECISION | On-call Incident Responder | Declares SEV1 incident IR-2026-0420-01 and activates the malware/ransomware and suspected ePHI compromise response playbook. | Incident activation record | Confirmed as the formal incident declaration time |

## append after containment strategies creation

| Timestamp (UTC) | Type | Actor | Description | Source | Certainty |
|---|---|---|---|---|---|
| Pending | ACTION | Evidence Lead | Calculated and recorded SHA-256 for existing `cs-ws-101.mem`; documented missing acquisition-time baseline. | ART-001 verification record | Pending verification |
| Pending | ACTION | Network Security Lead | Applied C2 egress deny rule for `45.152.66.114` and domain controls for `staging.office365-cdn.net`; recorded enforcement results. | Firewall/proxy/DNS change records | Pending verification |
| Pending | ACTION | EDR Operator | Isolated `CS-WS-101`; recorded collection and isolation results. | EDR/network isolation logs | Pending verification |
| Pending | ACTION | EDR Operator | Isolated `CS-WS-104`; recorded collection and isolation results. | EDR/network isolation logs | Pending verification |
| Pending | ACTION | EDR Operator | Isolated `CS-WS-107`; recorded collection and isolation results. | EDR/network isolation logs | Pending verification |
| Pending | ACTION | Infrastructure Lead | Isolated `FILE-SVR-01` after clinical coordination; preserved relevant access evidence. | EDR/network logs and evidence manifest | Pending verification |
| Pending | ACTION | EDR Operator | Isolated `CS-WS-112`; recorded collection and isolation results. | EDR/network isolation logs | Pending verification |
| Pending | ACTION | IAM Lead | Revoked identified sessions/tokens and remediated compromised credentials; recorded validation results. | Identity-provider and domain audit logs | Pending verification |
| Pending | ACTION | SOC Lead / Network Security Lead | Validated C2 blocking, reviewed post-enforcement telemetry, and recorded any residual connections. | Firewall, proxy, DNS, and EDR logs | Pending verification |
| Pending | ACTION | Incident Commander / Clinical Director | Reviewed containment status, patient-care safeguards, and remaining risks. | Incident bridge notes and clinical status report | Pending verification |