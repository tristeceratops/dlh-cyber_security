# Incident Timeline: IR-2026-0420-01

**Classification:** Incident Evidence  
**Timezone:** UTC  
**Status:** Open — append-only record

| Timestamp | Type | Actor | Description | Source | Certainty |
|---|---|---|---|---|---|
| 2026-04-20T19:43:22Z | OBSERVATION | On-call nurse, reported by Mike Torres | Nurse reports that workstation CS-WS-101 is unusually slow and desktop filenames or files appear different. Torres has not independently verified the reported changes. | Torres call transcript | Reported; not independently verified |
| 2026-04-20T19:44:20Z | OBSERVATION | Mike Torres | SIEM rule wz-edr-200214 reports service installation activity on CS-WS-104, CS-WS-107, and CS-WS-112 within a twelve-minute window. | Torres call transcript | Alert confirmed by caller; underlying activity requires investigation |
| 2026-04-20T19:52:00Z | DECISION | On-call Incident Responder | Declares SEV1 incident IR-2026-0420-01 and activates the malware/ransomware and suspected ePHI compromise response playbook. | Incident activation record | Confirmed as the formal incident declaration time |