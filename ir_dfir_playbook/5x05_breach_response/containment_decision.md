**Incident:** IR-2026-0420-01  
**Classification:** Incident Evidence — Confidential  
**Decision authority:** Incident Commander, with Clinical Director concurrence on patient-care safeguards  
**Status:** Chosen strategy documented; execution requires timestamped verification.

## Strategy 1 — Monitor while investigating

- **Action:** Keep all five assets connected while collecting additional telemetry.
- **Attacker effect:** C2, lateral movement, credential misuse, and ransomware staging may continue.
- **Patient-care effect:** Scheduling and clinical documentation remain available initially, but service disruption and data integrity risks increase.
- **Evidence preserved/destroyed:** Preserves live activity and volatile state; risks losing evidence if encryption, cleanup, or attacker-triggered changes occur.
- **Time to execute:** Immediate.
- **Reversibility:** High, but continued compromise may cause irreversible harm.

## Strategy 2 — Isolate all five assets immediately

- **Action:** Isolate WS-101, WS-104, WS-107, WS-112, and FILE-SVR-01 using EDR or network controls.
- **Attacker effect:** Severely restricts lateral movement and external C2 communication if isolation is effective.
- **Patient-care effect:** May interrupt clinical documentation and file access; scheduling server disruption may affect appointments.
- **Evidence preserved/destroyed:** Preserves disk and central logs if protected; isolation may destroy live network connections and some volatile context.
- **Time to execute:** Target 5–10 minutes, subject to control availability.
- **Reversibility:** Generally reversible through controlled reconnection after validation.

## Strategy 3 — Prioritized isolation with immediate C2 blocking (CHOSEN)

- **Action:** Block `staging.office365-cdn.net` and `45.152.66.114` at approved egress controls; capture immediately available volatile evidence without delaying urgent containment; isolate WS-101, WS-104, WS-107, WS-112, and FILE-SVR-01 in that order, escalating FILE-SVR-01 sooner if active malicious activity is confirmed. Preserve forensic images and logs before remediation where safe.
- **Attacker effect:** Blocks the identified C2 route and interrupts infected-host communication; host isolation limits lateral movement.
- **Patient-care effect:** Restricts potentially compromised workstations and file-server access. Clinical Operations must establish safe alternate access and manual scheduling procedures before disruption where feasible.
- **Evidence preserved/destroyed:** Preserves captured memory, disk images, audit logs, and network telemetry. Blocking and isolation may terminate live sessions and change volatile network state; record these effects.
- **Time to execute:** Begin immediately; target initial C2 blocking and first isolation within 5 minutes, with all five assets addressed within 15 minutes where operationally feasible.
- **Reversibility:** Firewall rules and network isolation are reversible; reconnection requires explicit security and clinical approval.

**Trade-off rationale:** Prioritized isolation reduces the likelihood of further credential misuse, ransomware execution, and additional PHI access while preserving evidence before remediation wherever safely possible. WS-101 is the initial compromise host, WS-104 and WS-107 show beaconing and ransomware staging, WS-112 is also compromised, and FILE-SVR-01 contains evidence of 1,847 clinical-document reads. Because disconnecting the file server or scheduling services may disrupt patient care, the Incident Commander must coordinate with the Clinical Director and establish safe alternatives. Immediate containment takes precedence if encryption or patient harm is imminent.

**Rollback trigger:** Do not reconnect any asset until the Incident Commander approves restoration following documented eradication, credential remediation, clean-system validation, verified monitoring, and Clinical Director confirmation that patient-care dependencies can safely resume. Any renewed beacon, unauthorized service, or unexplained outbound connection cancels rollback and returns the asset to isolation.