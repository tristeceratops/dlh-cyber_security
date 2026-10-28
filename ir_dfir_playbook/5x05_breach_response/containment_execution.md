**Incident:** IR-2026-0420-01  
**Status:** Execution log opened; actions below are pending until performed and independently verified.  
**Time standard:** UTC.

## Execution prerequisites

- Preserve ART-001 (`cs-ws-101.mem`) and compute its current SHA-256 before analysis; Torres did not record an acquisition-time hash.
- Confirm evidence collection paths, authorized responders, network-control access, and clinical alternatives.
- Record actual execution timestamps. Never backfill an unperformed action as complete.
- Append a corresponding `ACTION` entry to `incident_timeline.md` for each completed action.

## Step 1 — Verify existing memory evidence

- **UTC timestamp:** Pending
- **Actor:** Evidence Lead / assigned forensic analyst
- **Action:** Compute SHA-256 for `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem`; record the digest, file size, analyst, and time.
- **Expected outcome:** Existing memory dump is preserved unchanged and a baseline hash is recorded for subsequent copies.
- **Observed outcome:** Pending.
- **Deviation notes:** No acquisition-time hash exists. A newly calculated hash cannot retrospectively prove the original acquisition's integrity.

## Step 2 — Block C2 egress

- **UTC timestamp:** Pending
- **Actor:** Network Security Lead
- **Action:** Add an urgent, logged deny rule at the egress firewall or equivalent enforcement point for destination IP `45.152.66.114` and block `staging.office365-cdn.net` through managed DNS/proxy controls. Verify the actual enforcement points and ensure the rule covers all relevant outbound routes.
- **Expected outcome:** Connections to the known C2 destination are denied, and the rule is logged and independently validated.
- **Observed outcome:** Pending.
- **Deviation notes:** Do not rely on a domain-only firewall rule if the device cannot inspect DNS names. Confirm IP, DNS, proxy, IPv6, and alternate-egress coverage as applicable.

## Step 3 — Isolate WS-101

- **UTC timestamp:** Pending
- **Actor:** EDR Operator / Incident Commander authorization
- **Action:** Isolate `CS-WS-101` through the approved EDR or network-control mechanism after immediate evidence capture where safe. Maintain access to the approved management and evidence channels.
- **Expected outcome:** The host cannot communicate with other compromised systems or external C2, except through explicitly permitted management channels.
- **Observed outcome:** Pending.
- **Deviation notes:** Torres captured memory at 19:38Z on April 20, before the 19:43:18Z call and 19:52Z declaration. Do not delay urgent containment for a second memory capture.

## Step 4 — Isolate WS-104

- **UTC timestamp:** Pending
- **Actor:** EDR Operator
- **Action:** Capture volatile memory if immediately feasible, then isolate `CS-WS-104`; preserve its service, process, network, and event-log evidence.
- **Expected outcome:** Beaconing and lateral movement from the host are interrupted while evidence remains available for analysis.
- **Observed outcome:** Pending.
- **Deviation notes:** Sysmon records show `WinHealthSvc`, `svchost32.exe`, and beaconing. If encryption is imminent, isolate immediately and document lost volatile evidence.

## Step 5 — Isolate WS-107

- **UTC timestamp:** Pending
- **Actor:** EDR Operator
- **Action:** Capture volatile memory if immediately feasible, then isolate `CS-WS-107`; preserve process, network, event-log, and ransomware-staging artifacts.
- **Expected outcome:** Host communication is restricted and evidence is available for investigation.
- **Observed outcome:** Pending.
- **Deviation notes:** Verify isolation using EDR status and network telemetry rather than relying solely on a successful command response.

## Step 6 — Isolate FILE-SVR-01

- **UTC timestamp:** Pending
- **Actor:** Infrastructure Lead, coordinated with Clinical Operations
- **Action:** Check current malicious activity and patient-care dependencies. Capture volatile evidence if safe, then isolate `FILE-SVR-01` using a control that does not inadvertently disable unrelated clinical services. Preserve the complete Security EVTX logs and the 1,847 relevant Event ID 4663 records.
- **Expected outcome:** Unauthorized access and lateral movement are interrupted while PHI access evidence and required clinical alternatives are maintained.
- **Observed outcome:** Pending.
- **Deviation notes:** The file server's clinical documentation role makes this a high-impact action. Escalate isolation immediately if active encryption or ongoing unauthorized access is observed.

## Step 7 — Isolate WS-112

- **UTC timestamp:** Pending
- **Actor:** EDR Operator
- **Action:** Capture volatile memory if immediately feasible, then isolate `CS-WS-112`; preserve relevant event logs and disk evidence.
- **Expected outcome:** The final identified compromised workstation is isolated from other systems and external C2.
- **Observed outcome:** Pending.
- **Deviation notes:** Supplied records show beacon activity and ransomware staging. Reassess priority if new evidence indicates active encryption or an immediate threat to patient care.

## Step 8 — Revoke and rotate compromised credentials

- **UTC timestamp:** Pending
- **Actor:** Identity and Access Management Lead, with Incident Commander authorization
- **Action:** Use the following sequence, preserving relevant identity and authentication logs before changes where safe:
  1. Identify accounts and tokens used on affected hosts, including `MEDDEFENSE\jdoe`, and enumerate all successful authentications during the compromise window.
  2. Revoke active sessions, refresh tokens, and other revocable authentication tokens for affected accounts; disable or restrict accounts confirmed compromised.
  3. Reset compromised user credentials from a known-clean administrative workstation and invalidate reusable credentials as supported by the identity platform.
  4. Rotate any exposed service-account credentials, secrets, and keys identified during investigation. Validate service dependencies before rotating production service credentials.
  5. Review privileged accounts and domain authentication for evidence of compromise. Escalate broader domain credential remediation, including any required Kerberos ticket invalidation, to the identity/domain security lead.
  6. Confirm that the compromised accounts cannot authenticate using old credentials or tokens, and monitor for new authentication attempts.
- **Expected outcome:** Identified compromised credentials and active sessions are invalidated; authentication logs and verification evidence are retained.
- **Observed outcome:** Pending.
- **Deviation notes:** `MEDDEFENSE\jdoe` appears in the supplied process, network, and file-access records. Do not assume this is the only compromised identity; the full 72-hour authentication scope remains to be established.

## Step 9 — Verify C2 severance

- **UTC timestamp:** Pending
- **Actor:** SOC Lead and Network Security Lead
- **Action:** Confirm the egress deny rule is active; inspect firewall, proxy, DNS, and EDR telemetry for subsequent connection attempts to `staging.office365-cdn.net` and `45.152.66.114`; verify the five assets are isolated; investigate any new outbound connections or alternate C2 indicators.
- **Expected outcome:** The known C2 route is blocked, no successful connections are observed after enforcement, and all identified affected assets are confirmed isolated.
- **Observed outcome:** Pending.
- **Deviation notes:** A lack of observed traffic alone does not prove eradication. Record the observation window, log sources, rule counters, and any telemetry gaps. Continue monitoring for alternate destinations and persistence.

## Step 10 — Confirm containment and clinical status

- **UTC timestamp:** Pending
- **Actor:** Incident Commander and Clinical Director
- **Action:** Review isolation status, credential revocation evidence, firewall logs, preservation records, and availability of safe clinical alternatives. Record outstanding risks and authorize continued containment.
- **Expected outcome:** The team has documented evidence that the known C2 route is blocked, affected assets are contained, credentials have been addressed, and patient-care alternatives are operational.
- **Observed outcome:** Pending.
- **Deviation notes:** Do not declare the incident eradicated solely because the known C2 destination is blocked. Maintain containment until recovery criteria are met.