# Containment Decision: IR-2026-0414-01

- **Incident ID:** IR-2026-0414-01
- **Affected asset:** WST-WS-031 (`10.42.118.31`)
- **Asset classification:** High-criticality clinical workstation
- **Decision owner:** James Chen, IR Commander / SOC Lead
- **Decision status:** Proposed — approval and execution must be verified against incident records

## Candidate strategies

### A. Network isolation (quarantine VLAN)

- **action:** Move WST-WS-031 to VLAN 999, block all outbound traffic, and allow forensic access only from the authorized IR jumpbox. Verify that the quarantine policy prevents access to external command-and-control infrastructure and unauthorized lateral movement.
- **attacker effect:** Severs command-and-control connectivity and blocks outbound data transfer. The attacker may retain local access or persistence, but remote communication is restricted. Controlled forensic observation remains possible through the jumpbox.
- **evidence effect:** Preserves volatile memory, running processes, and local artifacts because the host remains powered on. Network connections and their states may change when isolation occurs; capture available connection data before isolation when safely feasible.
- **patient care effect:** One laboratory workstation becomes unavailable for normal use. The working assumption is that the site has four spare workstations available; confirm their availability and suitability with Laboratory Services before execution.
- **time to execute:** Approximately 5 minutes, assuming VLAN and firewall changes can be applied immediately.
- **reversibility:** Fully reversible at the network configuration level. Restoration must remain subject to forensic clearance and security validation.

### B. Host power-off

- **action:** Immediately power off WST-WS-031 using the approved emergency procedure.
- **attacker effect:** Terminates active processes and network sessions, immediately stopping on-host execution and communication from the powered-off system. Persistence mechanisms may remain on disk and could reactivate if the host is restarted.
- **evidence effect:** Destroys volatile memory, running-process state, active socket information, and other transient artifacts that have not been captured. Disk evidence remains potentially available, although abrupt power loss can complicate recovery and filesystem analysis.
- **patient care effect:** The workstation becomes completely unavailable until it can be examined, cleared, and returned to service or replaced. Laboratory workflows may be disrupted if suitable alternatives are unavailable.
- **time to execute:** Approximately 1 minute, assuming immediate physical or authorized remote access.
- **reversibility:** Power can be restored, but lost volatile evidence cannot be recovered. Returning the host to operation is not equivalent to reversing the evidence loss.

### C. Selective process termination + egress block

- **action:** Apply an outbound firewall block for WST-WS-031, then terminate the suspicious PowerShell process (PID 7812) and MSBuild process (PID 8104), after verifying process identities and capturing any remaining required live-state evidence. Preserve process and firewall action logs.
- **attacker effect:** Blocks outbound command-and-control traffic and terminates the identified suspicious processes. However, an unidentified process, scheduled task, service, or other persistence mechanism could continue execution or restart the payload. This approach does not isolate the entire host from lateral movement.
- **evidence effect:** A firewall block may alter network state, and process termination destroys process memory and execution state. Previously captured memory, process lists, and network records remain available, but additional live-response opportunities are lost.
- **patient care effect:** Offers the possibility of keeping the workstation available for clinical work after security validation. However, terminating processes can disrupt legitimate applications, and residual compromise makes continued clinical use potentially unsafe.
- **time to execute:** Approximately 2–5 minutes, assuming firewall and endpoint-response access are available.
- **reversibility:** Partially reversible. Firewall rules can be removed and processes may be restarted, but terminated process state and lost volatile evidence cannot be restored.

## Chosen: A — Network isolation (quarantine VLAN)

**Rationale:** Quarantine VLAN isolation best balances immediate containment, evidence preservation, and patient-care continuity. It severs outbound command-and-control traffic while keeping the workstation powered on, preserving volatile evidence for further forensic analysis, and permitting controlled IR jumpbox access. Although the workstation is unavailable for normal use during isolation, the assumed availability of four spare laboratory workstations limits the operational impact, subject to confirmation by Laboratory Services. Option B would stop execution quickly but irreversibly destroy uncaptured volatile evidence. Option C is more selective and may preserve some clinical functionality, but it destroys process state, risks missing additional malicious activity or persistence, and leaves greater opportunity for lateral movement. Option A is therefore preferred, provided that isolation is verified and clinical alternatives are available.

## Execution window

- **Evidence preservation end:** 2026-04-14T03:14:00Z — proposed; verify against acquisition logs and hash-manifest records.
- **Containment execution start:** 2026-04-14T03:16:00Z — proposed; verify against network-control logs.
- **Elapsed time between evidence preservation and containment:** 2 minutes.
- **Ordering requirement:** Confirm that the volatile memory dump, process list, active network connections, and required telemetry have been captured and integrity-checked before isolation, where safely feasible. Do not delay urgent containment if active harm is ongoing.
- **Containment verification:** Confirm VLAN 999 assignment, outbound blocking, and successful authorized jumpbox access. Record the operator, timestamps, verification results, and any exceptions in the incident timeline.

## Approval

- **Approving authority:** James Chen, IR Commander / SOC Lead.
- **Authorization time:** 2026-04-14T03:10:00Z — proposed; verify against the actual approval record.
- **Approval condition:** Confirm clinical workarounds with Laboratory Services and ensure that forensic access is restricted to the authorized IR jumpbox.
- **Audit requirement:** Record the actual approver, authorization timestamp, and any conditions or dissenting recommendations before treating the decision as formally approved.

## Rollback plan

1. **Detect unintended impact:** If quarantine prevents required clinical workflows, blocks necessary safety-related communications, or disrupts forensic access, notify the IR Commander and Laboratory Services immediately.
2. **Assess alternatives:** Confirm whether the spare workstations are available and suitable. Prefer transferring affected work to an approved spare rather than reconnecting a potentially compromised endpoint.
3. **Restore controlled access if necessary:** If isolation itself creates an unacceptable operational or safety impact and a suitable workaround is unavailable, the IR Commander must authorize a controlled change. Revert the VLAN assignment within five minutes of that authorization, if technically feasible, and implement Option C: a verified host-specific outbound firewall block followed by selective termination of the identified suspicious processes.
4. **Verify the fallback:** Confirm that outbound command-and-control traffic remains blocked, document any residual lateral-movement exposure, and maintain enhanced monitoring. Do not return the workstation to unrestricted network access.
5. **Preserve the audit trail:** Record the reason for rollback, authorizing person, start and end times, network changes, process actions, evidence impact, and patient-care consequences in `incident_timeline.md`.
6. **Reassess containment:** If the fallback cannot reliably prevent malicious communications or execution, escalate immediately to the IR Commander and clinical operations leadership for an alternative isolation method or workstation replacement.

## Decision review

Reassess the selected strategy if forensic findings identify additional active processes, evidence of lateral movement, failed egress controls, unavailable clinical substitutes, or a need to modify forensic access. Any change to the selected containment method requires a documented decision and an auditable execution record.
