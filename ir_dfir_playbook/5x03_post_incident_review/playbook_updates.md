# Playbook Updates: IR-2026-0414-01

**Playbook:** `playbook_credential_exposure.yaml`  
**Incident:** `IR-2026-0414-01`  
**Related evidence:** `forensic_findings_summary.md`  
**Status:** Proposed changes — validate in staging before production adoption.

> **Gap mapping note:** GAP-002 is used for the VPN-trigger gap as indicated by the supplied example. The other Gap IDs must be reconciled against the authoritative Task 2 gap register before remediation tracking is finalized.

---

### Change PB-UPD-001

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `applies_to.triggers`  
**Gap closed:** GAP-002  
**Finding reference:** `forensic_findings_summary.md` — initial Office 365 session at `2026-04-13T18:14:41Z` from `45.63.9.88`, reported as geolocated to Russia; Conditional Access risk signals were suppressed by the compliant-device rule.

**Before:**

```yaml
triggers:
  - Alert: credential submitted to external domain
  - Alert: confirmed credential compromise
```

**After:**

```yaml
triggers:
  - Alert: credential submitted to external domain
  - Alert: confirmed credential compromise
  - Alert: VPN authentication from a country not observed for this account in the preceding 30 days
  - Alert: impossible-travel detected from geographically inconsistent sign-ins within 2 hours
  - Alert: high-risk sign-in or anomalous authentication involving a compliant device
```

**Reason:** The existing playbook did not independently trigger on an unfamiliar-country VPN authentication or impossible-travel activity. The incident summary identifies a foreign-origin session and suppressed risk signals. Adding these triggers enables investigation to begin even when a direct credential-compromise alert has not fired.

**Implementation note:** The 30-day per-account country baseline and impossible-travel detection require a supported identity-risk or SIEM detection mechanism. Confirm that the trigger source is configured and that compliant-device status does not suppress the relevant risk alerts.

**Validation:** Generate a controlled unfamiliar-country sign-in for a test account and confirm that the playbook is activated, the identity investigation is created, and the originating IP and sign-in risk details are captured.

---

### Change PB-UPD-002

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `response_steps.containment.scope_expansion`  
**Gap closed:** Confirm against Task 2 gap register; provisional mapping: GAP-004  
**Finding reference:** `forensic_findings_summary.md` — Kerberos-launched MSBuild activity on `WST-WS-017`, with a launch relationship originating from `WST-WS-031`; Pass-the-Ticket technique T1550.003 was confirmed.

**Before:**

```yaml
response_steps:
  - Isolate the initially compromised endpoint
  - Reset the compromised user's password
  - Collect endpoint evidence
```

**After:**

```yaml
response_steps:
  - Isolate the initially compromised endpoint
  - Reset or revoke compromised credentials and sessions as appropriate
  - Collect endpoint evidence
  - scope_expansion:
      trigger:
        - Pass-the-Ticket indicator detected
        - Kerberos authentication from an unexpected source host
        - Credential use or suspicious process execution on a newly identified host
      actions:
        - Identify source and destination hosts from authentication and endpoint telemetry
        - Review Kerberos ticket activity and logon events for the affected account
        - Search EDR, Sysmon, domain-controller, VPN, and identity logs for related activity
        - Add newly implicated endpoints to the incident scope
        - Isolate additional endpoints when evidence indicates active compromise
        - Preserve volatile memory and relevant forensic artifacts before remediation where feasible
        - Document host, account, timestamp, evidence, and containment decision
        - Reassess scope after each newly discovered host
```

**Reason:** The investigation confirmed Pass-the-Ticket activity involving `WST-WS-031` and `WST-WS-017`. A playbook that only contains the initially compromised endpoint can leave related systems active. The new checklist formalizes host discovery, evidence preservation, scope expansion, and additional containment.

**Validation:** In a tabletop or controlled simulation, introduce a Pass-the-Ticket indicator associated with a second host. Verify that the workflow identifies the additional host, records the evidence and decision, and expands containment when the evidence meets the isolation criteria.

---

### Change PB-UPD-003

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `response_steps.credential_remediation.kerberos_ticket_compromise`  
**Gap closed:** Confirm against Task 2 gap register; provisional mapping: GAP-005  
**Finding reference:** `forensic_findings_summary.md` — Pass-the-Ticket technique T1550.003 confirmed; compromised account `MEDDEFENSE\dmarsh`; suspicious Kerberos-launched activity on `WST-WS-017`.

**Before:**

```yaml
response_steps:
  - Reset compromised account password
  - Revoke active sessions where supported
```

**After:**

```yaml
response_steps:
  - Reset compromised account password and revoke active sessions where supported
  - If Pass-the-Ticket is confirmed, assess domain-wide Kerberos ticket exposure
  - Escalate to the Active Directory incident lead before domain-wide ticket remediation
  - Verify domain-controller health, replication status, and backup/recovery readiness
  - Perform the approved krbtgt double-reset procedure when the incident lead confirms it is required
  - Separate the two krbtgt password resets by the required Kerberos ticket lifetime and replication-validation interval
  - Verify successful replication of each reset to all relevant domain controllers before proceeding
  - Monitor authentication failures, unusual Kerberos activity, and renewed ticket abuse after remediation
  - Record reset timestamps, domain-controller replication evidence, approvals, and validation results
```

**Reason:** The original step only reset the compromised user's password. That action does not invalidate all forged Kerberos tickets, including tickets potentially forged using a compromised `krbtgt` key. Confirmed Pass-the-Ticket activity warrants a structured assessment of ticket exposure and escalation to the Active Directory team. A double reset of `krbtgt` is mandatory when the incident response lead determines that the domain's `krbtgt` secret or Golden Ticket capability is compromised; it should not be executed blindly for every Pass-the-Ticket event.

**Safety and operational requirement:** The two resets must be performed with the prescribed interval and replication checks. An incorrectly timed or incompletely replicated reset can leave tickets valid or disrupt authentication. Follow the organization's tested Microsoft-supported procedure and recovery plan.

**Validation:** In a non-production AD lab, exercise the approved double-reset procedure and verify that both resets replicate to all domain controllers, the required interval is observed, and the documented Kerberos validation checks complete successfully.

---

### Change PB-UPD-004

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `decision_nodes.ephi_blast_radius_assessment`  
**Gap closed:** Confirm against Task 2 gap register; provisional mapping: GAP-006  
**Finding reference:** `forensic_findings_summary.md` — 14 patient lab report PDFs accessed on `LIS-WSIDE-01` by `MEDDEFENSE\dmarsh` at `2026-04-14T03:43:30Z`; DLP review remained outstanding; no confirmed exfiltration at the time of the summary.

**Before:**

```yaml
response_steps:
  - Contain compromised endpoints
  - Reset compromised credentials
  - Collect forensic evidence
  - Close incident after containment validation
```

**After:**

```yaml
decision_nodes:
  ephi_blast_radius_assessment:
    condition: ePHI system, clinical application, or patient-data repository is in the incident blast radius
    actions:
      - Identify affected clinical systems, data repositories, and user accounts
      - Preserve access logs, file-read events, authentication events, and relevant network telemetry
      - Determine the types of ePHI involved and the number of individuals potentially affected
      - Establish whether data was viewed, acquired, copied, staged, transmitted, or exfiltrated
      - Record what is known, unknown, and still under investigation
      - Notify the Privacy Officer and Security Officer under the organization's incident-response process
      - Refer the event for a documented HIPAA Breach Notification Rule assessment
      - Record the four-factor assessment and supporting evidence
      - Track outstanding DLP, egress, and forensic analysis to completion
      - Do not infer that exfiltration occurred solely from file access; do not infer that exfiltration did not occur because it is unconfirmed
    hipaa_four_factor_assessment:
      factor_1:
        name: Nature and extent of PHI
        evaluate:
          - Types of identifiers and PHI involved
          - Sensitivity of the information
          - Re-identification risk
      factor_2:
        name: Unauthorized person
        evaluate:
          - Identity and role of the recipient or person who used the information
          - Whether that person was authorized to receive or access the PHI
      factor_3:
        name: Actual acquisition or viewing
        evaluate:
          - Evidence that PHI was actually acquired or viewed
          - Relevant access, copy, staging, and transmission logs
      factor_4:
        name: Mitigation
        evaluate:
          - Actions taken to mitigate potential harm
          - Whether the PHI recipient's use or disclosure can be mitigated
          - Evidence supporting the effectiveness of mitigation
    decision_outcome:
      - Document the Privacy Officer's determination and supporting evidence
      - Escalate unresolved questions to privacy/legal counsel
      - Apply applicable notification timelines and obligations based on the documented determination
```

**Reason:** The incident involved 14 patient lab report PDFs on `LIS-WSIDE-01`, but the summary did not confirm whether the data was exfiltrated. The previous playbook had no decision branch for ePHI-system involvement, risking premature closure without a formal privacy assessment.

The four-factor assessment follows the HIPAA Breach Notification Rule framework for evaluating whether a breach of unsecured PHI is presumed and whether there is a low probability that the PHI was compromised. The assessment must be performed by the responsible privacy/legal function based on the evidence and applicable requirements.

**Validation:** In a tabletop using the 14-PDF scenario, verify that the playbook opens the ePHI decision branch, records all four assessment factors, assigns the Privacy Officer review, and keeps the incident open while the required DLP and exfiltration investigation remains outstanding.

---

## Change control and acceptance criteria

| Change ID | Required validation evidence | Acceptance criterion |
|---|---|---|
| PB-UPD-001 | Identity sign-in logs and playbook activation record | An unfamiliar-country or impossible-travel sign-in triggers investigation, including when device compliance is present. |
| PB-UPD-002 | Incident scope record, host inventory, and containment audit trail | A Pass-the-Ticket indicator causes related hosts to be investigated and scope to be expanded when justified. |
| PB-UPD-003 | AD change records, replication evidence, and Kerberos validation results | The approved procedure is followed, both resets replicate, and the prescribed interval is observed when a double reset is required. |
| PB-UPD-004 | Completed four-factor assessment and privacy-review record | ePHI involvement invokes the assessment branch and prevents unsupported conclusions about exfiltration or breach notification. |

**Finalization requirement:** Reconcile the provisional Gap IDs with Task 2, incorporate these changes into the controlled playbook, obtain the appropriate identity, Active Directory, and privacy approvals, and retain the validation evidence with the incident record.