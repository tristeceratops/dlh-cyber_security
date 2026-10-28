# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 2026-10-26
**Report date:** 2026-10-28
**Facilitator:** Tristeceratops
**Participants:** James Chen, Sarah Park, Incident Commander, Vendor Risk Manager, Privacy Officer, Legal Counsel, Communications Lead, Infrastructure Lead, Clinical Director representative
**Classification:** Internal — Exercise Use Only

---

## Executive summary

The Nexus Supply Chain Compromise tabletop tested MedDefense's ability to respond to a malicious vendor-signed software update while maintaining patient safety and meeting privacy, legal, and communication obligations.

The simulation demonstrated that participants recognized the supply chain threat, understood that a valid digital signature does not guarantee software integrity, and distinguished confirmed compromise from unverified PHI exposure. However, several decisions lacked documented owners, deadlines, and measurable acceptance criteria.

The most significant gaps were the absence of a time-bound containment decision, an incomplete manual scheduling fallback, insufficient procedures for validating potentially altered appointment records, and inadequate tracking of vendor notification obligations. The simulated executive briefing also failed to meet the T+90-minute deadline.

**Most important recommended action:** Within 21 days, establish and test a cross-functional vendor-compromise response procedure that defines containment authority, clinical continuity triggers, evidence preservation, and named decision owners. This should be validated through a focused tabletop retest.

---

## Findings table

| Finding ID | Inject | Capability tested | Gap description | Severity | Recommended action | Owner role | Deadline (days) | Validation method |
|---|---|---|---|---|---|---|---:|---|
| F-001 | INJ-01, INJ-02 | CAP-03 | No named owner or activation deadline for manual scheduling; no final time-bound isolation decision or reassessment trigger. | P1 | Establish a vendor-isolation decision matrix with clinical escalation, fallback activation authority, and maximum decision intervals. | IT Director | 21 | Approved procedure and tabletop retest demonstrating a documented decision and fallback activation deadline. |
| F-002 | INJ-03 | CAP-02 | Vendor evidence requests lacked a specific follow-up deadline and escalation interval. | P2 | Create a vendor incident checklist covering evidence requests, response deadlines, escalation contacts, and written status updates. | Vendor Risk Manager | 14 | Review a completed checklist and demonstrate escalation during a vendor-response simulation. |
| F-003 | INJ-04 | CAP-06 | No authoritative source or approval owner was identified for validating questionable appointment records; correction controls were not defined. | P1 | Establish an appointment-integrity procedure defining trusted comparison sources, clinical approval, audit preservation, corrections, and patient follow-up. | Clinical Operations Lead | 30 | Clinical Director reviews the procedure; sample records are validated and corrections traced in a simulation. |
| F-004 | INJ-05 | CAP-07 | Final release authority and the next public-update time were not documented. | P2 | Define spokesperson authority, Legal and Privacy approval requirements, holding-statement templates, and update intervals. | Communications Lead | 14 | Approved communications matrix and timed holding-statement exercise. |
| F-005 | INJ-06 | CAP-08 | The team did not produce a completed executive briefing by T+90 minutes or a consolidated decision and action register. | P1 | Implement a standard executive incident briefing template and require a named briefing owner, decision log, and deadline tracking. | Incident Commander | 21 | Timed retest delivers the briefing by T+90 with documented decisions, owners, deadlines, and uncertainties. |
| F-006 | INJ-06 | CAP-05 | The team did not produce a verified vendor discovery timestamp or a documented notification deadline record. | P1 | Establish a breach-notification tracking procedure that records vendor discovery time, the BAA's 24-hour requirement, evidence requests, and MedDefense's independent HIPAA assessment. | Privacy Officer | 14 | Review a simulated breach timeline and verify separate tracking of vendor and MedDefense obligations. |
| F-007 | INJ-00, INJ-03 | CAP-01 | Participants initially focused on suspicious network traffic and did not immediately articulate the automatic vendor update channel as a possible attack path. | P2 | Add vendor-update compromise indicators and signature-validation limitations to detection and investigation playbooks. | SOC Lead | 21 | Playbook review and retest requiring participants to correlate suspicious traffic with recent vendor updates. |
| F-008 | INJ-03 | CAP-02 | Independent update verification requirements were not defined as measurable acceptance criteria. | P1 | Establish a software-update trust checklist requiring independent integrity verification, approved hashes or trusted build provenance, technical sign-off, and retained evidence. | IT Director | 30 | Demonstrate that a proposed update cannot be approved solely on the basis of a valid vendor signature. |

---

## P1 finding narratives

### F-001: Vendor containment and clinical continuity decisions are not sufficiently time-bound

**Source:** INJ-01 and INJ-02; CAP-03.

The simulated team recognized the conflict between security containment and patient-care continuity but did not establish a named manual scheduling activation owner, an activation deadline, or a final isolation deadline. This leaves MedDefense vulnerable to prolonged exposure if containment is delayed and to avoidable patient-care disruption if scheduling is disconnected without a fallback. The IT Director should establish a decision matrix defining isolation authority, clinical consultation requirements, fallback activation triggers, and maximum decision intervals. Validation should include a retest in which the team records the authorized decision, deadline, and continuity arrangements.

### F-003: Appointment integrity verification and correction authority are undefined

**Source:** INJ-04; CAP-06.

Participants identified audit preservation and prioritized appointments due that day, but did not name an authoritative comparison source or final approval owner for correcting disputed records. Without a defined process, unauthorized changes could remain undetected or legitimate appointments could be incorrectly altered, potentially delaying treatment. The Clinical Operations Lead should develop an appointment-integrity procedure covering trusted sources, audit preservation, record comparison, correction authorization, and patient follow-up. The Clinical Director should review the procedure, and a simulation should demonstrate traceable validation and correction of sample records.

### F-005: Executive briefing and decision tracking did not meet the required deadline

**Source:** INJ-06; CAP-08.

The team discussed containment, PHI exposure, vendor obligations, and appointment integrity but did not deliver a completed executive briefing by T+90 or produce a consolidated decision register. This limits leadership's ability to approve urgent actions when evidence remains incomplete. The Incident Commander should introduce a standardized briefing template that separates confirmed facts, hypotheses, unknowns, patient-safety risks, decisions required, and accountable owners. A timed retest should verify delivery within 90 minutes and confirm that all outstanding actions have owners and deadlines.

### F-006: Vendor notification timing and MedDefense's independent obligations were not fully operationalized

**Source:** INJ-06; CAP-05.

The Privacy Officer correctly distinguished Nexus's contractual obligations from MedDefense's independent responsibilities, but the team did not establish a verified vendor discovery timestamp or a documented deadline record. The absence of this information can delay legal and privacy assessments. The Privacy Officer should implement a notification-tracking procedure that records the vendor's discovery time, the applicable BAA deadline, evidence requests, internal assessment milestones, and escalation owners. Validation should use a simulated incident timeline to confirm that deadlines remain visible even when the vendor's facts are incomplete.

### F-008: Update integrity verification lacks measurable acceptance criteria

**Source:** INJ-03; CAP-01 and CAP-02.

The team correctly rejected the assumption that a legitimate Nexus signature proves software integrity, especially given the previously documented absence of independent client-side hash pinning. However, participants did not define the complete evidence required before trusting a replacement update. Because the compromised signing infrastructure could produce malicious but validly signed software, relying on the signature alone could permit reinfection. The IT Director should establish a release-acceptance checklist requiring independently trusted integrity evidence, verified build provenance, technical approval, and retained validation artifacts. A retest should demonstrate that a signed update is rejected until every required verification step is satisfied.

---

## What worked

- **Early incident recognition:** At INJ-00, James Chen declared a SEV2 incident and requested preservation of endpoint and network evidence before containment.
- **Recognition of supply chain risk:** At INJ-01 and INJ-03, participants understood that compromised build infrastructure undermined trust in a legitimate vendor signature and kept updates restricted pending verification.
- **Appropriate uncertainty in communications and privacy assessments:** At INJ-05 and INJ-06, participants avoided claiming confirmed PHI theft and explicitly recognized that MedDefense must assess its own HIPAA obligations rather than rely exclusively on Nexus.

---

## Exercise design feedback

1. **Host location consistency:** INJ-00 originally placed the suspicious server at West Campus, while the vendor profile located SCHED-SVR-01 at Main Campus. The scenario was revised to use SCHED-SVR-01 at Main Campus consistently.
2. **Observable action criteria:** The evaluation approach was refined to distinguish completed actions from promises by requiring a stated result or record for completion, and a named owner, deliverable, and deadline for commitments.
3. **BAA deadline trigger:** The exercise was revised to treat Nexus's discovery timestamp as unresolved until confirmed in writing, requiring an owner, request, and follow-up deadline instead of an assumed timestamp.
4. **Executive briefing clock:** T+0 was defined as the start of the 90-minute deadline, with T+90 as the explicit delivery target.
5. **Recovery verification:** Update recovery criteria were strengthened to require a trusted comparison source, an independent verification method, a technical approver, retained evidence, and a documented restoration decision.