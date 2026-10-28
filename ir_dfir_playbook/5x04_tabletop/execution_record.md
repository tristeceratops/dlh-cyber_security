# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-10-28
**Simulated by:** ChatGPT — Facilitator
**Classification:** Internal — Exercise Use Only

Note: This is a simulated exercise, not a real incident.

---

## INJ-00 (T+0 min)

**Inject delivered:**

The SOC has flagged unusual outbound traffic from the Nexus scheduling server at the West Campus to 193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe. The alert fired 45 minutes ago. The Nexus system is currently operational. Patient scheduling is running normally. No other anomalies have been detected.

**Participant responses:**
- James Chen (SOC Lead): "Declare SEV2 and preserve EDR, DNS, and firewall evidence."
- Sarah Park (IT Director): "Assess the affected host before deciding on isolation."
- Incident Commander: "Activate incident response and assign investigation owners."
- Vendor Risk Manager: "Locate Nexus's incident-response contacts."
- Privacy Officer: "Begin assessing potentially affected patient data."
- Legal Counsel: "Record the detection timeline and preserve evidence."
- Communications Lead: "Prepare for internal escalation."
- Infrastructure Lead: "Document the host and network connections."
- Clinical Director: "Assess scheduling continuity risks."

**Evaluation:**
- Incident declared within five minutes: PASS — SEV2 declared at T+2.
- Two roles notified: PASS — Incident Commander and Infrastructure Lead identified.
- Evidence collection before containment: PASS — Telemetry preservation requested first.
- Nexus considered as a potential threat source: FAIL — No explicit update-channel hypothesis raised.

**Facilitator note:** Asked whether traffic could originate from the automatic vendor update mechanism. Participants initially focused on network compromise.

---

## INJ-01 (T+20 min)

**Inject delivered:**

Nexus Patient Scheduling has published a security advisory. Their build pipeline was compromised by a threat actor with access to their code-signing certificate. All software updates distributed in the last 21 days may contain a malicious component. Nexus advises all customers to take immediate action. They do not yet have a patch.

**Participant responses:**
- James Chen: "A valid signature is no longer sufficient; restrict the agent's network access."
- Sarah Park: "Containment needs a clinical continuity plan."
- Incident Commander: "Suspend updates and set a ten-minute containment decision deadline."
- Vendor Risk Manager: "Contact Nexus SecOps for indicators and affected builds."
- Privacy Officer: "Assess exposure without assuming a confirmed breach."
- Legal Counsel: "Preserve the advisory and review contractual duties."
- Communications Lead: "Prepare an internal holding statement."
- Infrastructure Lead: "Identify the installed version and disable automatic updates."
- Clinical Director: "Prepare manual scheduling at all three sites."

**Evaluation:**
- Update channel identified as a threat: PASS — Signing infrastructure compromise recognized.
- Containment decision or escalation documented: PASS — Ten-minute deadline set.
- Clinical representative consulted: PASS — Clinical Director participates.
- Manual fallback owner and activation deadline assigned: FAIL — No named owner or activation deadline.
- Further updates restricted: PASS — Updates suspended pending verification.

**Facilitator note:** Asked who would activate manual scheduling if the service failed within 15 minutes. No accountable owner was named.

---

## INJ-02 (T+35 min)

**Inject delivered:**

EDR analysis confirms that the Nexus agent on SCHED-SVR-01 has made periodic outbound connections every four hours since the recent software update. The destination is not part of the vendor endpoints previously documented by MedDefense. The SOC recommends isolating the server. The Clinical Director objects that disconnecting Nexus without a fallback could disrupt appointments and delay care across the three sites. No confirmed evidence of patient data exfiltration is available.

**Participant responses:**
- James Chen: "Correlate the traffic with the update and preserve EDR and network evidence."
- Sarah Park: "Isolate after evidence preservation and clinical consultation."
- Incident Commander: "Authorize containment following evidence capture."
- Vendor Risk Manager: "Request affected-build information from Nexus."
- Privacy Officer: "No confirmed exfiltration does not prove PHI is safe."
- Legal Counsel: "Document containment authority and rationale."
- Communications Lead: "Avoid unsupported claims about data theft."
- Infrastructure Lead: "Prepare host isolation."
- Clinical Director: "Prepare manual scheduling but require an activation decision."

**Evaluation:**
- Traffic correlated with recent update: PASS — James identifies the relationship.
- Severity reassessed: PASS — Incident priority escalated.
- Evidence preservation identified: PASS — EDR and network logs named.
- Competing risks and decision authority identified: PASS — Security and clinical concerns discussed.
- Time-bound containment decision recorded: FAIL — No final isolation deadline or reassessment time.

**Facilitator note:** Asked what happens if the fallback is not ready in ten minutes. No maximum deferral period was established.

---

## INJ-03 (T+50 min)

**Inject delivered:**

Nexus SecOps confirms that its build infrastructure was compromised. A malicious update was signed using a legitimate Nexus code-signing certificate and distributed automatically. Nexus cannot provide a clean update or confirm every affected customer. MedDefense's previous vendor review had identified that the on-premises agent relied on code-signing certificate validation without an independent client-side hash pin.

**Participant responses:**
- James Chen: "Request hashes, build identifiers, signing details, and indicators of compromise."
- Sarah Park: "Keep updates suspended until independent verification."
- Incident Commander: "Do not trust the agent until recovery criteria are met."
- Vendor Risk Manager: "Open a vendor escalation and track unanswered requests."
- Privacy Officer: "Assess MedDefense evidence independently."
- Legal Counsel: "Track the BAA deadline and request Nexus's discovery timestamp."
- Communications Lead: "Do not describe the system as clean without evidence."
- Infrastructure Lead: "Require an independent integrity comparison."
- Clinical Director: "Maintain a safe interim scheduling process."

**Evaluation:**
- Documented vendor channel used: PASS — Nexus SecOps contacted.
- Technical evidence requested: PASS — Hashes, builds, and indicators requested.
- Follow-up information requested: PASS — Written evidence requested.
- Hash-pinning weakness recognized: PASS — Signature-only validation rejected.
- Recovery conditions identified: PASS — Independent verification required.
- Follow-up deadline recorded: FAIL — No specific deadline or escalation interval.

**Facilitator note:** Asked what evidence would justify trusting a replacement update. The team did not define a measurable verification checklist.

---

## INJ-04 (T+65 min)

**Inject delivered:**

The EHR application team discovers that several appointment records changed during the suspected compromise window. The changes have not been attributed to the Nexus incident, and the team cannot immediately determine whether they reflect legitimate rescheduling or unauthorized modification. Some affected appointments are due later today. Clinical Operations warns that cancelling all appointments would create significant patient-care disruption.

**Participant responses:**
- James Chen: "Preserve audit trails and correlate changes with the compromise timeline."
- Sarah Park: "Consider suspending automated updates."
- Incident Commander: "Prioritize appointments due today."
- Vendor Risk Manager: "Request Nexus's affected-build timeline."
- Privacy Officer: "Document possible access and logging gaps."
- Legal Counsel: "Preserve original record states."
- Communications Lead: "Avoid claiming malicious changes without evidence."
- Infrastructure Lead: "Preserve integration logs and prepare to pause updates."
- Clinical Director: "Assign site supervisors to verify urgent appointments and contact patients."

**Evaluation:**
- Changed records correlated with incident window: PASS — Timeline correlation requested.
- Audit evidence preserved: PASS — Original states and audit trails identified.
- Trusted validation source named: FAIL — No authoritative source or approval owner.
- Urgent appointments prioritized: PASS — Same-day appointments prioritized.
- Interim scheduling process considered: PASS — Controlled verification planned.
- Correction approval and traceability defined: FAIL — No formal correction procedure.

**Facilitator note:** Asked which source is authoritative if Nexus and the EHR disagree. No definitive source or correction authority was named.

---

## INJ-05 (T+80 min)

**Inject delivered:**

A journalist contacts MedDefense Communications about a possible healthcare scheduling breach involving a third-party vendor. The journalist requests confirmation that patient information has been stolen and asks for a statement within 30 minutes. MedDefense has not confirmed exfiltration or established the full scope. Nexus has not provided a final assessment.

**Participant responses:**
- James Chen: "We cannot confirm data theft."
- Sarah Park: "Use verified facts only."
- Incident Commander: "Coordinate with Legal and Privacy."
- Vendor Risk Manager: "Seek a vendor update without delaying our response."
- Privacy Officer: "Do not speculate about PHI exposure."
- Legal Counsel: "Review the statement and identify the approver."
- Communications Lead: "Prepare a holding statement."
- Infrastructure Lead: "Provide verified technical facts."
- Clinical Director: "Coordinate patient communications with clinical operations."

**Evaluation:**
- Authorized spokesperson identified: PASS — Communications leads.
- Legal and Privacy review included: PASS — Both roles engaged.
- Facts distinguished from unknowns: PASS — No unsupported data-theft claim.
- Final approval authority and next update recorded: FAIL — Neither is documented.
- Response deadline acknowledged: PASS — Statement preparation set within 30 minutes.

**Facilitator note:** Asked who releases the statement if Nexus does not respond. No final release authority was confirmed.

---

## INJ-06 (T+95 min)

**Inject delivered:**

Executive leadership requests an immediate briefing. Nexus confirms that it is investigating but cannot establish whether MedDefense patient data was accessed or whether all malicious activity has been removed. The BAA requires Nexus to notify MedDefense of a breach within 24 hours of discovery. MedDefense must independently assess its HIPAA obligations. Some appointment records remain unverified, and no definitive recovery timeline is available.

**Participant responses:**
- James Chen: "The vendor compromise is confirmed; PHI access and eradication remain unverified."
- Sarah Park: "Maintain restrictions pending independent recovery checks."
- Incident Commander: "Leadership must decide on containment and continuity."
- Vendor Risk Manager: "Track vendor evidence and notification commitments."
- Privacy Officer: "Assess MedDefense's obligations independently of the BAA."
- Legal Counsel: "Obtain the discovery timestamp and assess notification requirements."
- Communications Lead: "Include approved messaging and the next update."
- Infrastructure Lead: "Keep updates restricted pending verification."
- Clinical Director: "Assign owners for appointment verification and patient follow-up."

**Evaluation:**
- Executive briefing delivered by T+90: FAIL — No completed briefing recorded by the deadline.
- Facts and uncertainties separated: PASS — PHI access and eradication remain explicitly unconfirmed.
- Containment and patient safety addressed: PASS — Restrictions and record verification discussed.
- BAA and MedDefense obligations distinguished: PASS — Privacy identifies independent duties.
- Notification deadline tracked: FAIL — No verified discovery timestamp or deadline record.
- Privacy and Legal responsibilities assigned: PASS — Both roles identify assessment tasks.
- Decisions, owners, and deadlines recorded: FAIL — No consolidated action register.

**Facilitator note:** Asked for a 60-second board briefing and two decisions requiring approval. Participants described risks but did not produce a concise briefing or decision log.

---

# Design feedback

## DF-01: Inconsistent server location

**Problem:** INJ-00 places the server at West Campus, but the vendor profile locates SCHED-SVR-01 at Main Campus.

**Change:** Standardize the scenario and all injects on SCHED-SVR-01 at Main Campus.

**Validation:** Check host and location consistency across all exercise documents.

## DF-02: Planned actions are mistaken for completed actions

**Problem:** Participants receive credit for promising to contact Nexus or prepare a briefing without demonstrating completion.

**Change:** Require a completed action to have a stated result or record. For commitments, require an owner, deliverable, and deadline.

**Validation:** Re-score vendor contact, update suspension, and executive briefing criteria.

## DF-03: BAA deadline lacks a confirmed trigger time

**Problem:** The scenario provides a 24-hour notification obligation but not Nexus's discovery timestamp.

**Change:** Require Vendor Risk to request written confirmation, assign an owner, and track the deadline as unresolved until verified.

**Validation:** Pass only when the request, owner, and follow-up deadline are documented.

## DF-04: Executive briefing deadline is ambiguous

**Problem:** The original criteria do not explicitly establish when the 90-minute clock starts.

**Change:** Define T+0 as the starting point and T+90 as the deadline.

**Validation:** Record actual simulated briefing delivery time.

## DF-05: Recovery criteria lack measurable requirements

**Problem:** "Independent verification" is too vague to evaluate consistently.

**Change:** Require a trusted comparison source, independent verification method, technical approver, retained evidence, and documented restoration decision.

**Validation:** A valid vendor signature alone cannot satisfy the criterion.

---

# Final facilitator assessment

The simulated team recognized the supply chain threat and understood that a valid digital signature does not guarantee software integrity.

The principal gaps were:
- No accountable manual scheduling activation process.
- No time-bound containment decision.
- Incomplete appointment validation and correction controls.
- Inadequate vendor deadline tracking.
- No timely, structured executive briefing.

**Conclusion:** The team demonstrated basic incident-response awareness but did not consistently translate it into documented, time-bound decisions across Security, Clinical Operations, Vendor Risk, Privacy, Legal, and executive leadership.