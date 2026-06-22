# Healthcare mobile app
## Scenario
```
A healthcare mobile app allows patients to:

    View medical records

    Schedule appointments

    Message healthcare providers

    Receive prescription refills

The app uses:

    Mobile client (iOS/Android)

    REST API backend

    Cloud-hosted database

    Integration with hospital systems

```

## Questions
```
	1) Which asset is most critical in this system? Explain your reasoning using the CIA Triad.

	2) Apply STRIDE to the "message healthcare providers" feature. List at least four threats.

	3) What security controls would you prioritize to protect patient data? List five controls in order of priority and explain why.

```
## Answers
### Most critical asset
**Most critical asset: patient medical records and other PHI (Protected Health Information).**

This is the most critical asset because it has the highest impact across the CIA Triad. **Confidentiality** is essential because PHI is highly sensitive and protected by HIPAA, and exposure could reveal diagnoses, medications, test results, and personal identifiers. **Integrity** is critical because incorrect or modified medical data could lead to bad clinical decisions, wrong prescriptions, or delayed treatment. **Availability** also matters because patients and providers may need immediate access to records, appointment details, and prescription information; if the data is unavailable, care can be delayed and patient harm can result.

### STRIDE threats for messaging
| **STRIDE Category** | **Threat** | **Affected Component / Data Flow** | **Potential Impact** | **Suggested Mitigation** |
| --- | --- | --- | --- | --- |
| **Spoofing** | An attacker uses stolen credentials to impersonate a patient or a doctor and send messages from a trusted account. | Mobile app, authentication service, provider inbox | False medical instructions, unauthorized access to conversations, and loss of trust in the system. | Use MFA, strong authentication, session binding, device checks, and short-lived tokens with re-authentication for sensitive actions. |
| **Tampering** | A message or attachment is altered in transit, or an attacker modifies a refill request so the content no longer matches what the sender intended. | Mobile client to REST API, message storage | Incorrect medical instructions, altered prescription details, or unsafe provider actions based on manipulated data. | Use TLS for transit, integrity checks, server-side validation, signed request metadata where appropriate, and strict authorization on edits. |
| **Repudiation** | A patient or provider later denies sending a message or denies having received a clinical instruction. | Messaging service, audit trail, message history | Disputes over care, legal risk, and inability to prove what was communicated. | Keep tamper-evident audit logs, message timestamps, sender identity records, and delivery/read receipts for sensitive communications. |
| **Information Disclosure** | PHI in messages is exposed to unauthorized users through weak access control, insecure notifications, logs, or a leaked database record. | Provider inbox, push notifications, cloud database | Exposure of medical conditions, medications, and personal health history, leading to privacy harm and HIPAA violations. | Encrypt data in transit and at rest, minimize notification content, restrict inbox access, and avoid logging message bodies or attachments. |
| **Denial of Service** | An attacker floods the messaging feature with spam, oversized attachments, or repeated requests so patients cannot reach providers. | REST API, messaging queue, mobile app | Delayed care, unavailable communication during urgent situations, and operational disruption. | Apply rate limiting, request throttling, attachment size limits, abuse detection, and queue protections. |
| **Elevation of Privilege** | A normal patient gains access to another patient's messages or a provider-only inbox because of broken authorization checks. | Authorization layer, provider/admin endpoints, message store | Exposure of other patients' PHI and unauthorized clinical actions. | Enforce least privilege, server-side authorization checks on every request, role-based access control, and periodic access reviews. |

### Security controls to prioritize
| **Priority** | **Control** | **Why it is prioritized** |
| --- | --- | --- |
| **1** | End-to-end encryption plus encryption in transit and at rest | PHI is the most sensitive asset, so protecting confidentiality first is essential. Encrypting data in transit and at rest reduces the chance that intercepted traffic or a breached database exposes patient records. |
| **2** | Strong authentication with MFA | Messaging and record access must be tied to the right patient or clinician. MFA reduces account takeover risk and directly addresses spoofing threats. |
| **3** | Fine-grained access control and least privilege | Not every user should be able to read every record or message. Server-side authorization limits damage if an account or API endpoint is abused. |
| **4** | Audit logging and monitoring | PHI systems need traceability for investigations, compliance, and repudiation disputes. Logs help detect abuse, unauthorized access, and suspicious access patterns. |
| **5** | Input validation and secure API hardening | The mobile app and REST API should reject malformed or manipulated requests to reduce tampering, injection, and abuse of messaging or refill workflows. |

These controls are ordered to protect PHI first, reduce account takeover next, and then preserve accountability and application resilience.
