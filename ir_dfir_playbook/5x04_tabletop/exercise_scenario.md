# Tabletop Exercise: Nexus Supply Chain Compromise

- **Date:** 26-10-2026
- **Classification:** Internal - Exercise Use Only
- **Facilitator:** Tristeceratops
- **scenario version:** 1.0.0

## Organization background

MedDefense is a healthcare organization operating across three sites: West Campus, Main Campus, and North Site. It relies on Nexus Patient Scheduling to support approximately 3,500 patient-facing interactions per week, including outpatient scheduling, pre-registration, and insurance eligibility checks, making the platform an important part of its day-to-day operations. As a HIPAA-regulated organization, MedDefense must protect electronic protected health information (ePHI), maintain appropriate security safeguards, and ensure that third-party vendors handling patient data meet their contractual and regulatory obligations.


## Vendor background

Nexus Health Technologies, Inc., based in Austin, Texas, provides Nexus Patient Scheduling, a multi-tenant, cloud-hosted SaaS platform used by MedDefense for appointment scheduling, patient pre-registration, and insurance eligibility verification. The platform accesses patient demographic information, insurance data, and appointment details; the documented integration uses HL7 FHIR R4 over HTTPS, with OAuth 2.0 client credentials for authentication, outbound requests from MedDefense to Nexus, and inbound appointment confirmations and schedule updates through a site-to-site IPsec tunnel. Nexus also deploys automatic, digitally signed updates to an on-premises agent on MedDefense's Main Campus scheduling server, creating a potential supply-chain risk if a malicious update is accepted; the last vendor security review identified the absence of independent client-side hash pinning as a residual finding. MedDefense has a Business Associate Agreement (BAA) with Nexus, effective August 1, 2023, and amended May 20, 2025, requiring breach notification within 24 hours of discovery, an annual SOC 2 Type II report, and the return or destruction of PHI upon termination; the specific service-level agreement (SLA) terms are not provided in the available vendor profile and should be confirmed before the exercise.

## Opening situation

Three days ago, a threat actor compromised Nexus's build infrastructure, and a signed malicious update was automatically distributed. The backdoor has been running on MedDefense's Nexus agent hosts at all three sites since deployment.

Today, 45 minutes ago, the SOC detected unusual outbound traffic from the scheduling environment to an unknown external IP address. EDR alerts show connections recurring approximately every four hours. The full scope and impact have not yet been established.

## Known facts at exercise start

- **Alert:** Unusual outbound traffic to an unknown external IP, recurring every four hours.
- **Known host:** SCHED-SVR-01, the Main Campus scheduling server running the Nexus agent.
- **Other sites:** West Campus and North Site use the Nexus integration; their specific agent hostnames require verification.
- **Unknowns:** Whether patient data was accessed or altered, what systems are affected, and whether the vendor has identified the incident.

## Key Risks and Decisions

Appointment records may have been modified during the compromise window, potentially causing missed appointments or delayed care. Participants must weigh isolating affected systems against maintaining safe patient scheduling, determine how to verify appointment integrity, and establish whether other systems are affected.

Nexus's compromise may trigger MedDefense's HIPAA breach-assessment and notification obligations. The team must coordinate with Nexus, privacy, legal, and clinical leadership while preserving evidence and determining when it is safe to restore normal operations.