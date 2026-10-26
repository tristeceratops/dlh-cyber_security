# Tabletop Exercise: Nexus Supply Chain Compromise

- **Date:** 26-10-2026
- **Classification:** Internal - Exercise Use Only
- **Facilitator:** Tristeceratops
- **scenario version:** 1.0.0

## Organization background

MedDefense operates three healthcare sites: West Campus, Main Campus, and North Site. It relies on Nexus Patient Scheduling for approximately 3,500 patient-facing interactions each week, including appointment scheduling, pre-registration, and insurance checks. MedDefense must protect patient information under HIPAA while maintaining safe and reliable patient care.

## Vendor background

Nexus Health Technologies, Inc., based in Austin, Texas, provides MedDefense's cloud-based patient scheduling service. The platform handles patient demographics, insurance information, and appointment data and exchanges scheduling information with MedDefense's Epic/EHR environment.

MedDefense has a Business Associate Agreement (BAA) with Nexus requiring breach notification within 24 hours of discovery. A security incident involving Nexus could affect patient information, disrupt scheduling, and create additional obligations for MedDefense. The specific service availability and response commitments under the vendor's SLA must be confirmed.

## Opening situation

Three days ago, Nexus distributed a software update to its customers. Today, 45 minutes ago, MedDefense's Security Operations Center (SOC) detected unusual outbound traffic from a scheduling server to an unknown external IP address.

Endpoint security alerts show connections occurring approximately every four hours. The SOC has raised the incident for investigation, but the cause and potential impact remain unclear.

## Known facts at exercise start

- **Alert:** Repeated outbound connections to an unknown external IP address.
- **Known host:** SCHED-SVR-01, the Main Campus scheduling server.
- **Other sites:** Nexus supports scheduling operations across all three MedDefense sites.
- **Unknowns:** Whether the activity is malicious, whether other systems are affected, whether patient information has been accessed or altered, and whether Nexus is aware of a related issue.

## Key Risks and Decisions

Appointment records may have been modified, potentially leading to missed appointments or delayed treatment. MedDefense must consider how to protect patients and maintain scheduling services while investigating the alert.

The team must determine what evidence is needed before trusting the affected systems and vendor service, when to involve Nexus and internal leadership, and whether containment could disrupt patient care.

As Nexus is a Business Associate, MedDefense must also assess whether the incident triggers HIPAA breach notification obligations. The team must decide how to proceed while the facts remain incomplete and the vendor's understanding of the incident is not yet known.