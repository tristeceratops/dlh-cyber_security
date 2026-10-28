# IR Activation: IR-2026-0420-01

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52:00Z
- declared_by: On-call Incident Responder
- initial_severity: SEV1
- reasoning: Multiple clinical workstations exhibit suspicious service installations, the clinical coordinator reports possible file changes, and SCHED-SVR-01 shows sustained high CPU and disk activity. These indicators suggest active compromise with potential ransomware staging in a clinical environment. Patient safety, system availability, and ePHI confidentiality may be at risk. Immediate coordinated containment and evidence preservation are required.
- playbook_activated: Cybersecurity Incident Response — Malware/Ransomware and Suspected ePHI Compromise. Activated because multiple hosts show suspicious persistence indicators, potential file modification, and abnormal resource utilization, requiring investigation of lateral movement, containment, evidence preservation, and privacy impact.
- notifications:
    - 19:52Z: Incident Commander — incident declared SEV1; coordination and containment decisions required.
    - 19:54Z: SOC Lead (James Chen) — investigate SIEM alert wz-edr-200214 and correlate activity across affected hosts.
    - 19:56Z: IT Director (Sarah Park) — prepare containment resources and coordinate with clinical operations.
    - 19:58Z: Privacy Officer — initiate preliminary ePHI exposure assessment.
    - 20:00Z: Clinical Director representative — assess patient-care impact and prepare safe operational alternatives.
- first_communication: executive_status_update sent to Dr. Morales at 20:05Z
- first_communication_text: >
    MedDefense has declared a SEV1 cybersecurity incident involving suspicious
    activity on multiple clinical workstations at Main Campus and abnormal
    resource utilization on the scheduling server SCHED-SVR-01. Potential
    malware activity and unauthorized access to clinical information are under
    investigation. The affected systems have not yet been confirmed as fully
    compromised, and the scope of any patient information exposure remains
    unknown. Incident Response is coordinating technical investigation,
    evidence preservation, containment planning, and clinical continuity
    assessment. Further updates will follow as verified information becomes
    available.