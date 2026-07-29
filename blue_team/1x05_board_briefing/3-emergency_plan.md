# The 72-Hour Plan

## Introduction

### Goal
Design an emergency response plan prioritizing the actions MedDefense must take in the next 72 hours to reduce exposure to Crimson Tide.

### Context
The Security Strategy was a 6-month roadmap. Crimson Tide has compressed the timeline to 72 hours. You cannot implement the full strategy overnight. You must choose the actions that provide the maximum risk reduction in the minimum time, with the resources available right now.

The constraints are real:

-    Sarah Park has 2 IT staff available tonight (plus herself)

-    FortiGate firmware requires a support contract renewal ($2,400) before download

-    The segmentation project requires new switch configurations (2-3 days minimum)

-    Backup isolation can be done tonight (physical disconnect of NAS from network)

-    AD Kerberos configuration changes require a maintenance window (risk of breaking authentication)

## Answer

# MedDefense 72-Hour Emergency Response Plan

---

# Tier 1 – Tonight (0–12 Hours)

**Objective:** Reduce immediate exposure without requiring procurement, budget approval, or significant service interruption.

| Action | Phase Blocked | Owner | Prerequisites | Risk of Action | Risk of Inaction |
|--------|---------------|-------|---------------|----------------|------------------|
| Verify FortiGate 100F firmware version against vulnerable releases (CVE-2023-27997). | Phase 1 – Initial Access | Sarah | Administrative access to FortiGate | None (read-only verification). | Vulnerable firmware may remain exposed to active exploitation. |
| Review FortiGate VPN logs for unusual logins, CLI activity and IoCs from the CISA advisory. | Phases 1–2 | James | Access to firewall logs | May generate false positives requiring investigation. | Existing compromise could remain undetected. |
| If firmware is vulnerable and cannot be patched immediately, temporarily disable SSL-VPN or restrict access to approved source IPs. | Phase 1 | Sarah | Executive approval if remote clinical access is affected | Temporary loss of remote access for some staff. | Internet-facing RCE remains available to attackers. |
| Reset passwords for all privileged, VPN and service accounts suspected of elevated access. | Phases 2–3 | James | Active Directory administrative access | Users may temporarily lose access until credentials are updated. | Stolen credentials remain valid for attackers. |
| Verify integrity and availability of NAS-01 backups and disconnect backup storage from unnecessary network access where operationally possible. | Phase 5 | Sarah | Backup administrator access | Backup jobs may pause temporarily. | Ransomware could encrypt or delete backups. |
| Enable the highest available logging level on FortiGate, Active Directory and critical servers. | Phases 2–6 | You | Available log storage | Increased storage usage. | Critical forensic evidence may be lost. |
| Notify executive leadership and activate the Incident Response Team. | All Phases | James | None | Minor operational disruption. | Delayed decision-making during an active incident. |

---

# Tier 2 – Tomorrow (12–36 Hours)

**Objective:** Implement high-impact defensive measures requiring coordination, maintenance windows or Board approval.

| Action | Phase Blocked | Owner | Prerequisites | Risk of Action | Risk of Inaction |
|--------|---------------|-------|---------------|----------------|------------------|
| Renew Fortinet support contract if expired and immediately install the latest supported FortiOS firmware. | Phase 1 | External Vendor + Sarah | Emergency Board approval | Short VPN outage during upgrade. | Critical remote code execution vulnerability remains exploitable. |
| Enforce MFA for every VPN user and all privileged Active Directory accounts. | Phases 2–3 | James | Identity platform configured | Users may require enrollment assistance. | Credential theft continues to provide direct access. |
| Disable RC4 and DES Kerberos encryption types; allow AES-only authentication. | Phase 3 | James | Compatibility review for legacy systems | Older applications may fail authentication. | Kerberoasting remains viable. |
| Begin emergency network segmentation using firewall ACLs (servers, workstations, medical devices, backups). | Phases 3–5 | Sarah | Firewall rule planning | Incorrect rules could interrupt clinical workflows. | Attackers continue to move freely across the network. |
| Deploy SIEM monitoring for FortiGate, Domain Controller and EDR telemetry. | Phases 2–6 | You | Log forwarding configured | Alert tuning required. | Ongoing attacker activity may remain unnoticed. |
| Perform an emergency compromise assessment on Active Directory and privileged accounts. | Phases 2–4 | James | Security tools available | Time-consuming investigation. | Existing persistence mechanisms remain active. |

---

# Tier 3 – This Week (36–72 Hours)

**Objective:** Complete structural improvements requiring procurement, testing or vendor assistance.

| Action | Phase Blocked | Owner | Prerequisites | Risk of Action | Risk of Inaction |
|--------|---------------|-------|---------------|----------------|------------------|
| Complete production VLAN segmentation (Server, Clinical, Medical Device, Management and Guest). | Phase 3 | Sarah | Testing completed | Temporary connectivity issues during migration. | Flat network continues to enable rapid ransomware spread. |
| Implement immutable and encrypted backups with offline copies. | Phases 4–5 | Sarah | Backup platform configuration | Initial backup window may increase. | Recovery remains vulnerable to ransomware destruction. |
| Encrypt EHR and billing databases at rest using enterprise key management. | Phase 4 | James + DBA | Maintenance window | Database performance and testing required. | Raw database files remain readable if copied. |
| Deploy EDR to all servers and workstations and validate ransomware detection. | Phase 6 | External Vendor | Licensing and rollout plan | Agent compatibility testing required. | Malware execution may go undetected. |
| Conduct a Crimson Tide tabletop exercise using the current advisory. | Phase 7 | James | Executive participation | Staff time commitment. | Incident response weaknesses remain undiscovered. |
| Review vendor and remote-access accounts; remove unnecessary privileges and enforce least privilege. | Phases 2–3 | James | Account inventory | Temporary vendor access interruptions. | Third-party accounts remain attractive attack paths. |

---

# Resource Conflict Assessment

| Potential Conflict | Impact | Resolution |
|--------------------|--------|------------|
| **Sarah** is responsible for firewall verification, VPN restrictions, firmware upgrades and segmentation. | High workload on the same critical system. | Perform verification first, then firmware upgrade during a maintenance window. Delegate firewall rule validation to the Security Analyst where possible. |
| **James** must simultaneously manage privileged account resets, MFA deployment and Kerberos hardening. | Identity-related changes could overlap and increase authentication issues. | Complete password resets first, verify successful authentication, then enable MFA, followed by Kerberos AES-only enforcement after compatibility testing. |
| **FortiGate maintenance** and **VPN availability** compete for the same maintenance window. | Remote clinicians may temporarily lose access. | Schedule overnight maintenance and notify clinical departments in advance. Maintain emergency local access procedures during the outage. |
| **Network segmentation** and **SIEM deployment** both require firewall and logging changes. | Configuration changes may interfere with troubleshooting. | Deploy SIEM and baseline logging before segmentation so that post-change traffic can be monitored effectively. |
| **Backup isolation** and **backup verification** involve the same NAS infrastructure. | Disconnecting storage too early could interrupt validation. | Verify backup integrity first, then isolate or firewall the backup repository immediately afterward. |

### Overall Priority

1. **Immediately verify and secure the FortiGate appliance** (highest risk due to CVE-2023-27997).
2. **Protect credentials** through password resets and MFA.
3. **Prevent lateral movement** with emergency segmentation and Kerberos hardening.
4. **Protect recovery capability** by isolating and securing backups.
5. **Increase detection capability** through centralized monitoring and EDR deployment.