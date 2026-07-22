# The Segmentation Architecture

## Introduction

### Goal
Design a network segmentation plan that transforms MedDefense's flat network into a defensible architecture.

### Context
The flat network appeared in every kill chain you built in 1x01. It amplified every vulnerability in 1x02. It is the single architectural weakness whose resolution has the greatest cascading effect on MedDefense's risk posture. Now you design the fix.

This task is different from the others because it is a design exercise. You are not analyzing or assessing. You are creating a network architecture that does not yet exist.

## Answer

MEDDEFENSE NETWORK SEGMENTATION PLAN

PART 1 - ZONE DEFINITION

ZONE 1: Server Zone (VLAN 10)
IP Range: 10.10.10.0/24

Purpose:
Host critical business and clinical servers.

Systems Included:
- EHR servers
- Billing server
- File servers
- Active Directory domain controllers
- Database servers

Allowed Outbound Connections:
- Management Zone: administration traffic (HTTPS, SSH, RDP)
- Backup systems: backup traffic
- Clinical Workstations: required application traffic

Allowed Inbound Connections:
- Management Zone: administrator access
- Clinical Workstations: EHR/application access
- Medical Device Zone: required PACS/database communication only

Blocked:
- Direct access from Guest/IoT zone
- Direct internet access


ZONE 2: Clinical Workstation Zone (VLAN 20)
IP Range: 10.10.20.0/24

Purpose:
Support daily clinical operations.

Systems Included:
- Nurse station computers
- Physician workstations
- Shared clinical terminals

Allowed Outbound Connections:
- Server Zone: EHR, file services, authentication
- Internet: approved clinical websites

Allowed Inbound Connections:
- Management Zone: IT support
- Security tools: monitoring traffic

Blocked:
- Direct workstation-to-workstation communication
- Access to Medical Device Zone except approved applications


ZONE 3: Medical Device Zone (VLAN 30)
IP Range: 10.10.30.0/24

Purpose:
Protect patient-care equipment from general network compromise.

Systems Included:
- Infusion pumps
- Patient monitors
- MRI workstation
- PACS systems
- Imaging devices

Allowed Outbound Connections:
- Server Zone: PACS/EHR required communication
- Management Zone: approved device administration

Allowed Inbound Connections:
- Management Zone: maintenance access
- Server Zone: approved clinical applications

Blocked:
- Clinical Workstations directly accessing devices
- Guest/IoT access


ZONE 4: Management and Security Zone (VLAN 40)
IP Range: 10.10.40.0/24

Purpose:
Dedicated administrative and security operations network.

Systems Included:
- IT administrator workstations
- Security analyst workstation
- SIEM platform
- Network management tools

Allowed Outbound Connections:
- All internal zones for approved administration
- Vendor support connections when approved

Allowed Inbound Connections:
- All zones only for management protocols

Blocked:
- User devices initiating administrative connections


ZONE 5: Guest and IoT Zone (VLAN 50)
IP Range: 10.10.50.0/24

Purpose:
Separate untrusted devices from hospital systems.

Systems Included:
- Visitor WiFi
- Smart devices
- Non-clinical IoT equipment

Allowed Outbound Connections:
- Internet only

Allowed Inbound Connections:
- None

Blocked:
- Access to all internal MedDefense networks


ZONE 6: Backup Zone (VLAN 60)
IP Range: 10.10.60.0/24

Purpose:
Protect recovery systems from ransomware.

Systems Included:
- Backup servers
- Backup repositories

Allowed Outbound Connections:
- Backup updates
- Secure cloud replication

Allowed Inbound Connections:
- Server Zone: backup jobs only
- Management Zone: administration

Blocked:
- User workstation access


PART 2 - FIREWALL RULES

1.
Clinical Workstation Zone → Server Zone : TCP 443, 3389, database ports : ALLOW
Purpose: Allows staff to use EHR and approved applications.

2.
Management Zone → All Internal Zones : SSH, HTTPS, RDP : ALLOW
Purpose: Allows IT administration.

3.
Medical Device Zone → Server Zone : PACS/EHR required ports : ALLOW
Purpose: Allows clinical device communication.

4.
Server Zone → Backup Zone : Backup protocols : ALLOW
Purpose: Enables protected backups.

5.
Clinical Workstation Zone → Medical Device Zone : ANY : DENY
Purpose: Prevents compromised user computers from controlling medical devices.

6.
Guest/IoT Zone → Server Zone : ANY : DENY
Purpose: Prevents visitor devices from reaching sensitive hospital systems.

7.
Guest/IoT Zone → Internal Networks : ANY : DENY
Purpose: Blocks lateral movement from unmanaged devices.

8.
Medical Device Zone → Internet : ANY : DENY
Purpose: Prevents medical devices from communicating directly with attackers.

9.
Clinical Workstation Zone → Clinical Workstation Zone : SMB/RDP : DENY
Purpose: Limits ransomware spread between user computers.

10.
Server Zone → Internet : Restricted HTTPS only : ALLOW
Purpose: Allows updates while limiting exposure.


PART 3 - KILL CHAIN IMPACT

Kill Chain #1:
Spear Phishing Leading to Active Directory Compromise

Step 1 - Initial Access:
Attacker sends phishing email and steals administrator credentials.

Impact of segmentation:
No direct prevention at this stage. MFA is required to stop credential abuse.

Step 2 - Establish Foothold:
Attacker enters through VPN using stolen credentials.

Impact of segmentation:
Attacker is restricted to the VPN-accessible zone instead of the entire network.

Step 3 - Lateral Movement:
Attacker attempts to move from a compromised workstation to Active Directory.

Segmentation Break Point:
The attacker cannot freely access Server Zone systems because firewall rules restrict workstation-to-server communication.

Step 4 - Objective Execution:
Attacker attempts ransomware deployment through Active Directory.

Segmentation Break Point:
Restricted access between Clinical Workstations, Servers, Medical Devices, and Backups prevents full environment compromise.

Step 5 - Impact:
Hospital-wide outage attempt.

Segmentation Impact:
The attacker may compromise one zone but cannot easily encrypt all systems simultaneously.

Estimated Kill Chain Reduction:

Top 5 Kill Chains:
- Ransomware chain: disrupted by limiting lateral movement.
- Credential compromise chain: partially reduced; MFA still required.
- Medical device compromise chain: strongly reduced by device isolation.
- Insider data theft chain: reduced by access restrictions.
- Supply-chain compromise chain: reduced by vendor/device segmentation.

Estimated disruption:
Approximately 70% of major attack paths would be reduced because segmentation limits attacker movement after initial compromise.

Segmentation does not replace MFA, monitoring, or patching, but it reduces the blast radius when an attacker gains access.