# 6. The Legacy Dilemma

### Goal
Design a compensating control strategy for a system that cannot be patched, upgraded or replaced, under real operational constraints.

### Context
While building your asset inventory, you visit the Radiology department at MedDefense Central. The department runs an MRI scanner manufactured by a company that has since been acquired. The MRI's control software runs on Windows XP Embedded. The manufacturer's certification only covers this specific OS version. Any OS change voids the medical device certification and potentially violates regulatory requirements.

Key facts:

-    The MRI scanner cost $2.1 million and is 6 years into a 12-year expected operational lifespan.

-    Windows XP has not received security patches since April 2014.

-    The MRI control workstation must communicate with the PACS server (Picture Archiving and Communication System) to transmit imaging studies. It requires network connectivity.

-    The radiology department processes approximately 45 MRI studies per day. Downtime directly affects patient care.

-    The current network configuration places the MRI workstation on the same VLAN as the rest of the hospital workstations.

Marcus left a sticky note in the MRI's file folder: "CRITICAL: this has been on my desk for 6 months. Nobody wants to deal with it. The risk is real. -M"

## Answer

### 1. Risk Analysis

The MRI workstation represents a critical security risk because it runs Windows XP Embedded, an operating system that has not received security updates since 2014, leaving numerous publicly known vulnerabilities permanently unpatched. Since the workstation shares the same VLAN as other hospital systems, a compromise of the MRI workstation could allow an attacker to move laterally to clinical workstations, servers, or other medical devices across the hospital network. The workstation must remain network-connected to communicate with the PACS server, making it continuously exposed to network-based attacks while unable to receive security fixes. As a result, the MRI workstation represents an enterprise-wide attack path rather than an isolated risk within the Radiology department.

---

### 2. Compensating Control Strategy

| Control | Category + Function | What it does | Risk Reduction | Limitations / Residual Risk |
|---------|----------------------|--------------|----------------|-----------------------------|
| **Network Segmentation and Firewall ACLs** | **Technical – Preventive** | Move the MRI workstation into a dedicated medical-device VLAN and configure firewalls or ACLs so it can communicate only with the PACS server and other required systems using approved ports and protocols. Block all unnecessary inbound and outbound traffic. | Greatly reduces the attack surface and prevents an attacker from easily using the MRI workstation as a stepping stone into the rest of the hospital network. This does not require changing the operating system. | Does not eliminate vulnerabilities on the workstation itself. If an authorized system (such as the PACS server) is compromised, the MRI could still be attacked. Configuration errors may also reduce effectiveness. |
| **Network Intrusion Detection/Monitoring** | **Technical – Detective** | Deploy IDS/IPS sensors or continuous network monitoring for the MRI VLAN to detect abnormal traffic, malware communication, unauthorized connections, or lateral movement attempts. Generate alerts for security staff. | Enables rapid detection and response before an attacker can spread throughout the environment. Monitoring compensates for the inability to install modern endpoint protection on Windows XP. | Primarily detects attacks rather than preventing them. Requires trained personnel to review alerts and respond quickly. False positives are possible. |
| **Strict Access Control and Privileged Account Management** | **Administrative – Preventive** | Limit access to authorized radiology personnel only, use unique administrator credentials, disable unnecessary accounts, enforce strong password policies, and restrict remote administration. Maintain an access approval process. | Reduces the likelihood of unauthorized access, insider misuse, credential theft, and accidental configuration changes without modifying the operating system. | Does not protect against software vulnerabilities or exploits that do not require valid credentials. Depends on user compliance and policy enforcement. |
| **Physical Security Controls** | **Physical – Preventive** | Place the MRI control workstation in a secured operator room with badge-controlled access, lock unused USB ports if possible, prohibit unauthorized removable media, and maintain visitor logs. | Reduces the risk of someone physically introducing malware or tampering with the workstation, which is particularly important because older systems are vulnerable to USB-based attacks. | Does not prevent network-based attacks. Authorized users could still accidentally introduce malware if procedures are not followed. |

---

### 3. Implementation Priority

**Highest Priority: Network Segmentation with Firewall Access Controls**

If MedDefense can implement only one control immediately, **network segmentation** provides the greatest reduction in overall organizational risk.

**Justification:**

- It directly addresses the biggest architectural weakness: the MRI workstation currently resides on the same VLAN as general hospital workstations.
- Even if Windows XP is compromised, segmentation significantly limits an attacker's ability to move laterally to electronic health record systems, domain controllers, other medical devices, or administrative systems.
- The control requires no modification of the certified operating system or MRI application, preserving regulatory compliance.
- Compared with monitoring or administrative controls, segmentation both **prevents** many attack paths and **contains** the impact of a successful compromise, making it the most effective single compensating control under the stated constraints.

In summary, while no compensating control can remove the inherent risk of an unsupported operating system, isolating the MRI workstation behind tightly controlled network boundaries provides the largest immediate reduction in enterprise-wide cyber risk while maintaining clinical operations.