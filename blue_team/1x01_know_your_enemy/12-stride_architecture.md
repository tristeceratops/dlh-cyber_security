# STRIDE Across the Architecture

## Introduction

### Goal
Apply STRIDE at surface level to three additional critical systems to build a broad threat awareness across the MedDefense environment.

### Context
The EHR is the crown jewel, but it is not the only system an attacker cares about. Active Directory controls authentication for every user and service. The PACS server stores medical images that are essential for diagnosis. The network infrastructure is the fabric that connects everything.

A quick STRIDE pass on each of these systems identifies the most critical threats without the full depth of the EHR analysis. Think of it as triage: identify the most dangerous threat in each STRIDE category, then move on.

## Answer

## System: PACS / Medical Imaging

### Architecture Notes

The imaging environment consists of **pacs-srv-01 (Windows Server 2016)**, the **Siemens MAGNETOM MRI** controlled by the legacy **Windows XP MRI workstation (A-021)**, and radiology workstations connected over the hospital's flat internal network. Images are transferred from the MRI workstation to PACS for long-term storage and clinician access. The MRI workstation cannot be fully patched because of vendor certification constraints.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| **S** | An attacker uses stolen or shared radiology credentials to impersonate a technician and access PACS. | Unauthorized viewing or modification of patient imaging studies. | **High** |
| **T** | Malware on the Windows XP MRI workstation alters or corrupts diagnostic images before they are stored in PACS. | Incorrect diagnoses and compromised patient safety. | **Critical** |
| **R** | Shared radiology accounts make it impossible to determine which user viewed or modified medical images. | Loss of auditability and HIPAA compliance issues. | **High** |
| **I** | Imaging data is intercepted while traversing the flat internal network between MRI, PACS, and workstations. | Exposure of sensitive PHI and diagnostic records. | **High** |
| **D** | Ransomware encrypts PACS or the MRI workstation, preventing access to imaging studies. | Radiology operations stop, delaying diagnosis and treatment. | **Critical** |
| **E** | Exploitation of the Windows XP MRI workstation provides a foothold for lateral movement into other hospital systems. | Enterprise-wide compromise beyond Radiology. | **Critical** |

**Top Threat:**  
**Elevation of Privilege** is the greatest threat because the unsupported Windows XP MRI workstation is an ideal pivot point. Once compromised, the flat network allows attackers to move toward Active Directory, the EHR, and other critical systems with minimal resistance.

---

## System: Active Directory

### Architecture Notes

Active Directory consists of **ad-dc-01** and **ad-dc-02**, providing centralized authentication, authorization, DNS, and Group Policy for approximately 2,000 users and nearly every Windows workstation and server. MFA is deployed only for James Chen's account, making password compromise a major concern.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| **S** | Attackers steal administrator credentials through phishing and impersonate Domain Administrators. | Complete compromise of enterprise authentication. | **Critical** |
| **T** | Malicious changes to Group Policy or Active Directory objects distribute malware or weaken security settings. | Organization-wide security compromise. | **Critical** |
| **R** | Weak centralized logging allows privileged users or attackers to deny creating accounts or changing permissions. | Difficult forensic investigations and accountability gaps. | **High** |
| **I** | A compromised domain controller exposes password hashes and directory information for the entire organization. | Large-scale credential theft and PHI exposure. | **Critical** |
| **D** | Ransomware disables both domain controllers, preventing authentication across MedDefense. | Hospital-wide outage affecting nearly all IT services. | **Critical** |
| **E** | Attackers escalate from compromised user accounts to Domain Administrator due to limited MFA and privileged account protections. | Full control of all users, systems, and security controls. | **Critical** |

**Top Threat:**  
**Elevation of Privilege** is the most dangerous threat because Domain Administrator access effectively gives an attacker complete control over the MedDefense environment, including EHR systems, workstations, servers, and security infrastructure.

---

## System: Network Infrastructure

### Architecture Notes

The network infrastructure includes the **FortiGate-100F firewall**, **Cisco core switch**, **Netgear consumer router at Westside Clinic**, IPSec VPN tunnels between sites, and a largely flat **10.10.0.0/16** internal network. Internal segmentation is minimal, VPN users have broad access, and the firewall serves as the primary perimeter defense.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| **S** | Stolen VPN or firewall administrator credentials allow attackers to impersonate trusted users. | Unauthorized entry into the internal network. | **Critical** |
| **T** | Firewall rules or VPN configurations are modified to create persistent backdoors or bypass security controls. | Long-term unauthorized access and weakened perimeter security. | **Critical** |
| **R** | Insufficient centralized monitoring prevents reliable attribution of firewall or network configuration changes. | Delayed detection and limited forensic evidence. | **High** |
| **I** | Excessively permissive VPN access and flat networking expose internal systems after a single compromise. | Sensitive clinical and business data becomes accessible. | **Critical** |
| **D** | Failure or compromise of the FortiGate firewall or Westside router disrupts connectivity between sites. | Loss of access to EHR, file services, and other critical applications. | **Critical** |
| **E** | Attackers exploit the consumer-grade router or VPN access to pivot through the flat network and compromise critical servers. | Enterprise-wide compromise through unrestricted lateral movement. | **Critical** |

**Top Threat:**  
**Elevation of Privilege** represents the greatest risk because once an attacker gains any foothold inside the network, the lack of segmentation allows rapid movement to Active Directory, the EHR, database servers, and medical devices. Improving network segmentation and enforcing least-privilege VPN access would significantly reduce this risk.