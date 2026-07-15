# The ATT&CK Mapping

## Introduction

### Goal
Map realistic attack sequences to MITRE ATT&CK tactics, building fluency with the framework that every SOC uses daily.

### Context
MITRE ATT&CK is the shared language of the security industry. When a SOC analyst says "we detected T1566.001," every security professional in the world knows they are talking about a spear phishing attachment. When an incident report maps an attack to ATT&CK tactics, any team can understand the sequence without reading a narrative.

You do not need to memorize the entire framework. You need to be able to read an attack description and map each step to the correct tactic. The techniques will come with experience. The tactics are what matter now.

The 14 ATT&CK Enterprise Tactics (in attack sequence order): Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

---

# Answer

## Scenario Alpha: Operation Flatline (Ransomware)

### Step 1: Purchase target list from Initial Access Broker

- **Tactic:** Resource Development
- **Technique:** Acquire Infrastructure: Domains/Infrastructure (T1583/T1584 family) *(Alternative: Victim Network Information (T1590))*
- **MedDefense Factor:** MedDefense exposes a FortiGate VPN appliance on the Internet, making it identifiable during reconnaissance and commercially valuable to initial access brokers.

---

### Step 2: Spear phishing Sarah Park with malicious document

- **Tactic:** Initial Access
- **Technique:** Phishing: Spearphishing Attachment (**T1566.001**) *(Alternative: Spearphishing Link – T1566.002 if the malicious link is emphasized)*
- **MedDefense Factor:** Limited phishing detection, incomplete MFA deployment, and reliance on user awareness make IT staff attractive phishing targets.

---

### Step 3: Macro launches PowerShell, reverse shell, scheduled task persistence

- **Tactic:** Execution / Persistence / Command and Control
- **Technique:**
  - User Execution: Malicious File (**T1204.002**)
  - PowerShell (**T1059.001**)
  - Scheduled Task/Job (**T1053.005**)
  - Application Layer Protocol: Web Protocols (**T1071.001**)
- **MedDefense Factor:** Sophos protects endpoints but limited monitoring (Gap G-001) allows persistent malware and C2 traffic to remain unnoticed.

---

### Step 4: Internal network discovery

- **Tactic:** Discovery
- **Technique:**
  - System Network Configuration Discovery (**T1016**)
  - Remote System Discovery (**T1018**)
  - Domain Trust Discovery (**T1482**)
- **MedDefense Factor:** The flat 10.10.0.0/16 network and unrestricted VPN routing allow immediate visibility of nearly all critical assets.

---

### Step 5: Dump credentials using Mimikatz

- **Tactic:** Credential Access
- **Technique:** OS Credential Dumping (**T1003**) *(LSASS memory dumping)*
- **MedDefense Factor:** Domain administrator credentials were previously used on Sarah's workstation, enabling credential theft through cached credentials.

---

### Step 6: Pass-the-Hash to Domain Controller

- **Tactic:** Lateral Movement
- **Technique:** Pass the Hash (**T1550.002**)
- **MedDefense Factor:** Lack of privileged access management and broad administrative trust relationships allow stolen hashes to be reused across the domain.

---

### Step 7: Dump EHR database and exfiltrate with Rclone

- **Tactic:** Collection / Exfiltration
- **Technique:**
  - Data from Information Repositories (**T1213**)
  - Archive Collected Data (**T1560**)
  - Exfiltration Over Web Service (**T1567.002**)
- **MedDefense Factor:** PostgreSQL is broadly reachable, no SIEM exists, and outbound HTTPS traffic is largely unrestricted (Gap G-006).

---

### Step 8: Delete backups and Volume Shadow Copies

- **Tactic:** Impact
- **Technique:**
  - Inhibit System Recovery (**T1490**)
- **MedDefense Factor:** Backups reside on the same network and lack immutability or offline copies (Gap G-002).

---

### Step 9: Deploy ransomware through Group Policy

- **Tactic:** Impact
- **Technique:**
  - Data Encrypted for Impact (**T1486**)
  - Group Policy Modification (**T1484.001**) *(to distribute the payload)*
- **MedDefense Factor:** Domain-wide administrative control combined with centralized Group Policy enables rapid deployment to nearly every Windows system.

---

# Scenario Beta: The Quiet Departure (Insider Data Theft)

### Step 1: Insider decides to steal patient records

- **Tactic:** Collection
- **Technique:** Data from Information Repositories (**T1213**)
- **MedDefense Factor:** Maria already possesses legitimate read access to billing and EHR systems as part of her normal duties.

---

### Step 2: Assess accessible information

- **Tactic:** Discovery
- **Technique:** File and Directory Discovery (**T1083**) *(Alternative: Permission Groups Discovery – T1069)*
- **MedDefense Factor:** The EHR lacks behavioral monitoring and places few limits on large-scale record access.

---

### Step 3: Export patient data from the EHR

- **Tactic:** Collection
- **Technique:** Data from Information Repositories (**T1213**)
- **MedDefense Factor:** Export functionality is available to all read-only users, and audit logs are not actively reviewed (Gap G-004).

---

### Step 4: Copy files to USB drive

- **Tactic:** Exfiltration
- **Technique:** Exfiltration to Removable Media (**T1052.001**)
- **MedDefense Factor:** USB storage is unrestricted, and no Group Policy blocks removable media.

---

### Step 5: Delete exported CSV files

- **Tactic:** Defense Evasion
- **Technique:** File Deletion (**T1070.004**)
- **MedDefense Factor:** Local evidence can be removed easily, while server-side audit logs are never reviewed proactively.

---

### Step 6: Copy database credentials

- **Tactic:** Credential Access
- **Technique:** Unsecured Credentials: Credentials in Files (**T1552.001**)
- **MedDefense Factor:** Billing database credentials are stored in plaintext configuration files on user workstations.

---

### Step 7: Delayed account deactivation

- **Tactic:** Persistence
- **Technique:** Valid Accounts (**T1078**)
- **MedDefense Factor:** Offboarding is manual, lacks automation, and no SLA exists for account deactivation.

---

### Step 8: Remote VPN access after termination

- **Tactic:** Initial Access / Collection
- **Technique:**
  - Valid Accounts (**T1078**)
  - Remote Services: VPN (**T1133**)
  - Data from Information Repositories (**T1213**)
- **MedDefense Factor:** Active VPN credentials combined with permissive VPN access and stored database credentials allow continued access after employment ends.

---

# ATT&CK Coverage Assessment

Both scenarios repeatedly involve the **Initial Access**, **Credential Access**, **Discovery**, **Collection**, and **Exfiltration** tactics. Although the ransomware campaign continues into **Lateral Movement** and **Impact**, and the insider attack emphasizes **Persistence** and **Defense Evasion**, the common pattern is that attackers first obtain legitimate access, discover valuable assets, collect sensitive data, and remove it without detection. This indicates MedDefense's most urgent detection priorities should be around **Credential Access**, **Discovery**, **Collection**, and **Exfiltration**. Deploying centralized logging and SIEM (Gap G-001), implementing behavioral monitoring for privileged accounts, monitoring abnormal data access and exports, restricting outbound data transfers, and improving account lifecycle management would significantly improve visibility into both external and insider attacks.