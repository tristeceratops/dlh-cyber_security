# The Kill Chain Overlay

## Introduction

### Goal
Overlay the Crimson Tide attack chain onto the kill chains you built in 1x01, identifying where they converge and where MedDefense's planned controls would intercept.

### Context
You built 5 kill chains for MedDefense in Project 1x01. Crimson Tide's attack chain is a real-world instance of those theoretical models. How accurately did your threat modeling predict this attack ? Where does the Crimson Tide chain match your kill chains, and where does it diverge ?

## Answer

# Part 1 – Kill Chain Overlay

| My Kill Chain #1 (1x01 T10) | Crimson Tide Phase | Match? | Assessment |
|------------------------------|-------------------|--------|------------|
| **1. Spear phishing against IT administrator** | **Phase 1 – Exploitation of FortiGate SSL-VPN (CVE-2023-27997)** | ❌ Partial | My model assumed phishing was the initial access vector. Crimson Tide instead gains direct access through an internet-facing VPN vulnerability without requiring user interaction. |
| **2. Authenticate using stolen VPN/M365 credentials** | **Phase 2 – Internal reconnaissance from compromised FortiGate** | ✔ Partial | Both models assume attackers obtain valid credentials before moving internally. Crimson Tide captures VPN credentials directly from FortiGate memory rather than relying on previously stolen passwords. |
| **3. Enumerate Active Directory and move laterally** | **Phase 3 – Lateral movement using RDP/SSH/WMI and Kerberoasting** | ✔ Yes | This stage closely matches the original prediction. Both attack chains rely on excessive privileges and a flat internal network to compromise additional systems. Crimson Tide additionally uses Kerberoasting and cached credentials (Mimikatz), techniques not explicitly included in my model. |
| **4. Deploy ransomware through Domain Controller/GPO** | **Phase 6 – Ransomware deployment via GPO** | ✔ Yes | The predicted deployment mechanism is effectively identical. Both scenarios assume complete Active Directory compromise before ransomware execution. |
| **5. Hospital-wide operational outage** | **Phase 7 – Extortion after encryption** | ✔ Partial | My model correctly predicted major operational disruption. However, Crimson Tide consistently performs large-scale data theft before encryption and uses double-extortion, a step that was underestimated in my original model. |

## Accuracy Summary

### Correct Predictions
- Compromise of privileged credentials
- Active Directory enumeration
- Lateral movement inside a flat network
- GPO-based ransomware deployment
- Enterprise-wide operational disruption

### Missing or Underestimated Elements
- Exploitation of an unpatched FortiGate vulnerability as the initial access vector
- Credential extraction directly from FortiGate memory
- Kerberoasting using RC4-encrypted service tickets
- Large-scale data exfiltration before encryption
- Deliberate destruction of backup infrastructure
- Double-extortion strategy using stolen patient information

---

# Part 2 – Control Interception Map

| Crimson Tide Phase | Planned Control (1x03) | Status | Would it Stop This Phase? |
|--------------------|------------------------|---------|---------------------------|
| **1. Initial Access** | MFA for VPN accounts | **Funded / Not Deployed** | **Partially** (helps against stolen credentials but not CVE-2023-27997 exploitation) |
| **1. Initial Access** | Dedicated firewall management and patching | **Funded / Not Deployed** | **Partially** (reduces exposure once firmware is updated) |
| **2. Internal Reconnaissance** | SIEM/MDR monitoring | **Funded / Not Deployed** | **Partially** (detects suspicious activity but does not prevent it) |
| **3. Lateral Movement** | Network segmentation (Server, Clinical, Medical and Guest VLANs) | **Funded / Not Deployed** | **Yes** |
| **3. Lateral Movement** | MFA and stronger identity management | **Funded / Not Deployed** | **Partially** |
| **4. Data Exfiltration** | SIEM/MDR monitoring | **Funded / Not Deployed** | **Partially** (large transfers could be detected) |
| **4. Data Exfiltration** | Future encryption project (1x04 roadmap) | **Planned / Not Yet Implemented** | **Partially** (encrypted databases reduce impact of stolen files) |
| **5. Backup Destruction** | Immutable backups | **Funded / Not Deployed** | **Yes** |
| **5. Backup Destruction** | Network segmentation | **Funded / Not Deployed** | **Yes** |
| **6. Ransomware Deployment** | EDR upgrade | **Funded / Not Deployed** | **Partially** |
| **6. Ransomware Deployment** | SIEM/MDR monitoring | **Funded / Not Deployed** | **Partially** |
| **7. Extortion** | Incident Response Plan | **Funded / Not Deployed** | **No** (reduces response time but cannot prevent extortion once data is stolen) |
| **7. Extortion** | Disaster Recovery Policy | **Planned (Month 6)** | **Partially** |

---

# Part 3 – Gap Between Plan and Reality

If MedDefense had fully implemented the Security Strategy described in 1x03, the organization would significantly reduce the effectiveness of the Crimson Tide campaign, but it would not eliminate the threat completely. Network segmentation, immutable backups, MFA, SIEM/MDR, and EDR would largely prevent or contain **Phases 3 (Lateral Movement)** and **5 (Backup Destruction)** while improving detection during **Phases 2, 4, and 6**. However, **Phase 1 (FortiGate exploitation)** would still succeed if the appliance remained vulnerable, because MFA does not mitigate CVE-2023-27997 and the strategy does not explicitly address firmware lifecycle management. **Phase 7 (Extortion)** would also remain possible whenever sensitive data had already been exfiltrated. Overall, approximately **2 of the 7 phases would likely be blocked**, **3 would be partially mitigated**, and **2 could still succeed**, demonstrating that even a fully implemented security strategy must be complemented by continuous vulnerability management, timely patching, and cryptographic protections such as database encryption to reduce residual risk.