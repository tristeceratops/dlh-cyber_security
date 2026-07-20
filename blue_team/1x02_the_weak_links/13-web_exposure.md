# The Web Exposure

## Introduction

### Goal
Analyze web-facing vulnerabilities with specific attention to internet-exposed vs internal-only exposure.

### Context
A vulnerability on an internet-facing system and the same vulnerability on an internal-only system are not the same risk. The scan report has web-related findings on the patient portal (internet-facing), the NAS management interface (internal) and the EHR application server (internal but on the flat network). Each requires different analysis.

## Answer

# Web-Related Findings Analysis

| Priority | Host | Exposure | Findings | Combined Risk |
|---|---|---|---|---|
| 1 | **ehr-srv-01 (10.10.2.10)** | Internal, flat network | F017, F031, F030 | **Critical** |
| 2 | **billing-srv-01 (10.10.2.15)** | Internal, flat network | F001, F002, F011 | **Critical** |
| 3 | **web-srv-01 (10.10.2.50)** | Internet-facing | F005, F012, F013, F021 | **High** |
| 4 | **BD Alaris Pumps (10.10.3.40-46)** | Internal, flat network | F010 | **High** |
| 5 | **Philips IntelliVue (10.10.3.10-32)** | Internal, flat network | F016 | **Medium** |

---

## Host: ehr-srv-01 (10.10.2.10)

**Exposure:** Internal, reachable from any host (flat network).

**Findings**
- F017 – Tomcat version disclosure
- F031 – Ghostcat (CVE-2020-1938)
- F030 – TLS CN mismatch (operational)

**Combined Risk:** **Critical** (Ghostcat can expose configuration files and credentials.)

**Attack Scenario**
1. Internal foothold (phishing/VPN).
2. Identify Tomcat version (F017).
3. Exploit Ghostcat (F031).
4. Read DB credentials.
5. Access **ehr-db-01** (F003).

**1x01 Kill Chain:** Vulnerable Software Exploit → Credential Access → Lateral Movement.

**Priority:** **1**

---

## Host: billing-srv-01 (10.10.2.15)

**Exposure:** Internal, flat network.

**Findings**
- F001 – Apache mod_lua RCE
- F002 – Apache privilege escalation
- F011 – Ubuntu 18.04 EOL

**Combined Risk:** **Critical** (RCE + privilege escalation = full server compromise.)

**Attack Scenario**
1. Exploit Apache RCE.
2. Escalate to root.
3. Access billing application and MySQL (F006).

**1x01 Kill Chain:** Vulnerable Software Exploit → Privilege Escalation → Lateral Movement.

**Priority:** **2**

---

## Host: web-srv-01 (10.10.2.50)

**Exposure:** **Internet-facing**.

**Findings**
- F005 – TLS 1.0 enabled
- F012 – Missing security headers
- F013 – Certificate expires soon
- F021 – HTTP TRACE enabled

**Combined Risk:** **High** (Weakens the security of the public patient portal.)

**Attack Scenario**
1. Connect to patient portal.
2. Exploit weak TLS / missing headers.
3. Combine with web attack (e.g., XSS) to steal sessions.

**1x01 Kill Chain:** Initial Access.

**Priority:** **3**

---

## Host: BD Alaris Pumps (10.10.3.40-46)

**Exposure:** Internal, flat network.

**Findings**
- F010 – Vulnerable firmware
- F010 – Default credentials

**Combined Risk:** **High** (Easy administrative access to critical medical devices.)

**Attack Scenario**
1. Internal access.
2. Login with default credentials.
3. Disrupt infusion pumps.

**1x01 Kill Chain:** Default Credentials → Vulnerable Software Exploit.

**Priority:** **4**

---

## Host: Philips IntelliVue Monitors (10.10.3.10-32)

**Exposure:** Internal, flat network.

**Findings**
- F016 – Web management interface exposed

**Combined Risk:** **Medium** (Large attack surface but no confirmed exploit.)

**Attack Scenario**
1. Internal compromise.
2. Reach management interfaces.
3. Attempt unauthorized configuration.

**1x01 Kill Chain:** Lateral Movement.

**Priority:** **5**

---

# Why Finding 017 Was Important

Finding **017** only disclosed the Tomcat version, but it enabled SecurePoint to manually identify **Finding 031 (Ghostcat, CVSS 9.8)**.

**Lesson:**
- Version disclosure reveals exactly what attackers should target.
- Medium findings often enable discovery of Critical vulnerabilities.
- Always investigate version disclosure on critical systems before deprioritizing it.