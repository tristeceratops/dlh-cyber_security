# 3. The Walk-Through

## Introduction

### Goal
Apply structured risk reasoning (Vulnerability, Threat, Impact) to physical observations in a real environment.

### Context
James Chen takes you on a tour of MedDefense Central. "Walk through with fresh eyes," he says. "Marcus told me at least twice that the server room access was a problem. I flagged it to Sarah Park in IT. She said it was 'on the roadmap.' That was five months ago."

As you walk the facility, you observe details that a non-security professional would overlook. Each observation represents a potential security weakness. Your job is to decompose each one into its formal risk components.

A risk exists when three elements converge:

- Vulnerability: A specific weakness or gap in a system, process or physical setup.

- Threat: An event, actor or circumstance that could exploit the vulnerability.

- Impact: The consequence to the organization if the threat materializes, measured against the CIA pillars.

## Answer
### Observation 1: Server Room Access

**Vulnerability:**  
The server room can be accessed using the same generic badge issued to every employee, regardless of their role. There are also no security cameras monitoring the entrance and no visitor log to record who enters or leaves.

**Threat:**  
Someone who is not authorized to access the server room—such as an employee, contractor, or a person using a lost or stolen badge—could enter the room and tamper with or steal critical IT equipment.

**Impact:**  
- **Confidentiality:** Sensitive patient or organizational data could be exposed.
- **Integrity:** Systems or stored data could be altered or damaged.
- **Availability:** Critical servers could be shut down or damaged, disrupting hospital operations.

**Severity:** **Critical**  
The server room contains essential infrastructure, and the lack of proper access controls makes it possible for unauthorized individuals to compromise all three CIA security principles.

---

### Observation 2: Network Closet

**Vulnerability:**  
The network closet is left unlocked, and administrator credentials for the network switches are displayed openly on the wall, making them accessible to anyone who enters.

**Threat:**  
An unauthorized person could walk into the closet, use the exposed credentials to log into the network switches, and change configurations, monitor traffic, or even disable parts of the network.

**Impact:**  
- **Confidentiality:** Sensitive network traffic could be intercepted.
- **Integrity:** Network settings could be changed without authorization.
- **Availability:** Hospital systems could become unavailable due to network disruption.

**Severity:** **Critical**  
Leaving both the network equipment and administrative credentials unsecured creates an easy opportunity for someone to gain privileged access to the hospital's network.

---

### Observation 3: Nurse Station

**Vulnerability:**  
A workstation is left logged into the Electronic Health Record (EHR) system with a patient's information visible, and staff are encouraged to keep sessions active between shifts.

**Threat:**  
Anyone passing by the workstation could view confidential patient records or make unauthorized changes without needing to log in.

**Impact:**  
- **Confidentiality:** Patient medical information could be viewed by unauthorized individuals.
- **Integrity:** Patient records could be modified incorrectly or maliciously.
- **Availability:** Important medical information could be deleted or altered, affecting patient care.

**Severity:** **High**  
Leaving clinical workstations unattended while logged in creates an immediate risk to sensitive patient information and could directly impact patient safety.

---

### Observation 4: Medical IoT Device

**Vulnerability:**  
The vital signs monitor displays technical information such as its IP address and firmware version. The firmware has not been updated since 2019, and the device appears to share the same network as staff workstations.

**Threat:**  
An attacker could use the exposed information to identify the device, exploit known vulnerabilities in the outdated firmware, and potentially move across the hospital network to other connected systems.

**Impact:**  
- **Confidentiality:** Patient or device data could be accessed without authorization.
- **Integrity:** Device settings or monitoring data could be manipulated.
- **Availability:** The monitoring device or connected systems could be disrupted, affecting patient care.

**Severity:** **High**  
Outdated medical devices connected to the same network as user workstations increase the risk of cyberattacks spreading throughout the environment.

---

### Observation 5: Emergency Exit

**Vulnerability:**  
A fire exit connecting a public waiting area to a restricted administrative section has been propped open, allowing unrestricted access to secure areas.

**Threat:**  
A visitor or other unauthorized person could enter the administrative wing unnoticed and gain access to offices, IT equipment, or sensitive information.

**Impact:**  
- **Confidentiality:** Sensitive documents or information could be viewed or stolen.
- **Integrity:** Systems or records could be tampered with.
- **Availability:** Equipment could be damaged or stolen, disrupting hospital operations.

**Severity:** **High**  
Propping open a secured access point completely bypasses physical security controls and makes it much easier for unauthorized individuals to enter restricted areas.