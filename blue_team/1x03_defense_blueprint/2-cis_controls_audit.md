# The CIS Controls Audit

## Introduction

### Goal
Score MedDefense against the CIS Top 18 Controls to produce a concrete, actionable security maturity assessment.

### Context
NIST CSF tells you what functions to address. CIS Controls tell you exactly what to implement, in what order. The CIS Controls are organized into three Implementation Groups:

-    IG1 (Essential): The minimum standard every organization should meet. 56 safeguards. Think of this as "basic hygiene."

-    IG2 (Foundational): Additional safeguards for organizations with more complex environments. Builds on IG1.

-    IG3 (Organizational): Advanced safeguards for organizations with dedicated security teams handling sophisticated attacks.

MedDefense, as a healthcare organization handling regulated data with a small security team, should target IG1 fully implemented and IG2 partially implemented within 6 months.

## Answer

| CIS Control | Score | Evidence |
|-------------|-------|----------|
| **1. Inventory and Control of Enterprise Assets** | **Partial** | An asset inventory exists after 1x00, but unauthorized assets (e.g., Raspberry Pi, shadow IT) were discovered. |
| **2. Inventory and Control of Software Assets** | **Partial** | The scan identified outdated software (Tomcat, Windows XP MRI, legacy TLS), showing incomplete software inventory and lifecycle management. |
| **3. Data Protection** | **Partial** | PHI is classified, but GAP-014 identified missing DLP and insufficient monitoring of sensitive data exports. |
| **4. Secure Configuration of Enterprise Assets and Software** | **Partial** | Multiple misconfigurations were found (default credentials, missing security headers, legacy TLS, Tomcat information disclosure). |
| **5. Account Management** | **Partial** | Password policies exist, but GAP-013 shows manual offboarding and inactive accounts are not consistently managed. |
| **6. Access Control Management** | **Partial** | GAP-017 identified missing MFA for VPN and critical services despite existing authentication controls. |
| **7. Continuous Vulnerability Management** | **Not Implemented** | Finding 031 (Ghostcat) and other outdated software remained unpatched, indicating no formal vulnerability management process. |
| **8. Audit Log Management** | **Partial** | Logs are collected but GAP-004 identified no centralized SIEM or effective log monitoring. |
| **9. Email and Web Browser Protections** | **Partial** | Security awareness exists, but phishing remains a primary threat and browser/email protections are incomplete. |
| **10. Malware Defenses** | **Implemented** | Managed Windows endpoints have endpoint protection and antivirus deployed. |
| **11. Data Recovery** | **Partial** | GAP-005 identified backups exist but are not isolated or resilient against ransomware. |
| **12. Network Infrastructure Management** | **Partial** | Firewalls are deployed, but GAP-006 identified a flat network with insufficient segmentation. |
| **13. Network Monitoring and Defense** | **Not Implemented** | Marcus' assessment confirmed there is no centralized monitoring or intrusion detection capability. |
| **14. Security Awareness and Skills Training** | **Implemented** | Basic user security awareness training is documented in the security posture assessment. |
| **15. Service Provider Management** | **Partial** | Third-party providers exist, but building management and vendor dependencies are not fully governed. |
| **16. Application Software Security** | **Not Implemented** | No secure development or application security process was identified for internally managed web applications. |
| **17. Incident Response Management** | **Not Implemented** | GAP-012 identified the absence of a formal incident response plan and tested procedures. |
| **18. Penetration Testing** | **Not Implemented** | No penetration testing program was identified; only vulnerability scanning was performed. |

### Scorecard Summary

| Score | Count |
|-------|------:|
| **Implemented** | **2** |
| **Partial** | **11** |
| **Not Implemented** | **5** |

### Top 5 Priority Controls

| CIS Control | Justification |
|-------------|---------------|
| **Control 7 – Continuous Vulnerability Management** | Establishes a formal process to identify, prioritize and remediate vulnerabilities such as Ghostcat, outdated Tomcat and legacy TLS, reducing the largest number of exploitable findings from 1x02. |
| **Control 6 – Access Control Management** | Deploying MFA would directly break the credential-theft attack path identified in 1x01 (GAP-017), preventing stolen credentials from leading to full network compromise. |
| **Control 12 – Network Infrastructure Management** | Network segmentation would reduce the blast radius of every successful compromise by preventing unrestricted lateral movement across the flat 10.10.0.0/16 network (GAP-006). |
| **Control 13 – Network Monitoring and Defense** | Implementing SIEM/MDR would provide visibility into attacks currently going undetected because of GAP-004, significantly reducing attacker dwell time. |
| **Control 17 – Incident Response Management** | A documented and tested incident response plan would improve containment and recovery during ransomware or medical device incidents, addressing GAP-012. |