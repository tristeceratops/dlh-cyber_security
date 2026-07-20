# The Network Posture

## Introduction

### Goal
Quantify how the flat network architecture amplifies the effective risk of every individual vulnerability.

### Context
The flat network is not a finding in the scan report. It is the finding underneath every finding. Every vulnerability in the scan is more dangerous because of the flat network. A SQL injection on billing-srv-01 would be contained to the billing segment in a segmented network. In MedDefense's flat network, it is a stepping stone to the EHR, the domain controller and the medical devices.

## Answer

# Segmentation Impact Analysis

## CVE: CVE-2020-1938
Host: ehr-srv-01 (10.10.2.10)
CVSS Base Score: 9.8

Scenario A: Current (flat network):
  Who can reach this vulnerability: Any compromised host on the 10.10.0.0/16 internal network can reach the Tomcat AJP service on port 8009.
  What the attacker can reach AFTER exploitation: The attacker can access EHR application files, potentially obtain database credentials, compromise ehr-db-01, and access other clinical systems through lateral movement.
  Effective Risk: Critical. The flat network turns a single vulnerable server into a potential entry point to the clinical environment.

Scenario B: Hypothetical (segmented network):
  Who can reach this vulnerability: Only systems in the EHR/application VLAN with approved access to ehr-srv-01.
  What the attacker can reach AFTER exploitation: The attacker would mainly be limited to the EHR application segment unless firewall rules allow further pivoting to databases or other clinical systems.
  Effective Risk: High. The vulnerability remains serious, but the blast radius is reduced.

Risk Amplification Factor: Very High. The flat network increases the impact by allowing any compromised internal device to directly target a critical clinical server.

---

## CVE: CVE-2021-44790
Host: billing-srv-01 (10.10.2.15)
CVSS Base Score: 9.8

Scenario A: Current (flat network):
  Who can reach this vulnerability: Any host within 10.10.0.0/16 can access the Apache service on billing-srv-01.
  What the attacker can reach AFTER exploitation: The attacker can obtain remote code execution, combine with CVE-2019-0211 for root access, access billing data, and attempt movement toward other internal servers.
  Effective Risk: Critical. The vulnerability provides a direct compromise path into a high-value server.

Scenario B: Hypothetical (segmented network):
  Who can reach this vulnerability: Only systems in the billing/server VLAN with required business communication paths.
  What the attacker can reach AFTER exploitation: The attacker would be restricted to billing infrastructure unless firewall rules permit access to databases or other zones.
  Effective Risk: High. The server could still be compromised, but containment would be significantly improved.

Risk Amplification Factor: High. Segmentation would reduce the ability to turn a billing server compromise into an enterprise-wide compromise.

---

## CVE: CVE-2019-0708
Host: WS-RAD-01 (10.10.1.70 - MRI Workstation)
CVSS Base Score: 9.8

Scenario A: Current (flat network):
  Who can reach this vulnerability: Any host on the 10.10.0.0/16 network can attempt exploitation of exposed RDP services on the MRI workstation.
  What the attacker can reach AFTER exploitation: The attacker can control the MRI workstation, disrupt radiology operations, access imaging workflows, and potentially move toward PACS and other clinical systems.
  Effective Risk: Critical. A legacy medical device workstation becomes a pivot point into critical healthcare operations.

Scenario B: Hypothetical (segmented network):
  Who can reach this vulnerability: Only systems inside the radiology/medical device VLAN with authorized communication paths.
  What the attacker can reach AFTER exploitation: The attacker would mainly access radiology assets in the same VLAN unless firewall rules allow movement to PACS or clinical networks.
  Effective Risk: Medium-High. The workstation remains vulnerable, but patient-care impact is reduced.

Risk Amplification Factor: Very High. Network segmentation is essential because the vulnerable XP workstation cannot be fully secured through patching.

---

# Network Posture Summary

The flat network significantly amplifies the impact of vulnerabilities across the environment because any compromised workstation, medical device, or server can directly reach critical assets. Segmentation would reduce attacker movement, limit blast radius, and protect clinical systems even when vulnerabilities remain. Therefore, segmentation provides broader risk reduction than patching a single CVE because it protects against multiple attack paths simultaneously.