# The Network Posture

## Introduction

### Goal
Quantify how the flat network architecture amplifies the effective risk of every individual vulnerability.

### Context
The flat network is not a finding in the scan report. It is the finding underneath every finding. Every vulnerability in the scan is more dangerous because of the flat network. A SQL injection on billing-srv-01 would be contained to the billing segment in a segmented network. In MedDefense's flat network, it is a stepping stone to the EHR, the domain controller and the medical devices.

## Answer

# Segmentation Impact Analysis

## CVE-2020-1938 (Ghostcat)

**Host:** ehr-srv-01 (10.10.2.10)  
**CVSS:** 9.8

| Scenario | Analysis |
|---|---|
| **A - Flat network** | **Reachable by:** Any host on **10.10.0.0/16**. **After exploitation:** Read configuration files, obtain DB credentials, pivot to **ehr-db-01** and other critical servers. **Risk:** **Critical**. |
| **B - Segmented network** | **Reachable by:** Only application-tier VLAN. **After exploitation:** Limited to the application segment unless firewall rules allow further access. **Risk:** **High**. |

**Risk Amplification Factor:** **Very High** — Flat network exposes the EHR server to every compromised internal host.

---

## CVE-2021-44790 (Apache mod_lua RCE)

**Host:** billing-srv-01 (10.10.2.15)  
**CVSS:** 9.8

| Scenario | Analysis |
|---|---|
| **A - Flat network** | **Reachable by:** Any internal host. **After exploitation:** Chain with F002 for root access, then reach MySQL and other servers. **Risk:** **Critical**. |
| **B - Segmented network** | **Reachable by:** Only billing application systems. **After exploitation:** Limited to the billing VLAN. **Risk:** **High**. |

**Risk Amplification Factor:** **High** — Segmentation would significantly reduce lateral movement.

---

## CVE-2019-0708 (BlueKeep)

**Host:** WS-RAD-01 (MRI Workstation)  
**CVSS:** 9.8

| Scenario | Analysis |
|---|---|
| **A - Flat network** | **Reachable by:** Any host on **10.10.0.0/16**. **After exploitation:** Pivot to PACS, radiology systems, and adjacent clinical assets. **Risk:** **Critical**. |
| **B - Segmented network** | **Reachable by:** Only radiology VLAN. **After exploitation:** Contained within imaging systems. **Risk:** **Medium–High**. |

**Risk Amplification Factor:** **Very High** — Isolation would greatly reduce the exposure of this legacy system.

---

# Network Posture Summary

The flat network is the main risk multiplier in the environment. Almost every critical finding becomes reachable from any compromised internal host, enabling rapid lateral movement between clinical, identity, and billing systems. Network segmentation would reduce the attack surface for **all** vulnerabilities simultaneously, whereas patching a single CVE only removes one attack path while leaving unrestricted lateral movement intact.