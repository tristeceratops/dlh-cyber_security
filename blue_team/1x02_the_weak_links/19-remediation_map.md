# The Remediation Map

## Introduction

### Goal
Design specific remediation actions for each prioritized vulnerability, considering operational constraints and risks of the remediation itself.

### Context
Fixing a vulnerability always has a cost: the patch that breaks the billing application, the firewall rule that blocks legitimate clinical traffic, the server restart that takes the EHR offline during rounds. Remediation is not "apply patch." Remediation is "apply patch, but first understand what might break, test in a maintenance window, have a rollback plan, and communicate with the clinical teams."

## Answer

# Remediation Plan

### Finding 001 (CVE-2021-44790 - Apache mod_lua RCE)
- **Response Type:** Patch
  - **Patch Source:** Apache HTTP Server ≥2.4.52 (https://httpd.apache.org/security/vulnerabilities_24.html)
  - **Prerequisites:** Backup server, test billing application, maintenance window.
  - **Rollback Plan:** Restore VM/snapshot and previous Apache package.
  - **Operational Risk:** Temporary billing application outage.
- **Timeline:** Immediate (24-48h)
- **Owner:** IT
- **Cost Estimate:** $0-1K

---

### Finding 002 (CVE-2019-0211 - Apache Privilege Escalation)
- **Response Type:** Patch
  - **Patch Source:** Upgrade Apache to ≥2.4.39 (included in latest version).
  - **Prerequisites:** Same maintenance window as Finding 001.
  - **Rollback Plan:** Restore previous Apache installation.
  - **Operational Risk:** Service interruption during restart.
- **Timeline:** Immediate (24-48h)
- **Owner:** IT
- **Cost Estimate:** $0-1K

---

### Finding 003 (PostgreSQL Unrestricted Network Access)
- **Response Type:** Configuration Change
  - **Change Description:** Restrict `pg_hba.conf` to `ehr-srv-01`, configure host firewall to block all other connections.
  - **Impact Assessment:** Only approved application servers retain database access.
- **Timeline:** 7 days
- **Owner:** IT / DBA
- **Cost Estimate:** $0-1K

---

### Finding 004 (Windows XP MRI Workstation)
- **Response Type:** Compensating Control
  - **Control Description:** Isolate on dedicated VLAN, restrict firewall rules, disable SMB/RDP where possible, continuous monitoring.
  - **Residual Risk:** OS remains permanently vulnerable because it is unsupported.
- **Timeline:** Immediate
- **Owner:** IT + Clinical + Vendor
- **Cost Estimate:** $10-50K

---

### Finding 007 (LDAP Signing Disabled / SMBv1 Enabled)
- **Response Type:** Configuration Change
  - **Change Description:** Enforce LDAP signing and disable SMBv1 via Group Policy.
  - **Impact Assessment:** Legacy clients may require compatibility testing.
- **Timeline:** 7 days
- **Owner:** IT
- **Cost Estimate:** $0-1K

---

### Finding 010 (BD Alaris Pumps - Default Credentials & Firmware)
- **Response Type:** Compensating Control
  - **Control Description:** Change default credentials, isolate pumps in a medical-device VLAN, restrict access to clinical systems only.
  - **Residual Risk:** Firmware vulnerability remains until vendor-approved update.
- **Timeline:** 30 days
- **Owner:** Clinical + Vendor
- **Cost Estimate:** $1-10K

---

### Finding 011 (Ubuntu 18.04 without ESM)
- **Response Type:** Patch
  - **Patch Source:** Enroll in Ubuntu Pro ESM or migrate to Ubuntu 22.04 LTS.
  - **Prerequisites:** Full backup, application compatibility testing.
  - **Rollback Plan:** Restore system snapshot if migration fails.
  - **Operational Risk:** Billing application compatibility issues.
- **Timeline:** 30 days
- **Owner:** IT
- **Cost Estimate:** $1-10K

---

### Finding 031 (CVE-2020-1938 - Ghostcat)
- **Response Type:** Patch
  - **Patch Source:** Upgrade Tomcat to a patched version and disable AJP if unnecessary.
  - **Prerequisites:** Backup EHR server, validate EHR application, maintenance window.
  - **Rollback Plan:** Restore previous Tomcat configuration and application snapshot.
  - **Operational Risk:** Temporary EHR service interruption.
- **Timeline:** Immediate (24-48h)
- **Owner:** IT
- **Cost Estimate:** $1-10K