# The Priority Matrix

## Introduction

### Goal
Produce the definitive vulnerability remediation timeline organized by urgency.

### Context
This is the document that goes on the IT Director's desk Monday morning. It tells her: fix this today, this by Friday, this by month-end and this by quarter-end. No ambiguity. No "it depends." Clear actions, clear timelines, clear owners.

## Answer

# Priority Remediation Matrix

| Horizon | Timeline | Finding | Description | Remediation Action | Owner | Cost |
|----------|----------|---------|-------------|--------------------|-------|------|
| **Immediate** | 24–48h | **F001** | Apache mod_lua RCE (billing-srv-01) | Upgrade Apache to ≥2.4.52 | IT | $0–1K |
| Immediate | 24–48h | **F002** | Apache privilege escalation | Upgrade Apache (same maintenance window as F001) | IT | $0–1K |
| Immediate | 24–48h | **F003** | PostgreSQL accessible from entire network | Restrict `pg_hba.conf` and apply host firewall rules | IT / DBA | $0–1K |
| Immediate | 24–48h | **F007** | LDAP signing disabled + SMBv1 enabled | Enable LDAP signing and disable SMBv1 | IT | $0–1K |
| Immediate | 24–48h | **F031** | Ghostcat (Tomcat AJP) on EHR server | Patch Tomcat and disable AJP if unused | IT | $1–10K |
| **Short-term** | 7 days | **F005** | TLS 1.0 enabled on patient portal | Disable TLS 1.0/1.1 and enable modern TLS | IT | $0–1K |
| Short-term | 7 days | **F006** | MySQL bound to all interfaces | Restrict bind address and firewall access | IT / DBA | $0–1K |
| Short-term | 7 days | **F009** | SSH password authentication enabled | Enforce SSH key-only authentication | IT | $0–1K |
| Short-term | 7 days | **F012** | Missing HTTP security headers | Configure recommended security headers | IT | $0–1K |
| Short-term | 7 days | **F021** | HTTP TRACE enabled | Disable TRACE method | IT | $0–1K |
| **Medium-term** | 30 days | **F010** | BD Alaris firmware/default credentials | Change credentials and isolate medical VLAN | Clinical / Vendor | $1–10K |
| Medium-term | 30 days | **F013** | Portal certificate expires soon | Configure automatic certificate renewal | IT | $0–1K |
| Medium-term | 30 days | **F015** | Synology DSM exposed internally | Restrict management interface to admin IPs | IT | $0–1K |
| Medium-term | 30 days | **F016** | Philips monitor web interfaces exposed | Restrict access with VLANs and firewall ACLs | IT / Clinical | $1–10K |
| Medium-term | 30 days | **F018** | Weak Kerberos encryption | Disable DES/RC4, enforce AES | IT | $0–1K |
| Medium-term | 30 days | **F019** | Excessive RDP exposure | Limit RDP to authorized admins only | IT | $0–1K |
| Medium-term | 30 days | **F023** | USB storage unrestricted | Deploy USB restriction GPO | IT | $1–10K |
| Medium-term | 30 days | **F024** | Unencrypted DICOM communications | Enable DICOM TLS where supported | IT / Vendor | $10–50K |
| Medium-term | 30 days | **F025** | DNS zone transfer enabled | Restrict AXFR to authorized DNS servers | IT | $0–1K |
| **Long-term** | 90 days | **F004** | Windows XP MRI workstation (EOL) | Replace system or redesign isolated architecture | Clinical / Vendor | $50K+ |
| Long-term | 90 days | **F008** | Windows Server 2012 R2 (EOL) | Migrate to supported Windows Server | IT | $10–50K |
| Long-term | 90 days | **F011** | Ubuntu 18.04 without ESM | Upgrade to Ubuntu 22.04 LTS or enable Ubuntu Pro ESM | IT | $1–10K |
| Long-term | 90 days | **F014** | Consumer Netgear router | Replace with enterprise-grade firewall/router | IT | $10–50K |

---

# Budget Summary

- **Estimated Total Cost:** **~$100K–210K**
- **Annual Security Budget (1x00):** **$120K**
- **Assessment:** The remediation program is likely to exceed the annual budget if all long-term projects are completed in the same fiscal year.
- **Deferred Items:** MRI workstation replacement (F004), Netgear replacement (F014), and Windows Server 2012 migration (F008) should be deferred if necessary because they require significant capital expenditure and vendor coordination, while immediate patching and configuration changes provide the greatest short-term risk reduction.