# The Legacy Systems

## Answer

### Goal
Assess the unique risk profile of end-of-life systems that will never receive another security patch.

### Context
An end-of-life system is not just "another vulnerability." It is a system that is permanently vulnerable. Every CVE disclosed from this point forward that affects this OS version will remain unpatched. Forever. The MRI workstation running Windows XP has accumulated over a decade of unpatched critical vulnerabilities. The question is not whether it is vulnerable. The question is how many ways.

## Answer

# End-of-Life (EOL) Systems Assessment

## Summary

| System | Approx. Critical CVEs (Last 2 Years, NVD) | Highest Priority |
|---|---:|---|
| Windows XP SP3 (MRI Workstation) | 0 (No new XP-specific CVEs; OS unsupported since 2014) | Critical |
| Windows Server 2012 R2 (Print Server) | 100+ affecting supported components/products after EOL | Medium |
| Ubuntu 18.04 LTS (No ESM) | 500+ affecting packages included in Ubuntu 18.04 | High |

> **Note:** Because Windows XP has been unsupported for over a decade, the NVD no longer publishes new Windows XP-specific CVEs. The risk comes from permanently unpatched legacy vulnerabilities.

---

# System 1 – Windows XP SP3 (10.10.1.70 – MRI Workstation)

## EOL Research

**Approximate Results (last 2 years):** 0 Windows XP-specific CVEs

Most critical vulnerabilities still affecting the system:

- **CVE-2019-0708 (BlueKeep)** – CVSS 9.8
- **CVE-2008-4250 (MS08-067)** – CVSS 10.0

## Permanent Exposure

End-of-life differs from simply being unpatched because **the vendor permanently stops producing security updates**. Even if every available patch is installed, newly discovered vulnerabilities will never be fixed, making the system permanently vulnerable unless it is replaced.

## Scan Findings

| Finding | Description |
|---|---|
| 004 | Windows XP End-of-Life |
| 016 | Medical device web interfaces exposed |
| 024 | DICOM traffic unencrypted |
| GAP-003 | Legacy MRI workstation on flat network |

**Exploitable because EOL?**

Yes.

The legacy OS is the reason BlueKeep, EternalBlue and MS08-067 remain exploitable. A supported operating system would have received security updates years ago.

## Compensating Controls

From GAP-003 / Task 6:

- Network segmentation
- Dedicated VLAN
- IDS monitoring
- Strict access control
- Physical security

**Are they sufficient?**

No.

They reduce exposure but do not remove the underlying vulnerability.

Additional recommendations:

- Replace the workstation with a supported platform.
- Remove SMB/RDP if not required.
- Allowlist only required communications.
- Continuous monitoring for abnormal traffic.

---

# System 2 – Windows Server 2012 R2 (10.10.2.31 – Print Server)

## EOL Research

**Approximate Results (last 2 years):** 100+

Examples:

- CVE-2024-38080 (Windows TCP/IP RCE)
- CVE-2024-30080 (Windows Hyper-V privilege escalation)

*(Many later Windows vulnerabilities also affect Server 2012 R2 but no longer receive standard support.)*

## Permanent Exposure

After EOL, Microsoft no longer provides normal security patches. Every newly discovered vulnerability accumulates over time, steadily increasing attack surface until the system is upgraded or isolated.

## Scan Findings

| Finding | Description |
|---|---|
| 008 | Windows Server 2012 R2 End-of-Life |
| PrintNightmare | CVE-2021-34527 |

**Exploitable because EOL?**

Partially.

PrintNightmare is already known, but future Windows vulnerabilities affecting this platform will remain permanently unpatched.

## Compensating Controls

Current controls:

- Internal network placement
- Basic firewall protection

Additional recommendations:

- Migrate to a supported Windows Server version.
- Disable Print Spooler if unnecessary.
- Restrict printer administration.
- Limit network access to authorized print clients.

---

# System 3 – Ubuntu 18.04 LTS (10.10.2.15 – Billing Server)

## EOL Research

**Approximate Results (last 2 years):** 500+

Examples:

- CVE-2024-1086 (Linux Kernel Privilege Escalation)
- CVE-2024-6387 (OpenSSH "regreSSHion") – CVSS 8.1

Without Ubuntu Pro (ESM), these fixes are not received.

## Permanent Exposure

Unlike a temporarily unpatched system, an unsupported Ubuntu installation receives **no future operating system security fixes**. Every newly discovered kernel or system package vulnerability becomes permanent unless ESM is enabled or the OS is upgraded.

## Scan Findings

| Finding | Description |
|---|---|
| 001 | Apache mod_lua RCE |
| 002 | Apache Privilege Escalation |
| 006 | MySQL exposed |
| 009 | SSH password authentication |
| 011 | Ubuntu 18.04 without ESM |
| 026 | Outdated kernel |

**Exploitable because EOL?**

Yes.

Finding 026 (kernel) and future operating system vulnerabilities remain exploitable because the system is no longer receiving normal security updates.

## Compensating Controls

Current controls (GAP-008):

- Backups
- Endpoint protection
- Existing operational controls

Additional recommendations:

- Upgrade to Ubuntu 22.04/24.04 LTS.
- Enable Ubuntu Pro (ESM) immediately until migration.
- Restrict SSH access.
- Enable key-only authentication.
- Segment the billing server from general user networks.

---

# Business Decision

## Recommended Migration Priority

**Migrate the Windows XP MRI Workstation first.**

### Justification

| Factor | Assessment |
|---|---|
| Asset Criticality | Critical asset supporting patient diagnosis and MRI operations. |
| Threat Exposure | Flat network allows lateral movement; SMB and RDP are exposed with weaponized exploits. |
| Patient Safety | Direct impact on clinical imaging and radiology workflow. |
| Existing Controls | Only compensating controls exist; the underlying risk remains. |
| Attack Matrix | Vulnerable to phishing, VPN compromise, vulnerable software exploitation, insider misuse, and physical access. |

Although the billing server is highly exposed and the print server is unsupported, the **MRI workstation presents the greatest overall business risk** because:

- It supports a **patient-critical clinical workflow**.
- It is protected only by compensating controls (GAP-003).
- It runs an OS that has been unsupported for over 10 years.
- Public, weaponized exploits (BlueKeep, EternalBlue, MS08-067) remain effective.
- Compromise could interrupt patient diagnosis and provide attackers with a foothold into the clinical network.

For these reasons, migrating the MRI workstation provides the largest reduction in operational and cybersecurity risk within the available budget.