# The Medical IoT

## Introduction

### Goal
Assess vulnerabilities in connected medical devices with specific attention to patient safety implications.

### Context
A vulnerability on a workstation and a vulnerability on an infusion pump are not the same category of problem. One can steal data. The other can affect dosing. The scan report found findings on both Philips monitors and BD Alaris pumps. The BD bulletin is real. The risk is real.

## Answer

# Medical IoT Security Assessment

## 1. BD Alaris Assessment

**Affected Findings:**  
- Finding 010 — BD Alaris Infusion Pumps  
- CVE: CVE-2020-25165  
- Firmware detected: 12.1.2

## Vulnerability

CVE-2020-25165 affects BD Alaris PC Unit / Systems Manager network session authentication. An attacker on the network may establish an unauthorized network session between affected components. :contentReference[oaicite:0]{index=0}

## Vendor Mitigation

BD recommends:
- Update Alaris PC Unit software to a fixed version (12.1.1 or newer where available).
- Apply network isolation.
- Restrict device communication using ACLs.
- Limit access to required systems only. :contentReference[oaicite:1]{index=1}

## MedDefense Status

**Not implemented.**

Evidence from scan:
- Pumps remain on the flat network.
- Web management interfaces are reachable.
- Default credentials remain active on 7/7 pumps.

## Risk

High.

An attacker with internal network access could:
- Access pump management interfaces.
- Exploit device weaknesses.
- Disrupt infusion pump availability.

---

# 2. Philips IntelliVue Assessment

**Affected Finding:**  
- Finding 016 — Philips IntelliVue monitors  
- Hosts: 10.10.3.10-32

## Exposed Interfaces

| Interface | Purpose | Risk |
|---|---|---|
| Web management interface | Device administration | Unauthorized configuration access |
| HL7 port 2575 | Clinical data exchange | Patient data exposure |

Philips IntelliVue systems exchange patient monitoring information, including physiological data, alarms, waveforms, and clinical measurements. HL7 is used for exchanging clinical information with hospital systems. :contentReference[oaicite:2]{index=2}

## Attacker Capabilities

With network access, an attacker could potentially:

- View patient monitoring data.
- Identify patients and clinical status.
- Access device management interfaces.
- Attempt unauthorized configuration changes.
- Disrupt monitoring availability.

## Main Issue

The primary weakness is not a confirmed software vulnerability but **excessive network exposure**:
- Interfaces accessible across the flat network.
- No strong network isolation.
- Reliance on network trust.

---

# 3. Patient Safety Dimension

Medical device vulnerabilities are different because they can directly affect patient care, not only confidentiality or business operations. A compromised workstation may expose data or disrupt workflows, but a compromised infusion pump could alter medication delivery and create immediate patient harm. A compromised MRI or monitoring device could delay diagnosis or provide incorrect clinical information. The consequence can therefore move from a cybersecurity incident to a patient safety incident.

---

# 4. Why Medical Device Patching Is Harder

| Factor | Explanation |
|---|---|
| Regulatory constraints | Medical devices require validated changes; firmware updates may require regulatory approval. |
| Operational impact | Devices cannot always be taken offline because they support active patient care. |
| Vendor dependency | Hospitals often depend on manufacturers for approved firmware and update procedures. |
| Legacy lifecycle | Devices may remain deployed for many years beyond normal IT lifecycles. |
| Testing requirements | Updates must be tested with clinical workflows before deployment. |

## Conclusion

Medical IoT risk requires a combination of:
- Vendor-approved patching,
- Network segmentation,
- Strong access control,
- Device monitoring.

For MedDefense, segmentation is the immediate priority because many medical devices cannot be rapidly patched without operational and regulatory constraints.