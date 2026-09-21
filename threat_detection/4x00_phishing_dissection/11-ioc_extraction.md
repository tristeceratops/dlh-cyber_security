# IOC Report — MedDefense Phishing Campaign

## 1. Structured IOC Table

| Phase | IOC Type | IOC Value | Source | Context | Confidence | Action |
|---|---|---|---|---|---|---|
| Delivery | Domain | `meddefense-portal[.]com` | E2 | MedDefense lookalike phishing domain | HIGH | Block |
| Delivery | IP | `91[.]234[.]99[.]107` | E2 | Sending IP for E2 | HIGH | Block/Alert |
| Delivery | Email | `noreply@meddefense-portal[.]com` | E2 | Fake MedDefense IT sender | HIGH | Block |
| Credential Harvesting | URL | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | E2 | Recipient-specific credential-verification link | HIGH | Block |
| Credential Harvesting | Domain | `outlook-protection[.]com` | E3 | Microsoft impersonation domain | HIGH | Block |
| Delivery | IP | `51[.]38[.]42[.]17` | E3 | Sending IP for E3 | HIGH | Block/Alert |
| Delivery | Email | `security@outlook-protection[.]com` | E3 | Fake Microsoft security sender | HIGH | Block |
| Credential Harvesting | URL | `hxxps://outlook-protection[.]com/verify` | E3 | External account-verification page | HIGH | Block |
| Delivery | Domain | `medequip-supplies[.]net` | E5 | Supplier/payment phishing domain | HIGH | Block |
| Delivery | IP | `185[.]176[.]43[.]22` | E5 | Sending IP for E5 | HIGH | Block/Alert |
| Delivery | Email | `invoices@medequip-supplies[.]net` | E5 | Fake supplier invoice sender | HIGH | Block |
| Credential Harvesting | URL | `hxxps://medequip-supplies[.]net/[path-not-preserved]` | E5 | External payment/login destination; exact path unavailable | MEDIUM | Monitor |
| Attachment/Lure | File hash | Not available | E5 | Attachment referenced but hash not present in supplied evidence | LOW | Context only |
| Attachment/Lure | PDF URL | Not available | E5 | Embedded PDF URL not present in supplied evidence | LOW | Context only |
| Delivery | Domain | `meddefense-benefits[.]org` | E7 | MedDefense benefits/HR lookalike domain | HIGH | Block |
| Delivery | IP | `164[.]90[.]218[.]73` | E7 | Sending IP for E7 | HIGH | Block/Alert |
| Delivery | Email | `hr-notifications@meddefense-benefits[.]org` | E7 | Fake HR/Benefits sender | HIGH | Block |
| Credential Harvesting | URL | `hxxps://meddefense-benefits[.]org/enroll` | E7 | External benefits enrollment portal | HIGH | Block |
| Infrastructure | Tool | `PHPMailer 6.6.0` | E2/E3/E5/E7 | Common mail-generation tooling | MEDIUM | Monitor |
| Infrastructure | Pattern | SPF fail/softfail + DKIM none + DMARC fail | E2/E5/E7 | Shared authentication weakness | MEDIUM | Alert/Correlate |
| Infrastructure | IP set | `91[.]234[.]99[.]107`, `51[.]38[.]42[.]17`, `185[.]176[.]43[.]22`, `164[.]90[.]218[.]73` | E2/E3/E5/E7 | Four distinct sending IPs; no shared IP established | MEDIUM | Monitor |
| Context | Domain | `meddefense[.]com` | E2/E4/E7 | Legitimate MedDefense domain being impersonated | LOW | Context only |
| Context | Domain | `microsoft[.]com`, `outlook[.]com` | E3 | Legitimate Microsoft domains used for comparison | LOW | Context only |
| Context | Domain/Email | `hhs[.]gov` / `HC3@hhs[.]gov` | E8 | Legitimate HC3 advisory | LOW | Context only |
| Context | Pattern | Healthcare-sector phishing | E8 | HC3 reports active phishing targeting healthcare | HIGH | Alert/Correlate |

> **Evidence limitation:** The E5 attachment hash and embedded PDF URL are not present in the supplied evidence and should be extracted from the original message before distribution as confirmed IOCs.

## 2. IOC Categorization

### Delivery

The primary delivery indicators are the four phishing domains, their associated sender addresses, and observed sending IPs:

- `meddefense-portal[.]com`
- `outlook-protection[.]com`
- `medequip-supplies[.]net`
- `meddefense-benefits[.]org`
- `91[.]234[.]99[.]107`
- `51[.]38[.]42[.]17`
- `185[.]176[.]43[.]22`
- `164[.]90[.]218[.]73`

### Credential Harvesting

Confirmed malicious destinations:

- `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
- `hxxps://outlook-protection[.]com/verify`
- `hxxps://meddefense-benefits[.]org/enroll`

The E5 payment/login URL should be added once its exact value is recovered.

### Attachment / Lure Artifact

E5 is associated with an attachment/PDF lure, but the supplied evidence does not contain its SHA-256 hash or embedded URL. These should be extracted offline from the original message and added only after verification.

### Infrastructure

`PHPMailer 6.6.0` appears in E2, E3, E5, and E7. The repeated tooling and authentication weaknesses are useful campaign-correlation indicators, but PHPMailer is legitimate software and is therefore **not a standalone block indicator**.

### Context-Only Indicators

Do not block the legitimate domains `meddefense[.]com`, `microsoft[.]com`, `outlook[.]com`, or `hhs[.]gov`. Generic terms such as `verify`, `invoice`, `enroll`, or `security` are also unsuitable as standalone IOCs.

## 3. IOC Quality

### High-Confidence / Block

- Four phishing domains
- Confirmed phishing URLs
- Associated phishing sender addresses
- Sending IPs when correlated with the corresponding phishing activity

These indicators are directly tied to observed malicious messages.

### Medium-Confidence / Monitor

- `PHPMailer 6.6.0`
- PHP-generated mail patterns
- SPF/DKIM/DMARC failure combinations
- Individual IP addresses without supporting correlation
- Future hosting/registrar relationships

These are useful for detection and threat hunting but may produce false positives if used alone.

### Low-Confidence / Context Only

- Legitimate MedDefense, Microsoft, Outlook, and HHS domains
- Generic phishing terminology
- Common mail software
- Shared hosting/registrar information without additional evidence

These should not be used as standalone blocking indicators.

## 4. Defensive Use

**Mail security:** block the four confirmed phishing domains and associated sender addresses.

**DNS/Web security:** block confirmed phishing domains and URLs; investigate through passive or sandboxed methods rather than directly visiting them.

**SIEM/EDR:** hunt for DNS requests, web connections, emails, and authentication activity involving the confirmed domains/IPs. Correlate `PHPMailer 6.6.0` with suspicious external domains rather than blocking it independently.

**Threat hunting:** search historical telemetry for all four domains, four IPs, sender addresses, and similar E2/E5/E7 business-process lures.

## 5. HC3-Ready Summary

**Campaign:** Healthcare-sector phishing targeting multiple MedDefense functions.

**Domains:**  
`meddefense-portal[.]com` | `outlook-protection[.]com` | `medequip-supplies[.]net` | `meddefense-benefits[.]org`

**IPs:**  
`91[.]234[.]99[.]107` | `51[.]38[.]42[.]17` | `185[.]176[.]43[.]22` | `164[.]90[.]218[.]73`

**Senders:**  
`noreply@meddefense-portal[.]com` | `security@outlook-protection[.]com` | `invoices@medequip-supplies[.]net` | `hr-notifications@meddefense-benefits[.]org`

**URLs:**  
`hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`  
`hxxps://outlook-protection[.]com/verify`  
`hxxps://meddefense-benefits[.]org/enroll`

**Pattern:** Lookalike domains, role-specific healthcare lures, urgency, external credential/payment actions, PHPMailer 6.6.0, and weak sender authentication.

**HC3 correlation:** Email 8 independently identifies active healthcare-sector phishing using patterns consistent with the observed MedDefense activity. It provides campaign context but does not prove common actor attribution.