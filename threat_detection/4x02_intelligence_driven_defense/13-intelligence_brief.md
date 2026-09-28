# HEALTHBANE Intelligence Brief

**Audience:** Dr. Patricia Morales and MedDefense Health Systems Board  
**Assessment date:** 2026-09-28  
**Working campaign name:** HEALTHBANE (HC3 designation)  
**Overall assessment:** Confirmed multi-stage healthcare phishing campaign;
MedDefense Stage 1 exposure is confirmed, but MedDefense Stage 2/3 compromise
is not established in the supplied evidence.

## Executive Summary

HEALTHBANE is a coordinated, financially motivated cybercrime campaign targeting US healthcare organizations with lookalike phishing domains, credential harvesting, macro-enabled malware, and DNS-based data exfiltration. MedDefense received three confirmed campaign emails; one nurse clicked the link and credential submission is likely, but the 4x00 investigation did not confirm password capture or attacker authentication. HC3 observed Stage 1 at all six organizations it could see and observed the full malware-to-exfiltration chain at two, while the total campaign target set is at least 14 organizations. At other organizations, stolen credentials enabled follow-up `.docm` emails, PowerShell-based malware, scheduled-task and Registry Run-key persistence, and DNS TXT tunneling of patient and insurance data. MedDefense currently has useful IOC controls and investigative evidence, but most behavior-based endpoint, identity, DNS, and data-access detections remain partial or undeployed. The three highest actions are to complete endpoint and cloud-mail hunts, deploy macro/PowerShell/persistence and DNS-tunneling analytics, and enforce layered phishing controls with MFA and unusual-authentication monitoring. Attribution should remain unconfirmed: HC3 uses HEALTHBANE, Acme uses VITALSCORE, and a researcher proposes APT-MEDAGENT without victim telemetry.

## Adversary Profile

No separate Task 12 artifact is present in the workspace; this profile is
derived from the source assessment, kill-chain analysis, HC3 advisory, and
researcher report.

- **Actor assessment:** HC3 assesses a financially motivated mid-tier
	cybercrime operator with MODERATE confidence, but does not name a group.
- **Operating model:** mass-produced healthcare branding, recently registered
	lookalike domains, PHP credential-harvesting infrastructure, PHPMailer 6.6.0,
	compromised cloud mail, macro delivery, and staged C2 infrastructure.
- **Possible aliases:** Acme uses `VITALSCORE`; the researcher uses
	`APT-MEDAGENT` at MEDIUM confidence based on tooling and infrastructure
	overlap. Neither label is confirmed.
- **Confidence:** HIGH for the campaign pattern and primary indicators;
	LOW for named-actor attribution.
- **Defensive implication:** behavior and infrastructure-pattern detections
	should supplement short-lived domain/IP blocking.

## Campaign Analysis

### Timeline

| Window | Event | Confidence |
|---|---|---|
| 2026-03-02 to 2026-04-12 | Possible prior Acme infrastructure and phishing-domain activity. | LOW; historical context only. |
| 2026-04-14 | Earliest confirmed HEALTHBANE activity; MedDefense nurse clicked at 15:02:33 UTC and likely submitted credentials at 15:02:58. | HIGH for click; MEDIUM for submission. |
| 2026-04-14 to 2026-04-16 | Stage 1 phishing primary window; HC3 observed it at all 6 visible organizations. | HIGH. |
| 2026-04-16 to 2026-04-22 | Stage 2 credential-enabled follow-up emails and macro malware delivery. | HIGH campaign-wide; not confirmed at MedDefense. |
| 2026-04-23 to 2026-04-26 | Stage 3 DNS TXT exfiltration of patient and insurance data at two visible organizations. | HIGH campaign-wide; MedDefense impact unknown. |
| 2026-04-26 | Most recent reported activity date in the supplied intelligence. | HIGH as a reporting boundary, not proof of continued activity. |

### Stage 1: Credential Harvesting

The operator sent healthcare-themed spearphishing links from lookalike domains
to staff, billing, insurance, and benefits recipients. Landing pages used a
PHP form handler and PHPMailer 6.6.0; domains were typically registered 4-10
days before use. MedDefense confirmed three campaign emails, three sender
addresses, failed or missing email authentication on the primary lures, one
user click, and a 47-second HTTPS session. HC3 reports Stage 1 at 6/6 visible
organizations, but the total number of successful submissions is unknown.

### Stage 2: Malware Delivery

HC3 reports that stolen credentials were used to access cloud email and send
trusted-looking follow-up messages containing `HEALTHBANE_S2_invoice.docm`.
The macro retrieved `svchost_update.exe` from
`healthbane-c2.net/update/svchost_update.exe`, with PowerShell tooling and
persistence through `HealthSync Update Service` and a Registry Run key. HC3
observed this stage at 2/6 visible organizations; MedDefense's 4x00 EDR scan
found no matching Stage 2 hash, so local execution is not established.

### Stage 3: Data Exfiltration

The RAT encoded patient records and insurance claims into 44-60 character,
base32-like labels in DNS TXT queries to `data-sync.healthbane-c2.net` at
10-15 second intervals. HC3's packet captures confirm the behavior at two
organizations, and Acme corroborates the DNS-tunnel domain. The exact affected
organizations, fields, volume, and any MedDefense data transfer remain
unknown.

## ATT&CK Mapping

The Navigator layer contains 20 techniques: 18 **OBSERVED** by HC3 or directly
supported by evidence, and 2 **INFERRED** because HC3 assesses Valid Accounts
and Remote Services as likely but excludes them from its observed table.

| Classification | Techniques | Detection relevance |
|---|---|---|
| OBSERVED | T1589.002, T1583.001, T1585.002, T1587.001, T1608.005 | Reconnaissance and resource-development patterns support pre-delivery email and domain analytics. |
| OBSERVED | T1566.002, T1566.001, T1204.001, T1204.002, T1059.005, T1059.001 | Prioritize link/attachment controls, macro-to-PowerShell telemetry, and user-action correlation. |
| OBSERVED | T1053.005, T1547.001, T1056.003 | Hunt task creation, Run keys, and credential-capture workflows. |
| OBSERVED | T1071.004, T1071.001, T1048.003, T1041 | Detect DNS TXT tunneling, periodic web C2, encoded labels, and sensitive-data egress. |
| INFERRED | T1078, T1021 | Validate cloud-mail credential use and RDP/SMB lateral movement with identity and Windows logs. |

## Detection Gap Assessment

Current documented coverage is 1 technique DETECTED, 17 PARTIALLY DETECTED,
and 2 NOT DETECTED. The two Priority 1 gaps are observed email-identity
reconnaissance (T1589.002) and VBA execution (T1059.005). There are no
inferred techniques with zero documented coverage, but Valid Accounts and
Remote Services remain important validation gaps. Priority 3 work should close
partial coverage for newly registered domains, external `.docm` attachments,
PowerShell, scheduled tasks, Run keys, cloud-mail anomalies, web beacons, DNS
TXT tunneling, and RDP/SMB correlation.

The existing Wazuh rules 100080-100082 and IOC lists should remain active, but
they are not sufficient against domain rotation, authenticated lookalikes,
renamed malware, or stolen cloud credentials. The recommended implementation
order is: external-document/macro analytics, identity and cloud-mail
correlation, endpoint persistence and PowerShell analytics, then DNS and web
beacon analytics tied to sensitive-data access.

## Indicator of Compromise Table

Task 5 is not present as a separate file; this table consolidates the HC3,
MedDefense, researcher, and corroborated Acme indicators from Task 0/1. Low-
confidence commercial-only indicators are intentionally omitted from immediate
blocking and remain contextual or noise in the triage output.

| Attack phase | Type | Indicator | Confidence | Recommended action |
|---|---|---|---|---|
| Stage 1 | Domain | `meddefense-portal.com` | HIGH | Block/sinkhole; alert on email, DNS, and web access. |
| Stage 1 | Domain | `medequip-supplies.net` | HIGH | Block/sinkhole; alert on email and web access. |
| Stage 1 | Domain | `meddefense-benefits.org` | HIGH | Block/sinkhole; alert on email and web access. |
| Stage 1 | Domain | `outlook-protection.com` | HIGH | Block/alert; inspect authenticated lookalike mail because SPF/DKIM can pass. |
| Stage 1 | IP | `91.234.99.107` | HIGH | Block egress and correlate with phishing email telemetry. |
| Stage 1 | IP | `185.176.43.22` | HIGH | Block egress and correlate with phishing email telemetry. |
| Stage 1 | IP | `164.90.218.73` | HIGH | Block egress and correlate with phishing email telemetry. |
| Stage 1 | IP | `51.38.42.17` | HIGH | Block/alert; retain source provenance. |
| Stage 1 | URL | `https://meddefense-portal.com/verify/staff` | HIGH | Block and hunt for clicks/form interaction. |
| Stage 1 | URL | `https://medequip-supplies.net/invoices/pay` | HIGH | Block and hunt for clicks/form interaction. |
| Stage 1 | URL | `https://meddefense-benefits.org/enroll` | HIGH | Block and hunt for clicks/form interaction. |
| Stage 1 | Email | `noreply@meddefense-portal.com`; `invoices@medequip-supplies.net`; `hr-notifications@meddefense-benefits.org` | HIGH | Mail-block and search historical messages. |
| Stage 1 | Hash | `2f4a6c8e...d1f` (lure PDF) | MEDIUM | EDR/mail scan; do not rely on hash alone. |
| Stage 2 | Domain | `healthbane-c2.net` | HIGH | Block/sinkhole and hunt DNS/HTTPS. |
| Stage 2 | Domain | `update-healthbane.net` | MEDIUM | Monitor and block with corroboration; hunt for downloads. |
| Stage 2/3 | IP | `51.38.42.191` | HIGH | Block/alert; correlate C2 and DNS activity. |
| Stage 2 | IP | `45.77.218.9` | MEDIUM | Monitor/block with validation; not independently corroborated by all sources. |
| Stage 2 | URL | `https://healthbane-c2.net/update/svchost_update.exe` | HIGH | Block and hunt endpoint/process telemetry. |
| Stage 2 | Hash | `a1b2c3d4...3456` (DOCM) | HIGH | EDR/mail block; search attachment history. |
| Stage 2 | Hash | `b9c8a7d6...7654` (executable) | HIGH | EDR block and hunt process execution. |
| Stage 2 | Hash | `c7d6e5f4...c5d6` (PowerShell) | HIGH | EDR block and hunt PowerShell ancestry. |
| Stage 2 | Hash | `dd5efb6d...5678` (dropper variant) | MEDIUM | Monitor and scan; validate before broad enforcement. |
| Stage 3 | Domain | `data-sync.healthbane-c2.net` | HIGH | Block/sinkhole and deploy DNS TXT-tunnel analytics. |
| Stage 3 | URL | `https://healthbane-c2.net/api/ingest` | MEDIUM | Hunt and monitor; configuration-derived, not packet-confirmed. |

The strict source ledger contains additional Acme-only shared-hosting, CDN,
sinkholed, and ML-clustered items. They should remain contextual/noise rather
than automatic block rules until independently validated.

## YARA Rule Summary

### Rules developed

- `HEALTHBANE_PDF_Credential_Harvesting` in `9-yara_phishing_pdf.yar`:
	requires PDF magic, `wkhtmltopdf`, and multiple credential-path or parameter
	indicators.
- `HEALTHBANE_Email_Headers` in `10-yara_arsenal.yar`: detects PHPMailer
	version or custom-build headers, priority/urgency, healthcare lure language,
	and lookalike sender domains.
- `HEALTHBANE_Document_Metadata` in `10-yara_arsenal.yar`: detects PDF tooling,
	credential paths/parameters, and healthcare lure metadata.
- `HEALTHBANE_Campaign_Composite` in `10-yara_arsenal.yar`: combines email or
	document evidence families for stronger campaign-level matches.

### Test results and deployment status

The manifest defines 2 PDF true positives, 2 PDF true negatives, 3 malicious
email true positives, and 1 benign email true negative. The known email variant
`healthbane_email_03.eml` uses `PHPMailer 6.6.0 (custom build)`; the arsenal
was tuned to accept that variant without matching the benign MailChimp sample.
`11-yara_testing.sh` is the offline test harness and calculates TP, TN, FP, FN,
detection rate, false-positive rate, and precision, but no completed YARA run
was recorded in the supplied workspace because YARA execution was unavailable
or skipped. Deployment status is therefore **MONITOR / VALIDATE LOCALLY**, not
production DEPLOY, until the harness runs successfully and the sample results
are recorded.

## Recommendations

### Immediate: next 48 hours

1. Preserve 90 days of email, cloud-mail, DNS, proxy, EDR, identity, firewall,
	 and server logs; retain original messages and relevant endpoint evidence.
2. Run endpoint and cloud-mail hunts for the five HC3 hashes, `.docm` files,
	 macro-to-PowerShell chains, `HealthSync Update Service`, Run-key changes,
	 unusual mailbox sends, and logins after the MedDefense click.
3. Block the corroborated Stage 1/2/3 domains, IPs, URLs, and hashes while
	 excluding shared/CDN/cloud noise; reset potentially exposed credentials and
	 verify MFA coverage.

### Short-term: next 2 weeks

1. Deploy external `.docm` quarantine/sandboxing, Office macro telemetry,
	 PowerShell Script Block/AMSI collection, scheduled-task and Run-key alerts.
2. Expand Wazuh/identity rules from the single `dmarsh` case to all users,
	 cloud-mail sessions, unusual geography/ASN, new devices, and mailbox abuse.
3. Implement DNS label length/entropy/TXT-frequency analytics and web beacon
	 detection with allowlists and first-seen domain enrichment.
4. Run and document the YARA harness against the complete sample corpus, then
	 publish only validated rules to the endpoint/mail pipeline.

### Medium-term: next 30 days

1. Build integrated email, identity, endpoint, DNS, proxy, and sensitive-data
	 access correlation in the SOC workflow.
2. Establish role-aware RDP/SMB baselines and alert on clinical workstation
	 access to protected servers with successful Windows-logon correlation.
3. Enforce DMARC alignment, MFA for remote access, macro policy, attachment
	 controls, and newly registered-domain review.
4. Create a maintained campaign ledger with indicator provenance, confidence,
	 first/last seen, action, and false-positive disposition.

## Intelligence Gaps and Collection Priorities

| Unknown | Collection that would answer it | Owner / request |
|---|---|---|
| Was `dmarsh`'s password submitted and accepted? | Browser history, proxy/TLS metadata, packet capture, phishing-server logs, identity-provider events, and password-reset records. | SOC, network, IAM; request from the 4x01 investigation and identity provider. |
| Did an attacker use MedDefense credentials or send follow-up `.docm` mail? | Cloud-mail sign-in, mailbox audit, sent-item, OAuth/session, and attachment logs for 2026-04-14 through 2026-04-22. | IAM and messaging administrators. |
| Did any MedDefense endpoint execute Stage 2 malware? | EDR process trees, file inventory, Office telemetry, AMSI, PowerShell logs, scheduled-task events, Run-key telemetry, and hash/variant scans. | Endpoint engineering and SOC. |
| Was MedDefense among the two organizations with Stage 3 activity? | DNS resolver logs, endpoint DNS/process telemetry, egress/firewall data, file/database access logs, and affected-host correlation. | Network SOC, data protection, database/server owners. |
| What patient or insurance data, if any, was exposed? | Database/application audit, file access, DLP, DNS volume, destination responses, and business-record reconciliation. | Privacy, compliance, application owners, incident response. |
| Who operates the campaign? | Independent victim telemetry, infrastructure ownership records, kit reuse across validated incidents, and HC3/commercial-source coordination. | Threat intelligence lead; coordinate with HC3 and treat external labels as hypotheses. |
| Which Acme-only indicators are real versus noise? | Local DNS/proxy/EDR sightings, passive-DNS history, provider ownership, sandboxing, and shared-hosting validation. | Threat intelligence and network security; do not block from clustering alone. |
| Why do the lab totals reference 64 unique indicators while the strict visible ledger has 48? | Obtain the authoritative Task 5 indicator ledger or source exports and document its normalization rule. | Course/lab owner or intelligence-intake maintainer. |

## Decision posture

MedDefense should treat the Stage 1 exposure as a confirmed incident requiring
continued identity and endpoint validation, while treating Stage 2/3 impact as
an unresolved investigation question. The strongest immediate controls are
corroborated IOC enforcement plus behavior analytics for macro execution,
PowerShell, persistence, unusual authentication, and DNS TXT tunneling. No
named actor should be asserted to the board until independent attribution
evidence exists.
