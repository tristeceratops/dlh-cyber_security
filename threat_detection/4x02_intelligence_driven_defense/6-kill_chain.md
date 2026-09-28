# HEALTHBANE Kill Chain

## Scope and evidence rule

This timeline separates campaign-wide observations from MedDefense-specific
evidence. `Confirmed` means a source directly observed or reported the fact;
`corroborated` means another source independently supports it; `inferred` means
the behavior is a reasoned interpretation; and `unknown` means the supplied
materials cannot establish it. The campaign name HEALTHBANE is used because it
is the HC3 designation. VITALSCORE and APT-MEDAGENT are retained only as
source-specific labels, not as confirmed attribution.

## Campaign timeline

| Date or window | Event | Evidence and scope |
|---|---|---|
| 2026-03-02 | Earliest date attached to a possible related infrastructure item: Acme first saw `159.89.112.45`. | **Possible historical context only.** Acme says the IP is shared DigitalOcean infrastructure and does not establish HEALTHBANE activity. |
| 2026-03-28 to 2026-04-12 | Possible prior phishing-domain activity, including `rx-benefits-portal.com` and `healthcare-login.com`. | **Low-confidence Acme context.** These items predate the confirmed campaign window and are not independently corroborated. |
| 2026-04-14 | Earliest confirmed HEALTHBANE activity reported by HC3; MedDefense nurse clicked the Stage 1 link at 15:02:33 UTC and likely submitted credentials at 15:02:58. | HC3 identifies 2026-04-14 as first reported activity. MedDefense directly records the click and supporting HTTPS/user evidence, but submission was not packet-confirmed at 4x00 close. |
| 2026-04-14 to 2026-04-16 | HC3 Stage 1 primary window; three MedDefense phishing emails were investigated. | HC3 observed Stage 1 at all 6 visible organizations. MedDefense identified E2, E5, and E7; one user clicked. |
| 2026-04-14 to 2026-04-26 | HC3 reporting/observation window for the campaign. | HC3 advisory published 2026-04-25 and describes activity through 2026-04-26; its source material includes partner telemetry and sensor data. |
| 2026-04-16 to 2026-04-22 | Stage 2 malware delivery. | HC3 observed stolen credentials used to access cloud email, followed by internal-looking `.docm` messages and macro-driven download activity at 2 of 6 visible organizations. |
| 2026-04-23 to 2026-04-26 | Stage 3 DNS exfiltration. | HC3 reports packet captures from 2 organizations showing patient and insurance data sent through DNS TXT queries. |
| 2026-04-26 | Most recent reported event/date in the supplied materials. | HC3 Stage 3 window ends 2026-04-26; Acme indicator `last_seen` values also extend to 2026-04-26. This is not evidence of ongoing activity after that date. |

### Timeline interpretation

The earliest **confirmed** campaign date is 2026-04-14. The March and early
April Acme items are possible historical or infrastructure context, not a
confirmed HEALTHBANE start. Across HC3's six visible organizations, 6/6
experienced Stage 1 and 2/6 reached the observed Stage 2 and Stage 3 chain.
That is a campaign progression rate of 33% among visible organizations, not a
success rate across all 14 or more targeted organizations. MedDefense observed
one click among three campaign emails; credential submission remained likely,
not confirmed, at the 4x00 reporting boundary.

## Attack phases

### Stage 1: Credential Harvesting

#### Phishing operation

The operation sent healthcare-themed spear-phishing emails using lookalike
domains and landing pages that captured usernames and passwords through an
HTML form. The pages impersonated staff portals, insurance suppliers, HR
benefits, or Microsoft-related services. The researcher recovered a PHP kit
whose handler wrote submitted credentials to `logs/creds.log` and forwarded
them through PHPMailer 6.6.0.

#### Targeting pattern

Confirmed targeting was directed at US healthcare organizations, especially
hospital systems, outpatient clinics, billing services, and insurance
administrators. HC3 saw the strongest signal in the Midwest ISAC region.
Domains used healthcare terms and were registered shortly before use. HC3
reports at least 14 organizations targeted, with full or partner visibility at
6. MedDefense received eight emails for review, three of which were classified
as campaign messages.

#### Infrastructure used

- Lookalike domains: `meddefense-portal.com`, `medequip-supplies.net`,
  `meddefense-benefits.org`, and `outlook-protection.com`.
- Hosting and registration pattern: Namecheap registration with
  Hostinger/DigitalOcean/OVH hosting, as reported by HC3 and the researcher.
- Phishing kit: PHP form handler, target-branded static assets, and
  PHPMailer 6.6.0.
- Confirmed MedDefense endpoint: `/verify/staff` on
  `meddefense-portal.com`, with user and token parameters.

#### Known victims and success rate

HC3 reports Stage 1 at all 6 visible organizations, but does not provide the
full victim list or a credential-submission count. MedDefense identifies three
employees who received campaign emails: `dmarsh` clicked E2, while `arivera`
and `lpatterson` did not click. The available MedDefense evidence supports a
1/3 click rate and a 1/3 likely credential-submission rate for the three
observed campaign messages; it does not establish the operator's overall
phishing success rate.

#### MedDefense evidence

Confirmed: the three domains, three IPs, exact phishing URL, three sender
addresses, PHPMailer header, Namecheap registration pattern, SPF failures,
missing DKIM, and DMARC failures. Confirmed: one user clicked the link.
Assessment: the 47-second HTTPS session and user statement make credential
submission likely. Unknown: packet-level proof of the form POST and any
successful attacker login at the 4x00 close.

#### Stage 1 evidence quality

| Evidence state | Assessment |
|---|---|
| Confirmed | HC3 observed Stage 1 at 6 organizations; MedDefense observed the emails, click, domains, authentication results, and local indicators. |
| Corroborated | The same primary domains and IPs appear in HC3, Acme, the researcher, and/or MedDefense; the kit and PHPMailer pattern connect the infrastructure. |
| Inferred | One coordinated operation, mass-produced target branding, and likely credential submission by `dmarsh`. |
| Unknowns | Exact number of credential submissions, complete victim list, attacker mailbox volume, and whether any submitted MedDefense credentials were used. |

### Stage 2: Malware Delivery

#### Transition from stolen credentials

HC3 reports that credentials harvested in Stage 1 were used to authenticate to
cloud email accounts. The operator then sent follow-up messages from
compromised accounts to colleagues, making the attachment appear more trusted.
This transition is confirmed in two HC3-visible environments, but it is not
confirmed in the MedDefense 4x00 report.

#### Document and malware artifacts

- Document: `HEALTHBANE_S2_invoice.docm`.
- Macro: VBA execution that pulls a Windows executable.
- Executable: `svchost_update.exe`.
- Script: `sync_healthdata.ps1`.
- Variant: a dropper represented by the `dd5efb...` hash.
- ATT&CK techniques reported by HC3 include spearphishing attachment,
  malicious-file execution, VBA, and PowerShell.

#### Download infrastructure and persistence

The primary download URL was
`https://healthbane-c2.net/update/svchost_update.exe`; Acme and HC3 both
report the domain and URL. The executable established a scheduled task named
`HealthSync Update Service` and a Registry Run key. HC3 reports Stage 2 at 2
of 6 visible organizations during 2026-04-16 through 2026-04-22.

#### Evidence source and quality

| Evidence state | Assessment |
|---|---|
| Confirmed | HC3 reports sandbox and organization evidence for the macro, executable, PowerShell, download, scheduled task, and Run key. |
| Corroborated | Acme independently lists the primary hashes, the download URL, and persistence-related tags; the researcher recovered related kit tooling. |
| Inferred | Stolen credentials were the enabling transition and follow-up messages were intended to exploit trust relationships. This is directly reported by HC3 but the mechanism is not evidenced in MedDefense telemetry. |
| Unknowns | Whether any MedDefense mailbox sent a follow-up `.docm`, whether any MedDefense endpoint executed it, and whether the listed hashes cover all variants. MedDefense's 4x00 EDR scan found no matching Stage 2 hash. |

### Stage 3: Data Exfiltration

#### Data targeted

HC3 states that the RAT exfiltrated patient records and insurance claims data.
The material does not identify exact record fields, volume, affected patients,
or whether any MedDefense data left the environment.

#### Protocol and infrastructure

The observed method encoded data in base32-like subdomain labels within DNS
TXT-record queries to `data-sync.healthbane-c2.net`. HC3 observed 44-60
character labels at 10-15 second intervals. TXT responses contained base64-
encoded command strings. HC3 maps the behavior to DNS and exfiltration
techniques; Acme independently tags the domain as DNS tunneling.

#### Evidence source

HC3 reports packet captures from two compromised organizations and rates Stage
3 activity HIGH confidence. The researcher recovered an `EXFIL_ENDPOINT` of
`https://healthbane-c2.net/api/ingest` from kit configuration, which supports
the infrastructure relationship but is not packet evidence of exfiltration.
Acme contributes corroborating domain and tag data without victim telemetry.

#### What is confirmed and unclear

Confirmed: Stage 3 occurred at two HC3-visible organizations, used DNS TXT
queries, targeted patient and insurance data, and involved the HEALTHBANE C2
infrastructure. Unclear: which organizations were affected, whether the RAT
was present at MedDefense, whether MedDefense records were accessed or
exfiltrated, the total volume, and whether the `/api/ingest` URL was active in
the same observed flows.

#### Stage 3 evidence quality

| Evidence state | Assessment |
|---|---|
| Confirmed | HC3 packet captures show the DNS-TXT exfiltration behavior at two organizations. |
| Corroborated | Acme lists `data-sync.healthbane-c2.net` with a DNS-tunneling tag; HC3 and the researcher connect the broader C2 domain to the kit. |
| Inferred | The operator likely reused the same campaign infrastructure across stages and could rotate domains or endpoints. This is an operational inference, not proof of MedDefense impact. |
| Unknowns | MedDefense Stage 3 status, exact data volume and fields, all affected organizations, RAT execution evidence, and complete C2 response content. |

## What is not known

### Attribution gaps

HC3 uses HEALTHBANE and explicitly does not endorse `VITALSCORE`. Acme uses
`VITALSCORE` as a proprietary clustering label. The researcher proposes
APT-MEDAGENT at MEDIUM confidence from tooling and infrastructure overlap.
MedDefense makes no attribution. Shared PHPMailer, registrar, hosting, and kit
patterns support a possible common operator, but they do not establish a named
actor. The missing evidence is independent victim-side or intelligence-source
attribution.

### Missing victim telemetry

HC3 has direct or partner visibility at 6 of at least 14 targets, and the
researcher has no victim telemetry. The supplied MedDefense report covers
Stage 1 and explicitly excludes packet, endpoint, and follow-on authentication
analysis. Consequently, organization-level progression rates cannot be
generalized to all victims.

### Incomplete Stage 3 visibility

Stage 3 is confirmed at only 2 of 6 HC3-visible organizations. The materials
do not identify those organizations or show whether MedDefense is among them.
The 4x00 report predates the Stage 3 window and cannot answer that question.

### Commercial-feed uncertainty

Acme's feed is sampled, not fully human-reviewed, and mixes corroborated
indicators with shared hosting, CDN addresses, sinkholed domains, and weak
ML/keyword clusters. Its confidence scores and VITALSCORE label should not be
treated as independent confirmation. The feed is most useful for candidate
expansion and historical correlation after validation.

### Collection needed to fill the gaps

1. Preserve and correlate email gateway, cloud-mail audit, DNS, proxy, EDR,
	authentication, and firewall logs for at least 90 days, as HC3 recommends.
2. Review packet captures or endpoint/browser telemetry for the MedDefense
	phishing session to confirm the form POST and identify follow-on traffic.
3. Query cloud-mail audit logs for unusual logins, mailbox access, sent
	follow-up messages, and `.docm` attachments between 2026-04-16 and
	2026-04-22.
4. Run endpoint hunts for the five HC3 hashes, the scheduled task name, Run-key
	additions, macro-to-PowerShell chains, and the related download URL.
5. Analyze DNS logs for long base32-like labels, TXT responses, 10-15 second
	periodicity, and queries to `*.healthbane-c2.net` from MedDefense hosts.
6. Obtain an authoritative indicator ledger or source exports to resolve the
	Task 0 discrepancy between the lab's expected 64 unique indicators and the
	strict normalized values visible in the supplied lists.
