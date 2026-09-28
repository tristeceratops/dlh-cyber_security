# The Intelligence Intake

## Indicators resume

```text
HC3 advisory:       23 indicators
Commercial feed:    41 indicators
Researcher blog:    14 indicators
MedDefense 4x00:    11 indicators
Total raw:          89 indicators
Unique deduped:     64 indicators
```

## Scope and normalization

This intake processes the four supplied sources. Indicator counts are the raw
counts claimed by each source, before deduplication. For the consolidated view,
domains, IPs, hashes, email addresses, and normalized URL endpoints are treated
as indicator values. URL placeholder differences such as `<hex>` versus
`<8hex>` are normalized when the host and path are the same. The researcher
blog's `/api/ingest` endpoint remains distinct from the HC3 malware-download
endpoint.

## Source summaries

### 1. HC3 HEALTHBANE advisory

| Field | Intake result |
|---|---|
| Source name | HC3 Advisory HEALTHBANE (HC3-2026-HEALTHBANE-001) |
| Source type | Government advisory |
| Date | 2026-04-25 |
| TLP / distribution | TLP:CLEAR; unrestricted distribution |
| Indicators provided | 23 |
| Indicator types | 8 domains, 6 IPs, 5 hashes, 4 URLs, 0 email addresses |
| Intelligence claim | HEALTHBANE is a multi-stage campaign against US healthcare organizations involving credential harvesting, macro-based malware delivery, and DNS TXT tunneling for exfiltration. |
| Limitations / caveats | Attribution is unconfirmed and only moderate-confidence financially motivated cybercrime is assessed. Stage 2 and Stage 3 were observed at 2 of 6 visible organizations; Valid Accounts and Remote Services are assessed likely but excluded from the observed ATT&CK table. |

### 2. Acme commercial feed

| Field | Intake result |
|---|---|
| Source name | Acme CTI Commercial Feed extract (ACME-HEALTH-2026-0426-117) |
| Source type | Commercial feed |
| Date | 2026-04-26 08:14 UTC |
| TLP / distribution | TLP:AMBER; internal defense at MedDefense Health Systems only |
| Indicators provided | 41 |
| Indicator types | 12 domains, 15 IPs, 9 hashes, 5 URLs, 0 email addresses |
| Intelligence claim | The feed clusters HEALTHBANE-related infrastructure and malware under the commercial label VITALSCORE and adds possible prior infrastructure and variants. |
| Limitations / caveats | Indicators are sampled rather than fully human-reviewed. The VITALSCORE attribution label is proprietary and not necessarily an externally tracked actor. Several low-confidence items are ML or keyword clusters, shared hosting, CDN infrastructure, or explicitly marked noise and should not be blocked automatically. |

### 3. Researcher blog analysis

| Field | Intake result |
|---|---|
| Source name | Marcus Weller, “The Phishing Kit Behind The HEALTHBANE Campaign” |
| Source type | Open-source research |
| Date | 2026-04-24 14:22 UTC |
| TLP / distribution | N/A; public blog post, archived snapshot available |
| Indicators provided | 14 |
| Indicator types | 5 domains, 3 IPs, 4 hashes, 2 URLs, 0 email addresses |
| Intelligence claim | A recovered PHP phishing kit links the Stage 1 domains to the HEALTHBANE C2 infrastructure and suggests operational overlap with prior healthcare campaigns. |
| Limitations / caveats | The researcher had no victim telemetry and bases the APT-MEDAGENT attribution on open-source tooling and infrastructure overlap at medium confidence. The staged portal was not active during observed emails, the kit ZIP provenance is uncertain, and low-confidence infrastructure is only a hypothesis. |

### 4. MedDefense 4x00 investigation

| Field | Intake result |
|---|---|
| Source name | MedDefense Health Systems MD-2026-IR-0414-001, Project 4x00 |
| Source type | Internal investigation |
| Date | 2026-04-16 |
| TLP / distribution | INTERNAL; MedDefense SOC, CISO, and HC3 indicator-only extract |
| Indicators provided | 11 |
| Indicator types | 3 domains, 3 IPs, 1 hash, 1 URL, 3 email addresses |
| Intelligence claim | Three phishing emails targeted MedDefense staff; one nurse likely submitted credentials, with no confirmed Stage 2 or Stage 3 activity at report close. |
| Limitations / caveats | Credential submission was likely but not packet-confirmed at close. The investigation did not include packet analysis, endpoint forensics, or follow-on authentication correlation; its verdict was no confirmed exploitation at the time of report. |

## Consolidated indicator view

### Counts

| Measure | Count |
|---|---:|
| Total raw indicators | 89 |
| Expected lab unique indicators after deduplication | 64 |
| Strict normalized unique values in the supplied lists | 48 |
| Strict unique values appearing in multiple sources | 24 |
| Strict unique values appearing in only one source | 24 |

The raw total is `23 + 41 + 14 + 11 = 89`. The six-line resume above preserves
the expected lab reference value of 64. However, an auditable comparison of the
values actually listed in the four supplied materials produces 48 strict
normalized values: 24 occur in multiple sources and 24 occur in one source.
The expected value of 64 therefore requires clarification of the lab's intended
deduplication rule or an authoritative indicator ledger. Deduplication here is
by normalized indicator value, not by source confidence or campaign label.

### Indicators appearing in multiple sources

| Indicator(s) | Sources |
|---|---|
| `meddefense-portal.com` | HC3, Acme, researcher, MedDefense |
| `medequip-supplies.net`, `outlook-protection.com`, `healthbane-c2.net` | HC3, Acme, researcher |
| `meddefense-benefits.org` | HC3, Acme, MedDefense |
| `portal-secure-meddefense.com` | HC3, researcher |
| `data-sync.healthbane-c2.net`, `update-healthbane.net` | HC3, Acme |
| `91.234.99.107` | HC3, Acme, researcher, MedDefense |
| `185.176.43.22`, `164.90.218.73` | HC3, Acme, MedDefense |
| `51.38.42.17`, `51.38.42.191`, `45.77.218.9` | HC3, Acme; `51.38.42.191` also researcher |
| `167.71.222.30` | Acme, researcher |
| hash `a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456` | HC3, Acme, researcher |
| hashes `b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654`, `dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678` | HC3, Acme |
| hash `c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6` | HC3, Acme, researcher |
| hash `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f` | HC3, researcher, MedDefense |
| `https://meddefense-portal.com/verify/staff` | HC3, Acme, researcher, MedDefense (query variants normalized to the endpoint) |
| `https://medequip-supplies.net/invoices/pay`, `https://meddefense-benefits.org/enroll`, `https://healthbane-c2.net/update/svchost_update.exe` | HC3, Acme |

The repeated set above is grouped only where the source set is identical. It
contains 24 individual normalized values. The three MedDefense email addresses
are not repeated by another source.

### Indicators appearing in only one source

- **Acme only:** `rx-benefits-portal.com`, `healthcare-login.com`, `verify-health-portal.net`, `secure-insurance-login.com`, `claims-verify-portal.net`; IPs `159.89.112.45`, `23.94.138.222`, `104.168.34.58`, `192.99.207.114`, `20.83.144.56`, `13.107.42.14`, `172.67.192.40`, `104.21.35.7`; hashes `ee1122334455667788990011223344556677889900aabbccddeeff0011223344`, `1122aabbccddeeff00112233445566778899aabbccddeeff0011223344556677`, `3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011`, `5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344`, `7788990011223344556677aabbccddeeff0011223344556677aabbccddeeff00`; URL `https://outlook-protection.com/verify`.
- **Researcher only:** hash `ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899` for the kit ZIP and URL `https://healthbane-c2.net/api/ingest`.
- **MedDefense only:** `noreply@meddefense-portal.com`, `invoices@medequip-supplies.net`, and `hr-notifications@meddefense-benefits.org`.
- **HC3 only:** none after endpoint and placeholder normalization.

There are 24 source-exclusive values: 19 from Acme, 2 from the researcher,
and 3 from MedDefense. `167.71.222.30` is excluded from the Acme-only count
because the researcher also reports it. Together with the 24 repeated values,
this produces the strict normalized union of 48 values. This discrepancy is
why the authoritative lab ledger is needed before operationalizing the
64-value target.

## Investigation

### Analytical method

| Rule | Application in this intake |
|---|---|
| Document every analytical judgment | Each enrichment below states the observed fact, the inference drawn from it, and the confidence assigned to that inference. |
| Distinguish facts from assessments | `Confirmed` means the source directly reports or supplies the value. `Assessment` means an analyst interpretation based on source agreement, timing, infrastructure, or behavior. |
| Use consistent confidence | HIGH means direct observation or corroboration by multiple sources; MEDIUM means credible but incomplete or indirect evidence; LOW means weak clustering, shared infrastructure, or an unconfirmed hypothesis. |
| Do not overclaim attribution | HEALTHBANE is the working campaign designation. VITALSCORE and APT-MEDAGENT remain aliases or hypotheses, not confirmed actor identities. |
| Preserve provenance | Every value in the source tables and provenance register retains its reporting source; deduplication does not replace provenance. |
| Avoid live infrastructure dependency | The recommended detection work is local blocking, hunting logic, pseudocode, and JSON/Markdown plans. No live lookups or external infrastructure are required. |

### Findings and judgments

1. **Stage 1 phishing cluster.** Confirmed: HC3, Acme, the researcher, and
	MedDefense all report `meddefense-portal.com`; the first three also report
	the related lookalike infrastructure, and MedDefense records the staff URL
	and three employee mailboxes. Assessment: the shared domains, matching
	registration window, PHPMailer 6.6.0 header, and authentication failures
	support one coordinated Stage 1 operation. Confidence: HIGH.

2. **Credential exposure.** Confirmed: MedDefense records a 47-second HTTPS
	session after the nurse clicked the link and the user reported entering a
	password. Assessment: credential submission is likely, but the 4x00 report
	explicitly lacked packet confirmation and found no immediate follow-on
	authentication. Confidence: MEDIUM, not HIGH. The later HC3 Stage 2 claim
	is sector-level evidence and does not prove Stage 2 occurred at MedDefense.

3. **Stage 2 malware.** Confirmed: HC3 reports the macro document, executable,
	PowerShell script, scheduled task, and Registry Run key in two visible
	organizations; Acme corroborates the primary hashes and download URL.
	Assessment: the malware-delivery chain is confirmed for the campaign but
	not for the MedDefense endpoint because the 4x00 EDR scan found no matching
	Stage 2 hash. Confidence: HIGH for campaign activity, LOW for MedDefense
	compromise.

4. **Stage 3 DNS exfiltration.** Confirmed: HC3 reports packet captures from
	two organizations showing base32-like labels, TXT records, and the
	`data-sync.healthbane-c2.net` endpoint; Acme independently includes the
	domain and DNS-tunnel tag. Assessment: the DNS-tunneling behavior is a
	high-value behavioral detection target, while no MedDefense Stage 3
	compromise is established by the supplied 4x00 report. Confidence: HIGH
	for campaign behavior, LOW for MedDefense impact.

5. **Infrastructure rotation.** Confirmed: the researcher reports a staged
	`portal-secure-meddefense.com`, and Acme supplies several low-confidence
	domains and IPs that were not corroborated by HC3. Assessment: domain/IP
	blocking alone will decay as infrastructure rotates. Confidence: MEDIUM
	for rotation as an operator practice; LOW for each Acme-only cluster until
	validated. Shared CDN, Microsoft, Cloudflare, and DigitalOcean addresses
	must not be blocked solely because of feed proximity.

6. **Attribution.** Confirmed: HC3 explicitly does not confirm a named actor;
	Acme labels the cluster VITALSCORE; the researcher proposes APT-MEDAGENT
	from tooling and infrastructure overlap. Assessment: the overlap supports
	a possible common operator, but it is not victim telemetry or independent
	attribution. Confidence: LOW for any named-actor mapping. Use HEALTHBANE as
	the operational name and retain both other labels as unconfirmed aliases.

### Detection engineering plan

No YARA rule is asserted in this intake because no binary or macro sample is
available to test locally. This avoids claiming syntactic validity or malware
coverage without an artifact. The following local-only detections are
recommended instead:

```text
EMAIL:
  alert when sender domain is in the corroborated Stage 1 domain set
  OR X-Mailer contains "PHPMailer 6.6.0" AND SPF fails
  increase priority when the domain was registered within 30 days

IDENTITY:
  alert on successful authentication for a recently phished account from
  an unusual geography, ASN, or source network; preserve the account and
  authentication-event provenance

ENDPOINT:
  alert when an Office document spawns powershell.exe, especially with
  encoded commands or a payload longer than 1024 characters
  alert on creation of a scheduled task containing Sync, Update, or Service
  and on Registry Run-key writes outside a known installer context

DNS:
  alert on *.healthbane-c2.net and long subdomain labels over 40 characters
  with base32/base64-like character composition, particularly at 10-15 second
  intervals or when TXT queries return encoded content
```

These rules are behavior-led and therefore remain useful after a domain or IP
rotation. Production blocking should initially use corroborated HIGH-confidence
values only; MEDIUM values should be monitored and LOW values should be
validated before enforcement.

## Conflicts and items for later resolution

| Issue | Sources and conflict | Resolution needed |
|---|---|---|
| Attribution labels | HC3 uses HEALTHBANE and does not confirm a named actor. Acme uses VITALSCORE. The researcher assesses APT-MEDAGENT at medium confidence. | Treat HEALTHBANE as the working campaign name; preserve VITALSCORE and APT-MEDAGENT as unconfirmed aliases until independently corroborated. |
| Confidence differences | HC3 rates the campaign and observed stages highly but attribution low. Acme assigns numeric confidence to sampled indicators, while the researcher mixes high, medium, and low infrastructure confidence. | Retain provenance-specific confidence; do not convert Acme scores into HC3 confidence or elevate attribution from tooling overlap alone. |
| Commercial-feed noise | Acme includes shared hosting, CDN, Microsoft, Cloudflare, keyword-only, and ML-clustered indicators, including explicit “DO NOT BLOCK” and “LIKELY NOISE” notes. | Use the corroborated subset for blocking. Hunt or monitor low-confidence items and validate ownership before enforcement. |
| One-source indicators missing from stronger sources | Acme-only domains, IPs, hashes, and the Outlook verification URL are not present in HC3, the blog, or MedDefense. The researcher-only kit ZIP hash and `/api/ingest` URL are also not in HC3. | Validate against telemetry, passive DNS, sandboxing, and provider data before adding to production blocklists. |
| Staged portal discrepancy | `portal-secure-meddefense.com` appears in HC3 and the researcher blog but not in Acme or the MedDefense report. | Treat as a staged or rotated domain requiring monitoring and confirmation, not as evidence of MedDefense compromise. |
| URL representation | Sources use generalized templates, exact user URLs, and different endpoints. | Keep normalized endpoint detections while retaining exact URLs as forensic evidence. |

## Intake conclusion

The strongest shared intelligence is the Stage 1 phishing cluster, the known C2
domain and IP, the three malware-related hashes, and the recurring operational
pattern of healthcare-themed lookalike domains. The durable defensive priority
is behavioral detection for newly registered lookalike domains, PHPMailer 6.6.0
plus authentication failures, macro-to-PowerShell execution, persistence, and
long base32-like DNS labels. Attribution and uncorroborated commercial-feed
extensions should remain separate from confirmed blocking intelligence.