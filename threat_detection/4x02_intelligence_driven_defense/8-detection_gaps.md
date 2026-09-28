# HEALTHBANE Detection Gap Assessment

## Assessment rules

This assessment covers every technique in [7-attack_navigator.md](7-attack_navigator.md).
The status describes MedDefense's documented detection capability, not whether
the behavior occurred in the wider HEALTHBANE campaign.

- **DETECTED:** a documented rule, IOC action, YARA rule, or local analytic
	directly covers the technique.
- **PARTIALLY DETECTED:** relevant telemetry or indicators exist, but coverage
	is narrow, retrospective, IOC-only, unimplemented, or requires analyst
	review.
- **NOT DETECTED:** no documented detection or reliable telemetry covers the
	technique.

Priority is assigned as requested: Priority 1 is OBSERVED and NOT DETECTED;
Priority 2 is INFERRED and NOT DETECTED; Priority 3 covers PARTIALLY DETECTED
techniques. An IOC appearing in a report does not automatically count as a
behavioral detection.

## Coverage summary

| Measure | Count |
|---|---:|
| Techniques assessed | 20 |
| DETECTED | 1 |
| PARTIALLY DETECTED | 17 |
| NOT DETECTED | 2 |
| OBSERVED techniques | 18 |
| INFERRED techniques | 2 |

The principal gap is not absence of intelligence. It is the lack of deployed,
behavioral analytics that convert that intelligence into repeatable endpoint,
identity, email, and DNS detections.

## Technique assessments

### Reconnaissance

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity Information: Email Addresses | OBSERVED; **NOT DETECTED** | HC3 identifies email-identity gathering, but MedDefense has no documented detection for reconnaissance of staff identities. | Email gateway rules alert on known sender domains after delivery; they do not identify pre-phishing collection or unusual external targeting of employee identities. | Email security/SOC: correlate bulk targeting, healthcare-role addressing, newly created sender identities, and intelligence on lookalike domains. |

### Resource Development

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1583.001 | Acquire Infrastructure: Domains | OBSERVED; **PARTIALLY DETECTED** | MedDefense performed WHOIS/passive-DNS analysis; HC3 and 4x00 document domains registered 4-10 days before use; intake recommends newly registered-domain review. | The control is retrospective and IOC-based. There is no documented automated alert for newly registered healthcare lookalikes before delivery. | Threat intelligence/email security: enrich inbound domains with registration age, registrar, healthcare keyword patterns, and first-seen history; route new domains to review. |
| T1585.002 | Establish Accounts: Email Accounts | OBSERVED; **PARTIALLY DETECTED** | 4x00 rules cover inbound mail from listed campaign domains; headers and PHPMailer 6.6.0 are documented indicators. | Known sender/domain blocking does not detect newly established attacker mail accounts or lookalike identities that have not entered the IOC list. | Email security: detect new external sender identities, SPF/DKIM/DMARC failures, PHPMailer signatures, and display-name impersonation. |
| T1587.001 | Develop Capabilities: Malware | OBSERVED; **PARTIALLY DETECTED** | HC3 hash blocklist guidance and the 4x00 EDR hash scan provide artifact coverage; the commercial feed adds variants. | Hash blocking detects known files only and does not detect new malware variants, macro behavior, or capability development. | Endpoint engineering: use attachment sandboxing, macro child-process telemetry, signer/provenance checks, and behavior-based detections; maintain hashes as enrichment. |
| T1608.005 | Stage Capabilities: Link Target | OBSERVED; **PARTIALLY DETECTED** | Wazuh rule 100081 covers outbound HTTP(S) to listed campaign domains; the phishing URL is documented. | A known-domain rule misses rotated pages, newly staged domains, and credential-capture behavior on unlisted infrastructure. | Web/email security: detect newly registered lookalike landing pages, suspicious form POST destinations, and brand impersonation; retain URL IOCs for fast blocking. |

### Initial Access

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | OBSERVED; **DETECTED** | Wazuh rule 100080 alerts on inbound mail from listed campaign domains; rule 100081 alerts on outbound HTTP(S) to them. | Coverage is direct but depends on the known domain list and does not cover novel lookalikes or fully authenticated impersonation domains. | Keep the deployed IOC rules and add registration-age, authentication-result, display-name, URL, and user-click analytics. |
| T1566.001 | Phishing: Spearphishing Attachment | OBSERVED; **PARTIALLY DETECTED** | HC3 provides the `.docm` filename and hash; 4x00 performed an EDR scan and recommended disabling Office macros. | A hash scan can miss renamed or changed documents; no documented mail attachment behavior rule or macro execution alert is deployed. | Email/endpoint engineering: quarantine external `.docm`, detonate attachments, alert on macro-enabled documents from external senders, and monitor macro-to-child-process chains. |
| T1078 | Valid Accounts | INFERRED; **PARTIALLY DETECTED** | Wazuh rule 100082 alerts on `dmarsh` authentication from outside MedDefense networks for 30 days; HC3 assesses compromised-credential use as likely. | The rule is one-account, source-IP-based, and time-limited. It does not broadly detect cloud-mail token use, impossible travel, mailbox abuse, or valid credentials used from expected infrastructure. | Identity/SOC: centralize cloud-mail and identity-provider logs; alert on unusual geography/ASN, new device/session, mailbox sending, MFA anomalies, and impossible travel. |

### Execution

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1204.001 | User Execution: Malicious Link | OBSERVED; **PARTIALLY DETECTED** | MedDefense confirmed a user click through network evidence and Wazuh has an outbound-domain rule. | The analytic observes a destination, not the user action or successful page interaction; novel URLs and encrypted sessions can evade it. | Email/web security: capture safe-link clicks, browser telemetry, URL verdicts, and user-to-message correlation; alert on click followed by credential or unusual authentication activity. |
| T1204.002 | User Execution: Malicious File | OBSERVED; **PARTIALLY DETECTED** | HC3 reports users opening the `.docm`; hashes and filename are available and EDR scanning was performed. | No documented process telemetry confirms document opening, macro execution, or user-to-file linkage at MedDefense. | Endpoint engineering: collect Office process creation and AMSI/script telemetry; alert on external Office documents spawning PowerShell, cmd, wscript, or network clients. |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | OBSERVED; **NOT DETECTED** | HC3 and sandbox evidence establish VBA macro execution in the campaign; no deployed VBA-specific rule or YARA rule is documented. | The macro document hash is an IOC, not a detection for VBA execution or modified variants. | Endpoint/email engineering: enable Office macro and child-process logging, AMSI where available, and a tested rule for external `.docm` macro execution. |
| T1059.001 | Command and Scripting Interpreter: PowerShell | OBSERVED; **PARTIALLY DETECTED** | `sync_healthdata.ps1` and its hash are known; Task 0 recommends hunting encoded PowerShell payloads over 1024 characters. | The recommendation is not a documented deployed analytic, and hash-only coverage misses renamed scripts and alternate encodings. | Endpoint/SOC: enable PowerShell Script Block and AMSI logging; alert on Office-to-PowerShell, encoded commands, long payloads, and suspicious download/execution chains. |

### Persistence

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | OBSERVED; **PARTIALLY DETECTED** | HC3 supplies `HealthSync Update Service`; Task 0 recommends alerting on task names containing Sync, Update, or Service. | This is an IOC/name hunt and recommendation, not documented deployed task-creation monitoring; legitimate task names can also create noise. | Endpoint engineering: collect Windows Task Scheduler 4698/106 events and alert on non-admin creation, suspicious parent process, user-writable path, and the task name pattern. |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | OBSERVED; **PARTIALLY DETECTED** | HC3 reports the Run key and recommends alerting on Run-key additions outside installer context. | No deployed rule or baseline is documented; the recommendation lacks installer allowlisting and value/path context. | Endpoint engineering: monitor Sysmon Registry events and Windows autoruns; alert on user-writable paths, Office/PowerShell ancestry, unsigned binaries, and unusual account context. |

### Credential Access

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1056.003 | Input Capture: Web Portal Capture | OBSERVED; **PARTIALLY DETECTED** | Wazuh blocks/alerts on known phishing domains; the researcher recovered PHP handlers and MedDefense has the exact URL. | There is no visibility into the remote form POST, credential receipt, or use of submitted credentials; HTTPS hides contents in available network evidence. | Email/web/identity owners: correlate click logs, proxy URL paths, TLS metadata, cloud authentication, and password-reset events; obtain phishing-server or safe-link telemetry where authorized. |

### Command and Control

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | OBSERVED; **PARTIALLY DETECTED** | The network-forensics report documents TXT queries, long labels, and recommended DNS length/TXT-frequency analytics; HC3 has packet evidence. | The report is investigative evidence and a recommendation, not a documented deployed production analytic; normal TXT-heavy services may produce false positives. | DNS/SOC: implement label length/entropy, TXT frequency, periodicity, base32/base64 character, and destination-domain analytics with allowlists. |
| T1071.001 | Application Layer Protocol: Web Protocols | OBSERVED; **PARTIALLY DETECTED** | Wazuh rule 100081 covers known outbound HTTP(S); network forensics documents TLS SNI and repeated external connections. | Encrypted web traffic and rotating domains limit IOC rules; no documented beaconing analytic identifies the responsible process or periodic behavior. | Network/endpoint owners: combine proxy/TLS SNI, first-seen domains, interval regularity, destination reputation, and process-to-connection telemetry. |
| T1021 | Remote Services | INFERRED; **PARTIALLY DETECTED** | Network-forensics evidence documents RDP and TCP/445 traffic and recommends cross-role RDP detection; HC3 only assesses the technique as likely. | The mapping is generic and does not establish successful authentication or authorized versus malicious use; no deployed role-aware analytic is documented. | Network/identity/Windows owners: correlate RDP/SMB connections with logon events, account roles, source workstation baselines, server targets, and authentication success. |

### Exfiltration

| ATT&CK ID | Technique | Status | Detection evidence | Gap explanation | Recommendation |
|---|---|---|---|---|---|
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | OBSERVED; **PARTIALLY DETECTED** | HC3 packet captures and the network-forensics report document DNS TXT transfer patterns; Task 0 recommends long-label detection. | Current evidence is retrospective; no documented alert connects the DNS pattern to data access, source process, or confirmed record content. | DNS/data owners: alert on long encoded labels and repeated TXT queries, then correlate source host, file/database access, and destination response. |
| T1041 | Exfiltration Over C2 Channel | OBSERVED; **PARTIALLY DETECTED** | HC3 reports patient/insurance exfiltration over C2; researcher recovered `EXFIL_ENDPOINT`; C2/domain IOCs are available. | The C2 endpoint and hash controls do not prove successful transfer or distinguish command traffic from data transfer. | Network/endpoint/SOC: correlate egress bytes, DNS/HTTPS sessions, process identity, sensitive-data access, and periodic C2 with a response workflow. |

## Prioritized gap list

### Priority 1: observed and not detected

| Technique | Why the gap matters | Detection idea | Required data source | Owner / implementation path |
|---|---|---|---|---|
| T1589.002 | The campaign targets staff identities before delivery; email IOCs arrive after the reconnaissance has succeeded. | Detect unusual bulk healthcare-role targeting, new external sender identities, and correlation with newly registered lookalike domains. | Mail gateway headers, recipient graph, threat-intelligence registration data. | Email security plus SOC detection engineering. |
| T1059.005 | VBA is the bridge from a trusted-looking document to malware delivery and bypasses domain-only controls. | Alert on external `.docm` macro execution and Office spawning PowerShell or network clients. | Office telemetry, Sysmon process events, AMSI, EDR, attachment sandbox. | Endpoint engineering; deploy to EDR/SIEM. |

### Priority 2: inferred and not detected

No Task 7 technique currently meets both conditions for Priority 2. Valid
Accounts and Remote Services have partial coverage through Wazuh, network
captures, and investigation recommendations. They remain important validation
gaps rather than zero-visibility gaps.

### Priority 3: partially detected

| Technique(s) | Why the gap matters | Detection idea | Required data source | Owner / implementation path |
|---|---|---|---|---|
| T1583.001, T1608.005 | IOC lists cannot reliably catch infrastructure rotation or new landing pages. | Registration-age, first-seen, healthcare-keyword, URL-form, and brand-impersonation scoring. | DNS/proxy, email gateway, passive DNS/WHOIS or approved local feed. | Threat intelligence and email security. |
| T1585.002, T1566.002, T1566.001 | Known-domain blocking misses authenticated lookalikes and mutated attachments. | Combine DMARC/SPF, display-name similarity, PHPMailer signatures, external `.docm` policy, and sandbox verdicts. | Mail gateway, attachment sandbox, identity/email audit logs. | Email security. |
| T1078 | Stolen credentials can enable cloud-mail follow-on without malware on the original host. | Alert on impossible travel, unusual ASN/device, mailbox sending, MFA anomalies, and new OAuth/session activity. | Identity provider, cloud-mail audit, MFA, VPN logs. | IAM and SOC. |
| T1204.001, T1204.002, T1056.003 | Current controls show known destinations or hashes but not successful user interaction or credential capture. | Link-click and attachment-open correlation followed by browser, credential, and authentication telemetry. | Safe-link/browser, EDR, proxy/TLS, identity, password-reset logs. | Email security, endpoint, IAM. |
| T1059.001, T1053.005, T1547.001 | PowerShell and persistence allow the RAT to survive IOC rotation. | Office-to-PowerShell, encoded-command, task creation, and Run-key analytics with parent/path context. | PowerShell, Sysmon, Windows Event Logs, EDR. | Endpoint engineering. |
| T1587.001 | Hashes identify known payloads but not variants or capability changes. | Attachment detonation, script and binary behavior, signer/path reputation, and hash enrichment. | EDR, sandbox, file reputation, email gateway. | Endpoint and malware analysis. |
| T1071.001 | Web C2 can blend with ordinary HTTPS and rotate domains. | First-seen SNI, beacon interval analysis, unusual destinations, and process-to-network joins. | Proxy/TLS, NetFlow, DNS, EDR network telemetry. | Network detection and response. |
| T1071.004, T1048.003, T1041 | DNS tunneling and C2 exfiltration may expose patient or insurance data before blocking occurs. | Long-label/entropy/TXT-frequency analytics plus sensitive-data access and egress-volume correlation. | DNS resolver/Zeek, EDR, file/database audit, proxy/firewall. | Network SOC with data-protection and incident response. |
| T1021 | RDP/SMB can enable lateral movement, but network packets alone do not prove authentication or malicious action. | Detect clinical/non-IT workstation access to server RDP/SMB and correlate with successful Windows logons. | Network telemetry, Windows Security/RDP logs, AD, server audit, EDR. | Network, IAM, and Windows platform owners. |

## Recommended implementation order

1. Deploy the two Priority 1 analytics: pre-delivery targeting and
	 external-document macro execution.
2. Add identity and cloud-mail correlation for T1078, then expand email
	 detection beyond static domain lists.
3. Implement endpoint persistence and PowerShell analytics.
4. Deploy DNS TXT/label anomaly and web-beacon analytics with allowlists.
5. Correlate RDP/SMB with identity and server events, then connect sensitive
	 data access to egress alerts.

This plan keeps the existing high-value IOC rules, but makes behavioral and
cross-source correlation the path to closing the gaps that will survive
HEALTHBANE infrastructure rotation.
