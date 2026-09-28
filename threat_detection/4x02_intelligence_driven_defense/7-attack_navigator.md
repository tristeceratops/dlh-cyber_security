# HEALTHBANE ATT&CK Navigator Assessment

## Scope and classification

This mapping uses the HC3 advisory's MITRE ATT&CK v15 table. Techniques listed
by HC3 as directly observed are classified **OBSERVED**. HC3 also names Valid
Accounts and Remote Services as likely but excludes them from its observed
table; they are included here as **INFERRED**. The mapping describes campaign
activity across visible organizations, not confirmed compromise of MedDefense
at every phase.

## Technique coverage

### Reconnaissance

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity Information: Email Addresses | OBSERVED | HC3 reports email-identity gathering as part of the campaign's targeting activity. | HC3 advisory, ATT&CK table | Pre-Stage 1 reconnaissance |

### Resource Development

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1583.001 | Acquire Infrastructure: Domains | OBSERVED | Lookalike healthcare domains were acquired shortly before phishing activity. | HC3; MedDefense WHOIS/passive DNS findings | Pre-Stage 1 / infrastructure |
| T1585.002 | Establish Accounts: Email Accounts | OBSERVED | Campaign emails used healthcare-themed sender identities and attacker-controlled mail infrastructure. | HC3; researcher kit analysis; MedDefense headers | Stage 1 |
| T1587.001 | Develop Capabilities: Malware | OBSERVED | HC3 reports a macro document, Windows executable, RAT behavior, and PowerShell tooling. | HC3 sandbox and partner evidence | Stage 2 |
| T1608.005 | Stage Capabilities: Link Target | OBSERVED | Credential-capture pages were staged at healthcare-themed URLs and delivered through phishing messages. | HC3; researcher recovered PHP kit; MedDefense URL evidence | Stage 1 |

### Initial Access

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | OBSERVED | Stage 1 emails delivered links to credential-capture pages; one MedDefense user clicked. | HC3; MedDefense 4x00 | Stage 1 |
| T1566.001 | Phishing: Spearphishing Attachment | OBSERVED | Compromised accounts sent follow-up messages containing `HEALTHBANE_S2_invoice.docm`. | HC3 partner evidence | Stage 2 |
| T1078 | Valid Accounts | INFERRED | HC3 assesses use of compromised credentials for cloud email and lateral movement as likely, but withholds it from the observed table pending confirmation. | HC3 assessment | Stage 1 to Stage 2 transition |

### Execution

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1204.001 | User Execution: Malicious Link | OBSERVED | A MedDefense nurse clicked the phishing link; HC3 observed link execution across the campaign. | HC3; MedDefense 4x00 | Stage 1 |
| T1204.002 | User Execution: Malicious File | OBSERVED | HC3 reports users opening the macro-enabled follow-up document in affected organizations. | HC3 partner evidence | Stage 2 |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | OBSERVED | The `.docm` macro executed VBA to retrieve the Windows payload. | HC3 sandbox and partner evidence | Stage 2 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | OBSERVED | HC3 reports PowerShell execution and a `sync_healthdata.ps1` artifact. | HC3; Acme; researcher kit analysis | Stage 2 |

### Persistence

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | OBSERVED | The executable created a task named `HealthSync Update Service`. | HC3 partner evidence | Stage 2 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | OBSERVED | HC3 reports persistence through a Registry Run key. | HC3 partner evidence | Stage 2 |

### Credential Access

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1056.003 | Input Capture: Web Portal Capture | OBSERVED | PHP form handlers collected usernames and passwords; MedDefense investigated the credential-capture endpoint. | HC3; researcher kit; MedDefense 4x00 | Stage 1 |

### Command and Control

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | OBSERVED | The RAT communicated and exfiltrated through DNS TXT queries to HEALTHBANE infrastructure. | HC3 packet captures; Acme DNS-tunnel tagging | Stage 3 |
| T1071.001 | Application Layer Protocol: Web Protocols | OBSERVED | Phishing forms, malware downloads, and kit configuration used HTTP/HTTPS endpoints. | HC3; researcher kit; MedDefense network evidence | Stages 1-2 |
| T1021 | Remote Services | INFERRED | HC3 assesses Remote Services as likely in the follow-on activity but excludes it pending confirmation. | HC3 assessment | Stage 2 lateral movement |

### Exfiltration

| ID | Technique | Classification | Evidence or reasoning | Source | Attack phase |
|---|---|---|---|---|---|
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | OBSERVED | Patient and insurance data were encoded into DNS labels and sent via DNS TXT queries. | HC3 packet captures | Stage 3 |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | HC3 reports data exfiltration through attacker-controlled C2 infrastructure; the researcher recovered an `EXFIL_ENDPOINT`. | HC3; researcher kit configuration | Stage 3 |

## Summary

- **Total techniques identified:** 20.
- **Observed:** 18 techniques, score 100 in the Navigator layer (90%).
- **Inferred:** 2 techniques, score 50 in the Navigator layer (10%).
- **Highest coverage:** Execution and Resource Development, with 4 techniques
  each. Initial Access, Persistence, Command and Control, and Exfiltration
  each have 3 techniques when inferred coverage is included.
- **Least coverage:** Reconnaissance, Credential Access, and the inferred
  Lateral Movement coverage each have 1 technique. Tactics are counted by
  tactic assignment; Valid Accounts spans multiple ATT&CK tactics but is shown
  under Initial Access here for readability.

## Detection-planning priorities

1. **T1566.002, T1056.003, and T1204.001:** detect healthcare lookalike links,
	web credential capture, and user clicks. These are the confirmed entry path
	and directly relevant to the MedDefense incident.
2. **T1059.005, T1059.001, T1053.005, and T1547.001:** detect macro-to-
	PowerShell execution, suspicious encoded commands, scheduled-task creation,
	and Registry Run-key persistence.
3. **T1071.004, T1048.003, and T1041:** detect DNS TXT tunneling, long
	base32-like labels, periodic 10-15 second queries, and encoded C2 responses.
4. **T1078 and T1021:** hunt for unusual cloud-mail authentication and remote
	service use, but keep these at inferred status until local telemetry confirms
	them.

The most durable detections are behavior-based. Domain and hash blocking should
retain the source provenance and confidence recorded in the intake because
infrastructure rotation and shared hosting reduce the value of indiscriminate
blocking.
