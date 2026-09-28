# Source Assessment

## Assessment methodology

This assessment adapts the Admiralty Code for cyber threat intelligence. It
keeps **source reliability** separate from **information credibility**: a
reliable source can still report weak or uncorroborated information, while a
normally limited source can provide a credible fact for a narrowly observed
event.

### Admiralty ratings

**Source reliability** evaluates the source's collection process, expertise,
and history of accurate reporting:

| Rating | Meaning |
|---|---|
| A | Completely reliable: controlled collection, strong expertise, and consistently accurate reporting. |
| B | Usually reliable: credible organization or specialist with minor process or coverage limitations. |
| C | Fairly reliable: useful source with material visibility, methodology, or independence limitations. |
| D | Not usually reliable: inconsistent, indirect, or poorly controlled collection. |
| E | Unreliable: known accuracy or integrity problems. |
| F | Reliability cannot be judged. |

**Information credibility** evaluates the specific claim or indicator set:

| Rating | Meaning |
|---|---|
| 1 | Confirmed by independent sources or direct telemetry. |
| 2 | Probably true: strong evidence, but not fully independently confirmed. |
| 3 | Possibly true: plausible and partially supported. |
| 4 | Doubtful: weak support or significant contradiction. |
| 5 | Improbable: evidence materially contradicts the claim. |
| 6 | Truth cannot be judged from available information. |

Confidence is reported separately as **HIGH**, **MEDIUM**, or **LOW**. HIGH
means direct evidence or strong multi-source corroboration; MEDIUM means
credible but incomplete or indirect evidence; LOW means weak clustering,
unconfirmed attribution, shared infrastructure, or a material visibility gap.
Ratings apply to the source and claim as assessed here, not to every item in a
feed. Indicator-level confidence should remain source-specific.

## Source assessments

### HC3 government advisory

| Criterion | Assessment |
|---|---|
| Source reliability | **A**. HC3 is a sector coordination and threat-intelligence authority with partner telemetry and sensor visibility. |
| Information credibility | **1** for observed Stage 1 activity and **1-2** for Stage 2/3 campaign activity. The advisory cites direct observations, sandbox evidence, packet captures, and URLhaus corroboration. |
| Timeliness | **HIGH**. Published 2026-04-25 during the campaign window, with activity observed from 2026-04-14 through 2026-04-26 and a scheduled update. |
| Relevance to MedDefense | **HIGH** for sector tactics, confirmed campaign indicators, and detection priorities. It does not establish that MedDefense reached Stage 2 or Stage 3. |
| Limitations | HC3 saw full telemetry at only 6 organizations out of at least 14 targets; Stage 2/3 were observed at 2 of those 6. Attribution is explicitly unconfirmed. |
| Bias or visibility constraints | Sector-mission bias toward healthcare incidents and partner-reported telemetry. The sample may overrepresent organizations with stronger reporting or sensor coverage. |
| Overall assessment | **A / 1-2 / HIGH** for confirmed campaign facts; **LOW** for named-actor attribution. |

### Acme commercial feed

| Criterion | Assessment |
|---|---|
| Source reliability | **C**. The provider is potentially useful, but its own metadata says indicators are sampled and not all human-reviewed. |
| Information credibility | **1-2** for items corroborated by HC3 or the researcher; **3-6** for feed-only items depending on the explicit note. |
| Timeliness | **HIGH**. Extracted 2026-04-26 and includes first-seen/last-seen dates through the campaign. |
| Relevance to MedDefense | **HIGH** for corroborating primary domains, IPs, hashes, and URLs; **MEDIUM/LOW** for extensions that are only name-, keyword-, or clustering-based. |
| Limitations | Proprietary VITALSCORE attribution, sampled analyst review, shared infrastructure, sinkholed domains, CDN addresses, and weakly clustered indicators. Numeric confidence scores are not equivalent to independent confirmation. |
| Bias or visibility constraints | Commercial clustering and product-label incentives can broaden the campaign boundary. The feed is authorized only for internal MedDefense defense and does not provide victim telemetry. |
| Overall assessment | **C / 1-6 item-dependent / MEDIUM** overall. Use the corroborated subset confidently; treat feed-only expansion as a lead. |

### Researcher open-source analysis

| Criterion | Assessment |
|---|---|
| Source reliability | **B-C**. The researcher demonstrates technical access to a recovered kit and publishes methods, but is a solo researcher without victim telemetry. |
| Information credibility | **1-2** for directly recovered kit/configuration artifacts; **2-3** for infrastructure linkage; **3-4** for the named-actor attribution. |
| Timeliness | **HIGH**. Published 2026-04-24, one day before the HC3 advisory, based on activity and a kit observed during the campaign. |
| Relevance to MedDefense | **HIGH** for phishing-kit structure, PHPMailer 6.6.0, operator workflow, staged-domain behavior, and durable behavioral detections. **MEDIUM** for claims about MedDefense impact. |
| Limitations | No victim telemetry, incomplete view of the operation, uncertain provenance of the kit ZIP, staged portal not active during observed emails, and low-confidence VPS image-reuse evidence. |
| Bias or visibility constraints | Open-source artifact bias: the researcher can see exposed infrastructure and kit content but not closed victim-side activity. Attribution is based on tooling and infrastructure overlap, not intelligence reporting or incident telemetry. |
| Overall assessment | **B-C / 1-4 claim-dependent / MEDIUM**. Strong technical context; do not treat the actor label as confirmed. |

### MedDefense 4x00 internal investigation

| Criterion | Assessment |
|---|---|
| Source reliability | **B** for the local incident: the report is reviewed by the SOC Lead and approved by the CISO, with direct email/header and internal telemetry analysis. |
| Information credibility | **1** for the three received phishing messages and their indicators; **2-3** for credential submission because packet confirmation was outside scope. |
| Timeliness | **HIGH** for the initial incident window, dated 2026-04-16. It predates the sector advisory and later intelligence. |
| Relevance to MedDefense | **HIGH** for local users, URLs, sender addresses, authentication results, and detection gaps. **LOW** for general actor attribution or Stage 2/3 conclusions. |
| Limitations | No packet analysis, endpoint forensics, or follow-on authentication correlation at close; no confirmed exploitation; only three phishing emails were determined to be campaign-related. |
| Bias or visibility constraints | Single-organization and single-stage visibility. Internal containment and reporting priorities may emphasize MedDefense impact over campaign breadth. The report intentionally avoids attribution. |
| Overall assessment | **B / 1-3 claim-dependent / HIGH** for MedDefense Stage 1 facts; **MEDIUM** for likely credential exposure; not an attribution source. |

## Source comparison matrix

| Dimension | HC3 advisory | Acme commercial feed | Researcher blog | MedDefense 4x00 |
|---|---|---|---|---|
| Primary visibility | Six healthcare organizations, sector sensors, partner reporting | Broad indicator clustering across feeds | Exposed phishing kit and infrastructure artifacts | One healthcare organization and its email investigation |
| Reliability | A | C | B-C | B |
| Credibility pattern | 1 for direct observations; 1-2 for campaign stages | 1-2 when corroborated; 3-6 for weak feed-only items | 1-2 for recovered artifacts; 3-4 for attribution | 1 for received messages; 2-3 for likely credential submission |
| Timeliness | High, during campaign | High, 2026-04-26 | High, 2026-04-24 | High for 2026-04-14 to 2026-04-16 |
| Best use | Confirmed healthcare-sector facts and observed TTPs | Candidate expansion and corroboration | Technical detail and behavior-based detection | MedDefense-specific impact and response gaps |
| Main weakness | Limited organization sample; no named attribution | Noise, proprietary labels, and unreviewed clustering | No victim telemetry; open-source attribution | Narrow scope; later-stage activity outside scope |
| Recommended operational weight | Highest for sector facts | Conditional, based on corroboration | High for technical context, lower for attribution | Highest for local facts, not sector generalization |

## Attribution conflict

The labels describe a naming disagreement, not three independently proven
actors. **HC3** designates the campaign **HEALTHBANE**, explicitly does not
endorse the commercial `VITALSCORE` label, and does not confirm attribution to a
named group. **Acme** uses `VITALSCORE` as a proprietary clustering label; its
metadata warns that the label may not correspond to an externally tracked
actor. The **researcher** uses **APT-MEDAGENT** with MEDIUM confidence based on
tooling and infrastructure overlap with prior campaigns, while acknowledging
the absence of victim telemetry. **MedDefense 4x00** avoids attribution because
its direct evidence supports the phishing incident, not an actor identity.

Analytical judgment: use **HEALTHBANE** as the operational campaign name. Keep
`VITALSCORE` and `APT-MEDAGENT` as unconfirmed aliases in search and
correlation notes, not as confirmed actor identities or blocking criteria. The
shared PHPMailer version, registrar/hosting pattern, phishing kit structure,
and C2 references support a possible common operator, but they do not overcome
the lack of independent victim-side attribution. Attribution confidence is
therefore **LOW**.

## Weighting recommendation

1. **Confirmed healthcare-sector facts:** prioritize HC3. Its direct partner
	telemetry, packet evidence, and explicit confidence statements make it the
	controlling source for campaign stages, observed TTPs, and sector-level
	claims. Use MedDefense as the controlling source for what happened inside
	MedDefense itself.

2. **Technical details:** use the researcher for phishing-kit structure,
	configuration artifacts, PHPMailer 6.6.0, staged infrastructure, and
	behavior-based detection ideas. Promote a technical claim to confirmed
	operational intelligence when HC3, Acme, or local telemetry corroborates it.

3. **Noise and weak clustering:** treat Acme carefully. Its corroborated
	indicators are valuable, but feed-only domains, hashes, shared-hosting IPs,
	CDN/cloud addresses, historical domains, and `clustered_by_similarity`
	values should be contextual or noise until independently validated.

4. **Conflicting claims:** preserve every source and its original confidence;
	do not average confidence scores. Prefer direct telemetry over inference,
	multi-source agreement over a single feed, and the most specific local
	source for MedDefense impact. Record unresolved conflicts as hypotheses for
	hunting rather than silently choosing an attribution label.

5. **Blocking decisions:** require corroboration or direct local observation
	before blocking ambiguous infrastructure. Apply behavioral detections for
	newly registered healthcare lookalike domains, PHPMailer plus SPF failure,
	macro-to-PowerShell execution, persistence changes, and long DNS labels so
	coverage survives infrastructure rotation.
