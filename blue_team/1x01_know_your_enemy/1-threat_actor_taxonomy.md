# The Threat Actor Taxonomy

## Introduction

### Goal
Classify threat actors by type, attributes and motivation from observed behavior alone.

### Context
Intelligence analysts rarely know who attacked an organization at the time of investigation. What they have is behavior: what the attacker did, how they did it, what they targeted and what they left behind. From behavior, you infer the actor type. From the actor type, you predict their next move.

Frameworks defines six threat actor categories: nation-state, organized crime, hacktivist, insider threat, unskilled attacker and shadow IT. Each has characteristic attributes:

-    Internal vs External: Does the actor operate from inside or outside the organization ?

-    Resources and Funding: Does the actor have significant financial backing, or are they working with freely available tools ?

-    Sophistication: Does the actor develop custom tools and techniques, or rely on publicly available exploits ?

Motivations vary: data exfiltration, espionage, service disruption, blackmail, financial gain, philosophical or political beliefs, ethical motivations, revenge, chaos, war.

## Answer

Report A:
	Actor Type: Nation-state
	Internal/External: External - the zero-day VPN exploit, custom RAT, and stolen code-signing certificate point to a well-resourced outside actor.
	Resources: High - zero-day access, custom tooling, and certificate abuse require significant capability and support.
	Sophistication: High - encrypted DNS C2, signed malware, and long-term stealth indicate advanced tradecraft.
	Primary Motivation: Espionage - the target is proprietary drug trial data with massive strategic and economic value.
	Confidence Level: High - the behavior strongly matches a state-sponsored collection operation.

Report B:
	Actor Type: Organized crime
	Internal/External: External - the phishing, ransomware deployment, and extortion all originate outside the hospital.
	Resources: Medium - commodity RATs and ransomware-as-a-service are accessible, but the campaign still needs infrastructure and coordination.
	Sophistication: Medium - the attacker used known-vulnerability delivery and double extortion, which is common but effective.
	Primary Motivation: Financial gain - the ransom demand and data-theft threat are explicitly profit-driven.
	Confidence Level: High - the ransom note and exfiltration behavior are classic criminal extortion.

Report C:
	Actor Type: Hacktivist
	Internal/External: External - the defacement targeted the public website from outside the hospital.
	Resources: Low - SQL injection against a CMS is a low-cost attack using readily available techniques.
	Sophistication: Low - the attacker stopped at web defacement and did not attempt deeper compromise.
	Primary Motivation: Philosophical/political beliefs - the message protested a clinic closure and used activist branding.
	Confidence Level: High - the manifesto-style defacement and protest message make the motive explicit.

Report D:
	Actor Type: Insider threat
	Internal/External: Internal - the action was tied to a terminated IT administrator with prior access and knowledge of backup controls.
	Resources: Medium - the actor used existing access paths and administrative knowledge rather than novel tooling.
	Sophistication: Medium - creating a secondary VPN account and disabling backups before deletion shows planning.
	Primary Motivation: Revenge - the timing after termination and the destructive nature of the action point to retaliation.
	Confidence Level: High - the personnel event, hidden account, and backup sabotage strongly indicate a disgruntled insider.

Report E:
	Actor Type: Unskilled attacker
	Internal/External: External - the exploit was launched against multiple organizations from outside the clinic network.
	Resources: Low - the actor used a publicly available miner and an old, known vulnerability.
	Sophistication: Low - mass automated exploitation with no lateral movement or persistence is opportunistic and crude.
	Primary Motivation: Financial gain - the goal was cryptocurrency mining.
	Confidence Level: Medium - the scale suggests automation, but the technique set is still commodity-level.

Report F:
	Actor Type: Shadow IT
	Internal/External: Internal - the risky device was introduced by an employee inside the biomedical engineering department.
	Resources: Low - this was a personal Raspberry Pi and not an enterprise-managed platform.
	Sophistication: Low - the device ran default credentials and an outdated OS, showing poor security hygiene rather than advanced intent.
	Primary Motivation: Ethical motivations - the employee claimed the device was for monitoring network performance, though the behavior also reflects convenience/personal curiosity.
	Confidence Level: High - the unmanaged asset and the employee’s stated purpose clearly fit shadow IT.

Report G:
	Actor Type: Insider threat
	Internal/External: Could be either - the access used a legitimate physician account, but the physician was on leave and denied involvement, so the real actor could be the account holder or someone using stolen credentials.
	Resources: Medium - access to a legitimate account and a stable off-hours IP suggests some access to authorized credentials or a persistent foothold.
	Sophistication: Medium - 6 weeks of quiet, selective exfiltration is more disciplined than opportunistic abuse.
	Primary Motivation: Financial gain - the records were concentrated in high-value insurance patients, which strongly suggests resale or fraud value.
	Confidence Level: Low - the evidence supports both insider abuse and credential compromise; distinguishing them needs endpoint, MFA, and identity telemetry.

	Why multiple actor types fit:
	- Insider threat fits because a legitimate physician account was used repeatedly with no apparent technical compromise and the access was selective.
	- Organized crime also fits because the target set has clear resale value and the account may simply have been stolen.
	- To distinguish them, you would want device fingerprinting, MFA and session logs, geolocation, concurrent login checks, endpoint forensics on the physician’s devices, and evidence of account sharing or resale.

Report H:
	Actor Type: Organized crime
	Internal/External: External - the extortion email, Tor use, and proof-of-theft all indicate an outside attacker.
	Resources: Medium - the attacker had enough capability to find, exploit, and prove the API flaw, but relied on a known broken-auth weakness.
	Sophistication: Medium - the attack combined web exploitation, data theft, and extortion pressure, but not advanced custom malware.
	Primary Motivation: Blackmail - the sender explicitly demanded payment to suppress disclosure of the vulnerability and stolen records.
	Confidence Level: High - the extortion pattern and Tor-based access are consistent with criminal disclosure pressure.
