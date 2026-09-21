# Authentication Analysis

## Email 1 — healthcare-education-weekly.com

- SPF: **Pass.** The sending IP `198.51.100.42` is authorized to send for `healthcare-education-weekly.com`.
- DKIM: **Pass.** The message has a valid DKIM signature for `healthcare-education-weekly.com` using selector `mail01`, providing cryptographic evidence that the message was signed by a system authorized for that domain.
- DMARC: **Pass; action=none.** DMARC passed for the visible `From:` domain. `action=none` means the domain did not request quarantine or rejection because the message passed DMARC.
- Authentication verdict: **Authentication supports the apparent legitimacy of the sender.** SPF, DKIM, and DMARC all pass and are aligned with the visible sender domain.
- Investigation meaning: The authentication results provide no indication that the sender address was spoofed. The message is a bulk newsletter and contains normal subscription and unsubscribe information, so the authentication evidence is consistent with its **SPAM/P4-LOW** classification rather than indicating phishing or sender impersonation.
- Final verdict: **SPAM — authenticated bulk newsletter; authentication supports sender legitimacy but does not make the unsolicited content desirable.**

## Email 2 — meddefense-portal.com

- SPF: **Fail.** The sending IP `91.234.99.107` is not authorized to send for `meddefense-portal.com`.
- DKIM: **None.** The message has no DKIM signature, so there is no cryptographic authentication from the claimed sender domain.
- DMARC: **Fail; action=none.** DMARC failed for `meddefense-portal.com`. `action=none` means the domain's policy did not request quarantine or rejection despite the failed result.
- Authentication verdict: **Authentication contradicts the apparent legitimacy of the email.** SPF failure, absence of DKIM, and DMARC failure reduce trust in the claimed sender identity.
- Investigation meaning: The authentication failures directly support the **SUSPICIOUS/P1-URGENT** classification because the message claims to be MedDefense IT Security while using an external look-alike domain and an unauthorized sending IP. The lack of DKIM removes another source of sender and message integrity evidence. The urgent 24-hour verification request and credential-oriented link add supporting phishing indicators.
- Final verdict: **SUSPICIOUS — failed SPF and DMARC plus absent DKIM materially reduce trust in the claimed MedDefense sender and support the phishing classification.**

## Email 3 — outlook-protection.com

- SPF: **Pass.** The sending IP `51.38.42.17` is authorized to send for `outlook-protection.com`.
- DKIM: **Pass.** The message has a valid DKIM signature for `outlook-protection.com` using selector `default`.
- DMARC: **Pass; action=none.** DMARC passed for the visible `From:` domain. `action=none` means no quarantine or rejection was requested after the successful authentication.
- Authentication verdict: **Authentication supports the authenticity of the sending domain but contradicts the apparent Microsoft identity.** The three mechanisms authenticate `outlook-protection.com`; they do not establish that the sender is Microsoft.
- Investigation meaning: Passing SPF, DKIM, and DMARC does **not** make the email legitimate because those mechanisms validate the domain used to send the message, not whether that domain is the legitimate organization being impersonated. `outlook-protection.com` is not the same as `microsoft.com` or `outlook.com`. An attacker controlling a look-alike domain can configure valid SPF, DKIM, and DMARC for that domain. Therefore, the passing authentication results do not reduce the suspicion created by the false Microsoft identity, external verification link, PHPMailer infrastructure, and account-lockout threat. These indicators support the **SUSPICIOUS/P1-URGENT** classification.
- Final verdict: **SUSPICIOUS — SPF, DKIM, and DMARC pass only for the impersonating `outlook-protection.com` domain; they do not authenticate Microsoft.**

## Email 4 — meddefense.com

- SPF: **Pass.** The message originated from the internal Exchange host `10.10.1.15`, which is authorized for the MedDefense domain in the receiving environment.
- DKIM: **Pass.** The message has a valid DKIM signature for `meddefense.com` using selector `selector1`.
- DMARC: **Pass; action=none.** DMARC passed for the visible `From:` domain, and no quarantine or rejection action was requested.
- Authentication verdict: **Authentication supports the apparent legitimacy of the email.** SPF, DKIM, and DMARC all pass for the organization's actual `meddefense.com` domain, and the received chain shows internal Exchange infrastructure.
- Investigation meaning: The authentication results increase trust in the claimed internal sender and support the **LEGITIMATE/P3-NORMAL** classification. The message also directs staff to the normal internal portal and explicitly warns that IT will never email a password-change link, which is consistent with an internal security announcement.
- Final verdict: **LEGITIMATE — authentication and internal routing evidence support the claimed MedDefense sender.**

## Email 5 — medequip-supplies.net

- SPF: **Softfail.** The sending IP `185.176.43.22` is not authorized with an SPF pass for `medequip-supplies.net`; the softfail result is a weak/negative authentication signal indicating that the sender should not be treated as fully authorized.
- DKIM: **None.** The message is not DKIM-signed, so there is no cryptographic sender authentication from the claimed vendor domain.
- DMARC: **Fail; action=none.** DMARC failed for `medequip-supplies.net`. `action=none` means the domain did not request quarantine or rejection based on the failure.
- Authentication verdict: **Authentication contradicts the apparent legitimacy of the invoice.** SPF does not authenticate the sending host, DKIM provides no signature, and DMARC fails; together these results reduce trust in the claimed vendor identity.
- Investigation meaning: These weak/failed authentication results directly support the **SUSPICIOUS/P1-URGENT** classification because the email requests payment of `USD 24,716.38` while lacking reliable sender authentication. The external payment portal, PHP-based sending infrastructure, high priority flag, and Angela Rivera's report that the invoice looks wrong provide additional evidence that the message should not be trusted as a legitimate payment request. The authentication failures therefore reinforce, rather than merely accompany, the suspicious classification.
- Final verdict: **SUSPICIOUS — SPF softfail, absent DKIM, and failed DMARC reduce trust in the claimed vendor and support treating the payment request as potentially fraudulent.**

## Email 6 — canadian-pharma-discount.org

- SPF: **Softfail.** The sending domain's SPF evaluation does not produce a pass result, providing a weak/negative indication that the sending host is not properly authenticated for the domain.
- DKIM: **None.** No DKIM signature is present, so the message has no cryptographic authentication from the claimed sender domain.
- DMARC: **Fail; action=quarantine.** DMARC failed for `canadian-pharma-discount.org`, and the published policy requests quarantine of messages that fail DMARC.
- Authentication verdict: **Authentication reduces trust in the sender and supports the spam classification.** SPF is only a softfail, DKIM is absent, and DMARC fails; there is no successful sender-authentication evidence in the message.
- Investigation meaning: The weak/failed authentication directly supports the **SPAM/P4-LOW** classification by providing no reliable basis to trust the claimed bulk-pharmacy sender. The message also has an `X-Spam-Score` of `9.8`, is explicitly marked as spam, uses bulk-mail infrastructure, and advertises prescription drugs without a prescription. The authentication results therefore reinforce the assessment that this is untrusted bulk spam rather than a legitimate business communication.
- Final verdict: **SPAM — SPF softfail, absent DKIM, and failed DMARC reduce sender trust and support the spam classification.**

## Email 7 — meddefense-benefits.org

- SPF: **Fail.** The sending IP `164.90.218.73` is not authorized to send for `meddefense-benefits.org`.
- DKIM: **None.** No DKIM signature is present, so there is no cryptographic authentication of the claimed sender domain.
- DMARC: **Fail; action=none.** DMARC failed for `meddefense-benefits.org`, while the header shows that no quarantine or rejection action was requested by the domain policy.
- Authentication verdict: **Authentication strongly contradicts the apparent legitimacy of the email.** SPF failure, absent DKIM, and DMARC failure all reduce trust in the claimed MedDefense HR sender.
- Investigation meaning: These failed/weak authentication results directly support the **SUSPICIOUS/P1-URGENT** classification because the message claims to be MedDefense HR Benefits but uses an external look-alike domain that is not authenticated as an authorized sender. The urgent open-enrollment deadline, threat of losing coverage, external enrollment link, and Linda Patterson's report that she never signed up provide additional phishing evidence. The authentication failures therefore materially reduce confidence in the message and reinforce the phishing assessment.
- Final verdict: **SUSPICIOUS — failed SPF and DMARC with absent DKIM reduce sender trust and support treating the benefits-enrollment message as phishing.**

## Email 8 — hhs.gov / HC3

- SPF: **Pass.** The sending IP `134.174.47.82` is authorized to send for `hhs.gov`.
- DKIM: **Pass.** The message has a valid DKIM signature for `hhs.gov` using selector `hhs2026`.
- DMARC: **Pass; action=none.** DMARC passed for the visible `From:` domain, and no quarantine or rejection action was requested.
- Authentication verdict: **Authentication supports the apparent legitimacy of the sender.** SPF, DKIM, and DMARC all pass and align with the `hhs.gov` domain used by the claimed HC3 sender.
- Investigation meaning: The successful authentication results increase trust in the claimed HHS/HC3 sender and support the **LEGITIMATE/P2-HIGH** classification. The message is an advisory rather than a credential or payment request and describes phishing patterns that correspond with E2, E3, E5, and E7. Its preliminary status should still be retained because the message states that the indicators are not yet IOC-confirmed.
- Final verdict: **LEGITIMATE — authentication supports the claimed HHS/HC3 sender and is consistent with a legitimate sector advisory.**
