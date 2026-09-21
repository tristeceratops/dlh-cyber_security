# Authentication Analysis — MedDefense Health Systems Email Evidence Batch

## Email 1 — healthcare-education-weekly.com

- SPF: **Pass.** The sending IP `198.51.100.42` is authorized by the SPF policy for `healthcare-education-weekly.com`. This means the SMTP sending host is authorized to send mail for that envelope domain.
- DKIM: **Pass.** The message contains a valid DKIM signature for `healthcare-education-weekly.com` using selector `mail01`. This supports message integrity and indicates the signer controlled the relevant domain key.
- DMARC: **Pass; action=none.** The header `From:` domain authenticated successfully under DMARC. `action=none` indicates no enforcement action was requested because the message passed.
- Authentication verdict: Authentication **supports the apparent legitimacy** of the message. SPF, DKIM, and DMARC all pass and are aligned with the visible sender domain.
- Investigation meaning: The authentication evidence is consistent with a legitimate bulk newsletter from the claimed domain. The content also identifies a subscription date and provides standard unsubscribe mechanisms. Authentication alone does not establish that the sender is trustworthy, but there is no authentication-based contradiction in this sample.
- Final verdict: **Likely legitimate newsletter; no authentication-based indication of spoofing.**

## Email 2 — meddefense-portal.com

- SPF: **Fail.** The sending IP `91.234.99.107` is not authorized by the SPF policy for `meddefense-portal.com`. This contradicts the claim that the message was legitimately sent through an authorized mail system for that domain.
- DKIM: **None.** The message has no DKIM signature, so there is no cryptographic authentication of the message by the claimed domain.
- DMARC: **Fail; action=none.** DMARC failed for the visible `From:` domain. `action=none` means the receiving system was not instructed by the domain's DMARC policy to quarantine or reject the message based on that failure.
- Authentication verdict: Authentication **strongly contradicts the apparent legitimacy** of the email. The claimed MedDefense identity is not supported by SPF or DKIM, and DMARC fails.
- Investigation meaning: The message uses a look-alike external domain, an urgent 24-hour deadline, an account-lockout threat, and a credential-verification link. These characteristics are consistent with phishing. The workstation record confirms that Diane Marsh clicked the message at `2026-04-14 15:02:33 CDT`, so the event warrants incident investigation independent of the authentication failures.
- Final verdict: **Phishing; authentication failures and message content are mutually consistent with impersonation.**

## Email 3 — outlook-protection.com

- SPF: **Pass.** The sending IP `51.38.42.17` is authorized by SPF for `outlook-protection.com`.
- DKIM: **Pass.** The message has a valid DKIM signature for `outlook-protection.com` using selector `default`, supporting integrity and control of that sending domain.
- DMARC: **Pass; action=none.** DMARC authentication succeeds for the visible `From:` domain, and `action=none` indicates no enforcement action was requested.
- Authentication verdict: Authentication **supports the authenticity of the message as mail from `outlook-protection.com`, but contradicts the apparent claim that it is an official Microsoft message**. Passing authentication does not establish that the authenticated domain belongs to the organization being impersonated.
- Investigation meaning: SPF, DKIM, and DMARC validate the domain used by the sender; they do not prove that the domain is the legitimate brand domain. `outlook-protection.com` is not the same as `microsoft.com` or `outlook.com`. An attacker can register or control a look-alike domain and configure valid SPF, DKIM, and DMARC for it. Here, the sender presents itself as “Microsoft Account Protection,” uses Microsoft branding, and directs the recipient to `outlook-protection.com/verify`, making the domain identity itself the key contradiction. The message therefore demonstrates why successful email authentication is not equivalent to legitimacy or brand authenticity.
- Final verdict: **Phishing/impersonation; SPF, DKIM, and DMARC pass for the attacker's apparent domain but do not authenticate Microsoft.**

## Email 4 — meddefense.com

- SPF: **Pass.** The message originated from the internal Exchange host `10.10.1.15`, which is treated as authorized for `meddefense.com` in the receiving environment.
- DKIM: **Pass.** The message contains a valid DKIM signature for `meddefense.com` using selector `selector1`.
- DMARC: **Pass; action=none.** The visible `From:` domain passes DMARC, with no enforcement action requested.
- Authentication verdict: Authentication **supports the apparent legitimacy** of the email. The message is also shown as originating from an internal MedDefense Exchange server.
- Investigation meaning: The authentication evidence is consistent with an internal organizational announcement. Its content reinforces safe behavior by directing staff to use the normal internal portal and explicitly stating that IT will not email password-change links.
- Final verdict: **Legitimate internal IT announcement; authentication and routing evidence are consistent with the claimed sender.**

## Email 5 — medequip-supplies.net

- SPF: **Softfail.** The sending IP `185.176.43.22` is not authorized with a definitive SPF pass for `medequip-supplies.net`, but the domain's SPF result indicates a soft failure. This provides a negative authentication signal without being equivalent to an SPF hard fail.
- DKIM: **None.** The message is not DKIM-signed, so there is no cryptographic sender authentication from the claimed domain.
- DMARC: **Fail; action=none.** DMARC fails for the visible `From:` domain. The `action=none` value means the receiving system was not instructed to quarantine or reject the message solely on that failure.
- Authentication verdict: Authentication **contradicts the apparent legitimacy** of the invoice email. There is no DKIM support, SPF is only a softfail, and DMARC fails.
- Investigation meaning: The email requests payment of `USD 24,716.38`, provides an external payment portal, and includes a PDF containing a payment link. Angela Rivera already reported that the invoice looks wrong. These facts make the message inappropriate to treat as an authenticated vendor invoice without independent verification through an established vendor contact or procurement record.
- Final verdict: **Suspicious/likely fraudulent invoice email; do not rely on the email for payment authorization.**

## Email 6 — canadian-pharma-discount.org

- SPF: **Softfail.** The sending domain's SPF evaluation does not authorize the message with a pass result. This is a negative authentication signal.
- DKIM: **None.** No DKIM signature is present, so the claimed sender domain provides no cryptographic authentication.
- DMARC: **Fail; action=quarantine.** DMARC fails for the visible `From:` domain, and the domain's policy requests quarantine. The receiving system nevertheless has its own handling controls, and the message appears in this evidence batch.
- Authentication verdict: Authentication **strongly contradicts legitimacy**.
- Investigation meaning: The message is unsolicited pharmaceutical advertising, uses exaggerated discount claims, and explicitly offers prescription drugs without a prescription. Its spam score is `9.8` and its headers identify it as spam. The authentication failures are consistent with an untrusted bulk-mail source.
- Final verdict: **Spam; authentication failures and message characteristics provide no support for legitimacy.**

## Email 7 — meddefense-benefits.org

- SPF: **Fail.** The sending IP `164.90.218.73` is not authorized by SPF for `meddefense-benefits.org`.
- DKIM: **None.** No DKIM signature is present.
- DMARC: **Fail; action=none.** DMARC fails for the visible `From:` domain, while the domain's published policy shown to the receiver does not request an enforcement action.
- Authentication verdict: Authentication **strongly contradicts the apparent legitimacy** of the message claiming to be MedDefense HR Benefits.
- Investigation meaning: Linda Patterson says she never signed up for the purported benefits communication. The message uses a look-alike domain, an urgent enrollment deadline, a threat of coverage consequences, and an external enrollment link. Those characteristics match the phishing patterns described in Email 8.
- Final verdict: **Phishing/impersonation; authentication failures and the reported unsolicited nature support that assessment.**

## Email 8 — hhs.gov / HC3

- SPF: **Pass.** The sending IP `134.174.47.82` is authorized by SPF for `hhs.gov`.
- DKIM: **Pass.** The message contains a valid DKIM signature for `hhs.gov` using selector `hhs2026`.
- DMARC: **Pass; action=none.** DMARC succeeds for the visible `From:` domain, and `action=none` indicates no enforcement action was requested after the successful authentication.
- Authentication verdict: Authentication **supports the apparent legitimacy** of the message as mail from `hhs.gov`. It is consistent with the claimed HC3 sender and government domain.
- Investigation meaning: The message is a sector alert describing phishing patterns that closely correspond to Emails 2, 5, and 7, including look-alike domains, PHPMailer-based infrastructure, role-targeted lures, and urgency-based social engineering. The message itself is an advisory rather than evidence that every listed indicator has independently been confirmed in this batch; it explicitly says the observed patterns are not yet IOC-confirmed.
- Final verdict: **Likely legitimate HC3 advisory; authentication supports the claimed sender, while the advisory's preliminary status should be retained in incident records.**