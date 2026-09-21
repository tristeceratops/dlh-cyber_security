## Email 2 — Meddefense portal fake verification

- Psychological lever: Urgency, authority, fear, impersonation
- Pretext: The email claims to be from MedDefense IT Security and says the recipient must re-verify their portal account within 24 hours to prevent account suspension.
- Requested action: Click a link and log in/verify account credentials.
- Targeting level: SEMI-TARGETED: the lure uses the MedDefense organization and presents itself as an internal IT/security message, but the content does not show evidence of highly individualized knowledge about the recipient.
- Content red flags:
	- 24-hour deadline creates urgency.
	- Threat of account suspension creates fear.
	- Claims to come from MedDefense IT Security.
	- Uses the look-alike domain meddefense-portal.com instead of meddefense.com.
	- Requests account verification through an external portal.
	- SPF fails, DKIM is absent, and DMARC fails.
- Attacker knowledge required: The attacker likely needed to know the organization's name, its legitimate domain (meddefense.com), that employees use an online portal, and common IT/security terminology. No evidence indicates that extensive personal information about the recipient was required.
- Conclusion: A phishing lure using urgency, authority, fear, and impersonation to obtain account credentials through a fraudulent MedDefense portal.

## Email 3 —  Imitation of Microsoft account breach

- Psychological lever: Urgency, authority, fear, impersonation
- Pretext: The email claims to be from Microsoft Account Protection and warns the recipient about unusual sign-in activity, implying that immediate verification is required to prevent account lockout.
- Requested action: Click a verification link and log in/verify the Microsoft account.
- Targeting level: GENERIC: the lure imitates a common Microsoft security alert and does not contain evidence of recipient-specific information beyond the account context.
- Content red flags:
	- Claims to represent Microsoft Account Protection.
	- Threatens account lockout within a short period.
	- Uses an external verification link.
	- Sender domain is outlook-protection.com, not microsoft.com or outlook.com.
	- SPF, DKIM, and DMARC pass, but they authenticate outlook-protection.com, not Microsoft.
	- Uses external PHP-based mail infrastructure.
- Attacker knowledge required: The attacker mainly needed knowledge of Microsoft's branding, account-security notification patterns, and the existence of Microsoft/Outlook accounts. They did not appear to need detailed information about the individual recipient.
- Conclusion: A Microsoft impersonation phishing lure designed to create fear of account compromise and urgency to capture credentials.

## Email 5 — Invoice lure

- Psychological lever: Urgency, financial pressure, impersonation
- Pretext: The email presents itself as a legitimate supplier invoice and states that payment of USD 24,716.38 is required within seven days.
- Requested action: Click the payment/login link and make or arrange payment.
- Targeting level: SEMI-TARGETED: the message uses a business invoice scenario and a specific invoice number and amount, suggesting some preparation, but the available evidence does not establish extensive knowledge of the recipient's actual purchasing activity.
- Content red flags:
	- Specific high-value payment request.
	- Seven-day payment deadline.
	- External payment portal.
	- Sender uses medequip-supplies.net, requiring the recipient to trust an external supplier identity.
	- SPF softfails.
	- DKIM is absent.
	- DMARC fails.
	- PHP-based external sending infrastructure.
	- Recipient reported that the invoice appears incorrect.
- Attacker knowledge required: The attacker likely needed a plausible supplier name, invoice format, payment terminology, and possibly knowledge that the organization receives supplier invoices. A realistic invoice number and payment amount would make the lure more convincing, but the evidence does not establish how those details were obtained.
- Conclusion: A suspected invoice-payment phishing lure that combines financial pressure and urgency with a fabricated or untrusted supplier identity to encourage a high-value payment.

## Email 7 — Benefits enrollment phishing lure

- Psychological lever: Urgency, fear, scarcity, impersonation
- Pretext: The email claims to be from MedDefense Human Resources Benefits Administration and tells the recipient that open enrollment closes tomorrow. It threatens loss of current coverage if the recipient does not re-enroll.
- Requested action: Click the enrollment link and log in/provide benefits information.
- Targeting level: TARGETED: the message addresses Linda by name, references the recipient's supposed benefits status, and states that the message was sent to lpatterson@meddefense.com. These details indicate targeting beyond a generic bulk lure.
- Content red flags:
	- Uses the recipient's name.
	- Claims the recipient has not completed re-enrollment.
	- Very short deadline: enrollment closes tomorrow at midnight.
	- Threatens loss of current coverage.
	- Creates scarcity through a limited enrollment period.
	- Uses a look-alike domain, meddefense-benefits.org, rather than meddefense.com.
	- Directs the recipient to an external enrollment portal.
	- SPF fails, DKIM is absent, and DMARC fails.
	- Recipient reportedly never signed up for the benefits process.
- Attacker knowledge required: The attacker likely needed the recipient's name, work email address, knowledge that MedDefense has employee benefits/open enrollment, and enough organizational context to make the benefits-enrollment scenario believable. The recipient-specific details suggest access to some employee or organizational information.
- Conclusion: A targeted benefits-enrollment phishing lure using urgency, fear, scarcity, and MedDefense HR impersonation to obtain portal credentials or benefits information.