# Suspicious URL and Indicator Analysis

## Indicator 1

- Source email: **E2 — MedDefense portal fake verification**
- Original value: `https://meddefense-portal.com/verify`
- Defanged value: `hxxps://meddefense-portal[.]com/verify`
- Domain or IP: `meddefense-portal.com`
- Indicator type: **Suspicious URL / lookalike domain**
- Evidence from email:
  - The email claims to be from MedDefense IT Security.
  - The URL uses `meddefense-portal.com` rather than the legitimate `meddefense.com` domain.
  - The message requires account re-verification within 24 hours.
  - The email requests the recipient to use an external verification portal.
  - Sending IP: `91.234.99.107`.
  - SPF: **Fail**.
  - DKIM: **None**.
  - DMARC: **Fail**.
  - The sending infrastructure uses PHPMailer.
- Safe investigation method:
  - `whois meddefense-portal.com`
  - `dig meddefense-portal.com`
  - `nslookup meddefense-portal.com`
  - VirusTotal domain/URL lookup.
  - urlscan.io lookup.
  - Passive DNS or threat-intelligence lookup.
  - Offline review of the original `.eml` headers and HTML source.
  - Do **not** browse to the URL, submit credentials, follow redirects, or make direct HTTP requests to the suspicious site.
- Finding: The domain is a lookalike of the legitimate MedDefense domain and is used in a credential-verification pretext. The failed SPF/DMARC results and absent DKIM further reduce trust in the claimed sender. IOC searching should be performed against the domain and related sending infrastructure rather than interacting with the site.
- Risk rating: **HIGH**

---

## Indicator 2

- Source email: **E3 — Imitation of Microsoft account breach**
- Original value: `https://outlook-protection.com/verify`
- Defanged value: `hxxps://outlook-protection[.]com/verify`
- Domain or IP: `outlook-protection.com`
- Indicator type: **Suspicious URL / Microsoft impersonation domain**
- Evidence from email:
  - The email claims to be from Microsoft Account Protection.
  - The verification URL points to `outlook-protection.com`.
  - `outlook-protection.com` is not the same domain as `microsoft.com` or `outlook.com`.
  - The message threatens account lockout and demands verification.
  - SPF: **Pass**.
  - DKIM: **Pass**.
  - DMARC: **Pass**.
  - The successful authentication applies to `outlook-protection.com`; it does not authenticate Microsoft.
  - Sending IP: `51.38.42.17`.
  - The message uses PHPMailer-based external infrastructure.
- Safe investigation method:
  - `whois outlook-protection.com`
  - `dig outlook-protection.com`
  - `nslookup outlook-protection.com`
  - VirusTotal domain/URL lookup.
  - urlscan.io lookup.
  - Passive DNS or threat-intelligence lookup.
  - Offline inspection of the original email headers and HTML source.
  - Do **not** open the verification URL or submit Microsoft credentials.
- Finding: The URL is suspicious because the domain is designed to appear associated with Outlook/Microsoft while not being a Microsoft domain. Passing SPF, DKIM, and DMARC does not establish legitimacy because those mechanisms only authenticate the `outlook-protection.com` domain. The URL therefore remains a high-risk impersonation indicator.
- Risk rating: **HIGH**

---

## Indicator 3

- Source email: **E5 — Invoice lure**
- Original value: `https://medequip-supplies.net/...`
- Defanged value: `hxxps://medequip-supplies[.]net/...`
- Domain or IP: `medequip-supplies.net`
- Indicator type: **Suspicious payment URL / supplier impersonation**
- Evidence from email:
  - The message presents an invoice for **USD 24,716.38**.
  - The email requests payment through an external portal.
  - The sender uses `medequip-supplies.net`.
  - SPF: **Softfail**.
  - DKIM: **None**.
  - DMARC: **Fail**.
  - Sending IP: `185.176.43.22`.
  - The message uses PHPMailer infrastructure.
  - The recipient reported that the invoice appears incorrect.
  - The payment request creates financial pressure and includes a seven-day deadline.
- Safe investigation method:
  - `whois medequip-supplies.net`
  - `dig medequip-supplies.net`
  - `nslookup medequip-supplies.net`
  - VirusTotal domain/URL lookup.
  - urlscan.io lookup.
  - Passive DNS or threat-intelligence lookup.
  - Offline review of the invoice email and any locally preserved attachment or HTML source.
  - If an attachment exists in the evidence, calculate its hash and perform hash/reputation lookups without opening it.
  - Do **not** access the payment portal or submit payment information.
- Finding: The domain is associated with a high-value payment request and weak sender authentication. SPF softfail, absent DKIM, and failed DMARC reduce trust in the claimed supplier identity. The external payment portal and incorrect-invoice report reinforce the assessment that this is a potential payment-phishing lure.
- Risk rating: **HIGH**

---

## Indicator 4

- Source email: **E7 — Benefits enrollment phishing lure**
- Original value: `https://meddefense-benefits.org/enroll`
- Defanged value: `hxxps://meddefense-benefits[.]org/enroll`
- Domain or IP: `meddefense-benefits.org`
- Indicator type: **Suspicious URL / lookalike domain / credential-harvesting portal**
- Evidence from email:
  - The message claims to be from MedDefense Human Resources Benefits Administration.
  - The enrollment URL uses `meddefense-benefits.org` rather than the legitimate `meddefense.com`.
  - The email says open enrollment closes tomorrow.
  - It threatens loss of current coverage if the recipient does not act.
  - The recipient is directed to an external enrollment portal.
  - The email addresses Linda by name and references her work email address.
  - SPF: **Fail**.
  - DKIM: **None**.
  - DMARC: **Fail**.
  - Sending IP: `164.90.218.73`.
  - The recipient reportedly never signed up for the stated enrollment process.
- Safe investigation method:
  - `whois meddefense-benefits.org`
  - `dig meddefense-benefits.org`
  - `nslookup meddefense-benefits.org`
  - VirusTotal domain/URL lookup.
  - urlscan.io lookup.
  - Passive DNS or threat-intelligence lookup.
  - Offline inspection of the original `.eml` file and HTML source.
  - Do **not** access the enrollment portal or provide employee, benefits, or authentication information.
- Finding: The URL is consistent with a targeted benefits-enrollment phishing portal. The lookalike domain, failed SPF/DMARC, absent DKIM, recipient-specific information, deadline, and threat of coverage loss all support the phishing assessment.
- Risk rating: **HIGH**

---

## Indicator 5

- Source email: **Suspicious-email evidence batch — attribution not established from the supplied E2/E3/E5/E7 headers**
- Original value: `203.0.113.228`
- Defanged value: `203[.]0[.]113[.]228`
- Domain or IP: `203.0.113.228`
- Indicator type: **IP address indicator**
- Evidence from email:
  - `203.0.113.228` is explicitly included in the required suspicious-indicator set.
  - The supplied E2/E3/E5/E7 header analysis identifies different sending IPs:
    - E2: `91.234.99.107`
    - E3: `51.38.42.17`
    - E5: `185.176.43.22`
    - E7: `164.90.218.73`
  - Therefore, the supplied evidence does not establish that `203.0.113.228` is the sending IP of E2, E3, E5, or E7.
  - No specific attachment filename is established for this IP in the available evidence.
- Safe investigation method:
  - `whois 203.0.113.228`
  - `dig -x 203.0.113.228`
  - `nslookup 203.0.113.228`
  - VirusTotal IP lookup.
  - Passive DNS lookup.
  - Threat-intelligence lookup.
  - Search the IP against the original email headers and locally available evidence.
  - Correlate it with SIEM, proxy, DNS, or mail logs only if those datasets are available.
- Finding: `203.0.113.228` should be retained as an investigation indicator because it was supplied as part of the suspicious-indicator set. However, its association with a particular suspicious email cannot be established from the E2/E3/E5/E7 evidence currently provided. It should therefore remain **unconfirmed** rather than being incorrectly attributed to one of the four emails.
- Risk rating: **UNCONFIRMED — INVESTIGATE**

---

## Cross-Email Findings

- **E2:** `meddefense-portal[.]com` is a MedDefense lookalike domain used for an urgent account-verification lure. Authentication failures materially reduce sender trust.
- **E3:** `outlook-protection[.]com` is a Microsoft/Outlook impersonation domain. Authentication passes, but only for the attacker-controlled/lookalike domain; it does not authenticate Microsoft.
- **E5:** `medequip-supplies[.]net` is associated with a high-value invoice and external payment request. Weak/failed authentication reinforces the suspicious payment assessment.
- **E7:** `meddefense-benefits[.]org` is a MedDefense lookalike domain used for a targeted benefits-enrollment lure. The URL, recipient-specific details, deadline, and authentication failures support the phishing assessment.
- **203[.]0[.]113[.]228:** Retain as an IOC, but do not assign it to a specific email without supporting header evidence.
- **Attachments:** The supplied E2/E3/E5/E7 evidence does not establish a specific attachment filename or attachment hash. No attachment indicator should be invented. If the original `.eml` evidence contains an attachment, analyze the preserved file offline using filename, MIME type, hash, and metadata rather than opening it.
- **Investigation principle:** The recommended methods above are passive or reputation-based. They avoid directly contacting the suspicious URLs. CISA guidance supports collecting and searching indicators across available network and host artifacts during an investigation. :contentReference[oaicite:0]{index=0}