# Suspicious URL and Indicator Analysis

## Indicator 1

- Source email: **E2 — MedDefense portal fake verification**
- Original value: `https://meddefense-portal.com/verify`
- Defanged value: `hxxps://meddefense-portal[.]com/verify`
- Domain or IP: `meddefense-portal.com`
- Indicator type: **Suspicious URL / lookalike domain**
- Evidence from email:
  - The message claims to be from MedDefense IT Security.
  - The legitimate organizational domain identified in the evidence is `meddefense.com`, while this link uses `meddefense-portal.com`.
  - The email requests urgent account re-verification within 24 hours.
  - The sending infrastructure is external and uses `91.234.99.107`.
  - SPF failed, DKIM was absent, and DMARC failed.
  - The URL therefore combines a lookalike domain, credential-verification pretext, and authentication failures.
- Safe investigation method:
  - `whois meddefense-portal.com`
  - `dig meddefense-portal.com`
  - `nslookup meddefense-portal.com`
  - `curl -I https://meddefense-portal.com/verify`
  - Submit the URL to VirusTotal or urlscan.io for reputation and historical observations.
  - Do not submit credentials or follow the link interactively from a production workstation.
- Finding: The URL is consistent with a phishing credential-verification portal. The domain resembles the legitimate MedDefense domain but is not `meddefense.com`. Email authentication also failed, reducing confidence in the claimed sender.
- Risk rating: **HIGH**

---

## Indicator 2

- Source email: **E3 — Imitation of Microsoft account breach**
- Original value: `https://outlook-protection.com/verify`
- Defanged value: `hxxps://outlook-protection[.]com/verify`
- Domain or IP: `outlook-protection.com`
- Indicator type: **Suspicious URL / impersonation domain**
- Evidence from email:
  - The message claims to be from Microsoft Account Protection.
  - The verification URL uses `outlook-protection.com`.
  - `outlook-protection.com` is not the same domain as `microsoft.com` or `outlook.com`.
  - The email threatens account lockout and requests immediate verification.
  - SPF, DKIM, and DMARC all pass, but they authenticate `outlook-protection.com`, not Microsoft.
  - The sending IP identified in the evidence is `51.38.42.17`.
  - The message uses PHPMailer-based external infrastructure.
- Safe investigation method:
  - `whois outlook-protection.com`
  - `dig outlook-protection.com`
  - `nslookup outlook-protection.com`
  - `curl -I https://outlook-protection.com/verify`
  - Check the URL and domain with VirusTotal or urlscan.io.
  - Do not enter Microsoft credentials into the site.
- Finding: The URL is suspicious because it uses a domain designed to appear related to Outlook/Microsoft while not belonging to the legitimate Microsoft domain. Successful SPF, DKIM, and DMARC authentication does not make the URL legitimate because those controls only authenticate the `outlook-protection.com` domain.
- Risk rating: **HIGH**

---

## Indicator 3

- Source email: **E5 — Invoice lure**
- Original value: `https://medequip-supplies.net/...` **(payment portal referenced by the invoice email)**
- Defanged value: `hxxps://medequip-supplies[.]net/...`
- Domain or IP: `medequip-supplies.net`
- Indicator type: **Suspicious payment URL / supplier impersonation**
- Evidence from email:
  - The email presents an invoice for `USD 24,716.38`.
  - The message requests payment through an external portal.
  - The sender uses `medequip-supplies.net`.
  - SPF softfails, DKIM is absent, and DMARC fails.
  - The sending IP is `185.176.43.22`.
  - The message was generated using PHPMailer infrastructure.
  - The recipient reported that the invoice appears incorrect.
  - The invoice/payment pretext creates financial pressure and a payment deadline.
- Safe investigation method:
  - `whois medequip-supplies.net`
  - `dig medequip-supplies.net`
  - `nslookup medequip-supplies.net`
  - `curl -I https://medequip-supplies.net/`
  - Check the complete URL in VirusTotal or urlscan.io.
  - Do not submit payment information or credentials.
- Finding: The URL is suspicious because it is associated with an externally hosted payment request combined with weak sender authentication and a high-value invoice. The authentication failures reduce trust in the claimed supplier identity and reinforce the payment-phishing assessment.
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
  - The enrollment link uses `meddefense-benefits.org` instead of the organization's legitimate `meddefense.com` domain.
  - The message threatens loss of coverage if the recipient does not act before the deadline.
  - The recipient is directed to an external enrollment portal.
  - The email addresses Linda by name and references her work email, making the lure targeted.
  - SPF fails, DKIM is absent, and DMARC fails.
  - The sending IP is `164.90.218.73`.
  - The recipient reportedly never signed up for the stated enrollment process.
- Safe investigation method:
  - `whois meddefense-benefits.org`
  - `dig meddefense-benefits.org`
  - `nslookup meddefense-benefits.org`
  - `curl -I https://meddefense-benefits.org/enroll`
  - Check the domain and URL with VirusTotal or urlscan.io.
  - Do not enter employee, benefits, or authentication information.
- Finding: The URL is consistent with a targeted benefits-enrollment phishing portal. The lookalike domain, failed authentication, urgent deadline, threat of coverage loss, and recipient-specific information all increase the risk.
- Risk rating: **HIGH**

---

## Indicator 5

- Source email: **Suspicious-email evidence batch — indicator `203.0.113.228`**
- Original value: `203.0.113.228`
- Defanged value: `203[.]0[.]113[.]228`
- Domain or IP: `203.0.113.228`
- Indicator type: **IP address indicator**
- Evidence from email:
  - The IP is included in the supplied suspicious-indicator set and should therefore be retained as an investigation indicator.
  - The available E2/E3/E5/E7 context identifies different sending IPs (`91.234.99.107`, `51.38.42.17`, `185.176.43.22`, and `164.90.218.73`), so `203.0.113.228` should not be incorrectly attributed to one of those messages without the original header evidence.
  - No additional attachment filename or URL path associated with this IP is established in the supplied context.
- Safe investigation method:
  - `whois 203.0.113.228`
  - `dig -x 203.0.113.228`
  - `nslookup 203.0.113.228`
  - Check the IP in VirusTotal.
  - Search the IP in urlscan.io or other approved threat-intelligence sources.
  - Correlate the IP against the original email headers, proxy logs, DNS logs, or SIEM data if those sources become available.
- Finding: `203.0.113.228` should be preserved as an investigation indicator, but the supplied email context does not establish which suspicious email, URL, or attachment it belongs to. Its attribution should therefore remain unconfirmed until the original evidence is checked.
- Risk rating: **UNCONFIRMED — investigate**

---

# Cross-Email Findings

- **Lookalike domains:** E2 and E7 use domains incorporating the MedDefense name without using the legitimate `meddefense.com` domain.
- **Microsoft impersonation:** E3 uses `outlook-protection.com` while claiming to represent Microsoft. Passing SPF/DKIM/DMARC only authenticates that lookalike domain.
- **Payment lure:** E5 combines an external supplier domain with a `USD 24,716.38` invoice and payment request.
- **Authentication weakness:** E2, E5, and E7 have failed or weak SPF/DMARC results and no DKIM signature, reducing trust in their claimed identities.
- **External infrastructure:** E2, E3, E5, and E7 use external sending infrastructure and PHP/PHPMailer indicators identified in the header analysis.
- **Targeting:** E7 contains recipient-specific benefits information and the recipient's work address, making it more targeted than the other lures.
- **Attachment evidence:** No specific attachment filename can be established from the supplied E2/E3/E5/E7 context. If the original evidence contains an attachment or embedded PDF reference, its exact filename/URL should be extracted rather than inferred.