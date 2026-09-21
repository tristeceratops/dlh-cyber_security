# MedDefense Health Systems — Phishing Campaign Investigation Report

## 1. Executive Summary

The investigation identified four phishing emails, two spam messages, and two legitimate communications in the eight-email evidence set. Emails 2, 5, and 7 share technical and behavioral characteristics consistent with a coordinated phishing campaign targeting different MedDefense business functions. Email 8, a legitimate HC3 alert, provides independent healthcare-sector context consistent with the observed activity. Diane Marsh is confirmed to have clicked the Email 2 phishing link, but the evidence does not establish credential or endpoint compromise. Immediate containment and investigation are recommended.

## 2. Investigation Timeline

| Date | Event |
|---|---|
| Apr 14, 2026 19:47:48 UTC | E2 delivered to Diane Marsh. |
| Apr 14, 2026 | Diane Marsh reportedly clicked the E2 link from `WS-NURSE-04`; exact click time is unknown. |
| Apr 16, 2026 | E5 and E7 phishing emails observed. |
| Investigation scope | E1–E8 headers, authentication, content, URLs, infrastructure, targeting, campaign relationships, and the reported E2 click were reviewed. Endpoint, proxy, SIEM, and identity logs were not provided. |

## 3. Email-by-Email Analysis

| Email | Classification | Confidence | Key Evidence |
|---|---|---|---|
| E1 | `SPAM` | HIGH | SPF/DKIM/DMARC pass and align with the sender domain; unsolicited bulk medical newsletter; no strong phishing indicators. |
| E2 | `PHISHING-OPPORTUNISTIC` | HIGH | SPF fail, DKIM absent, DMARC fail; `meddefense-portal.com` impersonates MedDefense; 24-hour deadline; credential-verification URL; PHPMailer 6.6.0. |
| E3 | `PHISHING-OPPORTUNISTIC` | HIGH | Authentication passes only for `outlook-protection.com`; domain is not Microsoft; Microsoft impersonation; lockout threat; external verification URL. |
| E4 | `LEGITIMATE` | HIGH | SPF/DKIM/DMARC pass for `meddefense.com`; internal Exchange routing; normal internal password-change communication. |
| E5 | `PHISHING-OPPORTUNISTIC` | HIGH | SPF softfail, DKIM absent, DMARC fail; USD 24,716.38 invoice; external payment portal; suspicious supplier identity; PHPMailer 6.6.0. |
| E6 | `SPAM` | HIGH | SPF softfail, DKIM absent, DMARC fail; pharmaceutical advertising; `X-Spam-Score: 9.8`; unsolicited prescription-drug offer. |
| E7 | `PHISHING-TARGETED` | HIGH | SPF fail, DKIM absent, DMARC fail; MedDefense benefits lookalike domain; recipient-specific information; benefits deadline; threat of coverage loss; external enrollment portal. |
| E8 | `LEGITIMATE` | HIGH | SPF/DKIM/DMARC pass for `hhs.gov`; legitimate HC3 sender; security advisory content; no credential or payment request. |

### Classification Refinement

The initial triage identified E2, E3, E5, and E7 as suspicious. Deeper analysis refined these into phishing classifications without overturning the initial security disposition.

E2, E3, and E5 are classified as opportunistic phishing because the evidence supports common phishing scenarios without sufficient evidence of highly individualized targeting. E7 is classified as targeted phishing because it contains stronger recipient- and organization-specific benefits information.

## 4. Campaign Analysis

E2, E5, and E7 are likely connected because they share **PHPMailer 6.6.0**, weak sender authentication, urgent deadlines, external actions, and business-process impersonation. Their lures target different functions: **clinical portal access (E2), finance/payment (E5), and HR/benefits (E7)**, with activity on April 14 and April 16. Their domains and sending IPs differ, so the evidence supports campaign-level coordination but does not prove common infrastructure or a specific actor.

E8 strengthens the hypothesis by describing healthcare-sector phishing using patterns such as lookalike domains, role-specific lures, urgency, and external actions. E3 should be considered related phishing activity: its SPF/DKIM/DMARC passes authenticate `outlook-protection.com`, but the message impersonates Microsoft, demonstrating that successful authentication does not establish legitimacy.

## 5. Click Incident Assessment

Diane Marsh is confirmed to have clicked:

`hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`

from `WS-NURSE-04`. The evidence does **not** establish the exact click time, click-source IP, page execution, credential submission, MFA exposure, downloads, malware execution, or subsequent account compromise. `91.234.99.107` is the phishing email's sending IP, not Diane's confirmed workstation IP.

**Next actions:** review browser, DNS/proxy, EDR, and identity logs; check authentication/MFA/session activity; inspect downloads and processes; search for other affected users; and reset credentials/revoke sessions if exposure cannot be ruled out.

## 6. IOC Summary

**Domains:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`

**IPs:** `91[.]234[.]99[.]107`, `51[.]38[.]42[.]17`, `185[.]176[.]43[.]22`, `164[.]90[.]218[.]73`

**Senders:** `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`

**URLs:**  
`hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`  
`hxxps://outlook-protection[.]com/verify`  
`hxxps://meddefense-benefits[.]org/enroll`

**Additional indicators:** PHPMailer 6.6.0 and repeated SPF/DKIM/DMARC anomalies. The E5 attachment hash and PDF URL were not available in the supplied evidence and should be extracted from the original message before distribution.

## 7. Detection and Control Gaps

Existing authentication controls did not prevent delivery: E2, E5, and E7 had authentication failures, while E3 passed authentication for an attacker-controlled/lookalike domain. Detection should therefore combine authentication with **lookalike-domain detection, sender reputation, urgent business-process lures, external credential/payment links, and post-click identity/endpoint activity**.

Recommended detections include campaign-domain blocking, suspicious-domain DNS/web alerts, PHPMailer plus external-domain correlation, phishing-link access followed by authentication events, and monitoring for newly observed domains resembling `meddefense.com`.

## 8. Recommendations

### Immediate — 24 Hours

- Block the four confirmed phishing domains/URLs and associated senders.
- Investigate Diane Marsh's click and preserve endpoint/email evidence.
- Review identity/MFA activity and reset credentials/revoke sessions if exposure is possible.
- Hunt for additional recipients and users who accessed the indicators.

### Short-Term — 7 Days

- Hunt historical email, DNS, proxy, EDR, and identity telemetry for campaign indicators.
- Recover the missing E5 attachment hash/PDF URL.
- Tune impersonation, lookalike-domain, and external-link detection.
- Share validated IOCs and campaign characteristics with HC3.

### Medium-Term — 30 Days

- Strengthen phishing-resistant MFA and lookalike-domain detection.
- Integrate email, DNS, endpoint, and identity telemetry into phishing investigations.
- Update phishing-response procedures and conduct role-specific awareness exercises for clinical, finance, and HR teams.

## Final Assessment

The evidence supports a **coordinated healthcare-sector phishing campaign targeting MedDefense**, with E2, E5, and E7 sharing meaningful technical, temporal, and behavioral characteristics. The evidence does not establish a specific threat actor or prove that all sender infrastructure is controlled by one entity. The Diane Marsh click is confirmed, but compromise remains unproven pending endpoint and identity-log investigation.