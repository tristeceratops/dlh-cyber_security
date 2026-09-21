## Campaign Thread Analysis

### Shared Indicators

Emails 2, 5, and 7 show several common characteristics that support a coordinated phishing-campaign hypothesis:

| Indicator | E2 | E5 | E7 | Campaign Relevance |
|---|---|---|---|---|
| Lookalike / external sender domain | `meddefense-portal.com` | `medequip-supplies.net` | `meddefense-benefits.org` | All use external domains rather than the legitimate `meddefense.com` domain. E2 and E7 specifically imitate MedDefense-related services. |
| PHPMailer | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 | Strong common tooling indicator across all three messages. |
| DKIM | None | None | None | All three messages lack DKIM signatures. |
| DMARC | Fail | Fail | Fail | All three fail DMARC. |
| SPF | Fail | Softfail | Fail | All three have weakened sender authentication. |
| Priority / urgency | `X-Priority: 1`, `X-MSMail-Priority: High` | `X-Priority: 1` | High-priority/urgent presentation | Consistent attempt to make the messages appear important and time-sensitive. |
| Urgency | 24-hour verification deadline | Payment due within 7 days | Enrollment closes tomorrow | All use deadlines to pressure the recipient into acting quickly. |
| Business-process lure | Portal/EHR access | Invoice/payment | Benefits enrollment | Different organizational processes are used as the pretext. |
| External action | Credential verification | Payment/login portal | Benefits enrollment/login | Each attempts to move the recipient to an external action or portal. |

The strongest technical commonality is the repeated use of **PHPMailer 6.6.0** together with weak or failed email authentication. This does not by itself prove that the same infrastructure or actor sent all three messages, because PHPMailer is a commonly available email library.

The messages also share a common social-engineering structure: impersonate a trusted business process, introduce a deadline or consequence, and direct the recipient toward an external action.

The sender domains and sending IP addresses are different:

- E2: `meddefense-portal.com` — `91.234.99.107`
- E5: `medequip-supplies.net` — `185.176.43.22`
- E7: `meddefense-benefits.org` — `164.90.218.73`

Therefore, the available evidence does **not** establish a single shared server or IP address.

### Targeting Map

| Email | Target Group | Pretext / Business Process | Targeting Evidence | Requested Action |
|---|---|---|---|---|
| E2 | Clinical staff | MedDefense staff portal/security verification | References staff portal access, scheduling system, EHR gateway and shift-swap functions; recipient-specific identifier `dmarsh` | Verify portal access and provide credentials |
| E5 | Accounts payable / finance | Supplier invoice and payment | Invoice number and high-value payment request of USD 24,716.38; supplier/payment context | Review/pay invoice through external portal |
| E7 | HR / benefits-related staff | Employee benefits/open enrollment | Benefits enrollment context, recipient-specific information, deadline and threat of coverage loss | Access external benefits portal and provide information |

The targeting pattern is significant because the three messages do not rely on one generic lure. Instead, they address different organizational functions:

**Clinical operations → Finance/AP → HR/Benefits**

This is consistent with an attacker attempting to reach multiple departments by adapting the pretext to the responsibilities of each recipient group.

### Timing Map

| Email | Evidence Date | Timing Pattern |
|---|---|---|
| E2 | April 14, 2026 | First observed phishing message in the sequence |
| E5 | April 16, 2026 | Additional phishing message using a finance/payment pretext |
| E7 | April 16, 2026 | Additional phishing message using an HR/benefits pretext |

The evidence establishes E2 on **April 14** and E5 and E7 on **April 16**.

There is no basis in the supplied evidence for inserting an April 15 delivery. The available sequence therefore shows phishing activity on April 14 followed by additional activity on April 16.

The proximity of the messages in time, combined with their shared PHPMailer version, failed/weak authentication, urgency, and organizational targeting, is consistent with a campaign operating across multiple business functions.

However, timing alone cannot establish common authorship. A two-day window is compatible with coordinated activity but could also occur among unrelated phishing operations.

### Comparison With HC3 Alert

Email 8 is a legitimate HC3 alert from `hhs.gov` describing an active phishing campaign targeting regional healthcare organizations.

The observed MedDefense emails show several patterns that are consistent with the type of activity described by the alert:

| HC3 / Observed Pattern | E2 | E5 | E7 |
|---|---|---|---|
| Healthcare-sector targeting | Yes | Yes | Yes |
| Lookalike/external domains | Yes | Yes | Yes |
| Role-specific lures | Clinical/portal | Finance/payment | HR/benefits |
| Urgency/deadlines | 24 hours | 7 days | Tomorrow |
| External action or portal | Yes | Yes | Yes |
| Credential/payment/data objective | Credentials | Payment/credentials | Benefits information/credentials |

Email 8 therefore provides contextual support for interpreting E2, E5, and E7 as examples of healthcare-sector phishing activity.

The HC3 alert does **not**, by itself, prove that E2, E5, and E7 were sent by the same actor responsible for the campaign described by HC3. It establishes that similar phishing activity was actively targeting the healthcare sector and provides relevant threat context.

### Attribution Assessment

The evidence supports several conclusions with reasonable confidence:

1. **E2, E5, and E7 are phishing messages.**
2. **The messages share common characteristics**, including PHPMailer 6.6.0, absent DKIM, failed DMARC, weak/failed SPF, urgency, external action, and business-process impersonation.
3. **The messages appear to have been designed around different organizational roles**, allowing the same general phishing approach to be adapted for clinical operations, finance, and HR/benefits.
4. **The messages were delivered within a short period**, with E2 on April 14 and E5/E7 on April 16.
5. **The activity is consistent with the healthcare-sector phishing pattern described by Email 8.**

The evidence does **not** prove:

- that the three domains were operated by the same person or organization;
- that the three sending IP addresses belong to the same infrastructure provider or threat actor;
- that PHPMailer 6.6.0 uniquely identifies an attacker;
- that the same phishing kit or backend was used;
- that the activity was conducted by a particular named threat actor;
- that Email 8's threat actor and the sender of E2, E5, or E7 are definitively the same.

Additional passive investigation would be required to strengthen infrastructure linkage, including passive DNS, historical WHOIS/domain-registration information, certificate transparency records, hosting relationships, URL/HTML similarities, malware or attachment hashes if present, and threat-intelligence correlation.

### Conclusion

The evidence **supports the assessment that E2, E5, and E7 are likely components of a coordinated phishing campaign targeting MedDefense**, rather than three completely unrelated suspicious emails.

The strongest evidence for coordination is the combination of:

- common PHPMailer 6.6.0 tooling;
- consistent absence of DKIM and failed/weak SPF/DMARC;
- closely related delivery timing;
- urgency and deadline-based social engineering;
- external portals or actions;
- adaptation of the lure to different MedDefense business functions;
- use of external or lookalike domains;
- alignment with the healthcare-sector phishing pattern described in Email 8.

At the same time, the available evidence is insufficient to attribute the campaign to a specific threat actor or to prove that all three sender domains and IP addresses share the same underlying infrastructure.

**Assessment: The evidence supports a single coordinated campaign hypothesis with high confidence at the behavioral/campaign-pattern level, but infrastructure-level and actor-level attribution remains unproven.**