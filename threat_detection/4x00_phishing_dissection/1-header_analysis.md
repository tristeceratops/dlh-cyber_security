## Email 2 — meddefense-portal.com

### Header Evidence

* From: `noreply@meddefense-portal.com`
* Return-Path: `noreply@meddefense-portal.com`
* Sending IP: `91.234.99.107`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-5D7E2F4A@meddefense-portal.com>`

### Received Chain Summary

1. `mail.meddefense-portal.com` (`91.234.99.107`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. Localhost (`127.0.0.1`) → `mail.meddefense-portal.com`

### Anomalies

* [HIGH] SPF failed: `91.234.99.107` is not authorized to send for `meddefense-portal.com`.
* [HIGH] DKIM is absent; the message has no cryptographic signature.
* [HIGH] DMARC failed for the claimed `meddefense-portal.com` sender.
* [HIGH] Claimed MedDefense sender uses `meddefense-portal.com` rather than the organization's `meddefense.com` domain.
* [MEDIUM] Sending infrastructure identifies as `PHPMailer 6.6.0`, rather than the organization's internal mail infrastructure.
* [MEDIUM] Message-ID uses a PHP-generated format: `PHP-5D7E2F4A@meddefense-portal.com`.
* [MEDIUM] The message uses an urgent 24-hour deadline and threatens loss of portal, EHR gateway, and scheduling access.

### Conclusion

The headers strongly support treating E2 as a phishing message. The claimed sender domain fails SPF and DMARC, has no DKIM signature, and the external sending IP is not authorized for the domain. The PHPMailer-generated message and externally hosted look-alike domain further distinguish it from legitimate MedDefense internal mail.

---

## Email 3 — outlook-protection.com

### Header Evidence

* From: `security@outlook-protection.com`
* Return-Path: `security@outlook-protection.com`
* Sending IP: `51.38.42.17`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-9F2D7E1B@outlook-protection.com>`

### Received Chain Summary

1. `mail.outlook-protection.com` (`51.38.42.17`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. `wp-admin.outlook-protection.com` (`127.0.0.1`) → `mail.outlook-protection.com`

### Anomalies

* [HIGH] The visible sender claims to be `"Microsoft Account Protection"` but uses `outlook-protection.com`, not an official Microsoft domain.
* [HIGH] The verification link points to `https://outlook-protection.com/verify`, matching the impersonating domain rather than an official Microsoft service.
* [MEDIUM] Although SPF, DKIM, and DMARC all pass, they authenticate `outlook-protection.com`; they do not establish that the sender is Microsoft.
* [MEDIUM] Sending infrastructure uses `PHPMailer 6.6.0`, inconsistent with the claimed Microsoft identity.
* [MEDIUM] Message-ID is PHP-generated: `PHP-9F2D7E1B@outlook-protection.com`.
* [MEDIUM] Message uses an urgent 48-hour account-lockout threat.

### Conclusion

The authentication results are internally consistent with `outlook-protection.com`, but the authenticated domain itself does not match the claimed Microsoft identity. The external PHPMailer infrastructure, look-alike domain, and credential-verification link support classifying E3 as suspicious impersonation/phishing.

---

## Email 5 — medequip-supplies.net

### Header Evidence

* From: `invoices@medequip-supplies.net`
* Return-Path: `invoices@medequip-supplies.net`
* Sending IP: `185.176.43.22`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-7C2D4E1A@medequip-supplies.net>`

### Received Chain Summary

1. `mail.medequip-supplies.net` (`185.176.43.22`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. `billing-svc.medequip-supplies.net` (`127.0.0.1`) → `mail.medequip-supplies.net`

### Anomalies

* [HIGH] SPF softfailed: `185.176.43.22` is not properly authorized for `medequip-supplies.net`.
* [HIGH] DKIM is absent.
* [HIGH] DMARC failed for `medequip-supplies.net`.
* [HIGH] The message requests payment of USD 24,716.38 through an externally hosted payment portal.
* [MEDIUM] Sending infrastructure uses `PHPMailer 6.6.0`.
* [MEDIUM] Message-ID uses a PHP-generated format: `PHP-7C2D4E1A@medequip-supplies.net`.
* [MEDIUM] `X-Priority: 1 (Highest)` adds urgency to a financial request.
* [MEDIUM] Recipient reported that the invoice appears incorrect.

### Conclusion

E5 has multiple authentication failures combined with an externally hosted payment request and PHP-based sending infrastructure. The authentication and content evidence support treating the message as a suspicious invoice/payment phishing attempt.

---

## Email 7 — meddefense-benefits.org

### Header Evidence

* From: `hr-notifications@meddefense-benefits.org`
* Return-Path: `hr-notifications@meddefense-benefits.org`
* Sending IP: `164.90.218.73`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-2E4A7B1C@meddefense-benefits.org>`

### Received Chain Summary

1. `mail.meddefense-benefits.org` (`164.90.218.73`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. `wp-portal.meddefense-benefits.org` (`127.0.0.1`) → `mail.meddefense-benefits.org`

### Anomalies

* [HIGH] SPF failed: `164.90.218.73` is not authorized to send for `meddefense-benefits.org`.
* [HIGH] DKIM is absent.
* [HIGH] DMARC failed for `meddefense-benefits.org`.
* [HIGH] The claimed MedDefense HR sender uses `meddefense-benefits.org` instead of the organization's `meddefense.com` domain.
* [HIGH] The message links to an external benefits enrollment portal on the look-alike domain.
* [MEDIUM] Sending infrastructure uses `PHPMailer 6.6.0`.
* [MEDIUM] Message-ID uses a PHP-generated format: `PHP-2E4A7B1C@meddefense-benefits.org`.
* [MEDIUM] The message creates an urgent enrollment deadline and threatens loss of coverage.
* [MEDIUM] Recipient reported never signing up for the referenced enrollment activity.

### Conclusion

E7 shows SPF and DMARC failure, no DKIM signature, an external look-alike domain, and PHPMailer-based infrastructure. Combined with the urgent benefits-enrollment pretext and external enrollment link, the headers and content strongly support treating E7 as a phishing attempt.
## Email 2 — meddefense-portal.com

### Header Evidence

* From: `noreply@meddefense-portal.com`
* Return-Path: `noreply@meddefense-portal.com`
* Sending IP: `91.234.99.107`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-5D7E2F4A@meddefense-portal.com>`

### Received Chain Summary

1. `mail.meddefense-portal.com` (`91.234.99.107`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. Localhost (`127.0.0.1`) → `mail.meddefense-portal.com`

### Anomalies

* [HIGH] SPF failed: `91.234.99.107` is not authorized to send for `meddefense-portal.com`.
* [HIGH] DKIM is absent; the message has no cryptographic signature.
* [HIGH] DMARC failed for the claimed `meddefense-portal.com` sender.
* [HIGH] Claimed MedDefense sender uses `meddefense-portal.com` rather than the organization's `meddefense.com` domain.
* [MEDIUM] Sending infrastructure identifies as `PHPMailer 6.6.0`, rather than the organization's internal mail infrastructure.
* [MEDIUM] Message-ID uses a PHP-generated format: `PHP-5D7E2F4A@meddefense-portal.com`.
* [MEDIUM] The message uses an urgent 24-hour deadline and threatens loss of portal, EHR gateway, and scheduling access.

### Conclusion

The headers strongly support treating E2 as a phishing message. The claimed sender domain fails SPF and DMARC, has no DKIM signature, and the external sending IP is not authorized for the domain. The PHPMailer-generated message and externally hosted look-alike domain further distinguish it from legitimate MedDefense internal mail.

---

## Email 3 — outlook-protection.com

### Header Evidence

* From: `security@outlook-protection.com`
* Return-Path: `security@outlook-protection.com`
* Sending IP: `51.38.42.17`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-9F2D7E1B@outlook-protection.com>`

### Received Chain Summary

1. `mail.outlook-protection.com` (`51.38.42.17`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. `wp-admin.outlook-protection.com` (`127.0.0.1`) → `mail.outlook-protection.com`

### Anomalies

* [HIGH] The visible sender claims to be `"Microsoft Account Protection"` but uses `outlook-protection.com`, not an official Microsoft domain.
* [HIGH] The verification link points to `https://outlook-protection.com/verify`, matching the impersonating domain rather than an official Microsoft service.
* [MEDIUM] Although SPF, DKIM, and DMARC all pass, they authenticate `outlook-protection.com`; they do not establish that the sender is Microsoft.
* [MEDIUM] Sending infrastructure uses `PHPMailer 6.6.0`, inconsistent with the claimed Microsoft identity.
* [MEDIUM] Message-ID is PHP-generated: `PHP-9F2D7E1B@outlook-protection.com`.
* [MEDIUM] Message uses an urgent 48-hour account-lockout threat.

### Conclusion

The authentication results are internally consistent with `outlook-protection.com`, but the authenticated domain itself does not match the claimed Microsoft identity. The external PHPMailer infrastructure, look-alike domain, and credential-verification link support classifying E3 as suspicious impersonation/phishing.

---

## Email 5 — medequip-supplies.net

### Header Evidence

* From: `invoices@medequip-supplies.net`
* Return-Path: `invoices@medequip-supplies.net`
* Sending IP: `185.176.43.22`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-7C2D4E1A@medequip-supplies.net>`

### Received Chain Summary

1. `mail.medequip-supplies.net` (`185.176.43.22`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. `billing-svc.medequip-supplies.net` (`127.0.0.1`) → `mail.medequip-supplies.net`

### Anomalies

* [HIGH] SPF softfailed: `185.176.43.22` is not properly authorized for `medequip-supplies.net`.
* [HIGH] DKIM is absent.
* [HIGH] DMARC failed for `medequip-supplies.net`.
* [HIGH] The message requests payment of USD 24,716.38 through an externally hosted payment portal.
* [MEDIUM] Sending infrastructure uses `PHPMailer 6.6.0`.
* [MEDIUM] Message-ID uses a PHP-generated format: `PHP-7C2D4E1A@medequip-supplies.net`.
* [MEDIUM] `X-Priority: 1 (Highest)` adds urgency to a financial request.
* [MEDIUM] Recipient reported that the invoice appears incorrect.

### Conclusion

E5 has multiple authentication failures combined with an externally hosted payment request and PHP-based sending infrastructure. The authentication and content evidence support treating the message as a suspicious invoice/payment phishing attempt.

---

## Email 7 — meddefense-benefits.org

### Header Evidence

* From: `hr-notifications@meddefense-benefits.org`
* Return-Path: `hr-notifications@meddefense-benefits.org`
* Sending IP: `164.90.218.73`
* X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
* Message-ID: `<PHP-2E4A7B1C@meddefense-benefits.org>`

### Received Chain Summary

1. `mail.meddefense-benefits.org` (`164.90.218.73`) → `mx01.meddefense.com`
2. `mx01.meddefense.com` (`10.10.1.20`) → `inbound-relay.meddefense.com`
3. `wp-portal.meddefense-benefits.org` (`127.0.0.1`) → `mail.meddefense-benefits.org`

### Anomalies

* [HIGH] SPF failed: `164.90.218.73` is not authorized to send for `meddefense-benefits.org`.
* [HIGH] DKIM is absent.
* [HIGH] DMARC failed for `meddefense-benefits.org`.
* [HIGH] The claimed MedDefense HR sender uses `meddefense-benefits.org` instead of the organization's `meddefense.com` domain.
* [HIGH] The message links to an external benefits enrollment portal on the look-alike domain.
* [MEDIUM] Sending infrastructure uses `PHPMailer 6.6.0`.
* [MEDIUM] Message-ID uses a PHP-generated format: `PHP-2E4A7B1C@meddefense-benefits.org`.
* [MEDIUM] The message creates an urgent enrollment deadline and threatens loss of coverage.
* [MEDIUM] Recipient reported never signing up for the referenced enrollment activity.

### Conclusion

E7 shows SPF and DMARC failure, no DKIM signature, an external look-alike domain, and PHPMailer-based infrastructure. Combined with the urgent benefits-enrollment pretext and external enrollment link, the headers and content strongly support treating E7 as a phishing attempt.