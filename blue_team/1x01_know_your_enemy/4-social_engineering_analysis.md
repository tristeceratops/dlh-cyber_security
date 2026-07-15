# The Human Vector

## Introduction

### Goal
Identify, classify and analyze social engineering attack vectors in a healthcare context, including red flags and countermeasures.

### Context
The most sophisticated firewall in the world is useless if an attacker can call the front desk and talk their way into a password reset. Social engineering exploits the one system you cannot patch: human psychology. In healthcare, the exploitation surface is enormous. Clinical staff are trained to be helpful. Administrative staff handle urgent requests all day. Everyone is busy, stressed and inclined to take shortcuts.

The Security+ framework (2.2) defines these human-targeted vectors: phishing (email), vishing (voice/phone), smishing (SMS), pretexting (fabricated scenarios), business email compromise (BEC), impersonation, watering hole attacks, brand impersonation and typosquatting. Each exploits a different psychological lever: urgency, authority, familiarity, fear or helpfulness.

## Answer

# Social Engineering Threat Assessment – MedDefense

## Scenario 1 – Fake FortiGate Support Email

**Vector Type:** Phishing (Email)

**Target:**
Sarah Park (IT Director). As the individual responsible for network infrastructure and perimeter security, she routinely receives vendor notifications about firmware updates and security advisories, making vendor-themed phishing particularly convincing.

**Psychological Lever:**
Urgency and Fear

**Red Flags:**

- Sender domain is **fortinet-support.net** rather than the official vendor domain.
- Email pressures immediate action within 24 hours.
- Patch installation is delivered through an embedded link instead of official support channels.

**Technical Control:**

Email security gateway with URL reputation filtering, sandboxing, and DMARC/SPF/DKIM validation.

**Administrative Control:**

Require administrators to obtain firmware updates only through approved vendor portals and documented patch management procedures.

---

## Scenario 2 – CEO Wire Transfer Request

**Vector Type:** Business Email Compromise (BEC)

**Target:**
Robert Kim (CFO). Finance personnel possess authority to initiate payments and routinely receive executive requests involving confidential financial transactions.

**Psychological Lever:**
Authority and Urgency

**Red Flags:**

- Sender email address differs slightly from the CEO's legitimate address.
- Request bypasses normal procurement and approval procedures.
- Explicit instruction not to verify the request or discuss it with others.

**Technical Control:**

Advanced email authentication (DMARC, SPF, DKIM) combined with external sender warnings and anti-spoofing protection.

**Administrative Control:**

Mandatory out-of-band verification for all wire transfers or financial requests above an established approval threshold.

---

## Scenario 3 – Fake IT Help Desk Phone Call

**Vector Type:** Vishing (Voice Phishing)

**Target:**
Clinical nurse. Nurses regularly communicate with IT during shift work and often prioritize restoring access quickly to avoid disrupting patient care.

**Psychological Lever:**
Authority and Helpfulness

**Red Flags:**

- Caller requests the employee's password.
- Unexpected request citing an "emergency audit."
- Legitimate IT staff never require users to disclose passwords verbally.

**Technical Control:**

Self-service password reset platform with identity verification, eliminating the need for password disclosure over the phone.

**Administrative Control:**

Security awareness training emphasizing that IT personnel will never request user passwords under any circumstance.

---

## Scenario 4 – Fake Parking Permit Renewal Text

**Vector Type:** Smishing (SMS Phishing)

**Target:**
All MedDefense employees. Parking permits affect nearly every staff member, making the message broadly relevant and believable.

**Psychological Lever:**
Urgency

**Red Flags:**

- Unexpected text requesting Active Directory credentials.
- Link directs users to a login page outside normal HR communication channels.
- Threat of immediate towing pressures rapid action without verification.

**Technical Control:**

Conditional access with MFA for all Active Directory authentication, preventing stolen credentials from being sufficient for compromise.

**Administrative Control:**

Policy requiring employees to access HR services only through official internal portals rather than links received by text message.

---

## Scenario 5 – Compromised Healthcare Association Website

**Vector Type:** Watering Hole Attack

**Target:**
Physicians and clinicians completing Continuing Medical Education (CME) requirements. They regularly visit trusted professional association websites, making those sites attractive attack vectors.

**Psychological Lever:**
Familiarity

**Red Flags:**

- Unexpected browser redirects while visiting a trusted website.
- Browser requests unusual downloads or software installation.
- Security warnings or abnormal browser behavior appearing after navigation.

**Technical Control:**

Endpoint Detection and Response (EDR) combined with browser isolation or web filtering to detect exploit activity.

**Administrative Control:**

Require browsers and operating systems to remain fully patched and instruct employees to report unexpected redirects or software prompts immediately.

---

## Scenario 6 – Fake MedDefense Patient Portal

**Vector Type:** Typosquatting

**Target:**
Patients and employees searching online for the MedDefense patient portal. Users commonly access the portal through search engines rather than saved bookmarks.

**Psychological Lever:**
Familiarity

**Red Flags:**

- Domain name uses **meddefence-portal.com** instead of the official MedDefense domain.
- Sponsored advertisement appears above the legitimate search result.
- Login page requests credentials from an unfamiliar URL.

**Technical Control:**

Domain monitoring combined with defensive domain registration and takedown services for fraudulent lookalike domains.

**Administrative Control:**

Educate patients and staff to use bookmarked official portal URLs or links published directly through MedDefense communications.

---

## Scenario 7 – Tailgating into the IT Department

**Vector Type:** Impersonation

**Target:**
Employees entering the restricted IT corridor. Healthcare personnel are accustomed to helping colleagues and often assume anyone wearing scrubs belongs in the facility.

**Psychological Lever:**
Helpfulness and Familiarity

**Red Flags:**

- Individual enters without presenting a valid badge.
- Visitor badge is partially concealed and expired.
- Attempts to rely on another employee's badge rather than authenticating independently.

**Technical Control:**

Badge-controlled access integrated with anti-tailgating systems and security camera monitoring for restricted areas.

**Administrative Control:**

Enforce a strict "no tailgating" policy requiring every individual—including employees, contractors, and clinicians—to authenticate separately before entering secure areas.