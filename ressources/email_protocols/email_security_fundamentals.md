# Email Security Fundamentals

## What is email authentication?

Email authentication checks whether an email really comes from the domain it claims to use.
It helps receiving servers detect spoofing, forged messages, and malicious mail.

### Why it matters

| Benefit | Simple meaning |
|---------|----------------|
| Brand protection | Stops fake mail using your domain |
| Deliverability | Improves inbox placement |
| Trust | Reduces phishing success |
| Compliance | Helps meet policy and legal needs |

## Main threats

| Threat | What it means | Impact |
|--------|---------------|--------|
| **Email spoofing** | Forging the sender address | Phishing, fake messages |
| **Domain impersonation** | Using a similar domain name | Fraud, credential theft |
| **BEC** | Compromised account sends malicious mail | Money loss, data breach |
| **Spam** | Unwanted bulk mail | Reputation damage |
| **Malware distribution** | Links or attachments deliver malware | System compromise |

## Spoofing vs impersonation

| Item | Email spoofing | Domain impersonation |
|------|----------------|----------------------|
| Main idea | Fake sender address | Lookalike domain name |
| Example | `ceo@company.com` sent by attacker | `cornpany.com` instead of `company.com` |
| Goal | Trick filters and users | Trick users visually |

## How SPF, DKIM, and DMARC work together

```
Email arrives
   ↓
SPF checks sending IP
   ↓
DKIM checks message signature
   ↓
DMARC checks alignment + applies policy
   ↓
Accept / quarantine / reject
```

| Protocol | Main job | Protects against |
|----------|----------|------------------|
| **SPF** | Authorize sending servers | IP spoofing |
| **DKIM** | Sign message contents | Tampering |
| **DMARC** | Enforce policy and report | Domain spoofing |

## Fast memory view

| Question | Short answer |
|----------|--------------|
| What is it? | Verifying email origin and integrity |
| Why important? | Stops spoofing and phishing |
| Main risk? | Fake sender and fake domains |
