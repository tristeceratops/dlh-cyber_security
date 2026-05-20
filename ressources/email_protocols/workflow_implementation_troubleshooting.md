# Email Authentication Workflow, Implementation, and Troubleshooting

## Full flow

```text
Email sent
  ↓
SPF checks sending IP
  ↓
DKIM verifies signature
  ↓
DMARC checks alignment
  ↓
Policy decision: accept / quarantine / reject
```

## What each protocol protects

| Protocol | Protects against | Limitation |
|----------|------------------|------------|
| SPF | IP spoofing | Breaks on forwarding |
| DKIM | Message tampering | Does not authorize sender alone |
| DMARC | Domain spoofing | Needs SPF or DKIM to pass |

## What happens in common cases

| SPF | DKIM | DMARC result |
|-----|------|--------------|
| Pass | Pass | Accept |
| Pass | Fail | Accept if SPF is aligned |
| Fail | Pass | Accept if DKIM is aligned |
| Fail | Fail | Apply DMARC policy |

## Implementation order

```text
1. SPF
2. DKIM
3. DMARC monitoring
4. DMARC quarantine
5. DMARC reject
```

## How to implement each protocol

### SPF

1. List all sending sources
2. Publish a TXT SPF record
3. Use `-all` for strict policy
4. Test before production

### DKIM

1. Generate key pair
2. Publish public key in DNS
3. Configure signing on the mail server
4. Use 2048-bit keys
5. Test signatures

### DMARC

1. Start with `p=none`
2. Add reporting addresses
3. Review reports
4. Move to quarantine
5. End with reject

## DNS locations

| Protocol | DNS name | Record type |
|----------|----------|-------------|
| SPF | Domain root | TXT |
| DKIM | `selector._domainkey.domain` | TXT |
| DMARC | `_dmarc.domain` | TXT |

## Troubleshooting tools

| Task | Command |
|------|---------|
| Check SPF | `dig TXT example.com` |
| Check DKIM | `dig TXT selector._domainkey.example.com` |
| Check DMARC | `dig TXT _dmarc.example.com` |
| Inspect email headers | Look for SPF / DKIM / DMARC results |

## Common failure causes

| Problem | Common cause |
|---------|--------------|
| SPF fail | Wrong sending IP, forwarding, too many lookups |
| DKIM fail | Modified body, bad key, wrong selector |
| DMARC fail | SPF and DKIM not aligned |

## Best practices

| Area | Good practice |
|------|---------------|
| SPF | Keep under 10 DNS lookups |
| SPF | Never use `+all` |
| DKIM | Rotate keys regularly |
| DKIM | Use `relaxed/relaxed` when forwarding is expected |
| DMARC | Start with `p=none` |
| DMARC | Use reports before enforcement |

## Quick memory map

```text
SPF = who can send
DKIM = did the message change
DMARC = what to do if it fails
```
