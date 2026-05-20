# DMARC (Domain-based Message Authentication, Reporting & Conformance)

## What is DMARC?

DMARC builds on SPF and DKIM.
It tells receivers what to do when email fails authentication.

| Protocol | Main job |
|----------|----------|
| SPF | Authorize sending IPs |
| DKIM | Verify message integrity |
| DMARC | Apply policy and send reports |

## DMARC policy record

| Item | Format |
|------|--------|
| DNS name | `_dmarc.domain` |
| DNS type | TXT |
| Example | `v=DMARC1; p=reject; rua=mailto:reports@example.com` |

## Required and optional tags

| Tag | Meaning | Example |
|-----|---------|---------|
| `v` | Version | `v=DMARC1` |
| `p` | Policy | `p=none`, `p=quarantine`, `p=reject` |
| `rua` | Aggregate reports | `rua=mailto:reports@example.com` |
| `ruf` | Forensic reports | `ruf=mailto:forensics@example.com` |
| `pct` | Apply policy to a percentage | `pct=25` |
| `sp` | Subdomain policy | `sp=reject` |
| `adkim` | DKIM alignment mode | `adkim=r` |
| `aspf` | SPF alignment mode | `aspf=s` |

## DMARC policy levels

| Policy | Meaning | Action |
|--------|---------|--------|
| `none` | Monitor only | Accept mail |
| `quarantine` | Suspicious mail | Send to spam/junk |
| `reject` | Strong enforcement | Reject at SMTP level |

## Alignment

Alignment means the domain in the visible From header must match the domain used by SPF or DKIM.

### Strict vs relaxed

| Mode | Meaning |
|------|---------|
| Strict | Exact domain match |
| Relaxed | Subdomain match allowed |

## DMARC pass condition

```
DMARC passes if SPF passes and is aligned
OR DKIM passes and is aligned
```

## `pct` tag

`pct` is used for gradual rollout.

| Example | Meaning |
|---------|---------|
| `pct=25` | Only 25% of failing mail gets the policy action |
| `pct=100` | Full enforcement |

## `sp` tag

`sp` sets the policy for subdomains.

| Example | Result |
|---------|--------|
| `p=reject` | Main domain rejects failing mail |
| `sp=quarantine` | Subdomains quarantine failing mail |

## Reports

### Aggregate reports (`rua`)

- Sent periodically, usually daily
- Show statistics and trends
- Useful for monitoring

### Forensic reports (`ruf`)

- Sent for individual failures
- Useful for investigation
- Often limited by providers

## DMARC deployment strategy

```text
p=none → p=quarantine; pct=25 → p=quarantine; pct=100 → p=reject; pct=25 → p=reject; pct=100
```

## Best practice

| Do | Don’t |
|----|-------|
| Start with `p=none` | Jump straight to `p=reject` |
| Monitor reports | Ignore reports |
| Use `sp` for subdomains | Forget subdomains |
| Roll out gradually | Change everything at once |
