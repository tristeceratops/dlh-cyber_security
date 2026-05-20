# SPF (Sender Policy Framework)

## What is SPF?

SPF tells the world which mail servers are allowed to send email for your domain.
It solves **IP-based spoofing**.

## How SPF works

```
Sender IP → DNS SPF record → Allowed or not allowed
```

The domain owner publishes an SPF record in DNS.
The receiving server compares the sender IP with the allowed list.

## SPF record syntax

```text
v=spf1 mechanism mechanism -all
```

| Part | Meaning |
|------|---------|
| `v=spf1` | SPF version |
| mechanisms | Allowed senders |
| qualifier | What to do on match / fail |

## Main mechanisms

| Mechanism | Use | Example |
|-----------|-----|---------|
| `ip4` | Allow an IPv4 address or range | `ip4:192.0.2.1` |
| `include` | Use another domain's SPF | `include:_spf.google.com` |
| `mx` | Allow servers in MX records | `mx` |
| `a` | Allow the domain's A record | `a:example.com` |
| `all` | Match everything | `-all` |

## SPF qualifiers

| Qualifier | Symbol | Meaning |
|-----------|--------|---------|
| Pass | `+` | Authorized sender |
| Fail | `-` | Not authorized, reject |
| Softfail | `~` | Probably not authorized, mark suspicious |
| Neutral | `?` | No policy statement |

## Evaluation order

SPF checks mechanisms from left to right.
The first match decides the result.

```text
Check ip4 → if no match, check include → if no match, check mx/a → finally all
```

## SPF results

| Result | Meaning |
|--------|---------|
| `pass` | Sender is authorized |
| `fail` | Sender is not authorized |
| `softfail` | Probably not authorized |
| `neutral` | No statement |
| `temperror` | Temporary DNS problem |
| `permerror` | Permanent SPF error |

## The 10 DNS lookup limit

SPF allows only **10 DNS lookups**.
This prevents slow checks and DNS abuse.

### Why it matters

Too many `include`, `mx`, `a`, or `redirect` lookups can cause `permerror`.

## Why forwarding breaks SPF

Forwarding changes the sending server IP.
The new IP is often not in the original SPF record.

### Mitigation

- Use DKIM, which survives forwarding better
- Use DMARC with aligned DKIM
- Keep SPF simple

## What `-all` means

`-all` means: reject everything not explicitly allowed.
It is the strict and recommended final rule.

## SPF testing

| Method | Example |
|--------|---------|
| DNS lookup | `dig TXT example.com` |
| DNS lookup | `nslookup -type=TXT example.com` |
| Online tools | SPF validators |

## Best practice

| Do | Don’t |
|----|-------|
| Use `-all` | Use `+all` |
| Keep under 10 lookups | Add too many `include`s |
| Test before deployment | Publish without checking |
