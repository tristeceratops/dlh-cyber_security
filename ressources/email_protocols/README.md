# Email Security Protocols - Revision Notes

## Files

| File | What it covers |
|------|----------------|
| [Email Security Fundamentals](email_security_fundamentals.md) | Email authentication basics, threats, and the SPF/DKIM/DMARC overview |
| [SPF](spf.md) | SPF syntax, mechanisms, results, limits, and testing |
| [DKIM](dkim.md) | DKIM signatures, selectors, key management, and validation |
| [DMARC](dmarc.md) | DMARC policy, alignment, reports, and rollout strategy |
| [Workflow and Troubleshooting](workflow_implementation_troubleshooting.md) | How the protocols work together, deployment order, DNS, best practices, and debugging |

## Quick Map

```text
SPF  → Authorizes sending servers
DKIM → Signs and verifies message integrity
DMARC → Applies policy and sends reports
```
