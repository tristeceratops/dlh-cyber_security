# MedDefense Severity Matrix

## Purpose

## Severity Matrix

## Level Definitions

| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
|---|---|---|---|---|---|
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited  | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected |  degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

### SEV1

- Ransomware affecting clinical systems across multiple sites

- Confirmed exfiltration of patient records at scale

- Patient monitoring system offline during active care

### SEV2

- Confirmed compromise of a clinical-access account

- Malware confirmed on a single workstation at a clinical site

- Suspected exfiltration under investigation

### SEV3

- Suspicious login activity detected on hospital EHR account

- Malware detected on a non-critical administrative workstation

- Hospital appointment scheduling system experiencing intermittent delays

### SEV4

- Phishing email reported by hospital staff and quarantined before credentials are disclosed

- Outdated software detected on an isolated, non-critical hospital workstation

- Multiple failed login attempts against a hospital staff account

## Escalation Rule

Severity is reviewed at every status update. It increases when new evidence raises patient safety, data exposure, or service availability to the next tier. It decreases only after confirmed containment and IR Commander approval.