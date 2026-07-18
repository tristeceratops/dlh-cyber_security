# The Scan Report

## Introduction

### Goal
Develop the professional reflex of reading a scan report for structure and context before diving into individual findings.

### Context
Thirty-one findings. Four Critical. Seven High. The temptation is to jump straight to the red ones. Resist it.

A scan report is a dataset, not an analysis. Before you investigate any single finding, you need to understand the shape of the data: how many findings, what severity distribution, which systems are most affected, what the scanner covered and, critically, what it did not cover.

This is the same discipline that separates a junior analyst from a senior one. The junior panics at "4 Critical." The senior asks: "4 Critical out of how many ? On which systems ? Are they on the same asset ? Are they related ?"

## Answer

This scan was requested by James Chen, Deputy CISO, 5 days previous the report during morning off-peak hours (02:00 - 06:00).It was done by SecurePoint Consulting (third-party) with OpenVAS 22.x (Greenbone Community Edition) on the internal network ip 10.10.0.0/16. The network was scanned full and deep, with authentificated scanning where credentials were available.

Not scanned:
- Microsoft 365 / O365 services
- Mobile devices (IPdas)
- Assets offline during the scan window


| Severity | Count |
|----------|------:|
| Critical | 4 |
| High | 7 |
| Medium | 11 |
| Low | 5 |
| Informational | 4 |
| Total | 31 |

Most common Severity: **Medium (11 findings)**

Top 5 Hosts by finding count:


1. **10.10.2.15 (billing-srv-01)** - 6 findings
   - Billing application server

2. **10.10.2.10 (ehr-srv-01)** - 4 findings
   - EHR application server

3. **10.10.2.50 (web-srv-01)** - 4 findings
   - Patient portal server

4. **10.10.2.20 (ad-dc-01)** - 3 findings
   - Domain Controller

5. **10.10.1.70 (WS-RAD-01)** - 1 critical finding
   - MRI workstation

First observations:

- Billing server is the highest-risk asset with multiple critical and high findings.
- Flat network architecture appears throughout the report.
- Critical findings affect several important systems:
  - Billing server
  - EHR database
  - MRI workstation
- Multiple end-of-life systems are present:
  - Windows XP
  - Windows Server 2012 R2
  - Ubuntu 18.04 without ESM
- Medical devices have weak security controls and limited isolation.
- Multiple findings can be chained together to increase impact.
- Two undocumented Linux devices were discovered (possible shadow IT).

Most concerning assets:

- **billing-srv-01**
  - Remote code execution
  - Privilege escalation
  - Database exposure

- **ehr-db-01**
  - Patient database broadly accessible on internal network

- **WS-RAD-01**
  - Windows XP with known weaponized vulnerabilities

Scan limitations: 

This scan does not assess:

- Cloud services (Microsoft 365 / O365)
- Mobile devices
- Offline assets
- User phishing risk
- Penetration testing or exploit validation
- Business logic flaws in applications
- Physical security
- Compliance processes
- Incident response effectiveness

Also:

- Medical devices were scanned without credentials.
- Some findings may be false positives.
- The scan cannot confirm whether vulnerabilities have already been exploited.
