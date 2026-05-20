# Network Security - Study Guide

## The CIA Triad (Foundation of Security)

```
                    ┌─────────────────┐
                    │ CONFIDENTIALITY │
                    │   Who can see?  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
    ┌─────────────────┐           ┌─────────────────┐
    │    INTEGRITY    │           │  AVAILABILITY   │
    │ Is it accurate? │           │ Can I access it?│
    └─────────────────┘           └─────────────────┘
```

---

## 1. Confidentiality - "Who can see this data?"

**Goal:** Prevent unauthorized disclosure of information

### Threats to Confidentiality

| Threat | Description | Example |
|--------|-------------|---------|
| **Eavesdropping** | Intercepting communications | Packet sniffing on unencrypted Wi-Fi |
| **Data Breach** | Unauthorized access to data stores | Database hack exposing passwords |
| **Social Engineering** | Manipulating people to reveal info | Phishing emails for credentials |
| **Shoulder Surfing** | Observing screens/keyboards | Looking at someone's PIN entry |
| **Dumpster Diving** | Searching through discarded materials | Finding documents in trash |

### Controls for Confidentiality

| Control | Implementation | Example |
|---------|----------------|---------|
| **Encryption** | Transform data to unreadable format | AES-256 for data at rest |
| **Access Controls** | Restrict who can access | RBAC, ACLs |
| **Authentication** | Verify user identity | MFA, biometrics |
| **Data Classification** | Label data sensitivity | Public, Internal, Confidential, Secret |
| **Network Segmentation** | Isolate sensitive systems | VLANs, firewalls |

---

## 2. Integrity - "Has this data been tampered with?"

**Goal:** Prevent unauthorized modification of information

### Threats to Integrity

| Threat | Description | Example |
|--------|-------------|---------|
| **Man-in-the-Middle** | Modifying data in transit | Altering wire transfer amounts |
| **Malware** | Software that modifies files | Ransomware encrypting data |
| **SQL Injection** | Manipulating database queries | Changing user permissions |
| **Unauthorized Changes** | Insider modifying records | Employee changing payroll data |
| **Bit Rot** | Data degradation over time | Storage media failures |

### Controls for Integrity

| Control | Implementation | Example |
|---------|----------------|---------|
| **Hashing** | Create unique fingerprint of data | SHA-256 checksums |
| **Digital Signatures** | Cryptographically sign data | Code signing certificates |
| **Version Control** | Track all changes | Git for source code |
| **Access Controls** | Limit who can modify | Write permissions |
| **Input Validation** | Verify data before processing | Sanitize user inputs |
| **Checksums** | Verify file integrity | MD5/SHA for downloads |

---

## 3. Availability - "Can I access this when needed?"

**Goal:** Prevent disruption of access to information

### Threats to Availability

| Threat | Description | Example |
|--------|-------------|---------|
| **DDoS Attacks** | Overwhelming systems with traffic | Botnet flooding web server |
| **Hardware Failure** | Physical component breakdown | Hard drive crash |
| **Natural Disasters** | Environmental events | Flood destroying data center |
| **Power Outages** | Loss of electrical power | Extended blackout |
| **Ransomware** | Encrypting data making it inaccessible | WannaCry attack |

### Controls for Availability

| Control | Implementation | Example |
|---------|----------------|---------|
| **Redundancy** | Duplicate critical components | RAID, failover servers |
| **Backups** | Regular data copies | 3-2-1 backup strategy |
| **Load Balancing** | Distribute traffic | HAProxy, cloud load balancers |
| **DDoS Protection** | Filter malicious traffic | Cloudflare, AWS Shield |
| **Disaster Recovery** | Plan for major incidents | Hot/warm/cold sites |
| **UPS/Generators** | Backup power | Battery backup, diesel generators |

### Availability SLA Examples

| Level | Uptime | Downtime/Year |
|-------|--------|---------------|
| **99%** | "Two Nines" | 3.65 days |
| **99.9%** | "Three Nines" | 8.76 hours |
| **99.99%** | "Four Nines" | 52.6 minutes |
| **99.999%** | "Five Nines" | 5.26 minutes |

---

## CIA Trade-offs

```
        HIGH SECURITY                    HIGH USABILITY
   ◄─────────────────────────────────────────────────────►

   Military Systems    |    Banking    |    Social Media
   Top Secret Data     |    PII Data   |    Public Posts
```

---

## Beyond CIA: AAA + Non-Repudiation

### AAA (Authentication, Authorization, Accounting)

| Concept | Question | Example |
|---------|----------|---------|
| **Authentication** | Who are you? | Username + password |
| **Authorization** | What can you do? | Role-based permissions |
| **Accounting** | What did you do? | Audit logs |

### Non-Repudiation

**Definition:** Preventing denial of actions taken  
**Controls:** Digital signatures, audit logs, timestamps  
**Example:** Sender cannot deny sending an email

---

## 4. Defense in Depth (Layered Security)

```
┌──────────────────────────────────────────────────┐
│ Policies & Procedures                            │ ← Training, security policies
├──────────────────────────────────────────────────┤
│ Physical Security                                │ ← Guards, locks, cameras
├──────────────────────────────────────────────────┤
│ Perimeter Security                               │ ← Firewalls, DMZ, IDS/IPS
├──────────────────────────────────────────────────┤
│ Network Security                                 │ ← Segmentation, VLANs, NAC
├──────────────────────────────────────────────────┤
│ Host Security                                    │ ← Antivirus, patching
├──────────────────────────────────────────────────┤
│ Application Security                             │ ← Input validation, WAF
├──────────────────────────────────────────────────┤
│ Data Security                                    │ ← Encryption, DLP, backups
└──────────────────────────────────────────────────┘
```

---

## 5. Security Principles

| Principle | Description |
|-----------|-------------|
| **Least Privilege** | Grant minimum access needed for job |
| **Need to Know** | Access based on job requirements |
| **Separation of Duties** | Critical tasks require multiple people |
| **Zero Trust** | Never trust, always verify |

---

## Common Network Attacks

### Attack Categories

| Category | Description | Examples |
|----------|-------------|----------|
| **Reconnaissance** | Gathering information | Port scanning, OSINT |
| **Interception** | Capturing data | MitM, ARP spoofing |
| **Denial of Service** | Making unavailable | Floods, amplification |
| **Access Attacks** | Unauthorized access | Password attacks, exploitation |

### Man-in-the-Middle (MitM)

**What:** Attacker intercepts communication between two parties

**Techniques:**
- ARP Spoofing
- DNS Spoofing
- HTTPS Stripping
- Rogue Wi-Fi APs

### DDoS Attacks

| Type | Description | Example |
|------|-------------|---------|
| **Volumetric** | Overwhelm bandwidth | UDP flood, DNS amplification |
| **Protocol** | Exploit protocol weakness | SYN flood |
| **Application** | Target specific services | HTTP flood, Slowloris |

### Password Attacks

| Attack | Method | Defense |
|--------|--------|---------|
| **Brute Force** | Try all combinations | Account lockout |
| **Dictionary** | Common passwords | Complex policy |
| **Credential Stuffing** | Reused passwords | Unique passwords, MFA |
| **Phishing** | Social engineering | Training, email filtering |

---

## Security Controls

### 1. Firewalls

**Firewall Types:**

| Type | Description |
|------|-------------|
| **Packet Filtering** | Stateless, filters on IP/port/protocol |
| **Stateful** | Tracks connection state |
| **NGFW** | Deep packet inspection, application awareness |

**Firewall Rules Example:**

| # | Action | Source | Destination | Port | Proto |
|---|--------|--------|-------------|------|-------|
| 1 | ALLOW | 10.0.0.0/8 | Any | 80,443 | TCP |
| 2 | ALLOW | Any | 10.0.0.10 | 443 | TCP |
| 3 | DENY | Any | 10.0.0.0/8 | Any | Any |
| 99 | DENY | Any | Any | Any | Any |

**Best Practices:**
- ✓ Default deny
- ✓ Most specific rules first
- ✓ Document every rule
- ✓ Regular review

### DMZ Architecture

```
Internet → [External FW] → DMZ → [Internal FW] → Internal Network
                      (web/mail)
```

---

### 2. Intrusion Detection & Prevention

### IDS vs IPS

| System | Mode | Action |
|--------|------|--------|
| **IDS** | Passive | Monitor and alert |
| **IPS** | Active | Monitor, alert, and block |

### Detection Methods

| Method | Description | Limitation |
|--------|-------------|-----------|
| **Signature-based** | Known attack patterns | Can't detect zero-day |
| **Anomaly-based** | Baseline deviation | Higher false positives |
| **Heuristic** | Behavior patterns | Rules-based |

### IDS/IPS Types

| Type | Scope |
|------|-------|
| **NIDS/NIPS** | Network traffic |
| **HIDS/HIPS** | Individual hosts |

**Popular Tools:** Snort, Suricata, OSSEC, Zeek

---

### 3. Network Segmentation

### VLAN Segmentation

| VLAN | Subnet | Purpose |
|------|--------|---------|
| VLAN 10 | 10.10.0.0/24 | Servers |
| VLAN 20 | 10.20.0.0/24 | Workstations |
| VLAN 30 | 10.30.0.0/24 | Guest |

### Zero Trust Model

| Traditional | Zero Trust |
|-------------|-----------|
| Inside = trusted | No implicit trust |
| Perimeter focus | Verify every request |
| Once inside, free access | Least privilege always |

**Zero Trust Principles:**
1. Verify explicitly
2. Use least privilege access
3. Assume breach

---

### 4. SIEM (Security Information & Event Management)

**Functions:**
- Collection & Normalization
- Correlation & Analysis
- Alerting & Dashboards
- Incident Response

**Key Log Sources:**

| Source | Key Information |
|--------|-----------------|
| Firewall | Blocked/allowed connections |
| IDS/IPS | Detected threats |
| Authentication | Login success/failure |
| DNS | Query patterns |

**Solutions:** Splunk, Microsoft Sentinel, Elastic SIEM, Wazuh

---

## Network Access Control (NAC) & 802.1X

### What is NAC?

Network Access Control restricts network access based on identity, device compliance, and policy.

| Goal | Description |
|------|-------------|
| **Authentication** | Verify user/device identity |
| **Authorization** | Determine access level |
| **Compliance** | Check device meets security requirements |
| **Remediation** | Fix non-compliant devices |

### 802.1X Authentication Components

| Component | Role | Examples |
|-----------|------|----------|
| **Supplicant** | Client requesting access | Laptop, phone |
| **Authenticator** | Network device controlling access | Switch, AP |
| **Auth Server** | Validates credentials | RADIUS server |

### 802.1X Flow

```
Device connects to port
        ↓
Port in UNAUTHORIZED state
        ↓
Authenticator sends EAP-Request/Identity
        ↓
Supplicant responds with identity
        ↓
Authenticator forwards to RADIUS
        ↓
RADIUS validates credentials
        ↓
RADIUS sends Accept/Reject
        ↓
Port moves to AUTHORIZED (or DENIED)
```

### EAP Methods

| Method | Description | Security |
|--------|-------------|----------|
| **EAP-TLS** | Certificate-based | Most secure |
| **EAP-TTLS** | Tunneled TLS | Server cert + password |
| **PEAP** | Protected EAP | Similar to TTLS |

---

## Reconnaissance Fundamentals

### Port Scanning

| Scan Type | Method | Characteristics |
|-----------|--------|-----------------|
| **TCP Connect** | Full 3-way handshake | Reliable, logged |
| **SYN Scan** | SYN → SYN/ACK → RST | Stealthier |
| **UDP Scan** | Send UDP packets | Slow |

### Port States

| State | Meaning |
|-------|---------|
| **Open** | Service listening |
| **Closed** | No service listening |
| **Filtered** | Firewall blocking |

### Network Enumeration Protocols

| Protocol | Port | Information Exposed |
|----------|------|-------------------|
| **SNMP** | UDP 161 | Network config, device info |
| **NetBIOS** | UDP 137-139 | Computer names, shares |
| **SMB** | TCP 445 | Shares, users, OS info |
| **LDAP** | TCP 389 | Directory structure |
| **DNS** | TCP/UDP 53 | Zone transfers, records |

### Defense Against Reconnaissance

| Attack | Defense |
|--------|---------|
| Port scanning | Firewall rules, IDS/IPS, rate limiting |
| Banner grabbing | Remove/modify banners |
| SNMP enumeration | Disable SNMPv1/v2c, use SNMPv3 |
| DNS zone transfer | Restrict to authorized servers |

---

## Security Best Practices Checklist

### Perimeter
- ☐ Firewalls with default deny
- ☐ DMZ for public services
- ☐ IDS/IPS monitoring
- ☐ DDoS protection

### Access Control
- ☐ MFA where possible
- ☐ Least privilege
- ☐ Regular access reviews
- ☐ 802.1X/NAC for network access

### Encryption
- ☐ TLS 1.2+ for web traffic
- ☐ VPN for remote access
- ☐ SSH not Telnet

### Monitoring
- ☐ Centralized logging (SIEM)
- ☐ Vulnerability scanning
- ☐ Penetration testing

---

## Quick Summary

```
Security Foundation:        CIA Triad
                        ┌──┴──┬──┴──┬───┴──┐
                        ↓     ↓     ↓      ↓
                    CONF  INTEG  AVAIL   AAA

Defense Approach:    Defense in Depth (Layers)

Technical Controls:
├── Firewalls (traffic control)
├── IDS/IPS (threat detection)
├── NAC/802.1X (access control)
├── Segmentation (limit spread)
└── SIEM (monitoring)

Architectural:
├── Zero Trust (verify always)
├── DMZ (public services)
└── Least Privilege (minimal access)

Attacks:
├── Reconnaissance (scanning)
├── MitM (interception)
├── DDoS (availability)
└── Access Attacks (credentials)
```