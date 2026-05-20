# Network Services - Study Guide

## Network Services Overview

```
Network Connectivity Chain:
Device Gets IP → Device Reaches Internet → Device Resolves Names → Device Authenticates
    ↓                ↓                         ↓                      ↓
   DHCP              NAT                       DNS                  AUTH
```

---

## Part A: DHCP (Dynamic Host Configuration Protocol)

**What:** Automatically assigns IP addresses and network configuration to devices

**Ports:** UDP 67 (server) | UDP 68 (client)

**Why Important:** Critical service AND major attack vector (rogue servers, starvation attacks)

### What DHCP Provides

| Parameter | Description |
|-----------|-------------|
| IP Address | Unique address for the client |
| Subnet Mask | Network/host boundary |
| Default Gateway | Router for external traffic |
| DNS Servers | Name resolution servers |
| Lease Duration | How long the IP is valid |

### DORA Process (4 Steps)

```
Step 1: DISCOVER (Client → Broadcast)
        "Who is a DHCP server?"
           ↓
Step 2: OFFER (Server → Client)
        "Here's IP 192.168.1.100"
           ↓
Step 3: REQUEST (Client → Broadcast)
        "I accept 192.168.1.100"
           ↓
Step 4: ACK (Server → Client)
        "Confirmed!"
```

### DORA Detailed Flow

| Step | Message | Direction | Details |
|------|---------|-----------|---------|
| 1 | DISCOVER | Client → Broadcast | Source: 0.0.0.0, Dest: 255.255.255.255 |
| 2 | OFFER | Server → Client | "Here's IP 192.168.1.100" |
| 3 | REQUEST | Client → Broadcast | "I'll take 192.168.1.100" |
| 4 | ACK | Server → Client | "Confirmed!" |

### DHCP Lease Lifecycle (24-hour example)

| Timer | % of Lease | Time | Action |
|-------|-----------|------|--------|
| Initial | 0% | 0h | Client receives IP via DORA |
| T1 (Renewal) | 50% | 12h | Client unicasts REQUEST to server |
| T2 (Rebind) | 87.5% | 21h | Client broadcasts REQUEST to ANY server |
| Expiration | 100% | 24h | Client stops using IP, restarts DORA |

### DHCP Attacks

| Attack | Description | Impact |
|--------|-------------|--------|
| **Rogue DHCP Server** | Attacker's server provides false gateway/DNS | Man-in-the-Middle |
| **DHCP Starvation** | Floods server with DISCOVER using spoofed MACs | DoS - pool exhausted |

### DHCP Snooping (Defense)

| Port Type | Connected To | Allowed Messages |
|-----------|--------------|------------------|
| **Trusted** | Legitimate DHCP servers | All messages |
| **Untrusted** | End users | DISCOVER, REQUEST only |

---

## Part B: NAT (Network Address Translation)

**What:** Translates private IP addresses to public IP addresses for Internet access

**Why Important:** Preserves IPv4 address space AND obscures internal network (not true security!)

### NAT Types Comparison

| Feature | Static NAT | Dynamic NAT | PAT (Overload) |
|---------|-----------|-----------|----------------|
| **Mapping** | 1:1 | N:N | N:1 |
| **External Can Initiate** | Yes | No | No* |
| **IP Conservation** | None | Some | Maximum |
| **Use Case** | Servers | Legacy | Home/Office |

*Port forwarding enables external initiation with PAT

### Static NAT Example

| Inside (Private) | Outside (Public) |
|-----------------|-----------------|
| 192.168.1.10 (Web) | 203.0.113.10 |
| 192.168.1.20 (Mail) | 203.0.113.20 |

### PAT Example (Most Common)

| Inside Address:Port | Outside Address:Port |
|-------------------|-------------------|
| 192.168.1.10:50001 | 203.0.113.5:10001 |
| 192.168.1.11:50002 | 203.0.113.5:10002 |
| 192.168.1.12:50003 | 203.0.113.5:10003 |

### Port Forwarding

```
External Client connects to 203.0.113.5:80
                    ↓
                 NAT Device
                    ↓
        Internal Web Server: 192.168.1.10:80
```

### NAT Traversal

**Applications Affected:**

| Application | Issue |
|-------------|-------|
| FTP (active mode) | PORT command contains private IP |
| SIP/VoIP | Media stream IPs in payload |
| P2P applications | Direct connections needed |
| Online gaming | Real-time peer connections |

**Solutions:**

| Solution | Description |
|----------|-------------|
| **STUN** | Clients discover their public IP:port |
| **TURN** | Relay server for failed direct connections |
| **ICE** | Framework combining STUN/TURN |
| **UPnP** | Applications request port forwarding |

### Carrier-Grade NAT (CGNAT) ⚠️

Double NAT at ISP level. Customers receive private addresses from ISP.

- ❌ Cannot host servers
- ❌ Port forwarding not possible
- ❌ Shared IP reputation may be blacklisted

---

## Part C: DNS (Domain Name System)

**What:** Translates human-readable domain names → IP addresses

**Ports:** UDP 53 (queries) | TCP 53 (zone transfers)

**Why Important:** Prime attack target (spoofing, hijacking, tunneling, DDoS amplification)

### DNS Hierarchy

```
              . (Root)
              ↓
        .com, .org, .net (TLDs)
              ↓
        google, example (Domains)
              ↓
        www, mail (Subdomains)

Example FQDN: www.google.com.
```

### DNS Hierarchy Levels

| Level | Examples | Description |
|-------|----------|-------------|
| **Root (.)** | . | Top of hierarchy |
| **TLDs** | .com, .org, .net | Top-Level Domains |
| **Second-Level** | google, example | Registered domains |
| **Subdomains** | www, mail | Hosts within domain |

### DNS Server Types

| Server Type | Role |
|------------|------|
| **Root Name Servers** | Top of hierarchy (13 logical) |
| **TLD Name Servers** | Manage .com, .org, etc. |
| **Authoritative Servers** | Contain actual DNS records |
| **Recursive Resolvers** | Query on behalf of clients (8.8.8.8, 1.1.1.1) |

### DNS Resolution Process

```
Step 1: Browser Cache   → Check cached result
Step 2: OS Cache        → Check /etc/hosts
Step 3: Resolver Cache  → Check ISP resolver cache
Step 4: Root Server     → "Where is .com?"
Step 5: TLD Server      → "Where is example.com?"
Step 6: Authoritative   → "www = 93.184.216.34"
Step 7: Resolver        → Cache and return answer
```

### DNS Record Types

| Record | Purpose | Example |
|--------|---------|---------|
| **A** | IPv4 address | www → 93.184.216.34 |
| **AAAA** | IPv6 address | www → 2606:2800:… |
| **CNAME** | Alias | blog → www |
| **MX** | Mail exchanger | → mail.example.com |
| **NS** | Name server | → ns1.example.com |
| **TXT** | Text data | SPF, DKIM, verification |
| **PTR** | Reverse DNS | IP → domain |
| **SOA** | Start of Authority | Zone metadata |

### DNS Threats

| Attack | Description | Impact |
|--------|-------------|--------|
| **DNS Spoofing** | Inject false records into cache | Redirect to malicious sites |
| **DNS Hijacking** | Compromise DNS server/settings | All queries intercepted |
| **DNS Amplification** | Spoof victim IP, query open resolvers | DDoS with 50-70x amplification |
| **DNS Tunneling** | Encode data in DNS queries | Bypasses firewalls, C2 |

### DNSSEC (Security Extension)

Adds cryptographic signatures to verify DNS record authenticity:

| Record | Purpose |
|--------|---------|
| **RRSIG** | Digital signature |
| **DNSKEY** | Public key for zone |
| **DS** | Delegation Signer |

### Encrypted DNS

| Feature | DNS over HTTPS (DoH) | DNS over TLS (DoT) |
|---------|-------------------|------------------|
| **Port** | 443 | 853 |
| **Blockable** | Hard | Easy |
| **Example** | dns.google/dns-query | dns.google:853 |

### DNS Commands

```bash
# Windows
nslookup www.example.com
nslookup -type=MX example.com
ipconfig /flushdns

# Linux/macOS
dig www.example.com
dig @8.8.8.8 www.example.com
dig +short www.example.com
dig +trace www.example.com
sudo systemd-resolve --flush-caches
```

---

## Part D: Authentication & Directory Services

### Authentication vs Authorization

| Aspect | Authentication | Authorization |
|--------|----------------|---------------|
| **Question** | Who are you? | What can you do? |
| **Verification** | Credentials (username/password) | Permissions/roles |
| **Example** | Login to system | Access file/resource |

---

## RADIUS (Remote Authentication Dial-In User Service)

**What:** Centralized AAA (Authentication, Authorization, Accounting) for network access

**Ports:** UDP 1812 (auth) | UDP 1813 (accounting)  
**Legacy Ports:** UDP 1645, 1646

**Protocol:** UDP  
**Encryption:** Password only (weak)

### RADIUS Architecture

```
[User] → [Network Device (AP, VPN)] → [RADIUS Server] → [User Database]
         (RADIUS Client)              (Authenticator)   (LDAP, AD, Local)
```

### RADIUS Authentication Flow

| Step | Action |
|------|--------|
| 1 | User connects to network device (AP, VPN) |
| 2 | Device sends Access-Request to RADIUS server |
| 3 | RADIUS server validates credentials |
| 4 | Server responds: Access-Accept or Access-Reject |
| 5 | Device grants/denies access |

### RADIUS Security Issues

| Concern | Issue | Mitigation |
|---------|-------|-----------|
| **Shared Secret** | If compromised, all traffic exposed | Strong secrets, regular rotation |
| **UDP Protocol** | No connection guarantee | Use RADSEC (RADIUS over TLS) |
| **Password Encryption** | Only password encrypted | Consider RADSEC for full encryption |

---

## TACACS+ (Terminal Access Controller Access-Control System Plus)

**What:** Cisco-developed protocol for network device administration (routers, switches)

**Port:** TCP 49  
**Protocol:** TCP (reliable)  
**Encryption:** Entire packet body encrypted

### RADIUS vs TACACS+

| Feature | RADIUS | TACACS+ |
|---------|--------|---------|
| **Protocol** | UDP | TCP |
| **Encryption** | Password only | Entire packet |
| **AAA Separation** | Combined | Separate processes |
| **Primary Use** | Network access (users) | Device administration |
| **Standard** | Open (RFC 2865) | Cisco proprietary |

### When to Use Each

| Scenario | Recommended |
|----------|-------------|
| Wi-Fi authentication | RADIUS |
| VPN authentication | RADIUS |
| Router/Switch admin access | TACACS+ |
| Granular command authorization | TACACS+ |
| Multi-vendor environment | RADIUS |

---

## Kerberos

**What:** Ticket-based authentication for Single Sign-On (SSO) - foundation of Windows Active Directory

**Port:** TCP/UDP 88  
**Current Version:** Kerberos v5  
**Encryption:** AES (modern), DES (legacy)

### Kerberos Components

| Component | Abbreviation | Role |
|-----------|--------------|------|
| Key Distribution Center | KDC | Central authentication server |
| Authentication Server | AS | Validates initial credentials |
| Ticket Granting Server | TGS | Issues service tickets |
| Ticket Granting Ticket | TGT | Proves user authenticated |
| Service Ticket | ST | Access to specific service |

### Kerberos Authentication Flow

```
Step 1: User logs in → Request to AS
           ↓
Step 2: AS validates → Returns TGT
           ↓
Step 3: User requests service → Sends TGT to TGS
           ↓
Step 4: TGS issues → Service Ticket
           ↓
Step 5: User presents → Service Ticket to target
           ↓
Step 6: Service validates → Grants access
```

### Kerberos Attacks

| Attack | Description | Mitigation |
|--------|-------------|-----------|
| **Pass-the-Ticket** | Stolen ticket reused | Short ticket lifetime |
| **Golden Ticket** | Forged TGT using KRBTGT hash | Rotate KRBTGT password |
| **Silver Ticket** | Forged service ticket | Service account password rotation |
| **Kerberoasting** | Crack service account passwords | Strong service account passwords |

---

## LDAP (Lightweight Directory Access Protocol)

**What:** Protocol for accessing centralized directory services (user database)

**Ports:** TCP 389 (LDAP) | TCP 636 (LDAPS - encrypted)

**Standard:** RFC 4511  
**Common Use:** Active Directory, OpenLDAP

### LDAP Structure

| Term | Description | Example |
|------|-------------|---------|
| **DN** | Distinguished Name (full path) | CN=John,OU=Users,DC=corp,DC=com |
| **CN** | Common Name | John |
| **OU** | Organizational Unit | Users |
| **DC** | Domain Component | corp, com |

### LDAP Security Risks

| Risk | Description | Mitigation |
|------|-------------|-----------|
| **Clear text** | LDAP sends data unencrypted | Use LDAPS (port 636) |
| **Anonymous bind** | Access without credentials | Disable anonymous access |
| **LDAP injection** | Malicious queries | Input validation |

---

## NTP (Network Time Protocol)

**What:** Synchronizes clocks across network devices

**Port:** UDP 123  
**Accuracy:** Milliseconds over Internet  
**Stratum:** 0 (atomic clock) to 15

### Why NTP Matters for Security

| Dependency | Impact of Time Skew |
|------------|-------------------|
| **Kerberos** | Tickets rejected (default: 5 min tolerance) |
| **Certificates** | Validation failures |
| **Logs** | Event correlation impossible |
| **Forensics** | Timeline reconstruction fails |
| **MFA (TOTP)** | Token validation fails |

### NTP Security

| Attack | Description | Mitigation |
|--------|-------------|-----------|
| **NTP Amplification** | DDoS using NTP monlist | Disable monlist, rate limiting |
| **Time Spoofing** | Manipulate system time | Use authenticated NTP |

```bash
# Check NTP status
timedatectl                    # Linux systemd
w32tm /query /status           # Windows
ntpq -p                        # Traditional NTP
```

---

## Syslog

**What:** Centralized log collection and standardization

**Ports:** UDP 514 (traditional) | TCP 514 | TCP 6514 (TLS)

**Standard:** RFC 5424

### Syslog Severity Levels

| Level | Keyword | Description |
|-------|---------|-------------|
| 0 | Emergency | System unusable |
| 1 | Alert | Immediate action needed |
| 2 | Critical | Critical conditions |
| 3 | Error | Error conditions |
| 4 | Warning | Warning conditions |
| 5 | Notice | Normal but significant |
| 6 | Informational | Informational messages |
| 7 | Debug | Debug messages |

### Syslog Security

| Concern | Issue | Solution |
|---------|-------|----------|
| **UDP** | Unreliable, can be spoofed | Use TCP or TLS |
| **Clear text** | Logs visible on network | Use Syslog over TLS |
| **Storage** | Logs fill disk | Log rotation, SIEM |

---

## Part E: Proxies

**What:** Device/service that inspects and mediates application-layer traffic (Layer 7)

**Key Distinction:**
- **Proxy:** Can inspect Layer 7 (Application Layer)
- **Gateway:** Routes traffic but cannot inspect content
- **VPN:** Creates encrypted tunnel (often confused with proxies)

**Why Important:** Used for security testing, DDoS protection, content filtering, and pivoting in attacks

### Proxy vs Other Technologies

| Technology | Inspects Traffic | Layer | Use Case |
|-----------|------------------|-------|----------|
| **Proxy** | ✓ Yes | Layer 7 | Web filtering, security testing |
| **Gateway** | ✗ No | Layer 3-4 | Basic routing |
| **VPN** | ✗ No | Layer 2-3 | Encryption, anonymity |
| **WAF** | ✓ Yes | Layer 7 | Application protection |

---

## Forward Proxy

**What:** Client → Forward Proxy → Internet → Server

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ↓
┌──────────────────┐
│ Forward Proxy    │ (Corporate web filter)
│ (Web Filter)     │
└──────┬───────────┘
       │
       ↓
   Internet
       │
       ↓
┌──────────────────┐
│  Destination     │
│   Server         │
└──────────────────┘
```

**Use Cases:**
- Corporate web filtering and malware defense
- Anonymity (hiding client IP)
- Content caching
- Access control
- Web application security testing (Burp Suite)

**Browser Behavior:**
- Internet Explorer, Edge, Chrome: Obey "System Proxy" by default
- Firefox: Uses libcurl, doesn't automatically use system proxy

---

## Reverse Proxy

**What:** Internet → Reverse Proxy → Internal Servers

```
Internet
  │
  ↓
┌──────────────────┐
│ Reverse Proxy    │ (DDoS protection, WAF)
│ (Cloudflare)     │
└──────┬───────────┘
       │
       ↓
┌──────────────────┐
│  Internal        │
│  Web Server      │
└──────────────────┘
```

**Use Cases:**
- **DDoS Protection:** Cloudflare filters malicious traffic
- **Web Application Firewall (WAF):** Block attacks, HTTPS decryption possible
- **Load Balancing:** Distribute traffic
- **Penetration Testing:** Reverse shell over reverse proxy

**Pentesting Example:**
1. Gain SSH access to endpoint
2. Configure reverse proxy on infected endpoint
3. Attacker connects to reverse proxy
4. Traffic routed through SSH tunnel
5. Bypass firewalls and evade IDS logging

---

## Complete Network Services Stack

```
┌──────────────────────────────────────────────┐
│   AUTHENTICATION & AUTHORIZATION             │
│   RADIUS, TACACS+, Kerberos, LDAP, NTP      │
│   (WHO can access? WHEN?)                    │
├──────────────────────────────────────────────┤
│   APPLICATION LAYER SERVICES                 │
│   DNS (resolution)                           │
│   Proxies (filtering & inspection)           │
│   Syslog (logging)                           │
│   (WHAT traffic is allowed?)                 │
├──────────────────────────────────────────────┤
│   INTERNET ACCESS                            │
│   NAT (address translation)                  │
│   (HOW to reach the Internet?)               │
├──────────────────────────────────────────────┤
│   NETWORK CONNECTIVITY                       │
│   DHCP (IP assignment)                       │
│   (WHERE on the network?)                    │
└──────────────────────────────────────────────┘
```

---

## Quick Reference: Ports

| Service | Port | Protocol |
|---------|------|----------|
| DHCP Server | 67 | UDP |
| DHCP Client | 68 | UDP |
| DNS | 53 | UDP/TCP |
| LDAP | 389 | TCP |
| LDAPS | 636 | TCP |
| Kerberos | 88 | TCP/UDP |
| RADIUS | 1812 | UDP |
| RADIUS Accounting | 1813 | UDP |
| TACACS+ | 49 | TCP |
| NTP | 123 | UDP |
| Syslog | 514 | UDP/TCP |
| Syslog TLS | 6514 | TCP |

---

## Security Summary

```
🔴 HIGH RISK:
   - DHCP Starvation
   - DNS Spoofing/Hijacking
   - Rogue DHCP Servers
   - Unencrypted LDAP
   - NTP Amplification

🟡 MEDIUM RISK:
   - RADIUS (password only encrypted)
   - ARP Spoofing
   - Syslog over UDP

🟢 BEST PRACTICES:
   - Use RADSEC (RADIUS over TLS)
   - Enable DHCP Snooping
   - Use DNSSEC
   - Encrypt DNS (DoH/DoT)
   - Use LDAPS
   - Authenticate NTP
```
