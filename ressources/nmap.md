# Nmap Cheat Sheet & Network Discovery Guide

## What is Nmap?

**Nmap (Network Mapper)** is an open-source tool used for:

- Host discovery
- Port scanning
- Service detection
- Operating system detection
- Network inventory
- Security auditing

Nmap helps identify:

- Which hosts are alive
- Which ports are open
- What services are running
- Which operating system is being used

---

## How Does Nmap Work?

Nmap sends specially crafted packets to a target and analyzes the responses.

```text
┌─────────┐
│ Attacker│
└────┬────┘
     │
     │ Probe Packets
     ▼
┌─────────┐
│ Target  │
└────┬────┘
     │
     │ Responses
     ▼
Nmap analyzes:
- Host status
- Open ports
- Running services
- OS fingerprint
```

Different scan types use different protocols:

- ARP
- ICMP
- TCP
- UDP

---

# What are Subnetworks?

A **subnetwork (subnet)** is a smaller division of a larger network.

Example:

```text
Network:
192.168.1.0/24

Range:
192.168.1.1 - 192.168.1.254

Subnet Mask:
255.255.255.0
```

Common subnet examples:

| CIDR | Hosts |
|--------|--------|
| /24 | 254 |
| /25 | 126 |
| /26 | 62 |
| /27 | 30 |
| /28 | 14 |

Example:

```text
192.168.1.0/24
├── 192.168.1.1
├── 192.168.1.2
├── ...
└── 192.168.1.254
```

---

# How to Enumerate Targets

Before scanning ports, identify live hosts.

Methods:

1. ARP Scan
2. ICMP Echo Scan
3. ICMP Timestamp Scan
4. ICMP Address Mask Scan
5. TCP SYN Ping
6. TCP ACK Ping
7. UDP Ping

Example:

```bash
nmap -sn 192.168.1.0/24
```

`-sn` = Host discovery only (no port scan)

---

# ARP Scan

## What is ARP?

**Address Resolution Protocol (ARP)** maps:

```text
IP Address  →  MAC Address
```

Example:

```text
192.168.1.10 → AA:BB:CC:DD:EE:FF
```

## How ARP Scan Works

```text
Who has 192.168.1.10?
Tell 192.168.1.100
```

Target replies:

```text
192.168.1.10 is AA:BB:CC:DD:EE:FF
```

If a reply is received:

```text
Host is UP
```

## Nmap ARP Scan

```bash
nmap -PR 192.168.1.0/24
```

### Advantages

- Very reliable
- Very fast
- Works on local networks

---

# ICMP Echo Scan

## What is it?

The classic "ping".

Nmap sends:

```text
ICMP Echo Request
```

Target replies:

```text
ICMP Echo Reply
```

Diagram:

```text
Attacker                 Target

Echo Request ---------->
                     <--------- Echo Reply
```

## Nmap Command

```bash
nmap -PE 192.168.1.0/24
```

---

# ICMP Timestamp Scan

## What is it?

Requests the target's system time.

Nmap sends:

```text
ICMP Timestamp Request
```

Target replies:

```text
ICMP Timestamp Reply
```

## Nmap Command

```bash
nmap -PP 192.168.1.0/24
```

Useful when Echo Requests are blocked.

---

# ICMP Address Mask Scan

## What is it?

Requests the subnet mask used by the target.

Nmap sends:

```text
ICMP Address Mask Request
```

Target replies:

```text
255.255.255.0
```

## Nmap Command

```bash
nmap -PM 192.168.1.0/24
```

Rarely enabled on modern systems.

---

# TCP SYN Ping Scan

## What is it?

Instead of ICMP, Nmap sends a TCP SYN packet.

Example:

```text
SYN → Port 80
```

Responses:

```text
SYN/ACK  => Host Alive
RST      => Host Alive
No Reply => Unknown
```

Diagram:

```text
Attacker                 Target

SYN ------------------->
                     <----------- SYN/ACK
```

## Nmap Command

```bash
nmap -PS80,443 192.168.1.0/24
```

Useful when ICMP is blocked.

---

# TCP ACK Ping Scan

## What is it?

Nmap sends a TCP ACK packet.

Target usually responds:

```text
RST
```

A response means:

```text
Host Exists
```

## Nmap Command

```bash
nmap -PA80,443 192.168.1.0/24
```

Useful for bypassing certain firewall rules.

---

# UDP Ping Scan

## What is it?

Nmap sends UDP packets.

Target may respond:

```text
ICMP Port Unreachable
```

This indicates:

```text
Host Alive
```

Diagram:

```text
UDP Packet ----------->
                    <--------- ICMP Port Unreachable
```

## Nmap Command

```bash
nmap -PU53,161 192.168.1.0/24
```

Useful when ICMP and TCP are filtered.

---

# What Can Nmap Detect?

## Host Discovery

```text
Is the machine alive?
```

Example:

```bash
nmap -sn 192.168.1.0/24
```

---

## Open Ports

```text
22  SSH
80  HTTP
443 HTTPS
```

Example:

```bash
nmap 192.168.1.10
```

---

## Running Services

Example:

```text
22/tcp open ssh OpenSSH 9.2
80/tcp open http Apache 2.4
```

Command:

```bash
nmap -sV 192.168.1.10
```

---

## Operating System Detection

Example:

```text
Linux
Windows
FreeBSD
Cisco IOS
```

Command:

```bash
sudo nmap -O 192.168.1.10
```

---

## Version Detection

```bash
nmap -sV 192.168.1.10
```

---

## Script Scanning (NSE)

Nmap can run scripts to gather information.

```bash
nmap --script default 192.168.1.10
```

Examples:

- SMB enumeration
- HTTP information
- SSL checks
- DNS information

---

# How to Scan an IP Address with Nmap

## Basic Scan

```bash
nmap 192.168.1.10
```

---

## Scan Multiple Hosts

```bash
nmap 192.168.1.10 192.168.1.20
```

---

## Scan a Subnet

```bash
nmap 192.168.1.0/24
```

---

## Scan a Range

```bash
nmap 192.168.1.1-100
```

---

# How to Check Ports with Nmap

## Default Top Ports

```bash
nmap 192.168.1.10
```

Scans the most common ports.

---

## Scan Specific Ports

```bash
nmap -p 22,80,443 192.168.1.10
```

---

## Scan Port Range

```bash
nmap -p 1-1000 192.168.1.10
```

---

## Scan All TCP Ports

```bash
nmap -p- 192.168.1.10
```

Equivalent:

```text
1 - 65535
```

---

## SYN Scan (Stealth Scan)

```bash
sudo nmap -sS 192.168.1.10
```

Most common scan.

Process:

```text
Attacker               Target

SYN ------------------>
                   <----------- SYN/ACK

RST ------------------>
```

Connection never fully established.

---

# Common Commands Cheat Sheet

```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Basic scan
nmap 192.168.1.10

# Service detection
nmap -sV 192.168.1.10

# OS detection
sudo nmap -O 192.168.1.10

# SYN scan
sudo nmap -sS 192.168.1.10

# Scan all ports
nmap -p- 192.168.1.10

# Aggressive scan
sudo nmap -A 192.168.1.10

# ARP discovery
nmap -PR 192.168.1.0/24

# ICMP Echo
nmap -PE 192.168.1.0/24

# TCP SYN Ping
nmap -PS80,443 192.168.1.0/24

# TCP ACK Ping
nmap -PA80,443 192.168.1.0/24

# UDP Ping
nmap -PU53,161 192.168.1.0/24
```

---

# Typical Workflow

```text
1. Discover Hosts
      │
      ▼
nmap -sn 192.168.1.0/24

2. Scan Ports
      │
      ▼
nmap -p- TARGET

3. Identify Services
      │
      ▼
nmap -sV TARGET

4. Detect OS
      │
      ▼
nmap -O TARGET

5. Run NSE Scripts
      │
      ▼
nmap --script default TARGET
```

This workflow moves from host discovery → port discovery → service enumeration → operating system fingerprinting → deeper enumeration.