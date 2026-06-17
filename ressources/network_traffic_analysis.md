# Packet Analysis & Traffic Monitoring Cheat Sheet

---

# What is Packet Capture?

Packet Capture (PCAP) is the process of recording network traffic as it travels across a network.

Think of it as:

```text
Network Traffic
       ↓
Packet Capture
       ↓
Recorded Conversation
```

Every packet contains information such as:

- Source IP
- Destination IP
- Protocol
- Ports
- Payload data

Example:

```text
192.168.1.10:52344
        ↓
93.184.216.34:443
```

---

# Why is Packet Capture Important?

Packet captures allow you to:

- Troubleshoot network problems
- Investigate security incidents
- Analyze malware communications
- Detect unauthorized activity
- Verify firewall behavior
- Understand application traffic

Example:

```text
User reports website unavailable
            ↓
Capture traffic
            ↓
Find DNS failure
```

Without packet captures:

```text
Guessing
```

With packet captures:

```text
Evidence
```

---

# How Does Wireshark Work?

Wireshark captures packets and dissects them into readable fields.

```text
Raw Packet
      ↓
Dissector Engine
      ↓
Human Readable Data
```

Example packet:

```text
Ethernet
 └── IP
      └── TCP
           └── HTTP
```

Wireshark displays:

```text
Packet List
      ↓
Protocol Details
      ↓
Raw Bytes
```

---

# Wireshark Interface

```text
+--------------------------------+
| Packet List                    |
+--------------------------------+
| Ethernet II                    |
| Internet Protocol              |
| TCP                            |
| HTTP                           |
+--------------------------------+
| Raw Hex Data                   |
+--------------------------------+
```

---

# Capture Filters vs Display Filters

Many beginners confuse these.

---

## Capture Filters

Applied BEFORE packets are captured.

```text
Network
   ↓
Filter
   ↓
Capture
```

Only matching packets are saved.

Example:

```text
host 192.168.1.10
```

Capture only:

```text
192.168.1.10 traffic
```

Benefits:

- Smaller capture files
- Lower resource usage

---

## Display Filters

Applied AFTER packets are captured.

```text
Capture Everything
        ↓
Display Filter
        ↓
Show Matching Packets
```

Example:

```text
ip.addr == 192.168.1.10
```

Captured packets remain available.

---

## Comparison

| Feature | Capture Filter | Display Filter |
|----------|----------|----------|
| Applied Before Capture | Yes | No |
| Applied After Capture | No | Yes |
| Reduces File Size | Yes | No |
| More Flexible | No | Yes |

---

# Common Wireshark Display Filters

## Show DNS

```text
dns
```

---

## Show HTTP

```text
http
```

---

## Show TCP

```text
tcp
```

---

## Show UDP

```text
udp
```

---

## Show Specific IP

```text
ip.addr == 192.168.1.10
```

---

## Show Port 80

```text
tcp.port == 80
```

---

## Show Failed DNS

```text
dns.flags.rcode != 0
```

---

# Following TCP Streams

One of Wireshark's most useful features.

Purpose:

```text
Reassemble an entire TCP conversation
```

Instead of viewing:

```text
Packet 1
Packet 2
Packet 3
Packet 4
```

You see:

```text
Complete Conversation
```

Example:

```text
GET /index.html HTTP/1.1
Host: example.com
```

Steps:

```text
Right Click Packet
      ↓
Follow
      ↓
TCP Stream
```

Useful for:

- HTTP analysis
- Malware traffic
- Login sessions
- Debugging applications

---

# What is tcpdump?

tcpdump is a command-line packet capture tool.

Think:

```text
Wireshark = GUI
tcpdump   = CLI
```

---

# Why Use tcpdump?

Useful when:

- SSH access only
- No graphical environment
- Servers
- Remote systems
- Quick captures

Example:

```bash
tcpdump -i eth0
```

Capture packets on:

```text
eth0
```

---

# When Should You Use tcpdump Instead of Wireshark?

Use tcpdump when:

```text
Linux Server
Cloud Instance
Container
SSH Session
```

Example:

```bash
tcpdump -i eth0 -w capture.pcap
```

Later:

```text
Open capture.pcap in Wireshark
```

Best of both worlds.

---

# Constructing tcpdump Filters

General format:

```bash
tcpdump [filter]
```

---

## Host Filter

```bash
tcpdump host 192.168.1.10
```

---

## Source Host

```bash
tcpdump src host 192.168.1.10
```

---

## Destination Host

```bash
tcpdump dst host 192.168.1.10
```

---

## TCP Only

```bash
tcpdump tcp
```

---

## UDP Only

```bash
tcpdump udp
```

---

## Port Filter

```bash
tcpdump port 80
```

---

## Multiple Conditions

```bash
tcpdump tcp and port 443
```

---

## Exclude Traffic

```bash
tcpdump not port 22
```

---

## Complex Example

```bash
tcpdump \
'host 192.168.1.10 and tcp and port 443'
```

Flow:

```text
Host?
  ↓
TCP?
  ↓
Port 443?
  ↓
Capture
```

---

# Common Indicators of Network Anomalies

An anomaly is traffic that deviates from normal behavior.

Examples:

```text
Unexpected Protocols
Large Data Transfers
Repeated Failed Connections
DNS Spikes
Port Scanning
Beaconing Traffic
```

---

## Examples

### Excessive DNS Requests

```text
10 requests/minute
      ↓
5000 requests/minute
```

Possible:

```text
Malware
DNS Tunneling
```

---

### Many Failed Connections

```text
SYN
SYN
SYN
SYN
```

Possible:

```text
Scanning
Misconfiguration
```

---

### Unknown External Connections

```text
Internal Host
      ↓
Unknown Country
```

Potential:

```text
Data Exfiltration
Malware C2
```

---

# Identifying Unauthorized Connections

Look for:

```text
Unknown IPs
Unexpected Ports
Strange Domains
Odd Traffic Times
```

Questions:

```text
Who initiated the connection?
Where is it going?
Why is it occurring?
```

---

## Example Investigation

```text
192.168.1.50
      ↓
185.x.x.x
      ↓
Port 4444
```

Questions:

```text
Is this expected?
Is software installed?
Is it malware?
```

---

# Wireshark Traffic Statistics Tools

Wireshark provides several built-in analysis tools.

Menu:

```text
Statistics
```

---

## Protocol Hierarchy

Shows:

```text
Ethernet
 ├─ IP
 ├─ TCP
 ├─ UDP
 └─ DNS
```

Useful for:

```text
Traffic composition
```

---

## Conversations

Shows:

```text
Source ↔ Destination
```

Useful for:

```text
Top talkers
```

---

## Endpoints

Shows:

```text
IP addresses
MAC addresses
```

Useful for:

```text
Active hosts
```

---

## I/O Graphs

Visualizes:

```text
Traffic over time
```

Useful for:

```text
Traffic spikes
DDoS analysis
Bandwidth issues
```

---

## Flow Graph

Visualizes:

```text
Packet exchanges
```

Example:

```text
Client       Server

 SYN  ------>
      <------ SYN ACK

 ACK  ------>

 GET  ------>

      <------ Response
```

---

# DNS Analysis

DNS is often one of the first protocols analyzed.

Display filter:

```text
dns
```

---

# DNS Query Flow

```text
Client
   ↓
DNS Query
   ↓
Resolver
   ↓
Response
```

Example:

```text
A example.com ?
```

Response:

```text
93.184.216.34
```

---

# What to Look For

## Failed Lookups

```text
NXDOMAIN
```

May indicate:

```text
Misconfiguration
Malware
Typos
```

---

## Excessive Queries

```text
Thousands per minute
```

Potential:

```text
Malware
DNS Tunneling
```

---

## Suspicious Domains

Example:

```text
asd7f8as9d.example.xyz
```

Could indicate:

```text
Command & Control
DNS Tunneling
```

---

# Best Practices for Capturing Traffic

---

## Capture Only What You Need

Bad:

```text
Entire Network
For 7 Days
```

Good:

```text
Specific Host
Specific Protocol
```

---

## Use Capture Filters

Example:

```text
host 192.168.1.10
```

Benefits:

```text
Smaller files
Less noise
```

---

## Synchronize Time

Ensure systems have accurate clocks.

Use:

```text
NTP
```

Important for:

```text
Incident response
Correlation
```

---

## Save Raw Captures

Keep originals.

```text
capture.pcap
```

Analyze copies instead.

---

## Document Context

Record:

```text
Date
Purpose
Host
Interface
Location
```

---

## Monitor Storage

Captures grow quickly.

Example:

```text
1 Gbps network
      ↓
Huge PCAP files
```

---

# How Encryption Affects Traffic Analysis

Encryption protects packet contents.

Without encryption:

```text
HTTP
FTP
Telnet
```

You can often read:

```text
Usernames
Passwords
Pages
Commands
```

---

## Encrypted Example

HTTPS traffic:

```text
TLS Encrypted
```

Payload becomes:

```text
Unreadable Ciphertext
```

Instead of:

```text
GET /login
```

You see:

```text
Encrypted Application Data
```

---

# What Can Still Be Seen?

Even with encryption, metadata is usually visible.

Examples:

```text
Source IP
Destination IP
Protocol
Port
Packet Size
Timing
Connection Duration
```

Example:

```text
192.168.1.10
      ↓
142.x.x.x
Port 443
```

You know:

```text
HTTPS connection occurred
```

But not:

```text
Page contents
Password
Message content
```

---

# Encryption Visibility Summary

| Information | Visible? |
|-------------|-----------|
| Source IP | Yes |
| Destination IP | Yes |
| Protocol | Yes |
| Port | Yes |
| Packet Size | Yes |
| Timing | Yes |
| HTTP Content | No |
| Passwords | No |
| Messages | No |

---

# Typical Traffic Analysis Workflow

```text
1. Capture Traffic
       ↓
Wireshark / tcpdump

2. Identify Hosts
       ↓
Endpoints

3. Identify Protocols
       ↓
Protocol Hierarchy

4. Filter Traffic
       ↓
DNS / HTTP / TCP

5. Follow Streams
       ↓
Conversations

6. Detect Anomalies
       ↓
Unexpected Traffic

7. Investigate Connections
       ↓
IPs / Domains / Ports

8. Build Findings
       ↓
Report
```