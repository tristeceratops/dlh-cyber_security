# Network Communication & Addressing - Study Guide

## Layer Breakdown

```
<span style="color: #03ce83">Layer 4 (Transport)</span>    → PORTS        (TCP/UDP)
<span style="color: #FFD700">Layer 3 (Network)</span>      → IP ADDRESSES (Routing)
<span style="color: #FFA500">Layer 2 (Data Link)</span>    → MAC ADDRESSES (Local delivery)
```

---

## 1. MAC Address (<span style="color: #FFA500">Layer 2</span> - Physical)

**What:** Hardware identifier for local network communication  
**Format:** 6 hexadecimal pairs → `00:1A:2B:3C:4D:5E`  
**Scope:** Local Area Network (LAN) only

### Special MAC Addresses

| Address | Purpose |
|---------|---------|
| `FF:FF:FF:FF:FF:FF` | Broadcast (all devices) |
| `01:00:5E:xx:xx:xx` | IPv4 Multicast |
| `33:33:xx:xx:xx:xx` | IPv6 Multicast |

### Common Vendor OUIs

| OUI | Vendor |
|-----|--------|
| `00:1A:2B` | Apple |
| `00:50:56` / `00:0C:29` | VMware |
| `DC:A6:32` / `B8:27:EB` | Raspberry Pi |

---

## 2. IP Address (<span style="color: #FFD700">Layer 3</span> - Logical)

**What:** Logical identifier for routing across networks  
**Versions:** IPv4 (32-bit) | IPv6 (128-bit)

### IPv4 vs IPv6

| Feature | IPv4 | IPv6 |
|---------|------|------|
| **Length** | 32 bits | 128 bits |
| **Total Addresses** | ~4.3 billion | ~340 undecillion |
| **Broadcast** | ✓ Yes | ✗ Multicast only |
| **IPsec** | Optional | Built-in |
| **Example** | `192.168.1.1` | `2001:db8:85a3::8a2e:370:7334` |

---

## 3. Ports (<span style="color: #03ce83">Layer 4 - Transport</span>)

**What:** Application identifier on a device  
**Protocol:** TCP / UDP  
**Range:** 0 - 65,535

### Port Categories

| Category | Range | Usage | Requires Admin |
|----------|-------|-------|---|
| **Well-Known** | 0-1023 | HTTP (80), HTTPS (443), SSH (22), DNS (53) | ✓ Yes |
| **Registered** | 1024-49151 | MySQL (3306), PostgreSQL (5432), RDP (3389) | ✗ No |
| **Dynamic/Private** | 49152-65535 | Temporary/Client connections (ephemeral) | ✗ No |

---

## 4. Device Identification Summary

### The Complete Picture

```
┌─────────────────────────────────────┐
│  MAC Address                        │  <span style="color: #FFA500">Layer 2</span>
│  (Hardware ID - Local Network)      │
├─────────────────────────────────────┤
│  IP Address                         │  <span style="color: #FFD700">Layer 3</span>
│  (Logical ID - Routing)             │
├─────────────────────────────────────┤
│  Port Number                        │  <span style="color: #03ce83">Layer 4</span>
│  (Service ID - Application)         │
└─────────────────────────────────────┘
```

**Together:** MAC + IP + Port = **Complete Network Connection**

---

## 5. IP Address Classes (Legacy)

| Class | Range | Use Case | First Bits |
|-------|-------|----------|-----------|
| **A** | 1.0.0.1 - 126.255.255.254 | Large networks | `0xxxxxxx` |
| **B** | 128.1.0.1 - 191.255.255.254 | Medium networks | `10xxxxxx` |
| **C** | 192.0.1.1 - 223.255.254.254 | Small networks | `110xxxxx` |
| **D** | 224.0.0.0 - 239.255.255.255 | Multicast | `1110xxxx` |
| **E** | 240.0.0.0 - 255.255.255.255 | Reserved/Experimental | `1111xxxx` |

---

## 6. CIDR (Classless Inter-Domain Routing)

**Format:** `192.0.2.0/24`  
**Meaning:** `/24` = 24 bits for network | 8 bits for hosts

### Subnetting Formulas

| What | Formula | Notes |
|------|---------|-------|
| **# of Subnets** | `2^n` | n = bits borrowed |
| **Hosts per Subnet** | `2^h - 2` | h = host bits (-2 for network & broadcast) |
| **Block Size** | `256 - mask_octet` | Increment between subnets |

### Example: Subnet 192.168.10.0/24 into 4 Subnets

**Solution:** 4 = 2² → Borrow 2 bits → New mask: `/26`

| Subnet | Network | First Host | Last Host | Broadcast |
|--------|---------|-----------|-----------|-----------|
| 1 | 192.168.10.0/26 | 192.168.10.1 | 192.168.10.62 | 192.168.10.63 |
| 2 | 192.168.10.64/26 | 192.168.10.65 | 192.168.10.126 | 192.168.10.127 |
| 3 | 192.168.10.128/26 | 192.168.10.129 | 192.168.10.190 | 192.168.10.191 |
| 4 | 192.168.10.192/26 | 192.168.10.193 | 192.168.10.254 | 192.168.10.255 |

### Why Subnetting?

✓ Reduced broadcast traffic  
✓ Improved security through isolation  
✓ Efficient IP address usage  
✓ Better organization

---

## 7. Address Resolution Protocol (ARP)

**Purpose:** Maps IP addresses → MAC addresses (<span style="color: #FFA500">Layer 2</span> ↔ <span style="color: #FFD700">Layer 3</span>)

### ARP Process

| Step | Action | Direction | Message |
|------|--------|-----------|---------|
| 1 | Request | A → Broadcast | "Who has 192.168.1.20?" |
| 2 | Reply | B → A (Unicast) | "I'm at BB:BB:BB:BB:BB:BB" |
| 3 | Cache | Host A | Entry stored |

### ARP Commands

```bash
# Windows
arp -a

# Linux
arp -n
ip neigh show
```

### ARP Security Threats ⚠️

- **ARP Spoofing:** Fake ARP replies
- **ARP Poisoning:** Corrupted ARP cache
- **Man-in-the-Middle:** Traffic interception

---

## 8. Routing

**Definition:** Process of selecting the path for traffic between networks

### Routing Table Example

| Destination | Gateway | Mask | Interface |
|-------------|---------|------|-----------|
| default | 192.168.1.1 | 0.0.0.0 | wlp4s0 |
| 192.168.1.0 | 0.0.0.0 | 255.255.255.0 | wlp4s0 |

---

## 9. Quick Reference: MAC vs IP

| Aspect | MAC Address | IP Address |
|--------|-------------|-----------|
| **Layer** | <span style="color: #FFA500">Layer 2</span> | <span style="color: #FFD700">Layer 3</span> |
| **Scope** | Local network only | Global routing |
| **Fixed?** | Hardcoded (fixed) | Flexible (assigned) |
| **Format** | `00:1A:2B:3C:4D:5E` | `192.168.1.1` |
| **Purpose** | Deliver to device | Deliver to network |

---

## Next Steps: Network Services

| You Know | You'll Learn |
|----------|------------|
| IP addresses identify devices | DHCP assigns addresses automatically |
| Subnets organize networks | NAT allows private → public IPs |
| IPs are numbers | DNS translates names to IPs |

### Security Note

These services are **attack surfaces**:
- DHCP spoofing
- DNS poisoning
- NAT traversal
