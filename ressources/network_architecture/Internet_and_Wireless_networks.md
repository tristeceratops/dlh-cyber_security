# Internet Architecture & Wireless Networks - Study Guide

## Big Picture

```
Internet Architecture
Network of networks
Tier ISPs → ASes → BGP → IXPs / CDNs / Anycast

Wireless Networks
Wi-Fi / Cellular
APs → Security protocols → Monitoring
```

---

## Part A: Internet Architecture

### Internet Structure

The Internet is a global network of interconnected networks.

| Tier | Role | Example |
|------|------|---------|
| **Tier 1** | Global backbone | NTT, Lumen, Cogent |
| **Tier 2** | Regional networks | Comcast, Orange |
| **Tier 3** | Local ISPs | Home cable/DSL providers |
| **Customer** | End users | Homes, businesses |

### Autonomous Systems (AS)

An **Autonomous System (AS)** is a network under one routing policy.
Each AS has an **ASN**.

| ASN | Organization |
|-----|--------------|
| AS15169 | Google |
| AS13335 | Cloudflare |
| AS32934 | Meta |
| AS16509 | Amazon |
| AS8075 | Microsoft |

### BGP (Border Gateway Protocol)

**Purpose:** Exchanges routes between ASes

| Feature | Value |
|---------|-------|
| Type | Path Vector Protocol |
| Port | TCP 179 |
| Updates | Incremental |
| Routing | Policy-based |

#### BGP Types

| Type | Scope |
|------|-------|
| **eBGP** | Between different ASes |
| **iBGP** | Inside the same AS |

#### Simplified Path Preference

1. Weight
2. LOCAL_PREF
3. AS_PATH
4. MED

#### BGP Security

| Attack | Impact |
|--------|--------|
| **BGP Hijacking** | Traffic is redirected |
| **BGP Leak** | Wrong route is advertised |

**Protections:** RPKI, BGP ROV, prefix filtering

### Peering vs Transit

| Type | Payment | Traffic Exchange |
|------|---------|------------------|
| **Peering** | Settlement-free | Only each other's customers |
| **Transit** | Customer pays | Full Internet access |

### Internet Exchange Points (IXPs)

IXPs let networks exchange traffic directly.

```
Without IXP:  Traffic → Transit provider → Destination
With IXP:     Traffic → IXP switch fabric → Destination
```

| IXP | Location | Traffic |
|-----|----------|---------|
| DE-CIX Frankfurt | Germany | >12 Tbps |
| AMS-IX | Netherlands | >10 Tbps |
| LINX | London | >6 Tbps |
| Equinix Ashburn | USA | >5 Tbps |

### Submarine Cables

| Fact | Value |
|------|-------|
| Global cables | ~400+ |
| Capacity | 100+ Tbps per cable |
| Lifespan | 25+ years |

| Cable | Route | Capacity |
|-------|-------|----------|
| MAREA | US-Spain | 160 Tbps |
| Dunant | US-France | 250 Tbps |
| Grace Hopper | US-UK-Spain | 352 Tbps |

### CDNs and Anycast

**CDNs:** cache content near users to reduce latency.

| Benefit | Result |
|---------|--------|
| Caching | Faster delivery |
| DDoS protection | Better resilience |
| Load balancing | Shared traffic |
| TLS termination | Easier edge security |

**Anycast:** multiple servers share one IP, and BGP sends users to the nearest server.

```
User → nearest edge server
US   → US server
EU   → EU server
Asia → Asia server
```

---

## Part B: Wireless Networks

### Wireless Basics

Wireless extends connectivity without cables, but signals can leak outside buildings.

### Wi-Fi Frequency Bands

| Band | Frequency | Channels | Characteristics |
|------|-----------|----------|-----------------|
| **2.4 GHz** | 2.4-2.5 GHz | 1-14 | Long range, crowded |
| **5 GHz** | 5.1-5.8 GHz | 36-165 | Faster, shorter range |
| **6 GHz** | 5.9-7.1 GHz | 1-233 | Wi-Fi 6E / newest |

**2.4 GHz note:** only channels **1, 6, 11** do not overlap.

### Wi-Fi Standards

| Standard | Year | Band | Max Speed | Marketing |
|----------|------|------|-----------|-----------|
| 802.11a | 1999 | 5 GHz | 54 Mbps | - |
| 802.11b | 1999 | 2.4 GHz | 11 Mbps | - |
| 802.11g | 2003 | 2.4 GHz | 54 Mbps | - |
| 802.11n | 2009 | Both | 600 Mbps | Wi-Fi 4 |
| 802.11ac | 2013 | 5 GHz | 3.5 Gbps | Wi-Fi 5 |
| 802.11ax | 2019 | Both + 6 | 9.6 Gbps | Wi-Fi 6/6E |
| 802.11be | 2024 | All | 46 Gbps | Wi-Fi 7 |

### Key Wi-Fi Technologies

| Technology | Purpose |
|-----------|---------|
| **MIMO** | More antennas, more streams |
| **MU-MIMO** | Serve multiple clients at once |
| **OFDMA** | Better spectrum efficiency |
| **Beamforming** | Focus signal toward clients |

### Wireless Security Protocols

| Protocol | Year | Security | Status |
|----------|------|----------|--------|
| **WEP** | 1997 | RC4, 24-bit IV | Broken |
| **WPA** | 2003 | TKIP | Deprecated |
| **WPA2** | 2004 | AES-CCMP | Current standard |
| **WPA3** | 2018 | SAE (Dragonfly) | Best |

### WPA2 vs WPA3

| Feature | WPA2 | WPA3 |
|---------|------|------|
| Key Exchange | 4-way handshake | SAE |
| Offline dictionary attack | Vulnerable | Protected |
| Forward secrecy | No | Yes |
| Management frame protection | Optional | Mandatory |

### Authentication Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Personal (PSK)** | Same password for all | Home, small office |
| **Enterprise (802.1X)** | Individual credentials via RADIUS | Corporate |

### Wireless Network Modes

| Mode | Description |
|------|-------------|
| **Infrastructure** | Clients connect through an AP |
| **Ad-Hoc** | Clients connect directly |
| **Mesh** | APs connect wirelessly |

### Enterprise Architecture

| Type | Description |
|------|-------------|
| **Autonomous APs** | Each AP independent |
| **Controller-Based** | Centralized management (WLC) |
| **Cloud-Managed** | Controller in cloud |

### Wireless Attacks

| Attack | Description |
|--------|-------------|
| **Evil Twin** | Fake AP with same SSID |
| **Deauthentication** | Forged frames disconnect clients |
| **WPA2 Handshake Capture** | Capture handshake, crack offline |
| **KRACK** | Key reinstallation attack on WPA2 |

### Wireless Tools

| Tool | Purpose |
|------|---------|
| **aircrack-ng** | Wi-Fi auditing suite |
| **Kismet** | Wireless detector |
| **Wireshark** | Packet capture / analysis |
| **hashcat** | Password cracking |
| **Bettercap** | Network attack framework |

### Wireless Best Practices

| Area | Best Practice |
|------|---------------|
| **Authentication** | Use WPA3 where possible, WPA2-AES minimum |
| **Enterprise** | Use 802.1X with certificates |
| **Personal** | Strong passphrase (15+ chars) |
| **Legacy** | Never use WEP or WPA-TKIP |
| **Segmentation** | Separate Corporate, Guest, and IoT SSIDs |
| **Monitoring** | Detect rogue APs and deauth attacks |

### Common Commands

```bash
# Linux
iwconfig
iw dev
sudo iwlist wlan0 scan
nmcli device wifi list

# Monitor mode
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon

# Windows PowerShell
netsh wlan show networks
netsh wlan show interfaces
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear
```

### Cellular Networks

| Generation | Speed | Technology |
|------------|-------|------------|
| **2G** | ~0.1 Mbps | GSM, CDMA |
| **3G** | 0.5-5 Mbps | UMTS, HSPA |
| **4G LTE** | 10-100 Mbps | LTE, LTE-A |
| **5G** | 100-1000+ Mbps | NR (New Radio) |

**5G slicing:** different slices for broadband, low latency, and IoT.

---

## Quick Summary

| Topic | Key Idea |
|------|----------|
| **Internet architecture** | ASes exchange routes with BGP |
| **IXPs** | Direct traffic exchange, lower cost and latency |
| **CDNs / Anycast** | Faster delivery and DDoS resilience |
| **Wi-Fi evolution** | From 11 Mbps to multi-gigabit speeds |
| **Wireless security** | WEP broken, WPA3 best |
| **Wireless attacks** | Evil twin, deauth, handshake capture |

