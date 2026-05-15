# Networking Ports Reference Guide

## Port Ranges

| Range           | Name                  | Description                      |
|:----------------|:----------------------|:---------------------------------|
| `0-1023`        | Well-Known            | System/privileged services       |
| `1024-49151`    | Registered            | Application services             |
| `49152-65535`   | Dynamic/Ephemeral     | Client-side temporary ports      |

# Essential Ports (Memorize These!)

| Port     | Protocol    | Service        | Description                  |
|:---------|:------------|:---------------|:-----------------------------|
| `20`     | `TCP`       | `FTP-Data`     | File transfer data           |
| `21`     | `TCP`       | `FTP`          | File transfer control        |
| `22`     | `TCP`       | `SSH`          | Secure shell                 |
| `23`     | `TCP`       | `Telnet`       | Remote terminal (insecure)   |
| `25`     | `TCP`       | `SMTP`         | Send email                   |
| `53`     | `TCP/UDP`   | `DNS`          | Domain name resolution       |
| `67`     | `UDP`       | `DHCP`         | Server                       |
| `68`     | `UDP`       | `DHCP`         | Client                       |
| `80`     | `TCP`       | `HTTP`         | Web traffic                  |
| `110`    | `TCP`       | `POP3`         | Receive email                |
| `143`    | `TCP`       | `IMAP`         | Receive email                |
| `443`    | `TCP`       | `HTTPS`        | Secure web                   |
| `3389`   | `TCP/UDP`   | `RDP`          | Windows remote desktop       |

# All Common Ports

## File Transfer

| Port     | Protocol    | Service        | Notes                     |
|:---------|:------------|:---------------|:--------------------------|
| `20`     | `TCP`       | `FTP-Data`     | Active mode data          |
| `21`     | `TCP`       | `FTP`          | Control connection        |
| `22`     | `TCP`       | `SFTP/SCP`     | Via SSH                   |
| `69`     | `UDP`       | `TFTP`         | Trivial FTP               |
| `115`    | `TCP`       | `SFTP`         | Simple FTP (legacy)       |
| `445`    | `TCP`       | `SMB`          | Windows file sharing      |
| `2049`   | `TCP/UDP`   | `NFS`          | Network File System       |

## Email

| Port     | Protocol    | Service        | Notes               |
|:---------|:------------|:---------------|:--------------------|
| `25`     | `TCP`       | `SMTP`         | Send email          |
| `110`    | `TCP`       | `POP3`         | Receive email       |
| `143`    | `TCP`       | `IMAP`         | Receive email       |
| `465`    | `TCP`       | `SMTPS`        | SMTP over SSL       |
| `587`    | `TCP`       | `SMTP`         | Submission          |
| `993`    | `TCP`       | `IMAPS`        | IMAP over SSL       |
| `995`    | `TCP`       | `POP3S`        | POP3 over SSL       |

## Web

| Port     | Protocol    | Service        | Notes                   |
|:---------|:------------|:---------------|:------------------------|
| `80`     | `TCP`       | `HTTP`         | Standard web            |
| `443`    | `TCP`       | `HTTPS`        | Secure web              |
| `8080`   | `TCP`       | `HTTP-Alt`     | Alternative HTTP        |
| `8443`   | `TCP`       | `HTTPS-Alt`    | Alternative HTTPS       |

## Remote Access

| Port     | Protocol    | Service          | Notes                          |
|:---------|:------------|:-----------------|:-------------------------------|
| `22`     | `TCP`       | `SSH`            | Secure shell                   |
| `23`     | `TCP`       | `Telnet`         | Insecure                       |
| `3389`   | `TCP/UDP`   | `RDP`            | Windows remote desktop         |
| `5900`   | `TCP`       | `VNC`            | Virtual Network Computing      |
| `5985`   | `TCP`       | `WinRM HTTP`     | PowerShell remoting            |
| `5986`   | `TCP`       | `WinRM HTTPS`    | Secure PowerShell remoting     |

## Network Services

| Port     | Protocol    | Service          | Notes                  |
|:---------|:------------|:-----------------|:-----------------------|
| `53`     | `TCP/UDP`   | `DNS`            | Name resolution        |
| `67`     | `UDP`       | `DHCP`           | Server                 |
| `68`     | `UDP`       | `DHCP`           | Client                 |
| `123`    | `UDP`       | `NTP`            | Time synchronization   |
| `161`    | `UDP`       | `SNMP`           | Monitoring             |
| `162`    | `UDP`       | `SNMP Trap`      | Alerts                 |
| `514`    | `UDP`       | `Syslog`         | Logging                |
| `546`    | `UDP`       | `DHCPv6`         | Client                 |
| `547`    | `UDP`       | `DHCPv6`         | Server                 |

## Directory Services

| Port     | Protocol    | Service        | Notes                    |
|:---------|:------------|:---------------|:-------------------------|
| `88`     | `TCP/UDP`   | `Kerberos`     | Authentication           |
| `389`    | `TCP`       | `LDAP`         | Directory services       |
| `636`    | `TCP`       | `LDAPS`        | Secure LDAP              |
| `3268`   | `TCP`       | `LDAP GC`      | Global Catalog           |
| `3269`   | `TCP`       | `LDAPS GC`     | Secure Global Catalog    |

## Database

| Port      | Protocol   | Service        | Notes                   |
|:----------|:-----------|:---------------|:------------------------|
| `1433`    | `TCP`      | `MS SQL`       | Microsoft SQL Server    |
| `1521`    | `TCP`      | `Oracle`       | Oracle Database         |
| `3306`    | `TCP`      | `MySQL`        | MySQL/MariaDB           |
| `5432`    | `TCP`      | `PostgreSQL`   | PostgreSQL              |
| `6379`    | `TCP`      | `Redis`        | Redis cache             |
| `27017`   | `TCP`      | `MongoDB`      | MongoDB                 |

## VPN

| Port      | Protocol   | Service          | Notes                  |
|:----------|:-----------|:-----------------|:-----------------------|
| `500`     | `UDP`      | `IKE`            | IPsec key exchange     |
| `1194`    | `UDP`      | `OpenVPN`        | OpenVPN default        |
| `1701`    | `UDP`      | `L2TP`           | Layer 2 Tunneling      |
| `1723`    | `TCP`      | `PPTP`           | Point-to-Point Tunnel  |
| `4500`    | `UDP`      | `IPsec NAT-T`   | NAT traversal          |
| `51820`   | `UDP`      | `WireGuard`      | WireGuard VPN          |

## Voice / Video

| Port              | Protocol    | Service    | Notes               |
|:------------------|:------------|:-----------|:--------------------|
| `5060`            | `TCP/UDP`   | `SIP`      | Session Initiation  |
| `5061`            | `TCP`       | `SIPS`     | Secure SIP          |
| `16384-32767`     | `UDP`       | `RTP`      | Real-time media     |

## Other Important Ports

| Port        | Protocol    | Service          | Notes                      |
|:------------|:------------|:-----------------|:---------------------------|
| `119`       | `TCP`       | `NNTP`           | Usenet news                |
| `137-139`   | `TCP/UDP`   | `NetBIOS`        | Legacy Windows             |
| `179`       | `TCP`       | `BGP`            | Border Gateway Protocol    |
| `194`       | `TCP`       | `IRC`            | Internet Relay Chat        |
| `464`       | `TCP/UDP`   | `Kpasswd`        | Kerberos password          |
| `500`       | `UDP`       | `ISAKMP`         | IPsec                      |
| `520`       | `UDP`       | `RIP`            | Routing protocol           |
| `853`       | `TCP`       | `DoT`            | DNS over TLS               |
| `1812`      | `UDP`       | `RADIUS Auth`    | Authentication             |
| `1813`      | `UDP`       | `RADIUS Acct`    | Accounting                 |
| `2082`      | `TCP`       | `cPanel`         | Web hosting                |
| `2083`      | `TCP`       | `cPanel SSL`     | Secure cPanel              |
| `3128`      | `TCP`       | `Squid`          | HTTP proxy                 |
| `8080`      | `TCP`       | `HTTP Proxy`     | Alternative HTTP           |

# Protocol Numbers (IP Header)

| Number   | Protocol   |
|:---------|:-----------|
| `1`      | `ICMP`     |
| `6`      | `TCP`      |
| `17`     | `UDP`      |
| `47`     | `GRE`      |
| `50`     | `ESP`      |
| `51`     | `AH`       |
| `89`     | `OSPF`     |

# Quick Security Reference

## Ports to Block or Monitor

### Block from Internet

- `23` — Telnet
- `135-139` — NetBIOS
- `445` — SMB
- `3389` — RDP (use VPN instead)
- `1433` — SQL Server
- `3306` — MySQL

### Monitor Closely

- `22` — SSH (if exposed)
- `25` — SMTP
- `53` — DNS
- `80/443` — Web services

# Secure Alternatives

| Insecure   | Port    | Secure Alternative   | Port         |
|:-----------|:--------|:---------------------|:-------------|
| `Telnet`   | `23`    | `SSH`                | `22`         |
| `FTP`      | `21`    | `SFTP / FTPS`        | `22 / 990`   |
| `HTTP`     | `80`    | `HTTPS`              | `443`        |
| `SMTP`     | `25`    | `SMTPS`              | `465 / 587`  |
| `POP3`     | `110`   | `POP3S`              | `995`        |
| `IMAP`     | `143`   | `IMAPS`              | `993`        |
| `LDAP`     | `389`   | `LDAPS`              | `636`        |
| `DNS`      | `53`    | `DoT / DoH`          | `853 / 443`  |

# Port Checking Commands

## Linux / macOS

### Check if a Port is Listening (Local)

```bash
netstat -tuln | grep :80
ss -tuln | grep :80
```

### Check if a Port is Open (Remote)

```bash
nc -zv hostname 80
telnet hostname 80
nmap -p 80 hostname
```

## PowerShell

```powershell
Test-NetConnection hostname -Port 80
```
