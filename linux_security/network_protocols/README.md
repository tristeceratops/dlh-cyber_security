# network protocols
## iptables
### flags
| Flag | Meaning |
|---|---|
| `-L` | list rules |
| `-n` | numeric output |
| `-v` | verbose |
| `--line-numbers` | add numbers to lines in output |
| `-P` | Set default policy |
| `-A` | Add rule |
| `-p` | protocol |
| `--dport` | Destination port |
| `-j` | Action |

---

### Possible protocols (`-p`)

| Value | Description |
|---|---|
| `tcp` | TCP protocol |
| `udp` | UDP protocol |
| `icmp` | Ping protocol |

---

### Possible actions (`-j`)

| Value | Description |
|---|---|
| `ACCEPT` | Allow traffic |
| `DROP` | Block traffic |
| `REJECT` | Block and notify sender |

---

### examples
- `-P INPUT DROP`  
  Blocks all incoming traffic by default.

- `-A INPUT -p tcp --dport ssh -j ACCEPT`  
  Allows incoming SSH connections (port 22).
