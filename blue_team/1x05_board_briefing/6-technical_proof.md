# The Technical Proof

## Introduction

### Goal
Demonstrate hands-on technical mastery by executing a rapid security check using tools from the entire module.

### Context
James Chen needs to know that you can DO what you recommend, not just write about it. Before the Board meeting, he asks you to run a quick technical validation on your own machine to prove proficiency. "Show me you can inspect a cert, verify a hash, check for an exploit and audit a system. Five minutes each."

## Answer

## Check 1 – Certificate Inspection

### Command
```bash
openssl s_client -connect nasa.gov:443 -servername nasa.gov </dev/null | openssl x509 -noout -subject -issuer -dates -text | grep -E "Subject:|Issuer:|Not Before|Not After|Public Key Algorithm|DNS:"
```

### 5-Line Summary

- Subject: CN=nasa.gov
- Issuer: Let's Encrypt (CN=YE2)
- Validity: 11 Jun 2026 – 9 Sep 2026
- Key Algorithm: EC Public Key (id-ecPublicKey)
- SAN Entries: nasa.gov, www.nasa.gov

---

## Check 2 – Hash Verification

### Command
```bash
echo "Original FortiGate firmware integrity test" > firmware_test.txt && sha256sum firmware_test.txt && echo "Modified content" >> firmware_test.txt && sha256sum firmware_test.txt
```

### Output

| State | SHA-256 Hash |
|------|------------------------------------------------------------------|
| Original | b26e5395e171b5d42cb070a5476f7e6c2ba924ffa223cff01e8b27f26033842d |
| Modified | 7112f76e95bb3d061f783908708d1efd0c64944e3e3056c300eebef724acb4da |

**Result:** The hashes are different, confirming that even a small file modification changes the SHA-256 digest.

**Why it matters:** Comparing the vendor-published SHA-256 hash with the downloaded FortiGate firmware verifies that the firmware has not been corrupted or tampered with before installation.

---

## Check 3 – Exploit Research

### Commands
```bash
searchsploit fortigate
```

```bash
searchsploit fortios
```

### Output Summary

Searchsploit returned multiple FortiGate/FortiOS exploits including:

- FortiGate SSH Backdoor
- LDAP Credential Disclosure
- Authentication Bypass
- SSL VPN Password Modification
- Cookie Reuse
- Multiple legacy vulnerabilities

No Searchsploit module specifically targets **CVE-2023-27997**.

However, a public proof-of-concept exists on GitHub:
https://github.com/onurkerembozkurt/fgt-cve-2023-27997-exploit

### Conclusion

Yes. A public exploit exists for **CVE-2023-27997** outside Exploit-DB. Once a public exploit is available, attackers can weaponize it rapidly, making immediate patching of vulnerable FortiGate appliances a high operational priority.

---

## Check 4 – System Audit

### Command
```bash
sudo lynis audit system --quick
```

### Results

**Hardening Index**

- **64/100**

**Top 3 Warnings**

1. No responsive backup DNS nameserver configured (NETW-2705).
2. PostgreSQL configuration file `postgresql.conf` is world-readable (DBS-1828).
3. PostgreSQL configuration files (`start.conf` and `pg_ctl.conf`) are world-readable (DBS-1828).

**Recommendation for MedDefense billing-srv-01**

Restrict PostgreSQL configuration file permissions (`chmod 600`) so only the database owner and administrators can read sensitive configuration information, reducing the risk of information disclosure that could assist an attacker.