# Cryptography - Study Guide

## 1. What is cryptography in cybersecurity?

Cryptography is the practice of securing communication and data against attackers.
It protects corporate secrets, classified information, and personal data.

| Goal | Protect |
|------|---------|
| Confidentiality | Keep data secret |
| Integrity | Detect changes |
| Authenticity | Verify who sent it |
| Non-repudiation | Prove an action happened |

### Simple scenario

```
Andy writes a message
	↓
Encrypt it with a key
	↓
Send ciphertext over the network
	↓
Sam decrypts it with the key
	↓
Original plaintext is recovered
```

If an attacker changes the message in transit, the decryption result can reveal tampering.

---

## 2. Main cryptography types

| Type | Key idea | Example |
|------|----------|---------|
| **Symmetric** | Same key encrypts and decrypts | AES |
| **Asymmetric** | Public key encrypts, private key decrypts | RSA, ECC |
| **Hashing** | One-way fingerprint | SHA-256 |

### Symmetric key families

| Family | Idea | Example |
|--------|------|---------|
| **Classical** | Old-style ciphers | Transposition, Substitution |
| **Modern** | Used in real systems | Stream cipher, Block cipher |

```
Symmetric:   Plaintext → [Same Key] → Ciphertext
Asymmetric:  Public Key → Encrypt | Private Key → Decrypt
Hashing:     Data → Hash (one-way)
```

### Classical ciphers

| Cipher | Idea |
|--------|------|
| **Transposition** | Change the position of letters |
| **Substitution** | Replace letters with other letters |

### Modern symmetric ciphers

| Cipher | Idea | Key point |
|--------|------|-----------|
| **Stream cipher** | Encrypts one bit/byte at a time | Same plaintext can produce different output each time |
| **Block cipher** | Encrypts fixed-size blocks | AES is the common example |

---

## 3. What is encryption?

Encryption converts readable data into unreadable data.

```
Plaintext  →  Encryption key  →  Ciphertext
```

**Use:** Protect data at rest and in transit.

---

## 4. What is decryption?

Decryption converts ciphertext back into readable data.

```
Ciphertext  →  Decryption key  →  Plaintext
```

---

## 5. Why is cryptography important?

| Reason | Simple benefit |
|--------|-----------------|
| Confidentiality | Stops unauthorized reading |
| Integrity | Detects tampering |
| Authentication | Confirms identity |
| Non-repudiation | Proves actions happened |

**Common uses:** HTTPS, VPNs, email security, passwords, digital signatures.

### Real-world use cases

| Area | Example |
|------|---------|
| Banking | Protect financial data |
| Healthcare | Protect patient records |
| Corporate | Protect internal secrets |
| Personal | Protect identity and messages |

---

## 6. What are the applications of cryptography?

| Application | What it protects |
|-------------|------------------|
| **HTTPS / TLS** | Web traffic |
| **VPN** | Network connections |
| **Disk encryption** | Stored data |
| **Digital signatures** | File and message authenticity |
| **Password hashing** | Stored passwords |
| **Secure email** | Message confidentiality |

---

## 7. What is a hash algorithm?

A hash algorithm turns data into a fixed-size fingerprint.

### Simple hash flow

```
Input data → Hash algorithm → Fixed-length hash
```

### Key properties

| Property | Meaning |
|----------|---------|
| One-way | Hard to reverse |
| Fixed size | Same output length |
| Fast | Quick to compute |
| Sensitive | Small input change = big output change |

**Use:** file integrity, password storage, digital forensics.

---

## 8. What does SHA stand for?

**SHA** = **Secure Hash Algorithm**

| Common version | Use |
|---------------|-----|
| SHA-1 | Old, weak |
| SHA-256 | Common and safe |
| SHA-512 | Stronger, larger output |

**Main use:** integrity checking and password storage.

---

## 9. What is John the Ripper?

John the Ripper is a password cracking tool used to test weak password hashes.

| Main use | Example |
|----------|---------|
| Crack password hashes | Linux shadow files, ZIP hashes |
| Test password strength | Security auditing |

### Basic idea

```
Hash file + wordlist/rules → Candidate passwords → Match found
```

### Common usage

| Action | Example |
|--------|---------|
| Basic crack | `john hashes.txt` |
| Use wordlist | `john --wordlist=rockyou.txt hashes.txt` |
| Show results | `john --show hashes.txt` |

### Advanced hashes

For harder hashes, use the right format and attack mode, then try rules or wordlists.

| Helpful option | Purpose |
|----------------|---------|
| `--format=` | Select hash type |
| `--wordlist=` | Use a dictionary |
| `--rules` | Mutate words automatically |

### Simple workflow

```
Identify hash type → Choose format → Use wordlist/rules → Check result
```

---

## 10. What is hashcat?

Hashcat is a fast password cracking tool, usually GPU-accelerated.

| Main strength | Why it matters |
|--------------|----------------|
| Speed | Very fast on large hash sets |
| GPU support | Uses graphics cards |
| Attack modes | Wordlist, brute-force, rules, mask |

### Basic usage

| Action | Example |
|--------|---------|
| Crack hashes | `hashcat -m <mode> -a <attack> hashes.txt wordlist.txt` |
| Show help | `hashcat --help` |
| Resume session | `hashcat --restore` |

### Common attack modes

| Mode | Meaning |
|------|---------|
| `-a 0` | Straight / wordlist |
| `-a 3` | Mask / brute-force style |

### Simple workflow

```
Identify hash type → Choose -m → Choose -a → Run attack
```

---

## 11. John the Ripper vs Hashcat

| Tool | Best for | Speed |
|------|----------|-------|
| **John the Ripper** | Flexible cracking, many formats | Good |
| **Hashcat** | Large-scale cracking with GPU | Very fast |

---

## Quick Memory Map

| Topic | Remember |
|------|----------|
| Cryptography | Secure communication in the presence of attackers |
| Encryption | Plaintext to ciphertext |
| Decryption | Ciphertext to plaintext |
| Symmetric | Same key |
| Asymmetric | Public/private keys |
| Hashing | One-way fingerprint |
| SHA | Secure Hash Algorithm |
| John the Ripper | Flexible hash cracking |
| Hashcat | Fast GPU cracking |
