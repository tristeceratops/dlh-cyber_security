# The Hash Laboratory

## Introduction

### Goal
Explore hashing through experimentation: observe the avalanche effect, crack weak hashes, understand salting and key stretching, and build an integrity verification tool.

### Context
Hashing is not encryption. Encryption is reversible (with the key). Hashing is one-way. This distinction matters enormously because MedDefense stores password hashes in Active Directory, and the difference between a well-hashed password and a poorly hashed one is the difference between "attacker has hashes but cannot use them" and "attacker has every user's password in 30 minutes."

## Answer

### Part 1

```bash
└─$ echo -n "MedDefense" | sha256sum
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098  -

└─$ echo -n "MedDefense1" | sha256sum
97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92  -
```
All of the 64 hexadecimals characters.
```bash
└─$ echo -n "MedDefense" | md5sum 
75d47fd4b4d183456d0f98fd9ba6ae4d  -

└─$ echo -n "MedDefense1" | md5sum
0d2aed72043f78c2935e61ba8520306d  -
```

### Part 2
How many unique outputs: 
| Algorithm | Output Size | Number of Possible Outputs           |
|-----------|-------------|--------------------------------------|
| MD5       | 128 bits    | 2^128 ≈ 3.40 × 10^38 possible outputs |
| SHA-256   | 256 bits    | 2^256 ≈ 1.16 × 10^77 possible outputs |

Shorter hash functions have fewer possible outputs, making it more likely that two different inputs will produce the same hash value, a situation known as a collision. A birthday attack exploits probability rather than brute force, showing that collisions can be found much faster than trying every possible hash value. In the context of Finding 018, if MedDefense's Active Directory uses RC4-based Kerberos encryption, which relies on MD5 as part of its cryptographic design, attackers who obtain Kerberos tickets can perform offline password-cracking attacks more efficiently against weak passwords. This increases the risk that user credentials can be recovered, especially if users choose short or predictable passwords, which is why RC4-based Kerberos encryption is considered deprecated.

### Part 3
```bash
echo -n "password123" | md5sum
482c811da5d5b4bc6d497ffa98491e38  -
```
On (https://crackstation.net/)[https://crackstation.net/], hash was cracked easily, result with Exact match found.

```bash
echo -n "s4lt9xQ2:password123" | md5sum
6d537fa53f1db2c22b0451ef4ef9fbe8  -
```
crackstation.net did not crack the hash, hash was not found in the pre-computed lookup tables of the website.

A **salt** is a random value that is added to a password before it is hashed. Because each user has a different salt, the same password produces a different hash for every user, making precomputed rainbow tables ineffective. Using a unique salt for every user also prevents attackers from identifying users who share the same password by comparing hash values. As a result, attackers must crack each password individually, significantly increasing the time and effort required.

### Part 4

bcrypt
bcrypt is a password hashing algorithm that adds a random salt and intentionally hashes passwords slowly. This makes brute-force attacks much slower because every password guess takes more time. The cost factor controls how much work bcrypt performs, with higher values making hashing slower and more secure.

PBKDF2
PBKDF2 hashes a password many thousands of times instead of only once. This repeated hashing makes brute-force attacks much more difficult because each password guess requires much more computation. The iteration count controls how many times the password is hashed; increasing it improves security but also increases the time needed to verify a password.

Argon2
Argon2 is a modern password hashing algorithm that uses both processing time and memory to protect passwords. Because it requires a large amount of memory, it is much harder for attackers to crack passwords using GPUs or specialized hardware. Its cost settings control the amount of memory, the number of iterations, and the number of CPU threads used.

Recommendation for MedDefense
Argon2id is the best choice for MedDefense because it provides the strongest protection against modern password-cracking attacks. It is recommended by security experts and is designed specifically for secure password storage.

Active Directory
Microsoft Active Directory does not use bcrypt, PBKDF2, or Argon2 by default. Instead, it stores passwords as NT hashes (based on the MD4 algorithm). Although this is still used for Windows compatibility, it is not as secure as modern password hashing algorithms because it is not salted or intentionally slow, making offline password-cracking attacks easier if the hashes are stolen.

### Part 5
(script)[3-hash_verify.sh]