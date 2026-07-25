# The Asymmetric Engine

## Introduction

### Goal
Generate RSA and ECC key pairs, discover the size limitation of asymmetric encryption through experimentation, and understand why the hybrid model exists.

### Context
If symmetric encryption is the workhorse, asymmetric encryption is the handshake. It solves the key distribution problem that symmetric encryption alone cannot: how do two parties who have never met agree on a shared secret ? The answer involves key pairs, where one key encrypts and the other decrypts. But this elegance comes at a cost that you are about to measure.

## Answer

### Part 1

Small patient record encryption:
``` bash
openssl pkeyutl -encrypt \
    -pubin \
    -inkey rsa_public.pem \
    -in jane_doe.txt \ 
    -out jane_doe.enc  
```
and then decrpytion:
``` bash
openssl pkeyutl -decrypt \
    -inkey rsa_private.pem \
    -in jane_doe.enc \
    -out decrypt.txt
```

100MB file encryption:
```bash
openssl pkeyutl -encrypt \
    -pubin \
    -inkey rsa_public.pem \
    -in testfile \    
    -out testfile.dec
Public Key operation error
4077E32AC27F0000:error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_type_2_ex:data too large for key size:../crypto/rsa/rsa_pk1.c:132:
```

RSA is only able to encrypt data up to a maximum size determined by the key length. This limitation makes it impractical for encrypting large files or large amounts of data directly, as the maximum plaintext size is only a few hundred bytes even with common key sizes.

### Part 2

```bash
ls -la ecc_private.pem rsa_private.pem 
-rw-------. 1 kali kali  302 Jul 25 07:47 ecc_private.pem
-rw-------. 1 kali kali 1704 Jul 25 07:14 rsa_private.pem
```

The RSA private key is 1704 bytes, while the ECC private key is 302 bytes, giving a size ratio of approximately 1704:302 ≈ 5.6:1. ECC achieves a similar level of security with much smaller keys because it relies on the computational difficulty of the elliptic curve discrete logarithm problem, allowing shorter keys to provide comparable cryptographic strength. This is especially important for constrained devices such as MedDefense's BD Alaris pumps and Philips monitors, where smaller keys reduce memory usage, computational overhead, and power consumption.

### Part 3

TLS uses both asymmetric and symmetric encryption because each one is good at a different job. When a patient connects to MedDefense's patient portal using HTTPS, asymmetric encryption is first used during the TLS handshake to securely create and exchange a shared session key. After that, symmetric encryption is used to encrypt all of the data sent between the patient and the server because it is much faster. This combination provides both secure key exchange and efficient data encryption, making it more practical than using only asymmetric or only symmetric encryption.

### Part 4

| Algorithm           | Type        | Key Length(s)       | Equivalent Security* | Status                    | Approved for Healthcare (Regulated Data) | MedDefense Usage |
|--------------------|-------------|---------------------|----------------------|---------------------------|------------------------------------------|------------------|
| AES                | Symmetric   | 128 / 192 / 256-bit | 128 / 192 / 256-bit  | Recommended               | Yes                                      | Encrypt patient records, databases, backups, TLS sessions |
| RSA                | Asymmetric  | 2048 / 4096-bit     | ~112 / ~152-bit      | Recommended               | Yes                                      | Digital certificates, authentication, key exchange |
| ECC (P-256/P-384)  | Asymmetric  | 256 / 384-bit       | ~128 / ~192-bit      | Recommended               | Yes                                      | TLS key exchange, digital signatures, IoT medical devices |
| DES                | Symmetric   | 56-bit              | 56-bit               | Obsolete                  | No                                       | Not permitted; vulnerable to brute-force attacks |
| 3DES               | Symmetric   | 168-bit (112-bit effective security) | ~112-bit | Deprecated (being phased out) | No (except limited legacy systems) | Legacy compatibility only |
| ChaCha20-Poly1305  | Symmetric   | 256-bit             | 256-bit              | Recommended               | Yes                                      | Secure mobile devices, VPNs, TLS where AES acceleration is unavailable |
| RC4                | Symmetric   | 40–2048-bit (commonly 128-bit) | N/A (broken) | Obsolete / Insecure       | No                                       | Never use; vulnerable to multiple practical attacks |