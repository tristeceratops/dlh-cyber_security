# The Certificate Anatomy

## Introduction

### Goal
Inspect real X.509 certificates from live websites using OpenSSL, identify every field that matters for security, and diagnose intentionally broken certificates.

### Context
Every time a patient opens the MedDefense portal, their browser performs a certificate check in milliseconds: Is this really MedDefense ? Is the certificate still valid ? Was it issued by a trusted authority ? You need to understand exactly what the browser is checking, because in 18 days, MedDefense's certificate expires and you are the person who will replace it.

## Answer

### Part 1

```bash
openssl s_client -connect letsencrypt.org:443 -servername letsencrypt.org -brief </dev/null
Connecting to 35.157.26.135
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
Peer certificate: CN=letsencrypt.org
Hash used: SHA256
Signature type: ecdsa_secp256r1_sha256
Verification: OK
Peer Temp Key: X25519, 253 bits
DONE
```

```bash
openssl s_client -connect github.com:443 -servername github.com -brief </dev/null
Connecting to 140.82.121.4
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
Peer certificate: CN=github.com
Hash used: SHA256
Signature type: ecdsa_secp256r1_sha256
Verification: OK
Peer Temp Key: X25519, 253 bits
DONE
```

```bash
openssl s_client -connect expired.badssl.com:443 -servername expired.badssl.com -brief </dev/null
Connecting to 104.154.89.105
depth=0 OU=Domain Control Validated, OU=PositiveSSL Wildcard, CN=*.badssl.com
verify error:num=10:certificate has expired
notAfter=Apr 12 23:59:59 2015 GMT
notAfter=Apr 12 23:59:59 2015 GMT
CONNECTION ESTABLISHED
Protocol version: TLSv1.2
Ciphersuite: ECDHE-RSA-AES128-GCM-SHA256
Peer certificate: OU=Domain Control Validated, OU=PositiveSSL Wildcard, CN=*.badssl.com
Hash used: SHA512
Signature type: rsa_pkcs1_sha512
Verification error: certificate has expired
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Peer Temp Key: ECDH, prime256v1, 256 bits
DONE
```

To download a certificate: 
```bash
openssl s_client -connect expired.badssl.com:443 -servername expired.badssl.com  </dev/null | openssl x509 -outform PEM > badssl.crt
```

| Field | Let's Encrypt (letsencrypt.org) | GitHub (github.com) | BadSSL (badssl.com) |
|-------|----------------------------------|---------------------|---------------------|
| Website | letsencrypt.org | github.com | badssl.com |
| Subject (CN) | letsencrypt.org | github.com | *.badssl.com |
| Subject (O) | Not present | Not present | Not present |
| Subject (L) | Not present | Not present | Not present |
| Subject (ST) | Not present | Not present | Not present |
| Subject (C) | Not present | Not present | Not present |
| Issuer | C=US, O=Let's Encrypt, CN=YE2 | C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36 | C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Domain Validation Secure Server CA |
| Serial Number | 05:05:bb:29:ef:e3:ee:15:2b:a3:e9:e6:87:28:10:b5:fe:b9 | 72:01:0e:03:f4:a0:67:fe:4e:79:62:66:43:07:18:f6 | 4a:e7:95:49:fa:9a:be:3f:10:0f:17:a4:78:e1:69:09 |
| Signature Algorithm | ECDSA with SHA-384 | ECDSA with SHA-256 | RSA with SHA-256 |
| Public Key Algorithm | EC (id-ecPublicKey) | EC (id-ecPublicKey) | RSA |
| Public Key Size | 256 bits (P-256) | 256 bits (P-256) | 2048 bits |
| Validity - Not Before | Jul 6 2026 15:24:34 GMT | Jul 3 2026 00:00:00 GMT | Apr 9 2015 00:00:00 GMT |
| Validity - Not After | Oct 4 2026 15:24:33 GMT | Sep 30 2026 23:59:59 GMT | Apr 12 2015 23:59:59 GMT |
| Subject Alternative Names (SAN) | cp.letsencrypt.org, cp.root-x1.letsencrypt.org, cps.letsencrypt.org, cps.root-x1.letsencrypt.org, lencr.org, letsencrypt.com, letsencrypt.org, www.lencr.org, www.letsencrypt.com, www.letsencrypt.org | github.com, www.github.com | *.badssl.com, badssl.com |
| Key Usage | Digital Signature | Digital Signature | Digital Signature, Key Encipherment |
| Extended Key Usage | TLS Web Server Authentication | TLS Web Server Authentication | TLS Web Server Authentication, TLS Web Client Authentication |
| Authority Information Access (OCSP URL) | Not present | http://ocsp.sectigo.com | http://ocsp.comodoca.com |
| Authority Information Access (CA Issuer URL) | http://ye2.i.lencr.org/ | http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt | http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt |
| Notes | Uses ECC P-256 key and is issued by Let's Encrypt YE2. | Uses ECC P-256 key issued by Sectigo. | Uses RSA-2048 key; intentionally expired certificate used for TLS testing. |

## Certificate Field Analysis (Explanation)

The **Subject** field identifies who the certificate belongs to. The Common Name (CN) and Subject Alternative Name (SAN) fields tell browsers which domain names are allowed to use the certificate. The **Issuer** identifies the Certificate Authority (CA) that signed the certificate and confirms which trusted organization verified the certificate.

The **Serial Number** is a unique identifier assigned by the CA to each certificate. It allows certificates to be tracked, managed, and revoked if the private key is compromised or the certificate is no longer trusted.

The **Validity Period** defines when the certificate is trusted. A certificate outside this date range will cause browser warnings because it may no longer be secure or controlled by the original owner.

The **Signature Algorithm** shows how the CA signed the certificate. It proves that the certificate was issued by a trusted CA and that the certificate data has not been modified. Modern algorithms such as ECDSA with SHA-256/SHA-384 provide stronger security than older algorithms.

The **Public Key Algorithm and Key Size** define the cryptographic strength of the certificate. ECC P-256 provides strong security with smaller keys, while RSA-2048 is still widely accepted but requires larger keys.

The **SAN extension** lists all domain names covered by the certificate. Browsers mainly use SAN instead of CN to verify that the website address matches the certificate. If the requested website is not included in SAN, the browser will show a certificate mismatch warning.

The **Key Usage** field limits what the certificate key can be used for, such as creating digital signatures or encrypting data. The **Extended Key Usage (EKU)** specifies the purpose more precisely, such as TLS Web Server Authentication, preventing certificates from being misused for other purposes.

The **Authority Information Access (AIA)** extension provides information about the CA, including OCSP URLs used to check whether a certificate has been revoked and CA Issuer URLs to download the issuing certificate.


## Part 2

The badssl.com certificate is invalid because it expired on April 12, 2015, meaning it is outside its validity period. A browser would display an error such as "Your connection is not private" or "NET::ERR_CERT_DATE_INVALID". This creates a risk because the browser cannot confirm that the certificate is still trustworthy, increasing the chance of a man-in-the-middle attack. I would not advise a patient to continue to a healthcare portal showing this warning because medical information and login credentials could be exposed.

## Part 3

MedDefense's patient portal should use an **OV (Organization Validation)** certificate because it provides confirmation that the certificate belongs to the real MedDefense organization, which is important for a healthcare service handling patient information.

The certificate should be issued by a trusted CA such as DigiCert, Sectigo, or Let's Encrypt because browsers already trust these authorities. The SAN entries should include only the official portal domains, for example `portal.meddefense.com`.

The certificate should use **ECC P-256** or **RSA-2048** because they provide strong security with good performance. The validity period should be short (around 90 days to 1 year) with automatic renewal to reduce the risk of expired certificates.

A **single-domain certificate** is more appropriate than a wildcard certificate because it limits exposure. If the private key is compromised, only the patient portal is affected instead of every subdomain covered by a wildcard certificate.