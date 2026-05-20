# DKIM (DomainKeys Identified Mail)

## What is DKIM?

DKIM uses cryptographic signatures to prove that an email was sent by an authorized domain and was not changed in transit.

| SPF | DKIM |
|-----|------|
| Checks sending IP | Checks message signature |
| Can break on forwarding | Usually survives forwarding |
| Authorizes servers | Verifies integrity |

## How DKIM works

```
Sender signs email with private key
        ↓
Public key is published in DNS
        ↓
Receiver gets email and verifies signature
```

## DKIM signature header

| Field | Meaning |
|------|---------|
| `v` | Version |
| `a` | Algorithm |
| `c` | Canonicalization method |
| `d` | Signing domain |
| `s` | Selector |
| `h` | Signed headers |
| `bh` | Body hash |
| `b` | Signature |

## What is a selector?

A selector points to the correct public key in DNS.
It helps with multiple keys and key rotation.

```text
selector._domainkey.example.com
```

## DKIM signing process

1. Choose headers to sign
2. Canonicalize headers and body
3. Hash the body
4. Sign the data with the private key
5. Add the `DKIM-Signature` header

## DKIM verification process

1. Read the `DKIM-Signature` header
2. Fetch the public key from DNS
3. Rebuild the signed data
4. Verify the signature
5. Compare body hash and headers

## Canonicalization

| Method | Meaning | Use |
|--------|---------|-----|
| `simple/simple` | Exact match | Strict, fragile |
| `relaxed/relaxed` | Normalized format | Recommended, forwarding-friendly |

## DKIM DNS record

| Item | Format |
|------|--------|
| Record type | TXT |
| Name | `selector._domainkey.domain` |
| Value | `v=DKIM1; k=rsa; p=publickey` |

## Keys and rotation

| Item | Recommendation |
|------|-----------------|
| Key size | 2048-bit minimum |
| Algorithm | `rsa-sha256` |
| Rotation | Regularly, often yearly |

### Rotation flow

```text
Generate new key → Publish new DNS record → Update signing server → Remove old key later
```

## Why DKIM is forwarding-friendly

Forwarding usually does not change the DKIM signature structure.
The signature can still verify even if the mail passes through another server.

## DKIM testing

| Method | Example |
|--------|---------|
| Header check | Look for `DKIM-Signature` |
| DNS check | `dig TXT selector._domainkey.example.com` |
| Validation tools | DKIM checkers |

## Best practice

| Do | Don’t |
|----|-------|
| Use 2048-bit keys | Use 1024-bit keys |
| Use `relaxed/relaxed` | Use strict settings when forwarding is expected |
| Rotate keys | Share private keys |
