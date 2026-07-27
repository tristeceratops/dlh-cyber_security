# The Chain of Trust

## Introduction

### Goal
Capture and verify a complete certificate chain, understand how trust propagates from root to leaf, and analyze what happens when the chain breaks.

### Context
A certificate is only as trustworthy as the chain behind it. The patient's browser trusts the portal's certificate because it trusts the intermediate CA that signed it, which it trusts because it trusts the root CA in its trust store. If any link in this chain is invalid, expired, revoked or untrusted, the entire connection fails.

## Answer

### Part 1

```bash
openssl s_client -showcerts intranet-dlh.hbtn.io:443 </dev/null
Connecting to 15.188.134.223
CONNECTED(00000003)
depth=2 C=US, O=Amazon, CN=Amazon Root CA 1
verify return:1
depth=1 C=US, O=Amazon, CN=Amazon RSA 2048 M04
verify return:1
depth=0 CN=hbtn.io
verify return:1
---
Certificate chain
 0 s:CN=hbtn.io
   i:C=US, O=Amazon, CN=Amazon RSA 2048 M04
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Sep  7 00:00:00 2025 GMT; NotAfter: Oct  6 23:59:59 2026 GMT
-----BEGIN CERTIFICATE-----
MIIFvDCCBKSgAwIBAgIQBupHsdcbNzxowCFweCdBtjANBgkqhkiG9w0BAQsFADA8
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRwwGgYDVQQDExNBbWF6b24g
UlNBIDIwNDggTTA0MB4XDTI1MDkwNzAwMDAwMFoXDTI2MTAwNjIzNTk1OVowEjEQ
MA4GA1UEAxMHaGJ0bi5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJRneThsrELtMooKB/ozzhJUNuYLJFfNfqG8dHAa5zxceGRpZGc0r2Y19NRsbB06
S2P8cq5iSsKa/ODYq7SLgJBJqCS63c5M26pScOiOzuA8cZfvwST3Jv/u5FTa0xKi
bWlGk7B1xeLvJQRTQlBTB6sB0fsfErrLmidIx+1EoB6h1vWGB942P0qYKuSlogIK
i5iE8O0QaMGDCrwSVu1Aemj3n/22iOi/W4tAzf9ouUFZlHAT446rRDepR8ls18Av
qakN28xTeA3Be746SdCoXxSmKOsA/nZaDDoKUP5CJwKoqvp1Tg8dakibDx/Yp1ks
OCHNr8/PbpRYFAYMrC1hJPUCAwEAAaOCAuIwggLeMB8GA1UdIwQYMBaAFB9SkmFW
glR/gWbYHT0KqjJch90IMB0GA1UdDgQWBBShqpDkezm2+pIE1bnWvLeG9HHGpTAd
BgNVHREEFjAUggdoYnRuLmlvggkqLmhidG4uaW8wEwYDVR0gBAwwCjAIBgZngQwB
AgEwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMDsGA1UdHwQ0
MDIwMKAuoCyGKmh0dHA6Ly9jcmwucjJtMDQuYW1hem9udHJ1c3QuY29tL3IybTA0
LmNybDB1BggrBgEFBQcBAQRpMGcwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLnIy
bTA0LmFtYXpvbnRydXN0LmNvbTA2BggrBgEFBQcwAoYqaHR0cDovL2NydC5yMm0w
NC5hbWF6b250cnVzdC5jb20vcjJtMDQuY2VyMAwGA1UdEwEB/wQCMAAwggF/Bgor
BgEEAdZ5AgQCBIIBbwSCAWsBaQB2ANdtfRDRp/V3wsfpX9cAv/mCyTNaZeHQswFz
F8DIxWl3AAABmSGGxskAAAQDAEcwRQIgECXb/nACMUHR8hs60w98+mvCWpw1w+Ww
C3tLK8SubRACIQC0kdeNcCMDM7wmInFPm30gMYDi387vbRwaiuMXLUyl6gB3AMIx
fldFGaNF7n843rKQQevHwiFaIr9/1bWtdprZDlLNAAABmSGGxvgAAAQDAEgwRgIh
AJk14xVQwh6gDUqjLoCmPguOsBtR9boUOH4POjS2oMsFAiEA2iWK4tBYxzJ/A2mT
grJHhc+1KbHyN93cPvECdnpv0RIAdgCUTkOH+uzB74HzGSQmqBhlAcfTXzgCAT9y
Z31VNy4Z2AAAAZkhhscIAAAEAwBHMEUCIGZ+VWOKS/xu4bCmvDWVMU0HX08znoRh
cXiF2s6PVSE9AiEA/UFgsh3tb88uJftdpbANjJUZNBOrALS/c7aG4QeYgqAwDQYJ
KoZIhvcNAQELBQADggEBAE8WEnsjkrN6pAtWx0gttv+V7d4ZplvJ3DIX5QJcPi2N
prVc2tiTBMHoZ+trj8scPYQnKCdTa+NJuQhHD8LDa0wqu6DKteiY9FhyzcB/aHnH
eWVTK1aKPKwTRc9eN8v8lSmWTTC/9Vge0Z8T2a2lJC7biU+jQf1/WBGBVrNPnDXk
IE5MvBy3XpmuEw8yICtlhXMzCxdms+LhufpZV8TYY2S4ombzrJtZESd8t2MqyoV6
mn1IJIv566rsUxd+l2h7GiWGNlURganKvP13NDe4PmZjKrtvw1/0E2BAt8i8XTNC
5C6VIsHfQjvX8O3UcfgbY8z9peR0+0SF7ol2sXHa7/0=
-----END CERTIFICATE-----
 1 s:C=US, O=Amazon, CN=Amazon RSA 2048 M04
   i:C=US, O=Amazon, CN=Amazon Root CA 1
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Aug 23 22:26:35 2022 GMT; NotAfter: Aug 23 22:26:35 2030 GMT
-----BEGIN CERTIFICATE-----
MIIEXjCCA0agAwIBAgITB3MSTyqVLj7Rili9uF0bwM5fJzANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTIyMDgyMzIyMjYzNVoXDTMwMDgyMzIyMjYzNVowPDEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEcMBoGA1UEAxMTQW1hem9uIFJT
QSAyMDQ4IE0wNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM3pVR6A
lQOp4xe776FdePXyejgA38mYx1ou9/jrpV6Sfn+/oqBKgwhY6ePsQHHQayWBJdBn
v4Wz363qRI4XUh9swBFJ11TnZ3LqOMvHmWq2+loA0QPtOfXdJ2fHBLrBrngtJ/GB
0p5olAVYrSZgvQGP16Rf8ddtNyxEEhYm3HuhmNi+vSeAq1tLYJPAvRCXonTpWdSD
xY6hvdmxlqTYi82AtBXSfpGQ58HHM0hw0C6aQakghrwWi5fGslLOqzpimNMIsT7c
qa0GJx6JfKqJqmQQNplO2h8n9ZsFJgBowof01ppdoLAWg6caMOM0om/VILKaa30F
9W/r8Qjah7ltGVkCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYD
VR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNV
HQ4EFgQUH1KSYVaCVH+BZtgdPQqqMlyH3QgwHwYDVR0jBBgwFoAUhBjMhTTsvAyU
lC4IWZzHshBOCggwewYIKwYBBQUHAQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8v
b2NzcC5yb290Y2ExLmFtYXpvbnRydXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDov
L2NydC5yb290Y2ExLmFtYXpvbnRydXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8E
ODA2MDSgMqAwhi5odHRwOi8vY3JsLnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jv
b3RjYTEuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IB
AQA+1O5UsAaNuW3lHzJtpNGwBnZd9QEYFtxpiAnIaV4qApnGS9OCw5ZPwie7YSlD
ZF5yyFPsFhUC2Q9uJHY/CRV1b5hIiGH0+6+w5PgKiY1MWuWT8VAaJjFxvuhM7a/e
fN2TIw1Wd6WCl6YRisunjQOrSP+unqC8A540JNyZ1JOE3jVqat3OZBGgMvihdj2w
Y23EpwesrKiQzkHzmvSH67PVW4ycbPy08HVZnBxZ5NrlGG9bwXR3fNTaz+c+Ej6c
5AnwI3qkOFgSkg3Y75cdFz6pO/olK+e3AqygAcv0WjzmkDPuBjssuZjCHMC56oH3
GJkV29Di2j5prHJbwZjG1inU
-----END CERTIFICATE-----
 2 s:C=US, O=Amazon, CN=Amazon Root CA 1
   i:C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., CN=Starfield Services Root Certificate Authority - G2
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: May 25 12:00:00 2015 GMT; NotAfter: Dec 31 01:00:00 2037 GMT
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgITBn+USionzfP6wq4rAfkI7rnExjANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaOCATEwggEtMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgGGMB0GA1UdDgQWBBSEGMyFNOy8DJSULghZnMeyEE4KCDAfBgNVHSMEGDAW
gBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEFBQcBAQRsMGowLgYIKwYBBQUH
MAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250cnVzdC5jb20wOAYIKwYBBQUH
MAKGLGh0dHA6Ly9jcnQucm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY2Vy
MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRydXN0
LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsF
AAOCAQEAYjdCXLwQtT6LLOkMm2xF4gcAevnFWAu5CIw+7bMlPLVvUOTNNWqnkzSW
MiGpSESrnO09tKpzbeR/FoCJbM8oAxiDR3mjEH4wW6w7sGDgd9QIpuEdfF7Au/ma
eyKdpwAJfqxGF4PcnCZXmTA5YpaP7dreqsXMGz7KQ2hsVxa81Q4gLv7/wmpdLqBK
bRRYh5TmOTFffHPLkIhqhBGWJ6bt2YFGpn6jcgAKUj6DiAdjd4lpFw85hdKrCEVN
0FE6/V1dN2RMfjCyVSRCnTawXZwXgWHxyvkQAiSr6w10kY17RSlQOYiypok1JR4U
akcjMS9cmvqtmg5iUaQqqcT5NJ0hGA==
-----END CERTIFICATE-----
---
Server certificate
subject=CN=hbtn.io
issuer=C=US, O=Amazon, CN=Amazon RSA 2048 M04
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: rsa_pkcs1_sha256
Peer Temp Key: ECDH, prime256v1, 256 bits
---
SSL handshake has read 4444 bytes and written 1813 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Protocol: TLSv1.2
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Session-ID: 723F29CC170294A00E1726911480414F48B07C4F97A85EEA0ABB0949855EE316
    Session-ID-ctx: 
    Master-Key: 113642BDF6A64B705C49B4BDE6447B4ACCAADB39D322C20CD3AAA1E7EFDE6A0A8EE743D2497EBB5D214FC7D23C78F818
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 85550 (seconds)
    TLS session ticket:
    0000 - 01 50 c8 04 cf cc 6e 59-5e ad 14 f5 02 a2 fe 62   .P....nY^......b
    0010 - 68 0c 4b 52 d0 42 fe 48-7e f2 c6 ab bb 49 2b 94   h.KR.B.H~....I+.
    0020 - 6b 71 2e 02 b6 a7 8f 37-f9 01 6d c6 75 89 67 78   kq.....7..m.u.gx
    0030 - 45 cf 83 d0 eb 51 08 82-a1 93 50 43 11 d6 b2 d7   E....Q....PC....
    0040 - 3b 82 05 77 f1 da 5a 72-20 1e 8e 35 0d d6 6c bc   ;..w..Zr ..5..l.
    0050 - 44 1d af de 07 04 38 ec-0e 46 ae e6 97 f0 67 65   D.....8..F....ge
    0060 - 4f f6 65 a2 22 2e 3a 91-2d 7c 8b 28 75 4f b9 bf   O.e.".:.-|.(uO..
    0070 - 79 e7 23 35 e1 ea a9 2e-99 32 c7 c3 cd 8f bc 28   y.#5.....2.....(
    0080 - 4f c5 23 ec 20 41 e7 3a-4a 95                     O.#. A.:J.

    Start Time: 1785139535
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
DONE
```

Certificate Chain Summary

Number of certificates: 3

1. Leaf (Server)
   Subject: CN=hbtn.io
   Issuer : C=US, O=Amazon, CN=Amazon RSA 2048 M04

2. Intermediate
   Subject: C=US, O=Amazon, CN=Amazon RSA 2048 M04
   Issuer : C=US, O=Amazon, CN=Amazon Root CA 1

3. Root
   Subject: C=US, O=Amazon, CN=Amazon Root CA 1
   Issuer : C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., CN=Starfield Services Root Certificate Authority - G2

Chain:
Leaf Issuer = Intermediate Subject
Intermediate Issuer = Root Subject

### Part 2

```bash
openssl verify -CAfile cert3.cert cert2.cert
openssl verify -CAfile cert3.cert -untrusted cert2.cert cert1.cert
cert2.cert: OK
cert1.cert: OK
```
and if we remove the intermediate certificate:
```bash
openssl verify -CAfile cert3.cert cert1.cert 
CN=hbtn.io
error 20 at 0 depth lookup: unable to get local issuer certificate
error cert1.cert: verification failed
```

In a chain of certificates, each following certificate need the previous one to be verified. That's why servers must send the full chain of certificate to assure a successful verification.

### Part 3

CRL (Certificate Revocation List)

A CRL is a certificate authority (CA)-signed document that contains the serial numbers of certificates that have been revoked before their expiration date. The CA publishes this list at regular intervals. When a client validates a certificate, it can download the CRL from the CA and check whether the certificate's serial number appears on the list. If it does, the certificate must no longer be trusted.

The main weaknesses of CRLs are their size and update delay. As more certificates are revoked, the CRL can become very large, increasing download time and bandwidth usage. Also, because CRLs are only refreshed periodically, a certificate that was compromised after the last update may still be accepted until the next CRL is published.

OCSP (Online Certificate Status Protocol)

OCSP allows a client to check the validity status of a specific certificate by sending a request to the CA's OCSP responder. Instead of downloading an entire revocation database, the client asks only about the certificate it needs to verify. The responder returns whether the certificate is valid, revoked, or unknown.

OCSP is more efficient than CRLs because it avoids transferring large lists and provides more recent revocation information. OCSP Stapling further improves this process by allowing the server to obtain a signed OCSP response from the CA and attach it during the TLS handshake. The client can then verify the certificate status directly from the server response without contacting the CA, reducing connection delays and improving privacy.

MedDefense Key Compromise Recovery Sequence

If the MedDefense portal private key is exposed, the compromised key and certificate must be replaced immediately:

1. Generate a new private key and create a new CSR on a trusted system.
2. Send the CSR to the certificate authority to request a new certificate.
3. Deploy the new certificate and private key on the web server (web-srv-01 Apache) and restart the service so it uses the new credentials.
4. Request revocation of the old certificate through the CA portal, specifying that the reason is key compromise, so the certificate is marked revoked through OCSP and CRL mechanisms.

After these steps, the old certificate is no longer trusted and the portal operates using a new certificate linked to a new private key.

### Part 4

```bash
grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt
144
```

```bash
openssl x509 -in AC_RAIZ_FNMT-RCM.pem -text       
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5d:93:8d:30:67:36:c8:06:1d:1a:c7:54:84:69:07
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=ES, O=FNMT-RCM, OU=AC RAIZ FNMT-RCM
        Validity
            Not Before: Oct 29 15:59:56 2008 GMT
            Not After : Jan  1 00:00:00 2030 GMT
        Subject: C=ES, O=FNMT-RCM, OU=AC RAIZ FNMT-RCM
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:ba:71:80:7a:4c:86:6e:7f:c8:13:6d:c0:c6:7d:
                    1c:00:97:8f:2c:0c:23:bb:10:9a:40:a9:1a:b7:87:
                    88:f8:9b:56:6a:fb:e6:7b:8e:8b:92:8e:a7:25:5d:
                    59:11:db:36:2e:b7:51:17:1f:a9:08:1f:04:17:24:
                    58:aa:37:4a:18:df:e5:39:d4:57:fd:d7:c1:2c:91:
                    01:91:e2:22:d4:03:c0:58:fc:77:47:ec:8f:3e:74:
                    43:ba:ac:34:8d:4d:38:76:67:8e:b0:c8:6f:30:33:
                    58:71:5c:b4:f5:6b:6e:d4:01:50:b8:13:7e:6c:4a:
                    a3:49:d1:20:19:ee:bc:c0:29:18:65:a7:de:fe:ef:
                    dd:0a:90:21:e7:1a:67:92:42:10:98:5f:4f:30:bc:
                    3e:1c:45:b4:10:d7:68:40:14:c0:40:fa:e7:77:17:
                    7a:e6:0b:8f:65:5b:3c:d9:9a:52:db:b5:bd:9e:46:
                    cf:3d:eb:91:05:02:c0:96:b2:76:4c:4d:10:96:3b:
                    92:fa:9c:7f:0f:99:df:be:23:35:45:1e:02:5c:fe:
                    b5:a8:9b:99:25:da:5e:f3:22:c3:39:f5:e4:2a:2e:
                    d3:c6:1f:c4:6c:aa:c5:1c:6a:01:05:4a:2f:d2:c5:
                    c1:a8:34:26:5d:66:a5:d2:02:21:f9:18:b7:06:f5:
                    4e:99:6f:a8:ab:4c:51:e8:cf:50:18:c5:77:c8:39:
                    09:2c:49:92:32:99:a8:bb:17:17:79:b0:5a:c5:e6:
                    a3:c4:59:65:47:35:83:5e:a9:e8:35:0b:99:bb:e4:
                    cd:20:c6:9b:4a:06:39:b5:68:fc:22:ba:ee:55:8c:
                    2b:4e:ea:f3:b1:e3:fc:b6:99:9a:d5:42:fa:71:4d:
                    08:cf:87:1e:6a:71:7d:f9:d3:b4:e9:a5:71:81:7b:
                    c2:4e:47:96:a5:f6:76:85:a3:28:8f:e9:80:6e:81:
                    53:a5:6d:5f:b8:48:f9:c2:f9:36:a6:2e:49:ff:b8:
                    96:c2:8c:07:b3:9b:88:58:fc:eb:1b:1c:de:2d:70:
                    e2:97:92:30:a1:89:e3:bc:55:a8:27:d6:4b:ed:90:
                    ad:8b:fa:63:25:59:2d:a8:35:dd:ca:97:33:bc:e5:
                    cd:c7:9d:d1:ec:ef:5e:0e:4a:90:06:26:63:ad:b9:
                    d9:35:2d:07:ba:76:65:2c:ac:57:8f:7d:f4:07:94:
                    d7:81:02:96:5d:a3:07:49:d5:7a:d0:57:f9:1b:e7:
                    53:46:75:aa:b0:79:42:cb:68:71:08:e9:60:bd:39:
                    69:ce:f4:af:c3:56:40:c7:ad:52:a2:09:e4:6f:86:
                    47:8a:1f:eb:28:27:5d:83:20:af:04:c9:6c:56:9a:
                    8b:46:f5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                F7:7D:C5:FD:C4:E8:9A:1B:77:64:A7:F5:1D:A0:CC:BF:87:60:9A:6D
            X509v3 Certificate Policies: 
                Policy: X509v3 Any Policy
                  CPS: http://www.cert.fnmt.es/dpcs/
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        07:90:4a:df:f3:23:4e:f0:c3:9c:51:65:9b:9c:22:a2:8a:0c:
        85:f3:73:29:6b:4d:fe:01:e2:a9:0c:63:01:bf:04:67:a5:9d:
        98:5f:fd:01:13:fa:ec:9a:62:e9:86:fe:b6:62:d2:6e:4c:94:
        fb:c0:75:45:7c:65:0c:f8:b2:37:cf:ac:0f:cf:8d:6f:f9:19:
        f7:8f:ec:1e:f2:70:9e:f0:ca:b8:ef:b7:ff:76:37:76:5b:f6:
        6e:88:f3:af:62:32:22:93:0d:3a:6a:8e:14:66:0c:2d:53:74:
        57:65:1e:d5:b2:dd:23:81:3b:a5:66:23:27:67:09:8f:e1:77:
        aa:43:cd:65:51:08:ed:51:58:fe:e6:39:f9:cb:47:84:a4:15:
        f1:76:bb:a4:ee:a4:3b:c4:5f:ef:b2:33:96:11:18:b7:c9:65:
        be:18:e1:a3:a4:dc:fa:18:f9:d3:bc:13:9b:39:7a:34:ba:d3:
        41:fb:fa:32:8a:2a:b7:2b:86:0b:69:83:38:be:cd:8a:2e:0b:
        70:ad:8d:26:92:ee:1e:f5:01:2b:0a:d9:d6:97:9b:6e:e0:a8:
        19:1c:3a:21:8b:0c:1e:40:ad:03:e7:dd:66:7e:f5:b9:20:0d:
        03:e8:96:f9:82:45:d4:39:e0:a0:00:5d:d7:98:e6:7d:9e:67:
        73:c3:9a:2a:f7:ab:8b:a1:3a:14:ef:34:bc:52:0e:89:98:9a:
        04:40:84:1d:7e:45:69:93:57:ce:eb:ce:f8:50:7c:4f:1c:6e:
        04:43:9b:f9:d6:3b:23:18:e9:ea:8e:d1:4d:46:8d:f1:3b:e4:
        6a:ca:ba:fb:23:b7:9b:fa:99:01:29:5a:58:5a:2d:e3:f9:d4:
        6d:0e:26:ad:c1:6e:34:bc:32:f8:0c:05:fa:65:a3:db:3b:37:
        83:22:e9:d6:dc:72:33:fd:5d:f2:20:bd:76:3c:23:da:28:f7:
        f9:1b:eb:59:64:d5:dc:5f:72:7e:20:fc:cd:89:b5:90:67:4d:
        62:7a:3f:4e:ad:1d:c3:39:fe:7a:f4:28:16:df:41:f6:48:80:
        05:d7:0f:51:79:ac:10:ab:d4:ec:03:66:e6:6a:b0:ba:31:92:
        42:40:6a:be:3a:d3:72:e1:6a:37:55:bc:ac:1d:95:b7:69:61:
        f2:43:91:74:e6:a0:d3:0a:24:46:a1:08:af:d6:da:45:19:96:
        d4:53:1d:5b:84:79:f0:c0:f7:47:ef:8b:8f:c5:06:ae:9d:4c:
        62:9d:ff:46:04:f8:d3:c9:b6:10:25:40:75:fe:16:aa:c9:4a:
        60:86:2f:ba:ef:30:77:e4:54:e2:b8:84:99:58:80:aa:13:8b:
        51:3a:4f:48:f6:8b:b6:b3
-----BEGIN CERTIFICATE-----
MIIFgzCCA2ugAwIBAgIPXZONMGc2yAYdGsdUhGkHMA0GCSqGSIb3DQEBCwUAMDsx
CzAJBgNVBAYTAkVTMREwDwYDVQQKDAhGTk1ULVJDTTEZMBcGA1UECwwQQUMgUkFJ
WiBGTk1ULVJDTTAeFw0wODEwMjkxNTU5NTZaFw0zMDAxMDEwMDAwMDBaMDsxCzAJ
BgNVBAYTAkVTMREwDwYDVQQKDAhGTk1ULVJDTTEZMBcGA1UECwwQQUMgUkFJWiBG
Tk1ULVJDTTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALpxgHpMhm5/
yBNtwMZ9HACXjywMI7sQmkCpGreHiPibVmr75nuOi5KOpyVdWRHbNi63URcfqQgf
BBckWKo3Shjf5TnUV/3XwSyRAZHiItQDwFj8d0fsjz50Q7qsNI1NOHZnjrDIbzAz
WHFctPVrbtQBULgTfmxKo0nRIBnuvMApGGWn3v7v3QqQIecaZ5JCEJhfTzC8PhxF
tBDXaEAUwED653cXeuYLj2VbPNmaUtu1vZ5Gzz3rkQUCwJaydkxNEJY7kvqcfw+Z
374jNUUeAlz+taibmSXaXvMiwzn15Cou08YfxGyqxRxqAQVKL9LFwag0Jl1mpdIC
IfkYtwb1TplvqKtMUejPUBjFd8g5CSxJkjKZqLsXF3mwWsXmo8RZZUc1g16p6DUL
mbvkzSDGm0oGObVo/CK67lWMK07q87Hj/LaZmtVC+nFNCM+HHmpxffnTtOmlcYF7
wk5HlqX2doWjKI/pgG6BU6VtX7hI+cL5NqYuSf+4lsKMB7ObiFj86xsc3i1w4peS
MKGJ47xVqCfWS+2QrYv6YyVZLag13cqXM7zlzced0ezvXg5KkAYmY6252TUtB7p2
ZSysV4999AeU14ECll2jB0nVetBX+RvnU0Z1qrB5QstocQjpYL05ac70r8NWQMet
UqIJ5G+GR4of6ygnXYMgrwTJbFaai0b1AgMBAAGjgYMwgYAwDwYDVR0TAQH/BAUw
AwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFPd9xf3E6Jobd2Sn9R2gzL+H
YJptMD4GA1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwOi8vd3d3
LmNlcnQuZm5tdC5lcy9kcGNzLzANBgkqhkiG9w0BAQsFAAOCAgEAB5BK3/MjTvDD
nFFlm5wioooMhfNzKWtN/gHiqQxjAb8EZ6WdmF/9ARP67Jpi6Yb+tmLSbkyU+8B1
RXxlDPiyN8+sD8+Nb/kZ94/sHvJwnvDKuO+3/3Y3dlv2bojzr2IyIpMNOmqOFGYM
LVN0V2Ue1bLdI4E7pWYjJ2cJj+F3qkPNZVEI7VFY/uY5+ctHhKQV8Xa7pO6kO8Rf
77IzlhEYt8llvhjho6Tc+hj507wTmzl6NLrTQfv6MooqtyuGC2mDOL7Nii4LcK2N
JpLuHvUBKwrZ1pebbuCoGRw6IYsMHkCtA+fdZn71uSANA+iW+YJF1DngoABd15jm
fZ5nc8OaKveri6E6FO80vFIOiZiaBECEHX5FaZNXzuvO+FB8TxxuBEOb+dY7Ixjp
6o7RTUaN8Tvkasq6+yO3m/qZASlaWFot4/nUbQ4mrcFuNLwy+AwF+mWj2zs3gyLp
1txyM/1d8iC9djwj2ij3+RvrWWTV3F9yfiD8zYm1kGdNYno/Tq0dwzn+evQoFt9B
9kiABdcPUXmsEKvU7ANm5mqwujGSQkBqvjrTcuFqN1W8rB2Vt2lh8kORdOag0wok
RqEIr9baRRmW1FMdW4R58MD3R++Lj8UGrp1MYp3/RgT408m2ECVAdf4WqslKYIYv
uu8wd+RU4riEmViAqhOLUTpPSPaLtrM=
-----END CERTIFICATE-----
```

```bash
openssl x509 -in AC_RAIZ_FNMT-RCM.pem -noout -dates
notBefore=Oct 29 15:59:56 2008 GMT
notAfter=Jan  1 00:00:00 2030 GMT
```
It suprised med but after research I understood that it was normal.

Server certificates usually have much shorter lifetimes (often around 1 year) to limit the impact of a compromise and encourage regular key rotation. Root CA certificates, however, are designed to be long-lived (often 10–30 years) because they are trusted by many systems and replacing them requires large-scale updates.