# The CSR Workshop

## Introduction

### Goal
Generate a Certificate Signing Request for the MedDefense patient portal, making every field decision deliberately and documenting the reasoning.

### Context
The patient portal certificate expires in 18 days. James Chen has approved the renewal. You are generating the CSR that will be submitted to the Certificate Authority. Every field in the CSR becomes a field in the certificate, and every field matters. A wrong Common Name locks out patients. A missing SAN entry breaks mobile access. A weak key algorithm undermines the entire purpose.

## Answer

### Part 1
Although **ECC P-256** offers excellent security with smaller key sizes and more efficient TLS handshakes, **RSA 2048-bit** is the better choice for this patient portal because compatibility is a top priority. RSA 2048 provides strong, widely accepted security while ensuring support for older browsers, mobile devices, and enterprise systems that patients may still use. For a web server handling approximately 800 patient connections per day, the performance advantage of ECC would be minimal, making RSA 2048 a practical balance between security, reliability, and broad compatibility. This approach also reduces the risk of certificate-related access issues while protecting sensitive patient data.

Generations key + certificate:
```bash
openssl req -x509 -newkey rsa:2048 -keyout private.key -out certificate.crt -days 365 -nodes
```

Verification:
```bash
openssl x509 -noout -modulus -in certificate.crt | openssl md5                              
openssl rsa  -noout -modulus -in private.key      | openssl md5
MD5(stdin)= 3ab541ccb9057c913478e1150f9a7217
MD5(stdin)= 3ab541ccb9057c913478e1150f9a7217
```

### Part 2

```bash
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [US]:
State or Province Name (full name) [New York]:
Locality Name [New York]:
Organization Name [MedDefense Health Systems]:
Organizational Unit Name [Information Technology]:
Common Name (e.g. server FQDN) [portal.meddefense.local]:
Email Address [meddefense.it@mail.com]:
Challenge Password []:exampleComplexPa77
```

### Part 3
```bash
openssl req -text -noout -in portal.csr                                 
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=US, ST=New York, L=New York, O=MedDefense Health Systems, OU=Information Technology, CN=portal.meddefense.local, emailAddress=meddefense.it@mail.com, challengePassword=exampleComplexPa77
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:9a:29:be:c2:5b:35:fd:07:4e:2b:1a:1a:dd:12:
                    2b:3f:51:21:22:fd:43:ae:00:01:0d:77:fb:5b:29:
                    eb:e3:45:49:aa:8f:d7:0f:c5:f5:ed:92:55:08:ee:
                    b6:b8:39:c9:20:32:9b:f2:0f:62:68:e8:0b:02:71:
                    85:06:ee:a8:0e:f3:1b:fd:b8:39:1a:d8:a8:89:b7:
                    49:e1:48:b3:e6:93:fa:f4:4b:00:00:86:8d:cb:fb:
                    60:e0:5d:c8:ba:e3:17:a1:57:42:d8:da:da:c2:e9:
                    10:cd:be:1e:f1:29:c5:84:5d:ad:3f:87:e9:e9:19:
                    f1:f7:18:fd:4c:53:cc:e4:21:17:ba:27:3f:68:ea:
                    39:48:22:30:b7:e7:82:f6:47:a2:f5:86:0b:89:35:
                    0a:8d:f6:31:88:4c:aa:06:2a:71:39:37:ca:2c:a3:
                    a5:00:ff:02:1c:47:f7:e0:a5:a6:83:8e:41:0c:64:
                    08:da:4a:19:a2:30:48:55:d0:e5:cf:f5:26:a7:ab:
                    bb:a2:bf:3d:12:00:c2:ec:c2:d4:61:fc:63:ef:37:
                    c6:24:db:2e:67:aa:ed:70:c7:a3:03:1b:e0:ed:68:
                    40:03:3f:d3:e9:5a:9e:ba:cb:51:f6:6c:35:91:b4:
                    aa:73:cb:29:d4:ed:df:d4:09:e1:8b:04:dc:86:c2:
                    67:d3
                Exponent: 65537 (0x10001)
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    DNS:portal.meddefense.local, DNS:login.meddefense.local, DNS:patient.meddefense.local
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        99:37:6b:ea:c4:a6:27:8d:a0:da:b2:20:cb:79:7a:6f:05:82:
        d6:3f:3b:b7:1c:ad:1d:8f:96:ed:de:f3:c9:0f:35:31:2c:ae:
        9e:c5:fa:a7:cc:57:6d:42:af:37:3e:54:47:4e:19:59:cb:af:
        bd:c5:af:0f:d0:58:ce:c9:dc:00:18:40:ae:d0:21:5a:c9:bc:
        8b:9e:64:50:1b:1f:a7:08:85:48:4e:4c:83:8f:f4:bc:6c:e2:
        02:d9:cf:06:5d:02:70:db:e7:0e:53:3e:7d:9a:73:a7:84:55:
        fe:9e:ff:ef:85:41:5c:0f:b4:8b:f3:7b:13:55:21:2c:09:b9:
        a9:ca:e1:ca:4c:b9:21:dc:6c:dd:75:85:d9:41:ed:79:d3:bf:
        c1:a7:31:e2:a7:93:48:2a:cd:2e:d0:1b:f8:cb:41:ee:4f:2e:
        fb:54:61:9d:4b:76:da:8b:45:56:b9:4d:f8:89:90:55:9f:c0:
        5c:88:7a:59:d4:af:af:99:74:fa:11:4a:c1:00:6a:10:ad:c8:
        e7:86:da:cd:01:36:1c:70:23:f7:c6:2b:41:be:ed:84:85:ad:
        90:7d:4a:fb:ff:63:c2:7a:7b:b8:ae:e7:66:8a:08:b0:cc:42:
        c3:2e:17:b3:97:22:ad:0b:aa:a8:52:73:d0:9e:27:27:44:00:
        75:60:38:1d
```

SANs are present (`DNS:portal.meddefense.local, DNS:login.meddefense.local, DNS:patient.meddefense.local`), the configuration was successful.

### Part 4

#### Step 1 – Generate the CSR
Generate a Certificate Signing Request (CSR) on the web server using the server's private key. Verify that the CSR contains the correct Common Name (CN) and all required Subject Alternative Names (SANs) before continuing.

#### Step 2 – Submit the CSR to the Certificate Authority
Submit the CSR to a trusted Certificate Authority (CA). For MedDefense, Let's Encrypt is recommended because it is free, trusted by all major browsers, and supports automatic certificate management through ACME. A commercial CA may be used if required by organizational policy.

#### Step 3 – Complete the Validation Process
Complete the validation process requested by the CA. If using Let's Encrypt, perform the required ACME challenge (HTTP-01 or DNS-01) to prove ownership of the domain. Wait for the CA to successfully validate the request.

#### Step 4 – Obtain the Certificate
After validation is complete, download the issued SSL/TLS certificate along with the required intermediate certificate(s). Check that the certificate contains the correct CN, SANs, issuing CA, and expiration date.

#### Step 5 – Install the Certificate
Copy the new certificate and the CA certificate chain to the public web server (web-srv-01). Configure the web server to use the new certificate together with the existing private key, then reload or restart the web server to apply the changes.

#### Step 6 – Verify the Installation
Access the patient portal using HTTPS and confirm that the new certificate is being presented. Verify that the browser reports the connection as secure, the certificate chain is valid, and the CN and SANs match the expected hostnames.

#### Step 7 – Remove the Old Certificate
Once the new certificate has been verified, remove the old certificate from the web server configuration. Archive the old certificate if required by organizational policy and securely delete any private keys that are no longer needed.

#### Step 8 – Monitor and Renew
Monitor the certificate's expiration date and renew it before it expires. If using Let's Encrypt, ensure the ACME client performs automatic renewals every 90 days and periodically verify that the renewal process completes successfully.