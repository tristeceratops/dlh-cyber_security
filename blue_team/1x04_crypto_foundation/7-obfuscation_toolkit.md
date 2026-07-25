# The Obfuscation Toolkit

## Introduction

### Goal
Distinguish between encryption, hashing and obfuscation techniques, design a tokenization scheme for MedDefense, and evaluate steganography as both a protection tool and a threat vector.

### Context
Not every data protection mechanism is encryption. Sec+ 1.4 distinguishes several obfuscation techniques: tokenization (replacing sensitive data with non-sensitive tokens), data masking (hiding parts of data while preserving format) and steganography (hiding data within other data). Each has a specific use case, and confusing them is a common exam mistake and a real-world design error.

## Answer

## Part 1 - Data Protection Technique Comparison

| Technique | What it does to the data | Can the original data be recovered? | Healthcare Use Case |
|-----------|--------------------------|-------------------------------------|---------------------|
| Encryption | Converts readable data into ciphertext using a key. | Yes, by anyone with the correct decryption key. | Encrypting patient records in databases and HTTPS traffic. |
| Hashing | Converts data into a fixed-length hash for verification. | No. Hashes are designed to be one-way. | Storing user passwords and verifying file integrity. |
| Tokenization | Replaces sensitive data with a random token. | Yes, but only by accessing the secure token vault. | Replacing patient payment card numbers with tokens. |
| Data Masking | Hides part of the original data while leaving it readable enough for work. | Only authorized users can view the full value. | Showing only the last four digits of an SSN to reception staff. |
| Steganography | Hides data inside another file, such as an image or audio file. | Yes, if the hidden data is extracted using the correct method. | Could be abused to hide patient records inside DICOM medical images. |

---

## Part 2 - MedDefense Tokenization Design

### What data is tokenized?
- Credit card numbers (PANs) are replaced with random tokens.
- Example:
  - Credit Card: **4111 1111 1111 1111**
  - Token: **TKN-84F2A91D7B45**

### Token Vault
- The real credit card numbers are stored in a secure token vault.
- The vault is encrypted using AES-256.
- Access is restricted to the payment processing service using role-based access control (RBAC), multi-factor authentication, and audit logging.

### If the Token Vault is Compromised
- An attacker could recover the real credit card numbers stored in the vault.
- However, tokens stored throughout the billing application would still be meaningless without the vault.
- Protecting the vault is therefore the most critical security requirement.

### Tokenization vs Encryption

| Tokenization | Encryption |
|--------------|------------|
| Replaces sensitive data with meaningless tokens. | Converts sensitive data into ciphertext. |
| Tokens have no mathematical relationship to the original data. | Anyone with the encryption key can recover the original data. |
| Reduces PCI-DSS scope because most systems never store card numbers. | Encrypted card numbers are still considered sensitive data. |
| Requires a secure token vault. | Requires secure encryption key management. |

---

## Part 3 - Data Masking Examples

| Data Field | Full Value | Nurse (Clinical) | Billing Clerk | Reception |
|------------|------------|------------------|----------------|------------|
| SSN | 987-65-4321 | XXX-XX-4321 | 987-65-4321 | XXX-XX-4321 |
| Patient Name | Maria Gonzalez | Maria Gonzalez | Maria Gonzalez | Maria Gonzalez |
| Diagnosis | Type 2 Diabetes | Type 2 Diabetes | Hidden | Hidden |

### Justification

- **SSN (Nurse):** Only the last four digits are needed for patient verification; the full SSN is not required for treatment.
- **SSN (Billing Clerk):** Full SSN may be required for insurance claims and billing verification.
- **SSN (Reception):** Only the last four digits are needed to confirm patient identity during check-in.

- **Patient Name (Nurse):** Full name is required to correctly identify and treat the patient.
- **Patient Name (Billing Clerk):** Full name is required for billing and insurance processing.
- **Patient Name (Reception):** Full name is required for scheduling and patient check-in.

- **Diagnosis (Nurse):** Full diagnosis is required to provide appropriate patient care.
- **Diagnosis (Billing Clerk):** Diagnosis should be hidden because billing staff generally do not need detailed clinical information.
- **Diagnosis (Reception):** Diagnosis should be hidden because reception staff only require administrative information.

---

## Part 4 - Steganography as a Threat Vector

Steganography is a concern because it allows sensitive information to be hidden inside files that appear completely normal. A malicious insider could embed patient records or other confidential information inside DICOM medical images and send those images to another hospital without raising immediate suspicion. Since DICOM files are already very large and routinely transferred between healthcare facilities, the hidden data would be difficult to notice using traditional data loss prevention methods. Unlike normal file transfers, the medical image would still open correctly, making the hidden information invisible to users. A control from the 1x03 strategy that would help detect this is **Data Loss Prevention (DLP) combined with behavioral monitoring**, which can identify unusual file sizes, abnormal transfer patterns, or unauthorized movement of large imaging files.