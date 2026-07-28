# Hardware Security and Key Management

## Introduction

### Goal
Evaluate TPM, HSM and secure enclave technologies, and design a key management strategy for MedDefense that solves the "where do you keep the keys ?" problem.

### Context
Every encryption scheme has a fatal weakness: the key. If you encrypt 50,000 patient records with AES-256 and store the key in a plaintext configuration file on the same server, you have not actually protected anything. You have added a speed bump.

Sec+ 1.4 identifies three hardware security technologies designed to solve this problem: TPM (Trusted Platform Module), HSM (Hardware Security Module) and secure enclaves. Each operates at a different scale and cost, and MedDefense needs to choose which is appropriate for its budget and risk profile.

## Answer