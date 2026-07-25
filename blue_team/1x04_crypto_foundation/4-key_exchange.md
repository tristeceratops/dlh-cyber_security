# The Key Exchange

## Introduction

### Goal
Simulate a Diffie-Hellman key exchange with OpenSSL to understand how two parties agree on a shared secret over an insecure channel, then analyze the man-in-the-middle vulnerability that certificates exist to solve.

### Context
The fundamental problem of symmetric encryption is key distribution: Alice and Bob need the same key, but they cannot send it over the network because Eve is listening. In 1976, Whitfield Diffie and Martin Hellman solved this problem with mathematics. You are about to reproduce their solution with OpenSSL.

But their solution has a weakness. If Eve is not just listening but actively intercepting and modifying traffic, Diffie-Hellman alone cannot detect her. This is why certificates exist. The connection between key exchange and PKI is the thread that runs through the rest of this project.

## Answer

### Part 1

Diffie-Hellman key exchange between Alice and Bob simulation:
- Generate shared DH parameters: `openssl dhparam -out dhparams.pem 2048`

- Generate Alice's private key from the parameters: `openssl genpkey -paramfile dhparams.pem -out alice_private.pem`

- Extract Alice's public key: `openssl pkey -in alice_private.pem -pubout -out alice_public.pem`

- Repeat for Bob: `openssl genpkey -paramfile dhparams.pem -out bob_private.pem && openssl pkey -in bob_private.pem -pubout -out bob_public.pem`

- Derive the shared secret from Alice's side using Bob's public key: `openssl pkeyutl -derive -inkey alice_private.pem -peerkey bob_public.pem -out alice_secret.bin`

- Derive the shared secret from Bob's side using Alice's public key: `openssl pkeyutl -derive -inkey bob_private.pem -peerkey alice_public.pem -out bob_secret.bin`

- Compare the two secrets: `diff alice_secret.bin bob_secret.bin` or `sha256sum alice_secret.bin bob_secret.bin`
```bash
diff alice_secret.bin bob_secret.bin

sha256sum alice_secret.bin bob_secret.bin
de1d0b46d292d4b8a6c0270431f27dfe7043370da8bbaf40e86297734a08c7c6  alice_secret.bin
de1d0b46d292d4b8a6c0270431f27dfe7043370da8bbaf40e86297734a08c7c6  bob_secret.bin
```

### Part 2

Alice and Bob used a mathematical process called Diffie-Hellman to create the same secret key without ever sending that key across the network. Each person created a private value that they kept hidden and combined it with a public value that could be shared openly. By combining their own private value with the other person's public value, both Alice and Bob were able to independently calculate the same secret. Eve, who was listening to the communication, could see the public information exchanged between Alice and Bob, but she did not have their private values. Without those private values, the mathematics makes it extremely difficult for Eve to calculate the same secret key. This allows two people to establish a secure connection even when an attacker can observe the entire exchange.

### Part 3

A plain Diffie-Hellman exchange does not verify who is sending the public keys, which allows a man-in-the-middle attack. Eve can intercept Alice's public key, replace it with her own, and create separate shared secrets with both Alice and Bob. Alice thinks she is communicating securely with Bob, and Bob thinks he is communicating securely with Alice, but Eve can read and modify the traffic between them. For MedDefense, if the VPN tunnel between Central and Westside uses unauthenticated DH, an attacker on the network path could intercept sensitive medical data or alter communications without being detected. Certificates prevent this by proving the identity of the devices involved, ensuring that the public key belongs to the real Central or Westside system and not an attacker.