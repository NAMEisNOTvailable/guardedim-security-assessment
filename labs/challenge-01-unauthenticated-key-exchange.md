# Challenge 01 - Unauthenticated Key Exchange

## Goal

Review the initial client/server key exchange and identify why the client cannot prove that the RSA public key came from the legitimate server.

## Target Files

- `client/client.py`
- `server/server.py`
- `common/encryption.py`

## What To Look For

- How the server sends its public key to a new client connection.
- How the client reads that public key before encrypting the AES session key.
- Whether the client validates the server identity before trusting the public key.

## Expected Observation

The client accepts the first RSA public key it receives and immediately uses it to encrypt the AES session key. A trusted identity check is missing, so the key exchange is vulnerable to public-key replacement in a man-in-the-middle scenario.

## Automated Demo

Run the local proxy demo from the repository root:

```bash
python demos/mitm_key_replacement_demo.py
```

The script starts the local GuardedIM server, places a localhost proxy between the client and server, replaces the unauthenticated RSA public key, and prints the captured plaintext message.

## Mitigation Direction

- Pin a known server public-key fingerprint.
- Use certificate validation or another authenticated key-exchange mechanism.
- Refuse to send the AES session key until server identity is verified.

## Safe Boundary

Use this challenge only against the local GuardedIM prototype. The exercise is intended for review and mitigation reasoning.
