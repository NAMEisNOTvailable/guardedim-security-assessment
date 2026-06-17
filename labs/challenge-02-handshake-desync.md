# Challenge 02 - Handshake Desynchronisation

## Goal

Review the handshake framing logic and identify how inconsistent length handling can desynchronise later encrypted messages.

## Target Files

- `client/client.py`
- `server/server.py`

## What To Look For

- The format used by the server when sending its RSA public key.
- How the client reads the public key during connection setup.
- How later encrypted messages are length-prefixed and parsed.

## Expected Observation

The server sends the public key with a 4-byte length prefix, but the client performs a fixed-size read instead of parsing that prefix exactly. Extra bytes can remain in the stream and be interpreted as the next encrypted message length, causing denial of service or protocol-state confusion.

## Automated Demo

Run the local framing demo from the repository root:

```bash
python demos/handshake_desync_demo.py
```

The script uses an in-process socket pair to show that the fixed-size client handshake read can consume bytes belonging to the following protocol frame.

## Mitigation Direction

- Read the 4-byte public-key length prefix explicitly.
- Validate the length against a reasonable maximum.
- Read exactly the declared number of key bytes before continuing.
- Close the connection on malformed framing.

## Safe Boundary

Keep testing local to the provided prototype. The goal is to understand protocol robustness and mitigation design.
