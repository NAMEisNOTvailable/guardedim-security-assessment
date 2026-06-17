# Vulnerable Lab Challenges

GuardedIM includes two intentionally introduced protocol flaws. The challenges are designed for local review and mitigation analysis, not public-network testing.

## Challenge Index

| Challenge | Goal | Primary files |
| --- | --- | --- |
| [01 - Unauthenticated key exchange](challenge-01-unauthenticated-key-exchange.md) | Identify why the client accepts an untrusted server public key during session setup. | `client/client.py`, `server/server.py`, `common/encryption.py` |
| [02 - Handshake desynchronisation](challenge-02-handshake-desync.md) | Identify how inconsistent handshake framing can desynchronise later encrypted messages. | `client/client.py`, `server/server.py` |

## Demo Scripts

The challenge observations can be reproduced with local-only scripts:

```bash
python demos/run_all.py
```

Run an individual challenge demo when reviewing one finding at a time:

```bash
python demos/mitm_key_replacement_demo.py
python demos/handshake_desync_demo.py
```

See [`demos/README.md`](../demos/README.md) for scope and expected output.

## Suggested Review Flow

1. Start from the target files listed in each challenge.
2. Trace the handshake from server public-key delivery to encrypted message framing.
3. Describe the failure mode and the security impact.
4. Propose a mitigation that preserves the intended encrypted messaging workflow.

Keep testing local to the provided prototype and do not use these exercises against third-party systems.
