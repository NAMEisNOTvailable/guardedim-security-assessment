# Local Vulnerability Demos

These scripts demonstrate the two GuardedIM lab findings against the local prototype only. They bind to `127.0.0.1`, start or simulate local services, and are intended for review and mitigation discussion.

Run them from the repository root after installing `requirements.txt`:

```bash
python demos/run_all.py
```

Run individual demos when reviewing one finding at a time:

```bash
python demos/mitm_key_replacement_demo.py
python demos/handshake_desync_demo.py
```

## Demo Coverage

| Demo | Shows | Safe boundary |
| --- | --- | --- |
| `run_all.py` | Runs both local demos and prints a short pass/fail report. | Calls only the two repository-local demo scripts below. |
| `mitm_key_replacement_demo.py` | A localhost proxy replaces the unauthenticated RSA public key, decrypts the AES session key, and reads one client message. | Starts the local GuardedIM server and proxy on `127.0.0.1` only. |
| `handshake_desync_demo.py` | A fixed-size client handshake read can consume bytes that belong to the following protocol frame. | Uses an in-process socket pair and does not connect to a network service. |

These demos are intentionally narrow. They are not scanners, do not target third-party systems, and do not contain persistence or credential collection logic.
