# GuardedIM Security Assessment Lab

[![Smoke tests](https://github.com/NAMEisNOTvailable/guardedim-security-assessment/actions/workflows/smoke.yml/badge.svg)](https://github.com/NAMEisNOTvailable/guardedim-security-assessment/actions/workflows/smoke.yml)

GuardedIM is a local security-assessment lab for a decentralised secure messaging prototype. It combines a runnable Python chat client/server, AES-GCM encrypted payloads, RSA-based session-key exchange, and Go control-plane components for WireGuard-oriented relay management.

The lab keeps two protocol flaws as local assessment targets that can be reproduced, explained, and mapped to mitigations in a safe localhost setting. The project is scoped as a secure-programming review lab.

## What This Demonstrates

- Applied cryptography review across RSA key exchange, AES-GCM session encryption, and message framing.
- Local proof-of-concept demos for unauthenticated key exchange and handshake desynchronisation.
- Secure-programming hardening around sender binding, filename validation, dangerous file extensions, and frame-size limits.
- Python runtime tests plus Go compile/unit checks through GitHub Actions.

## Project Snapshot

| Area | Summary |
| --- | --- |
| Domain | Secure messaging, applied cryptography, secure programming |
| Client/server prototype | Python socket service and Tkinter chat client |
| Control components | Go CLI and daemon code for server/user management, WireGuard peer updates, and mTLS-oriented control-plane design |
| Security mechanisms | RSA session-key exchange, AES-GCM message/file encryption paths, and mTLS-oriented control-plane design |
| Networking design | WireGuard-oriented server connectivity and peer management concepts, with a localhost Python prototype for testing |
| Data layer | CockroachDB/PostgreSQL-style metadata storage through Go `pgx` |
| Lab format | Local vulnerable target with guided protocol-analysis challenges |

## Engineering Focus

- Python socket server and Tkinter client for one-to-one chat, group chat, and file transfer.
- RSA-based session-key exchange with AES-GCM encrypted message and file payloads.
- Go control components for server setup, user registration, database access, and WireGuard peer updates.
- Two intentionally vulnerable lab targets: unauthenticated key exchange and handshake protocol desynchronisation.
- Security review coverage for MITM exposure, message framing, authentication boundaries, file handling, secret storage, and denial-of-service behaviour.

## Architecture at a Glance

```mermaid
flowchart LR
    GUI["Tkinter chat GUI"] --> PYCLIENT["Python client"]
    PYCLIENT -->|"RSA session-key setup"| PYSERVER["Python socket server"]
    PYCLIENT -->|"AES-GCM messages and files"| PYSERVER
    PYSERVER --> USERS["Connected users and groups"]
    PYSERVER --> COMMON["Shared crypto and validation helpers"]
    GOCLI["Go CLI"] --> GOSERVER["Go control-plane prototype"]
    GODAEMON["Go daemon"] --> GOSERVER
    GOSERVER --> DB["PostgreSQL/CockroachDB metadata"]
    GOSERVER --> WG["WireGuard peer management concept"]
```

See [Architecture Notes](docs/ARCHITECTURE.md) for the component map and design boundaries.

## Repository Structure

```text
client/      Python chat client and Go client-side setup helpers
server/      Python server prototype and Go server/database control helpers
common/      Shared Python encryption utilities
cmd/gdim/    Go CLI control commands
cmd/gdimd/   Go daemon entry point
docs/        Architecture notes and security findings
labs/        Guided vulnerable-lab challenges
demos/       Local proof-of-concept demos for the two lab findings
```

## Key Files

| Path | Purpose |
| --- | --- |
| `client/chat_gui.py` | Tkinter GUI for user chat interactions |
| `client/client.py` | Python client connection, encryption, message, group, and file-transfer logic |
| `server/server.py` | Python socket server, key exchange, message forwarding, and group handling |
| `common/encryption.py` | Shared AES-GCM and RSA helper functions |
| `cmd/gdim/` | Go command-line control surface |
| `cmd/gdimd/` | Go daemon entry point |
| `guarded_im_config.example.json` | Example configuration template |
| `.env.example` | Localhost Python prototype settings |
| `SECURITY_NOTES.md` | Security scope and review themes |
| `docs/FINDINGS.md` | Assessment finding matrix |
| `docs/MITIGATIONS.md` | Vulnerable design versus mitigation comparison |
| `labs/README.md` | Lab challenge index |
| `demos/README.md` | Local demo script index |

## 60-Second Verification

After installing the Python dependencies, run these checks from the repository root:

```bash
python -m unittest discover -s tests
python demos/run_all.py
go test ./...
```

The Python tests cover validation, runtime exchange, and sender binding. The demo runner reproduces the two local-only assessment findings. The Go check validates the control-plane packages when Go is available.

## Setup Notes

Install Python dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Create local configuration from the example:

```bash
cp guarded_im_config.example.json guarded_im_config.json
cp .env.example .env
```

Runtime keys are generated locally on first server start. To rotate them manually:

```bash
python -m server.server --gen-keys
```

Start the Python server and GUI client in separate terminals:

```bash
python -m server.server
python -m client.chat_gui
```

Build the Go control components when Go is available:

```bash
go build -o gdim ./cmd/gdim/*.go
go build -o gdimd ./cmd/gdimd/*.go
```

The Go code is kept as a control-plane prototype. It covers configuration parsing, database-backed server/user records, WireGuard peer setup paths, and the mTLS-oriented control server. Automated checks run lightweight Go unit and compile checks; a deployed system would require operational secret management, certificate lifecycle handling, and environment-specific service packaging.

## Lab Challenges

The lab is designed around two intentionally introduced protocol flaws:

| Challenge | Focus | Entry point |
| --- | --- | --- |
| 01 | Unauthenticated RSA key exchange and MITM reasoning | [`labs/challenge-01-unauthenticated-key-exchange.md`](labs/challenge-01-unauthenticated-key-exchange.md) |
| 02 | Handshake desynchronisation through inconsistent length handling | [`labs/challenge-02-handshake-desync.md`](labs/challenge-02-handshake-desync.md) |

Each challenge describes the target files, review goal, expected observation, and mitigation direction.

## Local Demo Scripts

The repository includes two local-only proof-of-concept demos. They bind to `127.0.0.1` or use in-process sockets and are intended for assessment discussion:

```bash
python demos/run_all.py
```

Run individual demos when reviewing one finding at a time:

```bash
python demos/mitm_key_replacement_demo.py
python demos/handshake_desync_demo.py
```

See [Local Vulnerability Demos](demos/README.md) for details.

## Security Review Focus

Security review focus:

- Which issues are intentionally vulnerable lab targets for the assessment?
- How is server identity validated before accepting public keys?
- How are session keys generated, exchanged, stored, and rotated?
- How can message framing errors desynchronise an encrypted protocol?
- How should file-transfer payloads be validated and constrained?
- How should private keys, certificates, database credentials, and local configuration stay out of source control?
- Which risks are mitigated in the prototype, and which remain documented limitations?

See [Security Notes](SECURITY_NOTES.md), [Security Assessment Findings](docs/FINDINGS.md), [Mitigation Comparison](docs/MITIGATIONS.md), and [Architecture Notes](docs/ARCHITECTURE.md).

## Excluded Runtime Files

Generated or machine-specific files are excluded:

- `.env` and machine-specific configuration
- generated binaries
- generated private/public key material
- local certificates and database credentials
- screenshots and test media
- real deployment secrets

## License

Original source code and documentation are licensed under the MIT License.

## Status

Academic secure-programming prototype focused on security assessment and mitigation review.
