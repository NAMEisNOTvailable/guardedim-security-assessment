# Security Notes

GuardedIM is a vulnerable assessment lab built around an academic secure-programming prototype.

Two vulnerabilities are intentionally retained as assessment targets: unauthenticated RSA key exchange and handshake protocol desynchronisation. They are documented in [Security Assessment Findings](docs/FINDINGS.md) instead of being silently fixed.

## Security Scope

Generated local files are excluded:

- no `.env` file
- no private keys or certificates
- no generated binaries
- no local database certificates
- no test media or assessment screenshots

## Review Themes

The project is best reviewed through these security themes:

- intentionally vulnerable lab targets and their mitigations
- server identity verification during key exchange
- public-key replacement and MITM risk
- AES-GCM session-key handling
- message framing and length parsing
- file-transfer validation
- sender identity binding
- database credential handling
- peer-review and static-analysis workflow

## Hardening Applied

- local secrets, generated keys, certificates, binaries, and media were excluded
- `.env.example` and `guarded_im_config.example.json` document local setup without exposing secrets
- sender identity is bound server-side instead of trusting client-controlled `from` fields
- duplicate connected usernames are rejected
- receive-side filename/path sanitisation and dangerous-extension checks are enforced
- oversized incoming encrypted frames are rejected server-side

## Secret Handling Boundary

Runtime keys and database certificates are represented as local files or process environment values for the lab. This keeps the prototype easy to inspect and run locally, but it is not a production secret-management model.

For a production service, the remaining work would be to move private keys and database credentials into a managed secret store or systemd credentials, enforce restrictive file permissions, define certificate rotation, and avoid exposing long-lived private material through process-level environment variables.

## Production Readiness

This code is not production-ready. It is intended for local vulnerability review, mitigation analysis, and secure-programming discussion.
