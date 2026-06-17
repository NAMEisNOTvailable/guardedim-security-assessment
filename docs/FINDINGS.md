# Security Assessment Findings

GuardedIM is a small vulnerable assessment lab, not production messaging software. The current codebase intentionally retains two protocol-level findings for attack analysis and mitigation reasoning. Other implementation issues are treated as hardening items rather than lab targets.

## Finding Matrix

| Finding | Assessment role | Classification | Repository status |
| --- | --- | --- | --- |
| Unauthenticated RSA key exchange | Intentionally vulnerable lab target for MITM analysis | Intentional assessment target | Retained in the localhost Python prototype and documented. Mitigation is server identity verification through certificate validation, fingerprint checking, or key pinning. |
| Handshake protocol desynchronisation | Intentionally vulnerable lab target for protocol-framing analysis | Intentional assessment target | Retained in the localhost Python prototype and documented. Mitigation is exact length-prefix parsing and maximum-length validation before accepting handshake data. |
| Client-controlled `from` fields | Hardening item | Addressed | The server binds sender identity to the authenticated connection state for forwarded messages and files. |
| Duplicate connected usernames | Hardening item | Addressed | The server rejects a second live connection using an already connected username. |
| File-transfer path traversal | Hardening item | Addressed | Receive-side filenames and path components are sanitised before writing under `chat_media/`. |
| Dangerous file extensions | Hardening item | Addressed | Client and server reject common executable/script file extensions for file transfer. |
| Oversized incoming frames | Hardening item | Addressed | Server-side frame parsing enforces a maximum encrypted-frame size. |

## Earlier Review Items Reclassified

The MITM key-replacement issue and the handshake framing mismatch should not be described as accidental bugs. They are intentionally planted assessment targets.

The SQL DDL comma, WireGuard daemon argument wiring, message-size constant, nonce-store race, sender binding, duplicate-name handling, and file-path handling are ordinary implementation issues. They are not intentionally retained assessment targets, so they can be fixed without changing the lab exercise.
