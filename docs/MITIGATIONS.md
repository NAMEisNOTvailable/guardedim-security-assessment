# Mitigation Comparison

GuardedIM intentionally keeps two protocol-level weaknesses in the localhost prototype so reviewers can reproduce the failure mode and reason about a safer design. The hardening items below show how the same codebase separates deliberate lab targets from ordinary implementation risks.

## Protocol Findings

| Area | Vulnerable lab behaviour | Security impact | Mitigation direction |
| --- | --- | --- | --- |
| Server identity during key exchange | The client accepts the server RSA public key without authenticating who supplied it. | A local MITM proxy can replace the key, recover the AES session key, and read encrypted client payloads. | Authenticate the server key through certificate validation, fingerprint verification, key pinning, or a mutually authenticated key exchange. |
| Handshake framing | The client uses inconsistent public-key length handling during the initial handshake. | Extra bytes can be consumed as part of the handshake, desynchronising the next protocol frame. | Parse the declared length exactly, enforce a maximum public-key length, and read exactly that many bytes before processing later frames. |

## Hardening Items Already Applied

| Area | Previous risk | Current control | Evidence |
| --- | --- | --- | --- |
| Sender spoofing | Client-controlled `from` fields could impersonate another user. | The server binds the sender to the authenticated connection state before forwarding messages and files. | `tests/test_runtime_integration.py` verifies that a forged sender is forwarded as the real connected user. |
| Duplicate usernames | Two live connections could use the same username. | The server rejects a second active connection for an already connected username. | Documented in `docs/FINDINGS.md` and enforced in the server connection flow. |
| File path traversal | Received filenames could include path components. | Receive paths are built from sanitised path parts and constrained under `chat_media/`. | `tests/test_client_paths.py` checks traversal attempts stay under the media root. |
| Dangerous file extensions | Executable or script payloads could be transferred directly. | Client and server validation reject common executable/script extensions. | `tests/test_validation.py` covers blocked extensions such as `.exe` and `.ps1`. |
| Oversized frames | Large encrypted frames could pressure memory or protocol handling. | Frame parsing enforces `MAX_FRAME_SIZE` before accepting payload data. | `common/encryption.py` defines limits used by the client, server, and tests. |

## Production Design Notes

The prototype is intentionally local and review-oriented. A production messenger would still need:

- authenticated server identity and certificate lifecycle management
- secret storage outside source files and process-level environment values
- stronger replay, nonce, and session-rotation controls
- deployment packaging, operational monitoring, and abuse-rate limits
- end-to-end review of file-transfer policy and metadata exposure

