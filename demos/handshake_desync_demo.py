from __future__ import annotations

import socket
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def make_public_key_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main() -> None:
    public_key = make_public_key_pem()
    next_payload = b'{"type":"server_notice","message":"next encrypted frame"}'
    next_frame = struct.pack(">I", len(next_payload)) + next_payload

    server_sock, client_sock = socket.socketpair()
    try:
        server_sock.sendall(struct.pack(">I", len(public_key)) + public_key + next_frame)

        first_read = client_sock.recv(4096)
        serialization.load_pem_public_key(first_read)

        declared_key_len = struct.unpack(">I", first_read[:4])[0]
        expected_handshake_len = 4 + declared_key_len
        swallowed = first_read[expected_handshake_len:]

        print("[demo] Challenge 02: handshake desynchronisation")
        print(f"[demo] declared public-key length: {declared_key_len} bytes")
        print(f"[demo] fixed client read consumed: {len(first_read)} bytes")
        print(f"[demo] extra protocol bytes swallowed by handshake read: {len(swallowed)} bytes")

        if swallowed != next_frame:
            raise SystemExit("[demo] expected the fixed read to consume the following frame")

        client_sock.settimeout(0.2)
        try:
            remaining = client_sock.recv(4)
        except TimeoutError:
            remaining = b""
        except socket.timeout:
            remaining = b""

        if remaining:
            raise SystemExit("[demo] expected no complete frame header after the fixed handshake read")

        print("[demo] PASS: the fixed-size handshake read consumed bytes belonging to the next frame.")
        print("[demo] Mitigation: parse the 4-byte key length, validate it, then read exactly that many key bytes.")
    finally:
        client_sock.close()
        server_sock.close()


if __name__ == "__main__":
    main()
