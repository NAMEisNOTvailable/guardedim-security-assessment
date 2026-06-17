import os
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from client.client import ChatClient


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Server did not listen on port {port}.")


def wait_until(predicate, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for expected runtime state.")


class RuntimeIntegrationTests(unittest.TestCase):
    def test_two_clients_can_exchange_message(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        port = free_port()

        with tempfile.TemporaryDirectory() as keys_dir:
            env = os.environ.copy()
            env["IP_ADDRESS"] = "127.0.0.1"
            env["PORT"] = str(port)
            env["GUARDEDIM_KEYS_DIR"] = keys_dir

            proc = subprocess.Popen(
                [sys.executable, "-m", "server.server"],
                cwd=repo_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            alice_events = []
            bob_events = []
            alice_users = []
            bob_users = []
            alice = None
            bob = None

            try:
                wait_for_port(port)

                def alice_message(chat, message, sender=None):
                    alice_events.append((chat, message, sender))

                def bob_message(chat, message, sender=None):
                    bob_events.append((chat, message, sender))

                alice = ChatClient("alice", alice_message, alice_users.append)
                bob = ChatClient("bob", bob_message, bob_users.append)

                with mock.patch.dict(os.environ, {"IP_ADDRESS": "127.0.0.1", "PORT": str(port)}):
                    bob.connect()
                    bob.start_receiving()
                    alice.connect()
                    alice.start_receiving()

                wait_until(lambda: any("alice" in users and "bob" in users for users in bob_users))
                self.assertTrue(alice.send_message("bob", "hello from alice"))
                wait_until(lambda: ("alice", "hello from alice", "alice") in bob_events)

                forged_payload = json.dumps({
                    "type": "message",
                    "from": "mallory",
                    "to": "bob",
                    "payload": "spoof attempt",
                })
                alice.send_encrypted(forged_payload)
                wait_until(lambda: ("alice", "spoof attempt", "alice") in bob_events)
                self.assertNotIn(("mallory", "spoof attempt", "mallory"), bob_events)
            finally:
                if alice:
                    alice.disconnect()
                if bob:
                    bob.disconnect()
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                if proc.stdout:
                    proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
