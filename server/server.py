import datetime
import json
import os
import socket
import struct
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from dotenv import load_dotenv

from common import encryption, validation

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.getenv("GUARDEDIM_KEYS_DIR", os.path.join(BASE_DIR, "..", "keys"))
os.makedirs(KEYS_DIR, exist_ok=True)
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

clients = {}
groups = {}
state_lock = threading.RLock()


def send_payload(conn: socket.socket, aes_key: bytes, payload: dict | str) -> None:
    if isinstance(payload, str):
        payload = {"type": "error", "message": payload}
    encrypted = encryption.encrypt_message(json.dumps(payload), aes_key)
    conn.sendall(struct.pack(">I", len(encrypted)) + encrypted)


def send_error(conn: socket.socket, aes_key: bytes, message: str) -> None:
    send_payload(conn, aes_key, {"type": "error", "message": message})


def read_frame(conn_file) -> bytes | None:
    header = conn_file.read(4)
    if not header:
        return None
    msg_len = struct.unpack(">I", header)[0]
    if msg_len > encryption.MAX_FRAME_SIZE:
        raise ValueError(f"Frame exceeds limit of {encryption.MAX_FRAME_SIZE} bytes.")

    data = conn_file.read(msg_len)
    if len(data) < msg_len:
        raise ValueError("Incomplete frame received.")
    return data


def recv_exact_socket(conn: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = conn.recv(length - len(chunks))
        if not chunk:
            raise ValueError("Connection closed during fixed-length read.")
        chunks.extend(chunk)
    return bytes(chunks)


def broadcast_user_list() -> None:
    with state_lock:
        usernames = list(clients.keys())
        targets = list(clients.values())

    for conn, key in targets:
        try:
            send_payload(conn, key, {"type": "user_list", "users": usernames})
        except Exception as e:
            print(f"Could not send user list: {e}")
            continue


def forward_payload(to_user: str, payload: json) -> None:
    with state_lock:
        target = clients.get(to_user)
    if target:
        dest_conn, dest_key = target
        send_payload(dest_conn, dest_key, payload)


def handle_client(conn: socket.socket, private_key: RSAPrivateKey) -> None:
    username = None
    try:
        encrypted_aes_key = recv_exact_socket(conn, 256)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

        username = conn.recv(1024).decode().strip()
        if not username:
            print("No username received.")
            return
        if not validation.is_safe_username(username):
            send_error(conn, aes_key, "Invalid username.")
            return

        with state_lock:
            if username in clients:
                send_error(conn, aes_key, "Username already connected.")
                return
            clients[username] = (conn, aes_key)

        try:
            payload = {
                "type": "user_list",
                "users": list(clients.keys())
            }

            send_payload(conn, aes_key, payload)
        except Exception as e:
            print(f"Could not send user list to {username}: ", e)
        broadcast_user_list()

        conn_file = conn.makefile('rb')
        while True:
            try:
                data = read_frame(conn_file)
            except ValueError as e:
                print(f"Frame error from {username}: {e}")
                break
            if data is None:
                break

            try:
                decrypted = encryption.decrypt_message(data, aes_key)
                payload = json.loads(decrypted)
                if not isinstance(payload, dict):
                    raise ValueError("Payload must be a JSON object.")
                payload["from"] = username

                match payload.get("type"):
                    case "create_group":
                        group_name = payload.get("group_name")
                        members = payload.get("members", [])

                        if not validation.is_safe_group_name(group_name):
                            send_error(conn, aes_key, "Invalid group name.")
                            continue
                        if not isinstance(members, list) or not all(
                                validation.is_safe_username(member) for member in members):
                            send_error(conn, aes_key, "Invalid group members.")
                            continue

                        members = sorted(set(members + [username]))
                        with state_lock:
                            group_exists = group_name in groups
                            if not group_exists:
                                groups[group_name] = {"members": members}

                        if group_exists:
                            send_error(conn, aes_key, "Group already exists.")
                            continue

                        for member in members:
                            with state_lock:
                                target = clients.get(member)
                            if member != username and target:
                                dest_conn, dest_key = target

                                group_invite = {
                                    "type": "group_invite",
                                    "group_name": group_name,
                                    "members": members
                                }
                                send_payload(dest_conn, dest_key, group_invite)

                        ack = {
                            "type": "group_created",
                            "group_name": group_name
                        }

                        send_payload(conn, aes_key, ack)

                    case "group_message":
                        group_name = payload.get("to")
                        message = payload.get("payload")

                        if not validation.is_safe_group_name(group_name):
                            send_error(conn, aes_key, "Invalid group name.")
                            continue
                        with state_lock:
                            members = groups.get(group_name, {}).get("members")
                        if not members or username not in members:
                            send_error(conn, aes_key, "Not a member of that group.")
                            continue

                        payload["to"] = group_name
                        payload["payload"] = message
                        payload["payload_type"] = "text"
                        payload["to_type"] = "group"
                        payload["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"

                        for member in members:
                            with state_lock:
                                target = clients.get(member)
                            if member != username and target:
                                mem_conn, mem_key = target
                                send_payload(mem_conn, mem_key, payload)

                    case "message":
                        to_user = payload.get("to")
                        if not validation.is_safe_username(to_user):
                            send_error(conn, aes_key, "Invalid recipient username.")
                            continue
                        if not encryption.check_message_size(str(payload.get("payload", ""))):
                            send_error(conn, aes_key, f"Message dropped. Exceeds limit of {encryption.MAX_MESSAGE_SIZE}.")
                            continue

                        payload["payload_type"] = "text"
                        payload["to_type"] = "user"
                        payload["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
                        forward_payload(to_user, payload)

                    case "message_file" | "group_file":
                        file_data = payload.get("payload")
                        file_to = str(payload.get("to", "")).lstrip("#")
                        filename = payload.get("filename")
                        is_group = payload.get("to_type") == "group"

                        if not file_data or not filename:
                            raise ValueError("Missing filedata or filename.")
                        if not validation.is_safe_transfer_filename(filename):
                            send_error(conn, aes_key, "Blocked dangerous filename.")
                            continue

                        if not encryption.check_file_size(file_data):
                            send_error(conn, aes_key, f"Message dropped. Exceeds limit of {encryption.MAX_FILE_SIZE} bytes.")
                            continue

                        payload["payload_type"] = "file"
                        payload["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"

                        if is_group:
                            if not validation.is_safe_group_name(file_to):
                                send_error(conn, aes_key, "Invalid group name.")
                                continue
                            with state_lock:
                                members = groups.get(file_to, {}).get("members")
                            if not members or username not in members:
                                send_error(conn, aes_key, "Not a member of that group.")
                                continue
                            for member in members:
                                with state_lock:
                                    target = clients.get(member)
                                if member != username and target:
                                    mem_conn, mem_key = target
                                    send_payload(mem_conn, mem_key, payload)
                        else:
                            if not validation.is_safe_username(file_to):
                                send_error(conn, aes_key, "Invalid recipient username.")
                                continue
                            forward_payload(file_to, payload)
            except Exception as e:
                print(f"Decryption error: {e}")

    except Exception as e:
        print(f"Client handler stopped: {e}")
    finally:
        with state_lock:
            if username in clients and clients[username][0] is conn:
                del clients[username]
        broadcast_user_list()
        conn.close()


def generate_keys() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def main(generate_keys_flag: bool = False) -> None:
    if generate_keys_flag:
        generate_keys()
        return
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        generate_keys()

    IP = os.getenv("IP_ADDRESS", "127.0.0.1")
    PORT = int(os.getenv("PORT", "12345"))

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((IP, PORT))

    server.listen(5)
    print(f"Server started on {IP}:{PORT}")

    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = f.read()

    while True:
        conn, _ = server.accept()

        conn.sendall(struct.pack(">I", len(public_key)) + public_key)
        threading.Thread(target=handle_client, args=(
            conn, private_key), daemon=True).start()


if __name__ == "__main__":
    import sys
    main("--gen-keys" in sys.argv)
