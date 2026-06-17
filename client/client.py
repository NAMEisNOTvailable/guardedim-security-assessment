import base64
import datetime
import json
import os
import socket
import struct
import threading
from pathlib import Path

from dotenv import load_dotenv

from common import encryption, validation

load_dotenv()

MEDIA_ROOT = Path("chat_media").resolve()


def safe_path_part(value: str | None, fallback: str) -> str:
    return validation.safe_path_part(value, fallback)


def safe_filename(value: str | None) -> str:
    return validation.safe_filename(value)


def build_receive_path(username: str, sender: str | None, filename: str) -> Path:
    user_part = safe_path_part(username, "unknown_user")
    sender_part = safe_path_part(sender, "unknown_sender")
    save_dir = MEDIA_ROOT / f"user_{user_part}" / f"from_{sender_part}"
    save_path = (save_dir / safe_filename(filename)).resolve()

    if not save_path.is_relative_to(MEDIA_ROOT):
        raise ValueError("Resolved file path escapes chat media directory.")
    return save_path


class ChatClient:
    def __init__(self, username: str, on_message_received, on_user_list: list) -> None:
        self.username = username
        self.aes_key = encryption.generate_aes_key()
        self.conn = None
        self.on_message_received = on_message_received
        self.on_user_list = on_user_list
        self.session_token = None

    def connect(self) -> None:
        if not validation.is_safe_username(self.username):
            raise ValueError("Username must be 1-32 chars: letters, numbers, dot, underscore, or hyphen.")

        IP = os.getenv("IP_ADDRESS", "127.0.0.1")
        PORT = int(os.getenv("PORT", "12345"))

        self.conn = socket.create_connection((IP, PORT))
        public_key_bytes = self.conn.recv(4096)
        encrypted_key = encryption.rsa_encrypt_key(
            public_key_bytes, self.aes_key)

        self.conn.sendall(encrypted_key)
        self.conn.sendall(self.username.encode())

    def start_receiving(self) -> None:
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def receive_loop(self) -> None:
        conn_file = self.conn.makefile('rb')
        while True:
            try:
                header = conn_file.read(4)
                if not header:
                    print("Server closed the connection")
                    break
                msg_len = struct.unpack(">I", header)[0]
                if msg_len > encryption.MAX_FRAME_SIZE:
                    print(f"Incoming frame exceeds limit of {encryption.MAX_FRAME_SIZE} bytes.")
                    break
                data = conn_file.read(msg_len)
                if len(data) < msg_len:
                    print("Incomplete message received")
                    break

                decrypted = encryption.decrypt_message(data, self.aes_key)
                payload = json.loads(decrypted)

                match payload.get("type"):
                    case "user_list":
                        users = payload.get("users")
                        if self.on_user_list:
                            self.on_user_list(users)

                    case "login_success":
                        self.session_token = payload.get("token")

                    case "error":
                        print(f"Server error: {payload.get('message', [])}")
                        self.conn.close()
                        return

                    case "message":
                        chat_type = payload.get("from")
                        sender = payload.get("sender", chat_type)
                        message = payload.get("payload")
                        self.on_message_received(chat_type, message, sender)
                    
                    case "group_message":
                        chat_type = f"#{payload.get('to')}"
                        sender = payload.get("from")
                        message = payload.get("payload")
                        self.on_message_received(chat_type, message, sender)

                    case "group_invite":
                        group_name = payload.get("group_name")
                        display_name = f"#{group_name}"
                        self.on_message_received(
                            display_name, f"Added to {group_name}", "System")

                    case "group_created":
                        group_name = payload.get("group_name")
                        display_name = f"#{group_name}"
                        self.on_message_received(display_name, f"Group {group_name} created.", "System")

                    case "message_file" | "group_file":
                        filename = payload.get("filename")
                        encoded_data = payload.get("payload")
                        sender = payload.get("from")
                        to = payload.get("to")
                        to_type = payload.get("to_type")

                        if not filename or not encoded_data:
                            print("Missing filename or filedata in payload.")
                            break

                        try:
                            filedata = base64.b64decode(encoded_data + "===")
                        except Exception as e:
                            print("Could not decode received file:", e)
                            break

                        save_path = build_receive_path(
                            self.username, sender, filename)
                        os.makedirs(save_path.parent, exist_ok=True)

                        try:
                            with open(save_path, 'wb') as f:
                                f.write(filedata)
                        except Exception as e:
                            print("Could not save received file:", e)
                            break
                        chat_target = f"#{to}" if to_type == "group" else sender
                        self.on_message_received(
                            chat_target, f"Received: {filename} from {sender}", "System")

                    case _:
                        print("Unknown message type from server.")
            except OSError:
                break
            except Exception as e:
                print("Error in receive loop:", e)
                continue

    def send_encrypted(self, payload: str) -> None:
        encrypted = encryption.encrypt_message(payload, self.aes_key)
        length_prefix = struct.pack(">I", len(encrypted))
        self.conn.sendall(length_prefix + encrypted)

    def send_group_message(self, to_group: str, message: str) -> bool:
        group_name = to_group.lstrip("#")
        if not validation.is_safe_group_name(group_name):
            self.on_message_received("System", "Invalid group name.")
            return False

        payload = json.dumps({
            "type": "group_message",
            "from": self.username,
            "to": group_name,
            "to_type": "group",
            "payload": message,
            "payload_type": "text",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
        })

        if not encryption.check_message_size(payload):
            self.on_message_received(
                "System", f"Message too long. Limit is {encryption.MAX_MESSAGE_SIZE} bytes.")
            return False

        self.send_encrypted(payload)
        return True

    def send_message(self, to_user: str, message: str) -> bool:
        if not validation.is_safe_username(to_user):
            self.on_message_received("System", "Invalid recipient username.")
            return False

        payload = json.dumps({
            "type": "message",
            "from": self.username,
            "to": to_user,
            "to_type": "user",
            "payload": message,
            "payload_type": "text",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            })

        if not encryption.check_message_size(payload):
            self.on_message_received(
                "System", f"Message too long. Limit is {encryption.MAX_MESSAGE_SIZE} bytes.")
            return False

        self.send_encrypted(payload)
        return True

    def create_group(self, group_name: str, members: list[str]) -> bool:
        if not validation.is_safe_group_name(group_name):
            self.on_message_received("System", "Invalid group name.")
            return False
        if not all(validation.is_safe_username(member) for member in members):
            self.on_message_received("System", "Invalid group member username.")
            return False

        payload = json.dumps({
            "type": "create_group",
            "from": self.username,
            "group_name": group_name,
            "members": members,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z" 
        })

        self.send_encrypted(payload)
        return True

    def send_file(self, to_user: str, file_path: str) -> bool:
        filename = os.path.basename(file_path)

        if not validation.is_safe_username(to_user):
            self.on_message_received("System", "Invalid recipient username.")
            return False

        if not validation.is_safe_transfer_filename(filename):
            self.on_message_received(
                "System", f"Blocked dangerous file: {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                file = f.read()
                encoded_file = base64.b64encode(file).decode('utf-8')

            payload = json.dumps({
                "type": "message_file",
                "from": self.username,
                "to": to_user,
                "to_type": "user",
                "payload": encoded_file,
                "payload_type": "file",
                "filename": filename,
                "payload_id": None,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            })

            if not encryption.check_file_size(encoded_file):
                self.on_message_received(
                    "System", f"File too large. Limit is {encryption.MAX_FILE_SIZE} bytes.")
                return False

            self.send_encrypted(payload)
            self.on_message_received(
                "System", f"Sent {os.path.basename(file_path)} to {to_user}")
            return True
        except Exception as e:
            self.on_message_received("System", f"Could not upload file: {e}")
            return False

    def send_group_file(self, to_group:str, file_path:str) -> bool:
        group_name = to_group.lstrip("#")
        filename = os.path.basename(file_path)

        if not validation.is_safe_group_name(group_name):
            self.on_message_received("System", "Invalid group name.")
            return False

        if not validation.is_safe_transfer_filename(filename):
            self.on_message_received(
                "System", f"Blocked dangerous file: {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                file = f.read()
                encoded_file = base64.b64encode(file).decode('utf-8')

            payload = json.dumps({
                "type": "group_file",
                "from": self.username,
                "to": group_name,
                "to_type": "group",
                "payload": encoded_file,
                "payload_type": "file",
                "filename": filename,
                "payload_id": None,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            })

            if not encryption.check_file_size(encoded_file):
                self.on_message_received(
                    "System", f"File too large. Limit is {encryption.MAX_FILE_SIZE} bytes.")
                return False

            self.send_encrypted(payload)
            self.on_message_received(
                "System", f"Sent {os.path.basename(file_path)} to {to_group}")
            return True
        except Exception as e:
            self.on_message_received("System", f"Could not upload file: {e}")
            return False

    def disconnect(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception as e:
            print("Error disconnecting: ", e)
