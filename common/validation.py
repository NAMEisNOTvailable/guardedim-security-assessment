import os
import re


USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
SAFE_PATH_PART_RE = re.compile(r"[^A-Za-z0-9._-]+")
BLOCKED_FILE_EXTENSIONS = {".exe", ".bat", ".cmd", ".msi", ".sh", ".ps1"}


def is_safe_username(value: str | None) -> bool:
    return bool(value and USERNAME_RE.fullmatch(value))


def is_safe_group_name(value: str | None) -> bool:
    return bool(value and GROUP_RE.fullmatch(value))


def safe_path_part(value: str | None, fallback: str) -> str:
    cleaned = SAFE_PATH_PART_RE.sub("_", str(value or "")).strip("._")
    return cleaned[:80] or fallback


def safe_filename(value: str | None) -> str:
    basename = os.path.basename(str(value or "").replace("\\", "/"))
    cleaned = SAFE_PATH_PART_RE.sub("_", basename).strip("._")
    return cleaned[:120] or "received_file"


def is_safe_transfer_filename(value: str | None) -> bool:
    if not value:
        return False
    raw_filename = str(value)
    if safe_filename(raw_filename) != raw_filename:
        return False
    filename = safe_filename(value)
    _, ext = os.path.splitext(filename.lower())
    return ext not in BLOCKED_FILE_EXTENSIONS
