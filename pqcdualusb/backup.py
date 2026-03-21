"""
Backup Operations Module
========================

Dual USB backup operations with post-quantum cryptography.

Provides secure backup and restore functionality across two USB devices
with quantum-resistant encryption and integrity verification.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from .crypto import _encrypt_backup
from .device import _device_id_for_path, _is_removable_path
from .storage import _atomic_write
from .audit import _audit
from .utils import ProgressReporter

BACKUP_DIR = ".system_backup"
BACKUP_SUFFIX = ".enc.json"

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def write_backup(token: bytes, passphrase: str, backup_root: Path, rotation: int = 0, progress_callback: Optional[ProgressReporter] = None) -> Path:
    """Write encrypted backup with optional progress reporting."""
    dev = _device_id_for_path(backup_root)
    if not _is_removable_path(backup_root):
        raise RuntimeError("Backup path does not appear to be a removable device")
    
    if progress_callback is None:
        progress_callback = ProgressReporter(description="Writing backup")
    
    progress_callback.set_total(len(token) + 1024)  # Approximate total for encryption overhead
    
    meta = {"sha3": hashlib.sha3_512(token).hexdigest(), "created_at": _now_iso(), "rotation": rotation, "backup_device": dev}
    
    progress_callback.update(len(token) // 2)  # Report progress during encryption
    payload = _encrypt_backup(token, passphrase, meta)
    
    progress_callback.update(len(token) // 2)  # Report remaining progress
    dst = backup_root / BACKUP_DIR / f"token{BACKUP_SUFFIX}"
    _atomic_write(dst, payload)
    
    progress_callback.finish()
    _audit("backup_written", {"file": str(dst), "device": dev})
    return dst

def _read_backup_meta(backup_file: Path) -> dict:
    data = json.loads(backup_file.read_text("utf-8"))
    return data.get("meta", {})

def _validate_backup_schema(data: dict) -> None:
    """Validate backup JSON structure before accessing nested keys."""
    required: dict = {"meta": dict, "aead": dict, "kdf": dict}
    for field, expected_type in required.items():
        if field not in data:
            raise ValueError(f"Invalid backup format: missing required field '{field}'")
        if not isinstance(data[field], expected_type):
            raise ValueError(f"Invalid backup format: field '{field}' must be an object")

    aead_fields = {"nonce": str, "ct": str}
    for field, expected_type in aead_fields.items():
        if field not in data["aead"]:
            raise ValueError(f"Invalid backup format: missing 'aead.{field}'")
        if not isinstance(data["aead"][field], expected_type):
            raise ValueError(f"Invalid backup format: 'aead.{field}' must be a string")

    if "salt" not in data["kdf"]:
        raise ValueError("Invalid backup format: missing 'kdf.salt'")
    if not isinstance(data["kdf"]["salt"], str):
        raise ValueError("Invalid backup format: 'kdf.salt' must be a string")


def restore_from_backup(backup_file: Path, restore_primary: Path, passphrase: str) -> tuple[Path, Path]:
    from .storage import write_token_primary  # Defer import to avoid cycle
    from .crypto import _derive_key_with_stored_params
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        data = json.loads(backup_file.read_text("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Backup file is not valid JSON: {e}") from e

    _validate_backup_schema(data)

    meta = data["meta"]
    aead = data["aead"]
    kdf_params = data["kdf"]
    try:
        salt = bytes.fromhex(kdf_params["salt"])
        nonce = bytes.fromhex(aead["nonce"])
        ct = bytes.fromhex(aead["ct"])
    except ValueError as e:
        raise ValueError(f"Backup file contains invalid hex data: {e}") from e

    key = _derive_key_with_stored_params(passphrase, salt, kdf_params)
    pt = AESGCM(key).decrypt(nonce, ct, json.dumps(meta, separators=(",", ":")).encode())
    return write_token_primary(pt, restore_primary)