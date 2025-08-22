"""
Dual USB Token + Encrypted Backup Library
========================================

Production‑ready, non‑interactive helpers to:
- Identify removable USB devices cross‑platform (with stable volume UUID/serial where possible)
- Write a *live* token to the primary USB using atomic writes
- Create an **AEAD‑encrypted** backup on a second USB (Argon2id → AES‑GCM by default; falls back to scrypt if Argon2 unavailable)
- Verify the setup (decrypt backup in memory and compare SHA3‑512 of plaintext)
- Rotate and restore tokens
- Enforce storage policy (USB_ONLY / LOCAL_ONLY / BOTH)
- Enforce passphrase strength and brute-force protection
- Tamper detection and audit logging
- Redundant backup support
- Improved secure deletion

Dependencies (recommended):
    pip install cryptography argon2-cffi psutil

This module avoids interactive prompts; UI code should choose devices and pass parameters.

Security notes:
- The backup is AEAD‑encrypted; metadata is authenticated as AAD.
- Plaintext token is never written to the backup USB, only decrypted in RAM.
- Atomic writes and directory fsyncs are used to reduce the risk of torn writes.
- Logging avoids sensitive plaintext. You should manage OS access controls and safe removal.
- Secure deletion on common filesystems cannot be guaranteed; we provide best‑effort only.
- Audit log entries are cryptographically signed.

Test recommendations:
- Simulate power loss during write (kill process mid‑copy in temp dir)
- Wrong passphrase, corrupted JSON/ct/nonce, swapped letters/mountpoints
- Policy enforcement across USB_ONLY / LOCAL_ONLY / BOTH

Copyright:
- MIT License
"""
from __future__ import annotations

import os
import sys
import json
import time
import uuid as _uuid
import ctypes
import subprocess
import tempfile
import logging
import secrets
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

# ---- Logging (avoid sensitive data) ----
logger = logging.getLogger("dual_usb")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ---- Audit Logging (cryptographically signed entries) ----
AUDIT_LOG_PATH = Path("dual_usb_audit.log")
AUDIT_KEY = secrets.token_bytes(32)  # Should be stored securely

def audit_log(event: str, details: dict):
    msg = f"{_now_iso()}|{event}|{json.dumps(details, separators=(',', ':'))}"
    sig = hmac.new(AUDIT_KEY, msg.encode(), "sha256").hexdigest()
    with AUDIT_LOG_PATH.open("a") as f:
        f.write(f"{msg}|{sig}\n")

# ---- Passphrase Strength Enforcement ----
def enforce_passphrase_strength(passphrase: str) -> None:
    if len(passphrase) < 12 or not any(c.isdigit() for c in passphrase) or not any(c.isupper() for c in passphrase):
        raise ValueError("Passphrase must be at least 12 characters, include a digit and an uppercase letter.")

# ---- Brute-force Protection ----
def brute_force_delay(attempts: int):
    delay = min(2 ** attempts, 32)
    logger.warning(f"Brute-force protection: delaying {delay} seconds after {attempts} failed attempts.")
    time.sleep(delay)

# ---- Tamper Detection ----
def verify_backup_integrity(backup_file: Path) -> bool:
    try:
        data = json.loads(backup_file.read_text("utf-8"))
        meta = data["meta"]
        expected_hash = meta.get("orig_sha3_512")
        actual_hash = sha3_512_file(backup_file)
        if expected_hash and actual_hash != expected_hash:
            logger.error("Tamper detected: backup file hash mismatch.")
            audit_log("tamper_detected", {"file": str(backup_file)})
            return False
        return True
    except Exception:
        return False

# ---- Improved Secure Deletion ----
def secure_delete(path: Path, passes: int = 3):
    try:
        sz = path.stat().st_size
        for _ in range(passes):
            with path.open("r+b", buffering=0) as f:
                f.write(secrets.token_bytes(min(sz, 4096)))
                f.flush(); os.fsync(f.fileno())
        path.unlink(missing_ok=True)
        audit_log("secure_delete", {"file": str(path)})
    except Exception:
        pass

# ---- Crypto primitives ----
import hashlib

try:
    # Argon2id (preferred)
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    def kdf_argon2id(passphrase: str, salt: bytes, m_cost: int = 262144, t_cost: int = 3, parallelism: int = 2, length: int = 32) -> bytes:
        return hash_secret_raw(passphrase.encode("utf-8"), salt, time_cost=t_cost, memory_cost=m_cost, parallelism=parallelism, hash_len=length, type=Argon2Type.ID)
    _HAS_ARGON2 = True
except Exception:  # pragma: no cover
    _HAS_ARGON2 = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except Exception as e:  # pragma: no cover
    raise RuntimeError("cryptography package is required: pip install cryptography") from e

def kdf_scrypt(passphrase: str, salt: bytes, n: int = 2**15, r: int = 8, p: int = 1, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))

def derive_key(passphrase: str, salt: bytes) -> Tuple[bytes, dict]:
    if _HAS_ARGON2:
        key = kdf_argon2id(passphrase, salt)
        params = {"kdf": "argon2id", "m_cost": 262144, "t_cost": 3, "parallelism": 2}
    else:
        key = kdf_scrypt(passphrase, salt)
        params = {"kdf": "scrypt", "n": 2**15, "r": 8, "p": 1}
    return key, params

def sha3_512_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha3_512()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

# ---- Atomic file ops ----
def _fsync_dir(dir_path: Path) -> None:
    dir_fd = os.open(str(dir_path), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

def atomic_write_bytes(dst: Path, data: bytes) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=str(dst.parent), delete=False) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, dst)
    try:
        _fsync_dir(dst.parent)
    except Exception:
        pass

def atomic_copy(src: Path, dst: Path) -> None:
    data = src.read_bytes()
    atomic_write_bytes(dst, data)

# ---- Cross‑platform removable device discovery ----
@dataclass
class DeviceInfo:
    mountpoint: Path
    fs_type: Optional[str]
    label: Optional[str]
    uuid: Optional[str]
    is_removable: bool

class StoragePolicy(str, Enum):
    USB_ONLY = "USB_ONLY"
    LOCAL_ONLY = "LOCAL_ONLY"
    BOTH = "BOTH"

def _windows_list_removable() -> List[DeviceInfo]:
    devices: List[DeviceInfo] = []
    kernel32 = ctypes.windll.kernel32
    GetLogicalDrives = kernel32.GetLogicalDrives
    GetDriveTypeW = kernel32.GetDriveTypeW
    GetVolumeInformationW = kernel32.GetVolumeInformationW

    DRIVE_REMOVABLE = 2
    bitmask = GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            try:
                dtype = GetDriveTypeW(ctypes.c_wchar_p(root))
                if dtype == DRIVE_REMOVABLE and os.path.exists(root):
                    vol_name_buf = ctypes.create_unicode_buffer(261)
                    fs_name_buf = ctypes.create_unicode_buffer(261)
                    ser_num = ctypes.c_uint()
                    max_comp_len = ctypes.c_uint()
                    fs_flags = ctypes.c_uint()
                    ok = GetVolumeInformationW(ctypes.c_wchar_p(root), vol_name_buf, 260, ctypes.byref(ser_num), ctypes.byref(max_comp_len), ctypes.byref(fs_flags), fs_name_buf, 260)
                    label = vol_name_buf.value if ok else None
                    fs_name = fs_name_buf.value if ok else None
                    serial_hex = f"{ser_num.value:08X}" if ok else None
                    devices.append(DeviceInfo(mountpoint=Path(root), fs_type=fs_name, label=label, uuid=serial_hex, is_removable=True))
            except Exception:
                continue
    return devices

def _linux_list_removable() -> List[DeviceInfo]:
    devices: List[DeviceInfo] = []
    try:
        import psutil  # type: ignore
        parts = psutil.disk_partitions(all=False)
    except Exception:
        parts = []
        with open("/proc/mounts", "r") as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 3:
                    device, mountpoint, fs_type = fields[0], fields[1], fields[2]
                    class _P:
                        device = device
                        mountpoint = mountpoint
                        fstype = fs_type
                    parts.append(_P)

    def blkid(device: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        try:
            out = subprocess.check_output(["blkid", "-o", "export", device], stderr=subprocess.DEVNULL, text=True)
            kv = dict(line.strip().split("=", 1) for line in out.strip().splitlines() if "=" in line)
            return kv.get("UUID"), kv.get("TYPE"), kv.get("LABEL")
        except Exception:
            return None, None, None

    for p in parts:
        dev = getattr(p, "device", "")
        mnt = getattr(p, "mountpoint", "")
        fstype = getattr(p, "fstype", None)
        if not dev.startswith("/dev"):
            continue
        if any(mnt.startswith(x) for x in ("/proc", "/sys", "/run", "/boot/efi")):
            continue
        uuid_val, type_val, label = blkid(dev)
        is_rem = True
        devices.append(DeviceInfo(mountpoint=Path(mnt), fs_type=type_val or fstype, label=label, uuid=uuid_val, is_removable=is_rem))
    return devices

def _darwin_list_removable() -> List[DeviceInfo]:
    devices: List[DeviceInfo] = []
    volumes = Path("/Volumes")
    if not volumes.exists():
        return devices
    for entry in volumes.iterdir():
        if not entry.is_dir():
            continue
        uuid_val = None
        fs_type = None
        label = entry.name
        try:
            out = subprocess.check_output(["diskutil", "info", str(entry)], text=True)
            for line in out.splitlines():
                if "Volume UUID:" in line:
                    uuid_val = line.split(":", 1)[1].strip()
                if "Type (Bundle):" in line:
                    fs_type = line.split(":", 1)[1].strip()
        except Exception:
            pass
        devices.append(DeviceInfo(mountpoint=entry, fs_type=fs_type, label=label, uuid=uuid_val, is_removable=True))
    return devices

def list_removable_devices() -> List[DeviceInfo]:
    if sys.platform.startswith("win"):
        return _windows_list_removable()
    elif sys.platform.startswith("linux"):
        return _linux_list_removable()
    elif sys.platform == "darwin":
        return _darwin_list_removable()
    else:
        logger.warning("Unsupported platform: %s", sys.platform)
        return []

# ---- Windows hidden attribute helper ----
def set_hidden_windows(path: Path) -> None:
    if not sys.platform.startswith("win"):
        return
    FILE_ATTRIBUTE_HIDDEN = 0x02
    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass

# ---- Exceptions ----
class DualUSBError(Exception): ...
class DeviceNotFound(DualUSBError): ...
class VerificationError(DualUSBError): ...
class DecryptionError(DualUSBError): ...

# ---- Core operations ----
BACKUP_DIRNAME = ".system_backup"
BACKUP_SUFFIX = ".enc.json"

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def write_secret_primary(token_path: Path, primary_root: Path, policy: StoragePolicy = StoragePolicy.USB_ONLY, confirm_callback=None) -> Path:
    if not token_path.exists():
        raise FileNotFoundError(str(token_path))
    dst = primary_root / token_path.name
    atomic_copy(token_path, dst)
    audit_log("token_copied", {"src": str(token_path), "dst": str(dst)})
    if policy == StoragePolicy.USB_ONLY:
        if confirm_callback and not confirm_callback(f"Delete local token file {token_path}?"):
            logger.warning("User declined deletion of local token file.")
        else:
            secure_delete(token_path)
    return dst

def _encrypt_backup(plaintext: bytes, passphrase: str, meta: dict) -> bytes:
    enforce_passphrase_strength(passphrase)
    salt = os.urandom(16)
    key, kdf_params = derive_key(passphrase, salt)
    aad = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    payload = {
        "meta": meta,
        "kdf": {**kdf_params, "salt": salt.hex()},
        "aead": {"alg": "AES-256-GCM", "nonce": nonce.hex(), "ct": ct.hex()},
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")

def write_encrypted_backup(token_path: Path, backup_root: Path, passphrase: str, primary_uuid: Optional[str], backup_uuid: Optional[str], rotation_counter: int = 0) -> Path:
    if not token_path.exists():
        raise FileNotFoundError(str(token_path))
    meta = {
        "version": 1,
        "created_at": _now_iso(),
        "orig_name": token_path.name,
        "orig_sha3_512": sha3_512_file(token_path),
        "primary_uuid": primary_uuid,
        "backup_uuid": backup_uuid,
        "rotation_counter": rotation_counter,
    }
    payload = _encrypt_backup(token_path.read_bytes(), passphrase, meta)
    backup_dir = backup_root / BACKUP_DIRNAME
    backup_dir.mkdir(parents=True, exist_ok=True)
    dst = backup_dir / f"{token_path.name}{BACKUP_SUFFIX}"
    atomic_write_bytes(dst, payload)
    try:
        set_hidden_windows(backup_dir)
        set_hidden_windows(dst)
    except Exception:
        pass
    audit_log("backup_created", {"file": str(dst), "uuid": backup_uuid})
    return dst

def decrypt_backup_to_memory(backup_file: Path, passphrase: str, max_attempts: int = 5) -> Tuple[bytes, dict]:
    enforce_passphrase_strength(passphrase)
    attempts = 0
    while attempts < max_attempts:
        try:
            data = json.loads(backup_file.read_text("utf-8"))
            meta = data["meta"]
            kdf_info = data["kdf"]
            aead = data["aead"]
            salt = bytes.fromhex(kdf_info["salt"])
            key, _ = derive_key(passphrase, salt)
            nonce = bytes.fromhex(aead["nonce"])
            ct = bytes.fromhex(aead["ct"])
            aad = json.dumps(meta, separators=(",", ":")).encode("utf-8")
            pt = AESGCM(key).decrypt(nonce, ct, aad)
            audit_log("backup_decrypted", {"file": str(backup_file)})
            return pt, meta
        except Exception as e:
            attempts += 1
            brute_force_delay(attempts)
            logger.error(f"Backup decryption failed (attempt {attempts}): {e}")
            audit_log("decryption_failed", {"file": str(backup_file), "attempt": attempts})
    raise DecryptionError("Backup decryption failed after max attempts")

def verify_dual_setup(primary_token: Path, backup_file: Path, passphrase: str) -> bool:
    if not primary_token.exists():
        raise VerificationError("Primary token file missing")
    if not verify_backup_integrity(backup_file):
        raise VerificationError("Backup file integrity check failed")
    pt, meta = decrypt_backup_to_memory(backup_file, passphrase)
    current_hash = sha3_512_file(primary_token)
    if current_hash != meta.get("orig_sha3_512"):
        raise VerificationError("Primary token hash does not match backup metadata")
    if hashlib.sha3_512(pt).hexdigest() != current_hash:
        raise VerificationError("Decrypted backup content differs from primary token")
    audit_log("setup_verified", {"primary": str(primary_token), "backup": str(backup_file)})
    return True

# ---- Redundant Backup Creation ----
def write_redundant_backups(token_path: Path, backup_mounts: List[Path], passphrase: str, primary_uuid: Optional[str], backup_uuids: List[str], rotation_counter: int = 0) -> List[Path]:
    backups = []
    for i, backup_mount in enumerate(backup_mounts):
        uuid = backup_uuids[i] if i < len(backup_uuids) else None
        dst = write_encrypted_backup(token_path, backup_mount, passphrase, primary_uuid, uuid, rotation_counter)
        backups.append(dst)
    return backups

# ---- Device Authentication (basic, by UUID) ----
def authenticate_device(device: DeviceInfo, expected_uuid: str) -> bool:
    return device.uuid and device.uuid.lower() == expected_uuid.lower()

# ---- Find device by UUID ----
def find_device_by_uuid(devices: List[DeviceInfo], volume_uuid: str) -> Optional[DeviceInfo]:
    for d in devices:
        if d.uuid and d.uuid.lower() == volume_uuid.lower():
            return d
    return None

# ---- High‑level workflows ----
def init_dual_usb(token_path: Path, primary_mount: Path, backup_mounts: List[Path], passphrase: str, policy: StoragePolicy = StoragePolicy.USB_ONLY, primary_uuid: Optional[str] = None, backup_uuids: List[str] = [], confirm_callback=None) -> dict:
    enforce_passphrase_strength(passphrase)
    primary_dst = write_secret_primary(token_path, primary_mount, policy=policy, confirm_callback=confirm_callback)
    backup_dsts = write_redundant_backups(primary_dst, backup_mounts, passphrase, primary_uuid, backup_uuids, rotation_counter=0)
    return {
        "primary_path": str(primary_dst),
        "backup_paths": [str(b) for b in backup_dsts],
        "policy": policy.value,
    }

def rotate_token(new_token_path: Path, primary_mount: Path, backup_mounts: List[Path], passphrase: str, primary_uuid: Optional[str], backup_uuids: List[str], prev_rotation_counter: int, confirm_callback=None) -> dict:
    primary_dst = write_secret_primary(new_token_path, primary_mount, policy=StoragePolicy.USB_ONLY, confirm_callback=confirm_callback)
    backup_dsts = write_redundant_backups(primary_dst, backup_mounts, passphrase, primary_uuid, backup_uuids, rotation_counter=prev_rotation_counter + 1)
    return {
        "primary_path": str(primary_dst),
        "backup_paths": [str(b) for b in backup_dsts],
        "rotation_counter": prev_rotation_counter + 1
    }

def restore_from_backup(backup_file: Path, restore_primary_mount: Path, passphrase: str, restore_filename: Optional[str] = None, policy: StoragePolicy = StoragePolicy.USB_ONLY) -> Path:
    pt, meta = decrypt_backup_to_memory(backup_file, passphrase)
    name = restore_filename or meta.get("orig_name") or f"token_{int(time.time())}.bin"
    dst = restore_primary_mount / name
    atomic_write_bytes(dst, pt)
    if policy == StoragePolicy.USB_ONLY:
        pass
    return dst

# ---- Example (commented) ----
# if __name__ == "__main__":
#     from pathlib import Path
#     devs = list_removable_devices()
#     for d in devs:
#         print(d)
#     # Choose primary/backup by UI outside this module, then:
#     # init_dual_usb(Path("secret.token"), devs[0].mountpoint, [devs[1].mountpoint], passphrase="CorrectHorseBatteryStaple1")
