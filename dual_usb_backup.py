"""
pqcdualusb.py
=============================

A single-file, runnable version of the PQC Dual USB Token + Encrypted Backup library (ASCII-only).

- USB-only: plaintext token bytes are written only to the primary USB mount.
- Encrypted backup: Argon2id (or scrypt fallback) -> AES-GCM with authenticated metadata.
- Atomic writes + directory fsync.
- Tamper-evident audit log: HMAC-SHA256 chain persisted to ~/.dual_usb_audit.key and dual_usb_audit.log.
- Device binding: stores & checks device identifier (UUID/label/fs/model when available) to detect cloned/copy USBs.
- Rollback protection: per-primary monotonic rotation counter with HMAC over all state fields.
- Strict removable-only enforcement in CLI.
- PQC audit signing (Dilithium via python-oqs) now defaults to ON when a key is present (dual-sign: HMAC + PQ).
- CLI included (init/verify/rotate/restore; verify supports --enforce-device, --no-enforce-rotation, --pq-audit-pk).
- Tests included (run this file with no args to execute tests). PQ tests auto-skip if oqs is unavailable.

Usage:
    python pqcdualusb.py --help   # CLI
    python pqcdualusb.py          # runs tests
"""
from __future__ import annotations

import os
import sys
import json
import time
import tempfile
import subprocess
import shutil
import logging
import hashlib
import hmac
import secrets
import platform
import threading
import mmap
import ctypes
import atexit
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, Dict, List, Union, Any
from contextlib import contextmanager

# ------------- Logging -------------
logger = logging.getLogger("dual_usb")
if not logger.handlers:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# ------------- Crypto deps -------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.exceptions import InvalidTag
except Exception as e:  # pragma: no cover
    raise RuntimeError("cryptography is required: pip install cryptography") from e

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    HAS_ARGON2 = True
except Exception:  # pragma: no cover
    HAS_ARGON2 = False

# Optional PQC (Dilithium) for audit signing
try:  # pragma: no cover (depends on environment)
    import oqs  # type: ignore
    HAS_OQS = True
except Exception:
    HAS_OQS = False

# ------------- Project imports -------------
from pqcdualusb.security import (
    SecureMemory,
    SecurityConfig,
    InputValidator,
    TimingAttackMitigation,
    secure_zero_memory,
)
from pqcdualusb.utils import (
    ProgressReporter,
    AuditLogRotator,
    secure_temp_file,
)
from pqcdualusb.usb import UsbDriveDetector
from pqcdualusb.pqc import (
    pq_available,
    pq_generate_keypair,
    pq_write_audit_keys,
    pq_enable_audit_signing,
    pq_sign,
    pq_verify,
)
from pqcdualusb.crypto import (
    _derive_key,
    _encrypt_backup,
    verify_backup,
)
from pqcdualusb.backup import (
    write_backup,
    _read_backup_meta,
    restore_from_backup,
)
from pqcdualusb.storage import (
    _atomic_write,
    _fsync_dir,
    _state_load,
    _state_save,
    _state_mac,
    _state_path,
    write_token_primary,
    verify_primary_binding,
    rotate_token,
    init_dual_usb,
    verify_dual_setup,
)
from pqcdualusb.audit import (
    _audit,
    verify_audit_log,
)
from pqcdualusb.device import (
    _device_id_for_path,
    _is_removable_path,
    list_usb_drives,
    select_usb_drive,
)
from pqcdualusb.exceptions import CliUsageError
from pqcdualusb.cli import _ensure_removable_and_distinct, cli

# ------------- CLI -------------
__version__ = "0.1.0"

if __name__ == "__main__":
    cli()