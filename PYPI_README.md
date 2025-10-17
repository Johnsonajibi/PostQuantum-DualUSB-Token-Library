# PQC Dual USB Library

[![PyPI version](https://badge.fury.io/py/pqcdualusb.svg)](https://badge.fury.io/py/pqcdualusb)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Post-Quantum](https://img.shields.io/badge/Security-Post--Quantum-red.svg)](https://en.wikipedia.org/wiki/Post-quantum_cryptography)
[![Downloads](https://pepy.tech/badge/pqcdualusb)](https://pepy.tech/project/pqcdualusb)

A comprehensive **Python library** for post-quantum cryptographic dual USB backup operations with advanced hardware security features and side-channel attack countermeasures.

> **📚 This is a library package** designed to be imported into your applications. It provides a set of functions to manage secure backups. For the full documentation, architecture, and contribution guidelines, please visit the [GitHub Repository](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library).

## 📋 Overview

The **PQC Dual USB Library** provides a robust, enterprise-grade solution for securing data against threats from both classical and quantum computers. It offers a functional API for developers to integrate post-quantum cryptography (PQC) into applications requiring secure data storage, especially for scenarios involving redundant backups on physical devices like USB drives.

The library is designed with a "secure-by-default" philosophy, automatically handling complex security operations like side-channel attack mitigation, secure memory management, and hybrid cryptographic schemes.

## 🌟 Key Features

-   **Post-Quantum Cryptography**: NIST-standardized Kyber1024 (KEM) and Dilithium3 (signatures) for future-proof security.
-   **Hybrid Encryption**: Combines classical AES-256-GCM with post-quantum key encapsulation for robust, dual-layer protection.
-   **Dual USB Backup**: Manages redundant, secure storage across multiple physical USB devices.
-   **Secure by Default**: Automatically handles secure memory wiping, side-channel countermeasures, and atomic file operations.
-   **Strong Key Derivation**: Uses Argon2id to protect user passphrases against brute-force attacks.
-   **Secure Audit Logging**: Creates a tamper-evident log of all critical security events.

## 📦 Installation

```bash
pip install pqcdualusb
```

The library requires at least one PQC backend. For details on setting up the recommended Rust backend or the `python-oqs` fallback, please see the [main project README](httpss://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library#backend-dependencies).

## 🚀 Quick Start Guide

This example demonstrates the end-to-end process of creating and managing a secure dual USB backup using the library's functions.

```python
import os
from pathlib import Path
import tempfile
import shutil

# Import the necessary functions from the library
from pqcdualusb.storage import init_dual_usb, rotate_token
from pqcdualusb.backup import restore_from_backup
from pqcdualusb.crypto import verify_backup

# --- Setup: Create temporary directories to simulate USB drives ---
# In a real application, these paths would point to your actual USB drives.
tmp_dir = Path(tempfile.mkdtemp(prefix="pqc_usb_test_"))
primary_path = tmp_dir / "PRIMARY"
backup_path = tmp_dir / "BACKUP"
primary_path.mkdir()
backup_path.mkdir()

print(f"Simulating drives:\n- Primary: {primary_path}\n- Backup:  {backup_path}")

# --- Core Variables ---
passphrase = "a-very-strong-and-unique-passphrase"
initial_secret = os.urandom(64)

# 1. Initialize the Dual USB Backup
print("\nStep 1: Initializing the dual USB backup...")
init_info = init_dual_usb(
    token=initial_secret,
    primary_mount=primary_path,
    backup_mount=backup_path,
    passphrase=passphrase
)
print("✅ Initialization complete.")

# 2. Verify the Backup Integrity
print("\nStep 2: Verifying the backup file...")
is_valid = verify_backup(Path(init_info['backup_file']), passphrase, initial_secret)
assert is_valid
print("✅ Backup integrity verified successfully.")

# 3. Rotate the Token with a New Secret
print("\nStep 3: Rotating the token with a new secret...")
new_secret = os.urandom(64)
rotate_info = rotate_token(
    token=new_secret,
    primary_mount=primary_path,
    backup_mount=backup_path,
    passphrase=passphrase,
    prev_rotation=0
)
print("✅ Token rotation complete.")

# 4. Restore from the Latest Backup
print("\nStep 4: Restoring the secret from the latest backup...")
restore_path = tmp_dir / "RESTORED"
restore_path.mkdir()
restored_token_path, _ = restore_from_backup(
    backup_file=Path(rotate_info['backup']),
    restore_primary=restore_path,
    passphrase=passphrase
)
# Check that the restored data matches the new secret
restored_data = restored_token_path.read_bytes()
assert restored_data == new_secret
print("✅ Restore successful. Restored data matches the new secret.")

# --- Cleanup ---
shutil.rmtree(tmp_dir)
print("\nCleanup complete.")
```

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/main/LICENSE) file for details.
