# PQC Dual USB Library

[![PyPI version](https://badge.fury.io/py/pqcdualusb.svg)](https://badge.fury.io/py/pqcdualusb)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Post-Quantum](https://img.shields.io/badge/Security-Post--Quantum-red.svg)](https://en.wikipedia.org/wiki/Post-quantum_cryptography)
[![GitHub stars](https://img.shields.io/github/stars/Johnsonajibi/PostQuantum-DualUSB-Token-Library.svg)](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/stargazers)
[![Downloads](https://pepy.tech/badge/pqcdualusb)](https://pepy.tech/project/pqcdualusb)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/Coverage-90%25-brightgreen.svg)]()

A comprehensive **Python library** for post-quantum cryptographic dual USB backup operations with advanced hardware security features and side-channel attack countermeasures.

> **📚 This is a library package** designed to be imported into your applications. It provides a set of functions to manage secure backups.

## 📋 Overview

The **PQC Dual USB Library** provides a robust, enterprise-grade solution for securing data against threats from both classical and quantum computers. It offers a functional API for developers to integrate post-quantum cryptography (PQC) into applications requiring secure data storage, especially for scenarios involving redundant backups on physical devices like USB drives.

The library is designed with a "secure-by-default" philosophy, automatically handling complex security operations like side-channel attack mitigation, secure memory management, and hybrid cryptographic schemes.

### Quick Import Example

```python
import os
from pathlib import Path
from pqcdualusb.storage import init_dual_usb, rotate_token, verify_dual_setup
from pqcdualusb.backup import restore_from_backup
from pqcdualusb.pqc import pq_write_audit_keys

# Use these functions to build your backup workflow.
# See the Quick Start Guide below for a detailed example.
```

## 🏛️ Architectural Vision

The core architecture is designed to be modular, extensible, and secure. It abstracts the complexity of cryptographic backends and hardware interactions, providing a clean and simple functional API to the application layer.

### High-Level Architecture

The library is composed of several focused modules that work together:

-   **`storage.py`**: Manages the state of the primary drive and orchestrates high-level operations like initialization and key rotation.
-   **`backup.py`**: Handles the creation and restoration of encrypted backup files.
-   **`crypto.py`**: Contains all core classical cryptographic logic, including key derivation (Argon2id) and authenticated encryption (AES-GCM).
-   **`pqc.py`**: Manages all Post-Quantum Cryptography operations (key generation, signing) using available backends.
-   **`device.py`**: Provides helper functions to validate device paths and check their properties (e.g., if they are removable).
-   **`audit.py`**: Implements a secure, structured logging system for all critical security events.
-   **`cli.py`**: Provides a reference implementation of a command-line interface that demonstrates how to use the library's functions.

### PQC Backend Selection Logic

The library prioritizes performance and security by intelligently selecting the best available Post-Quantum Cryptography backend. This flowchart illustrates the decision-making process.

```mermaid
graph TD
    A["Start: PostQuantumCrypto.__init__"] --> B{"Rust PQC Backend Available?"};
    B -- Yes --> C["Set Backend = 'rust_pqc'"];
    B -- No --> D{"python-oqs Backend Available?"};
    D -- Yes --> E["Set Backend = 'oqs'"];
    D -- No --> F["Raise RuntimeError: 'No PQC backend found'"];
    C --> G["End: Ready for PQC Ops"];
    E --> G;
```

## 🌟 Key Features

### Cryptographic Security
- **Post-Quantum Cryptography**: NIST-standardized Kyber1024 (KEM) and Dilithium3 (signatures).
- **Hybrid Encryption**: Combines classical AES-256-GCM with post-quantum key encapsulation for robust, dual-layer protection.
- **Power Analysis Protection**: Built-in software countermeasures (instruction jitter, random delays) to obfuscate power consumption patterns and mitigate side-channel attacks.
- **Secure Key Derivation**: Uses Argon2id, a memory-hard function, to stretch user passphrases and resist brute-force attacks.

### Hardware & Memory Security
- **Dual USB Backup**: Manages redundant, secure storage across multiple USB devices.
- **Device Validation**: Functions to verify that provided paths are on distinct, removable devices.
- **Secure Memory Management**: Automatically zeroes out memory that held sensitive data (keys, plaintexts) to prevent data leakage.
- **Timing Attack Mitigation**: Employs constant-time comparison operations where possible to prevent attackers from inferring secret data through timing variations.

## 🛡️ Threat Model and Security Guarantees

This library is designed to protect against a range of threats, from common software vulnerabilities to sophisticated nation-state-level attacks.

### Attack Vectors Considered
- **Quantum Attacks**: An adversary with a large-scale quantum computer attempting to break public-key cryptography.
    - **Mitigation**: **Hybrid Encryption**. The use of Kyber1024 ensures that even if classical algorithms are broken, the encapsulated key remains secure.
- **Side-Channel Attacks**: Timing attacks and power analysis.
    - **Mitigation**: Constant-time operations for critical comparisons and software-based countermeasures like instruction jitter and randomized dummy operations.
- **Physical Access Attacks**: Cold boot attacks or theft of USB drives.
    - **Mitigation**: **Secure Memory Wiping** and strong, multi-layered encryption. Data on the drives is useless without the user's passphrase.

### Limitations
- This library cannot protect against keyloggers, screen-capture malware, or other compromises of the host operating system. The security of the overall system depends on the security of the environment in which it runs.

## 🗺️ Roadmap

This project is under active development. Our goals for the near future include:

### Q4 2025
- **[Feature] High-Level `BackupManager` Class**:
    - Implement an optional `BackupManager` class to provide a simpler, high-level API for orchestrating dual-drive backups.
- **[Security] External Security Audit**:
    - Engage a third-party security firm to perform a full audit of the cryptographic and security-sensitive code.
- **[CI/CD] Automated PyPI Publishing**:
    - Set up GitHub Actions to automatically build and publish new releases to PyPI upon tagging.

### Q1 2026
- **[Feature] Hardware Security Module (HSM) Support**:
    - Add an abstraction layer to support storing PQC keys on HSMs (e.g., YubiKey, NitroKey) via a PKCS#11 interface.
- **[Performance] SIMD-Optimized Backends**:
    - Integrate official PQC implementations that use AVX2/NEON instructions for significant performance gains on supported platforms.

## 📦 Installation

### 1. Standard Installation
```bash
pip install pqcdualusb
```

### 2. Development Installation
For contributing or running tests, clone the repository and install in editable mode with development dependencies.
```bash
git clone https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library.git
cd PostQuantum-DualUSB-Token-Library
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### 3. Backend Dependencies
The library requires at least one PQC backend. The Rust backend is recommended for performance.

#### Rust PQC Backend (Recommended)
```bash
# Windows
./install_rust_windows.bat

# Linux/macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
python build_rust_pqc.py
```

#### OQS Backend (Alternative Fallback)
If the Rust backend is not available, the library will fall back to `python-oqs`.
```bash
pip install oqs
```

## 🚀 Quick Start Guide

This example demonstrates the end-to-end process of creating and managing a secure dual USB backup using the library's functions.

```python
import os
from pathlib import Path
import tempfile
import shutil

# Import the necessary functions from the library
from pqcdualusb.storage import init_dual_usb, rotate_token, verify_dual_setup
from pqcdualusb.backup import restore_from_backup
from pqcdualusb.crypto import verify_backup
from pqcdualusb.device import _is_removable_path # For mocking in this example

# --- Setup: Create temporary directories to simulate USB drives ---
# In a real application, these paths would point to your actual USB drives.
# For this example, we will mock the check for removable drives.
tmp_dir = Path(tempfile.mkdtemp(prefix="pqc_usb_test_"))
primary_path = tmp_dir / "PRIMARY"
backup_path = tmp_dir / "BACKUP"
primary_path.mkdir()
backup_path.mkdir()

print(f"Simulating drives:\n- Primary: {primary_path}\n- Backup:  {backup_path}")

# --- Core Variables ---
# A strong, unique password for encryption
passphrase = "a-very-strong-and-unique-passphrase"
# The initial secret data you want to protect
initial_secret = os.urandom(64)


# In a real scenario, you would validate the drives are removable.
# For this example, we assume they are.
# assert _is_removable_path(primary_path)
# assert _is_removable_path(backup_path)


# 1. Initialize the Dual USB Backup
print("\nStep 1: Initializing the dual USB backup...")
init_info = init_dual_usb(
    token=initial_secret,
    primary_mount=primary_path,
    backup_mount=backup_path,
    passphrase=passphrase
)
print("✅ Initialization complete.")
print(f"   - Primary token written to: {init_info['primary_token']}")
print(f"   - Encrypted backup written to: {init_info['backup_file']}")


# 2. Verify the Backup Integrity
print("\nStep 2: Verifying the backup file...")
is_valid = verify_backup(Path(init_info['backup_file']), passphrase, initial_secret)
assert is_valid
print("✅ Backup integrity verified successfully.")


# 3. Rotate the Token with a New Secret
print("\nStep 3: Rotating the token with a new secret...")
new_secret = os.urandom(64)
# The `prev_rotation` is 0 for the first rotation.
rotate_info = rotate_token(
    token=new_secret,
    primary_mount=primary_path,
    backup_mount=backup_path,
    passphrase=passphrase,
    prev_rotation=0
)
print("✅ Token rotation complete.")
print(f"   - New rotation counter: {rotate_info['rotation']}")


# 4. Verify the Complete Setup After Rotation
print("\nStep 4: Verifying the entire setup after rotation...")
# Get the latest token file from the primary drive
latest_token_path = sorted(primary_path.glob("token_*.bin"))[-1]
is_setup_valid = verify_dual_setup(
    primary_token_path=latest_token_path,
    backup_file=Path(rotate_info['backup']),
    passphrase=passphrase,
    enforce_device=False,      # Set to True in production on real hardware
    enforce_rotation=True
)
assert is_setup_valid
print("✅ Dual USB setup is consistent and valid.")


# 5. Restore from the Latest Backup
print("\nStep 5: Restoring the secret from the latest backup...")
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

## 🏛️ Detailed Architecture

This section provides a deep dive into the library's internal design, data flows, and security model.

### 1. High-Level System Architecture

The system is designed as a Python library that provides a secure, functional API to an application. It manages interactions between the host system and two physical USB drives (Primary and Backup) to store a sensitive token, ensuring redundancy and security through a split-trust model.

```mermaid
graph TD
    subgraph "Host System"
        App[Your Application] --> Lib_API{Public API Functions<br>(storage.py, backup.py)}
        
        subgraph "PQC Dual USB Library (pqcdualusb)"
            Lib_API --> Core_Modules[Core Modules<br>(crypto, pqc, device, audit)]
            Core_Modules --> Backends[Cryptographic Backends<br>(cryptography, argon2, oqs, rust_pqc)]
        end

        Lib_API --> FS_Primary[Primary USB Drive]
        Lib_API --> FS_Backup[Backup USB Drive]
    end

    subgraph "Physical Devices"
        FS_Primary -- "Stores<br>token_{rot}.bin<br>state.json" --> USB1((USB 1))
        FS_Backup -- "Stores<br>.system_backup/backup_{rot}.enc" --> USB2((USB 2))
    end

    style App fill:#cde4ff
    style Lib_API fill:#e6ffc2
    style Core_Modules fill:#fff2c2
    style Backends fill:#ffdac2
```

### 2. Detailed Component (Module) Architecture

The library is broken down into several focused modules. This promotes separation of concerns, making the system easier to maintain, test, and audit.

```mermaid
graph TD
    subgraph "Public API"
        storage["storage.py<br><i>Orchestrates all high-level operations</i>"]
        backup["backup.py<br><i>Handles backup creation and restoration</i>"]
    end

    subgraph "Internal Core Modules"
        crypto["crypto.py<br><i>Classical crypto (AES-GCM), KDF (Argon2), secure memory</i>"]
        pqc["pqc.py<br><i>Post-quantum crypto (Kyber, Dilithium), backend selection</i>"]
        device["device.py<br><i>Validates device paths and properties (removable, distinct)</i>"]
        audit["audit.py<br><i>Secure, tamper-evident logging</i>"]
        exceptions["exceptions.py<br><i>Custom exception types</i>"]
        utils["utils.py<br><i>Atomic writes and other helpers</i>"]
    end

    subgraph "External Dependencies"
        dep_crypto[cryptography]
        dep_argon[argon2-cffi]
        dep_oqs[python-oqs]
        dep_rust[Rust PQC Backend (.so/.pyd)]
        dep_psutil[psutil]
    end

    storage --> backup
    storage --> crypto
    storage --> pqc
    storage --> device
    storage --> audit
    storage --> utils

    backup --> crypto
    backup --> pqc
    backup --> audit
    backup --> utils

    crypto --> dep_crypto
    crypto --> dep_argon

    pqc -- "Prefers" --> dep_rust
    pqc -- "Falls back to" --> dep_oqs

    device --> dep_psutil
```

### 3. Data Flow Sequence Diagrams

#### 3.1. `init_dual_usb` Data Flow

This diagram shows the sequence of events when initializing the dual USB setup for the first time.

```mermaid
sequenceDiagram
    participant App as Your Application
    participant Storage as storage.py
    participant Device as device.py
    participant Backup as backup.py
    participant Crypto as crypto.py
    participant Utils as utils.py

    App->>+Storage: init_dual_usb(token, primary_mount, backup_mount, passphrase)
    Storage->>+Device: _ensure_removable_and_distinct(primary_mount, backup_mount)
    Device-->>-Storage: (Validation Success)
    
    Storage->>+Backup: write_backup(token, backup_mount, passphrase)
    Backup->>+Crypto: derive_key(passphrase)
    Crypto-->>-Backup: encryption_key
    Backup->>+Crypto: encrypt(data=token, key=encryption_key, ...)
    Crypto-->>-Backup: encrypted_package
    Backup->>+Utils: atomic_write(backup_path, encrypted_package)
    Utils-->>-Backup: (Write Success)
    Backup-->>-Storage: backup_file_path
    
    Storage->>+Utils: atomic_write(primary_token_path, token)
    Utils-->>-Storage: (Write Success)
    
    Storage->>Storage: Create state.json with rotation 0
    Storage->>+Utils: atomic_write(state_path, state_data)
    Utils-->>-Storage: (Write Success)
    
    Storage-->>-App: {primary_token, backup_file, rotation: 0}
```

#### 3.2. `rotate_token` Data Flow

This diagram illustrates the process of updating the secret token, which involves creating a new backup and then updating the primary drive.

```mermaid
sequenceDiagram
    participant App as Your Application
    participant Storage as storage.py
    participant Backup as backup.py
    participant Crypto as crypto.py
    participant Utils as utils.py

    App->>+Storage: rotate_token(new_token, ..., passphrase, prev_rotation)
    Storage->>Storage: Read state.json, verify prev_rotation
    
    Storage->>+Backup: write_backup(new_token, backup_mount, passphrase, rotation=1)
    Backup->>+Crypto: derive_key(passphrase)
    Crypto-->>-Backup: encryption_key
    Backup->>+Crypto: encrypt(data=new_token, key=encryption_key, ...)
    Crypto-->>-Backup: encrypted_package
    Backup->>+Utils: atomic_write(new_backup_path, encrypted_package)
    Utils-->>-Backup: (Write Success)
    Backup-->>-Storage: new_backup_path
    
    Storage->>+Utils: atomic_write(new_primary_token_path, new_token)
    Utils-->>-Storage: (Write Success)
    
    Storage->>Storage: Update state.json with rotation 1
    Storage->>+Utils: atomic_write(state_path, new_state_data)
    Utils-->>-Storage: (Write Success)
    
    Storage->>Storage: Remove old token and backup files
    
    Storage-->>-App: {rotation: 1, backup: new_backup_path}
```

### 4. Cryptographic Pipeline

The library uses a hybrid cryptographic model, combining classical authenticated encryption (AES-GCM) with post-quantum key encapsulation (Kyber) to derive the final encryption key.

```mermaid
graph TD
    subgraph "Inputs"
        A[User Passphrase]
        B[Per-backup Salt]
        C[Plaintext Secret]
    end

    subgraph "Key Derivation & Encapsulation"
        A -- Argon2id --> D{Derived Classical Key (DCK)}
        
        subgraph "PQC Module"
            E[PQC KEM Keypair Generation] --> F{Kyber Public Key (K_pub)}
            E --> G{Kyber Secret Key (K_sec)}
        end

        F -- Kyber KEM Encapsulate --> H{Ciphertext (CT)}
        F -- Kyber KEM Encapsulate --> I{Shared Secret 1 (SS1)}
    end

    subgraph "Hybrid Key Generation"
        D & I -- "SHA-256 KDF" --> J{Final Encryption Key (FEK)}
    end

    subgraph "Encryption & Packaging"
        C & J -- "AES-256-GCM Encrypt" --> K{Encrypted Data}
        
        F & H & K --> L((Encrypted Backup File<br><i>Contains: K_pub, CT, Encrypted Data, Salt, Nonce, Tag</i>))
    end

    G -- "Stored by user/app<br>Needed for decryption" --> M((Decryption Process))

    style L fill:#d4edda
```

### 5. File System Layout

The library creates a specific file and directory structure on the primary and backup USB drives to maintain state and store cryptographic materials securely.

```mermaid
graph LR
    subgraph "Primary USB Drive"
        direction TB
        root_p["/ (mount point)"]
        root_p --> token["token_{rotation}.bin<br><i>Raw secret data.</i>"]
        root_p --> state["state.json<br><i>{ 'rotation': 1, 'device_id': '...' }</i>"]
    end

    subgraph "Backup USB Drive"
        direction TB
        root_b["/ (mount point)"]
        root_b --> hidden_dir[".system_backup/"]
        hidden_dir --> backup_file["backup_{rotation}.enc<br><i>Encrypted secret (AES-GCM), includes PQC public key and metadata.</i>"]
    end

    subgraph "Host System (User Home)"
        direction TB
        host_root["~/"]
        host_root --> audit_key[".pqcdualusb_audit.key<br><i>HMAC key for securing the audit log.</i>"]
        host_root --> audit_log["pqcdualusb_audit.log<br><i>Append-only log of all security events.</i>"]
    end
```

### 6. Security Threat Model & Mitigations

The security of the library is built on a defense-in-depth strategy, mapping specific threats to concrete mitigation techniques implemented in the code.

```mermaid
graph TD
    subgraph "Threats"
        T1["<b>Quantum Computer Attack</b><br>An adversary uses a quantum computer to break classical public-key crypto."]
        T2["<b>Side-Channel Attack</b><br>Attacker analyzes power consumption or timing to leak secrets."]
        T3["<b>Physical Theft of Drive(s)</b><br>An attacker steals one or both USB drives."]
        T4["<b>Brute-Force on Passphrase</b><br>Attacker tries to guess the passphrase to decrypt the backup."]
        T5["<b>Data Corruption</b><br>Power loss during a write operation corrupts a file."]
        T6["<b>Memory Forensics</b><br>Attacker reads RAM (e.g., cold boot attack) to find keys."]
    end

    subgraph "Mitigations"
        M1["<b>Hybrid Encryption (crypto.py, pqc.py)</b><br>AES-GCM + Kyber1024 KEM. Even if one is broken, data remains secure."]
        M2["<b>Software Countermeasures (crypto.py)</b><br>Constant-time comparisons and secure memory wiping add noise and prevent leaks."]
        M3["<b>Authenticated Encryption (crypto.py)</b><br>AES-GCM ensures data cannot be decrypted or modified without the correct passphrase."]
        M4["<b>Key Derivation Function (crypto.py)</b><br>Argon2id is memory-hard, making brute-force computationally infeasible."]
        M5["<b>Atomic Writes (utils.py)</b><br>Files are written to a temporary location and then moved, preventing partial writes."]
        M6["<b>Secure Memory Wiping (crypto.py)</b><br>The `SecureMemory` context manager explicitly zeroes out sensitive data after use."]
    end

    T1 --> M1
    T2 --> M2
    T3 --> M3
    T4 --> M4
    T5 --> M5
    T6 --> M6
```

## 🧪 Testing

The library includes a comprehensive test suite to ensure correctness and security.

### Running Tests
```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all tests with verbose output
python -m pytest tests/ -v

# Run tests and generate a coverage report
python -m pytest tests/ --cov=pqcdualusb --cov-report=html
```

## 🤝 Contributing

Contributions are welcome! Please follow the standard fork-and-pull-request workflow.

### Development Setup
1.  Clone the repository.
2.  Create and activate a virtual environment.
3.  Install in development mode: `pip install -e ".[dev,test]"`
4.  Install pre-commit hooks: `pre-commit install`

### Code Style
-   **Formatting**: `black` and `isort`
-   **Linting**: `flake8`
-   **Type Checking**: `mypy`

The pre-commit hooks will automatically enforce the code style.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
