# PQC Dual USB Library - Comprehensive Architecture

This document provides a detailed overview of the architectural design of the **PQC Dual USB Library**. It is intended for developers contributing to the library or anyone interested in its internal workings, security model, and data flows.

## 1. High-Level System Architecture

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

---

## 2. Detailed Component (Module) Architecture

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

---

## 3. Data Flow Sequence Diagrams

### 3.1. `init_dual_usb` Data Flow

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

### 3.2. `rotate_token` Data Flow

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

---

## 4. Cryptographic Pipeline

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

---

## 5. File System Layout

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

---

## 6. Security Threat Model & Mitigations

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
