# PQC Dual USB Library# PostQuantum DualUSB Token Library



[![PyPI version](https://badge.fury.io/py/pqcdualusb.svg)](https://badge.fury.io/py/pqcdualusb)**Enterprise-grade dual USB backup system with post-quantum cryptography protection**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)[![PyPI version](https://badge.fury.io/py/pqcdualusb.svg)](https://badge.fury.io/py/pqcdualusb)

[![Security: Post-Quantum](https://img.shields.io/badge/Security-Post--Quantum-red.svg)](https://en.wikipedia.org/wiki/Post-quantum_cryptography)[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

[![Downloads](https://pepy.tech/badge/pqcdualusb)](https://pepy.tech/project/pqcdualusb)[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Downloads](https://pepy.tech/badge/pqcdualusb)](https://pepy.tech/project/pqcdualusb)

A comprehensive **Python library** for post-quantum cryptographic dual USB backup operations with advanced hardware security features and side-channel attack countermeasures.

## What is pqcdualusb?

## What is PQC Dual USB Library?

PostQuantum DualUSB Token Library is a Python package that implements quantum-resistant dual USB token storage with advanced security features. It's designed for organizations and individuals who need maximum protection for sensitive data against both current and future quantum computing threats.

The **PQC Dual USB Library** provides a robust, enterprise-grade solution for securing data against threats from both classical and quantum computers. It offers a high-level API for developers to integrate post-quantum cryptography (PQC) into applications requiring secure data storage, especially for scenarios involving redundant backups on physical devices like USB drives.

## Why choose pqcdualusb?

The library is designed with a "secure-by-default" philosophy, automatically handling complex security operations like side-channel attack mitigation, secure memory management, and hybrid cryptographic schemes.

### 🛡️ **Quantum-Resistant Security**

## Key Features- **Post-quantum cryptography** using Dilithium digital signatures

- **Future-proof protection** against quantum computer attacks  

### Cryptographic Security- **NIST-approved algorithms** following latest standards

- **Post-Quantum Cryptography**: NIST-standardized Kyber1024 (KEM) and Dilithium3 (signatures).

- **Hybrid Encryption**: Combines classical AES-256-GCM with post-quantum key encapsulation for robust, dual-layer protection.### 🔐 **Dual USB Architecture**

- **Power Analysis Protection**: Built-in software countermeasures to mitigate side-channel attacks.- **Split secret design** - no single point of failure

- **Secure Key Derivation**: Uses Argon2id to stretch user passphrases and resist brute-force attacks.- **Physical separation** of authentication tokens

- **Hardware binding** prevents USB drive cloning

### Hardware & Memory Security

- **Dual USB Backup**: Manages redundant, secure storage across multiple USB devices.### 💎 **Enterprise Features**

- **Cross-Platform Detection**: Reliably detects removable USB drives on Windows, Linux, and macOS.- **Memory protection** with secure allocation and cleanup

- **Secure Memory Management**: Automatically zeroes out memory that held sensitive data.- **Timing attack resistance** with constant-time operations

- **Timing Attack Mitigation**: Employs constant-time comparison operations to prevent timing side-channels.- **Comprehensive audit logging** with tamper-evident chains

- **Cross-platform support** for Windows, Linux, and macOS

## Quick Start

## Quick Start

```bash

# Install the library```bash

pip install pqcdualusb# Install the library

```pip install pqcdualusb



### Python API Example# Initialize dual USB setup

pqcdualusb init --primary /media/usb1 --secondary /media/usb2

This example demonstrates the end-to-end process of securing data using the hybrid (classical + post-quantum) system.

# Create encrypted backup

```pythonpqcdualusb backup --data "sensitive.json" --passphrase "strong-passphrase"

from pqcdualusb import PostQuantumCrypto, HybridCrypto

# Restore from backup

# 1. Initialize the cryptographic componentspqcdualusb restore --backup-file backup.enc --restore-primary /media/usb_new

pqc = PostQuantumCrypto()```

hybrid = HybridCrypto()

## Python API Example

# 2. Generate a PQC keypair for the recipient

recipient_public_key, recipient_secret_key = pqc.generate_kem_keypair()```python

from pqcdualusb import init_dual_usb, verify_dual_setup

# 3. Data to be encryptedfrom pathlib import Path

sensitive_data = b"This data is protected against future quantum attacks."

passphrase = "a-very-strong-and-unique-passphrase"# Set up dual USB security

primary = Path("/media/usb_primary")

# 4. Encrypt the datasecondary = Path("/media/usb_backup")

encrypted_package = hybrid.encrypt_with_pqc(

    data=sensitive_data,success = init_dual_usb(

    passphrase=passphrase,    primary_path=primary,

    kem_public_key=recipient_public_key    secondary_path=secondary,

)    passphrase="your-secure-passphrase"

)

print("✅ Data encrypted successfully!")

if success:

# 5. Decrypt the data    print("Dual USB setup complete!")

decrypted_data = hybrid.decrypt_with_pqc(    is_valid = verify_dual_setup(primary, secondary)

    package=encrypted_package,    print(f"Setup verification: {is_valid}")

    passphrase=passphrase,```

    kem_secret_key=recipient_secret_key

)## Use Cases



assert decrypted_data == sensitive_data- **Offline password managers** with air-gapped security

print("✅ Data decrypted successfully!")- **Cryptocurrency wallet protection** with dual redundancy

```- **Enterprise key custody** solutions

- **Secure document archival** with quantum protection

## Links- **Development environments** requiring secure key storage



- **GitHub Repository & Full Documentation**: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library## Security Features

- **Issue Tracker**: Bug reports and feature requests

- **Security Policy**: Responsible disclosure process| Component | Algorithm | Quantum Resistant |

|-----------|-----------|-------------------|

## License| Encryption | AES-256-GCM | ✅ |

| Key Derivation | Argon2id | ✅ |

MIT License - see LICENSE file for details.| Digital Signatures | Dilithium | ✅ |

| Authentication | HMAC-SHA256 | ✅ |

---| Memory Protection | OS-level locking | ✅ |



**Secure your digital assets with quantum-resistant protection!**## Performance

- **USB Detection**: < 1 second
- **Token Creation**: < 5 seconds
- **Backup/Restore**: 1-10 seconds  
- **Memory Usage**: < 100MB peak

## Requirements

- Python 3.8 or higher
- Windows, Linux, or macOS
- Two USB drives for dual storage setup

## Links

- **GitHub Repository**: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library
- **Documentation**: Full README with examples
- **Security Policy**: Responsible disclosure process
- **Issue Tracker**: Bug reports and feature requests
- **Releases**: Version history and changelogs

## License

MIT License - see LICENSE file for details.

---

**Secure your digital assets with quantum-resistant protection!**
