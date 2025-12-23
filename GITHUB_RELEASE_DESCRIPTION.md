# v0.1.4 - Professional Documentation Update

**Making Security Software More Professional** | October 18, 2025

## What is pqcdualusb?

**pqcdualusb** is a Python library that provides maximum security by splitting your sensitive data (passwords, API keys, encryption keys, etc.) across two separate USB drives. This ensures that even if an attacker steals one drive, they cannot access your secrets without the second drive.

Think of it like splitting a treasure map in half - you need both pieces to find the treasure!

**Key Innovation:** Uses **post-quantum cryptography** - encryption algorithms specifically designed to resist attacks from quantum computers, protecting your data against both current and future threats.

## Who Should Use This?

- **Password Manager Developers**: Secure offline backup storage
- **Security Professionals**: Air-gapped secret storage systems
- **Cryptocurrency Users**: Cold wallet key management
- **Enterprise IT**: Secure credential storage for critical systems
- **Privacy Advocates**: Maximum security for sensitive personal data

## What Changed in v0.1.4?

We cleaned up the documentation to make it more professional and accessible. All emojis have been removed to meet enterprise documentation standards and improve compatibility with screen readers and corporate environments.

**Why this matters:**
- Better for enterprise adoption (banks, hospitals, government)
- Improved accessibility for screen readers
- More professional tone for a security library
- Compatible with all documentation systems and tools

---

## How It Works

Think of it like splitting a treasure map in half:
1. **USB Drive #1** stores part of your secret
2. **USB Drive #2** stores the other part + encrypted backup
3. An attacker needs **both drives** to access your data
4. Uses post-quantum encryption that even quantum computers can't crack

---

## Requirements

- **Python**: 3.8 or higher
- **Two USB Drives**: Any size (library only stores small encrypted files)
- **Operating System**: Windows, Linux, or macOS

---

## Installation

**Step 1: Install the library**
```bash
pip install --upgrade pqcdualusb
```

**Step 2: Verify installation**
```bash
python -c "import pqcdualusb; print('Installation successful!')"
```

---

## Quick Start Guide

### Basic Usage

```python
from pathlib import Path
from pqcdualusb.storage import init_dual_usb

# Example: Storing an API key securely
my_secret = b"sk-1234567890abcdef"  # Your sensitive data

# Set up dual USB protection
init_dual_usb(
    token=my_secret,
    primary_mount=Path("/media/usb1"),     # Path to first USB drive
    backup_mount=Path("/media/usb2"),      # Path to second USB drive  
    passphrase="MyStr0ngP@ssphrase123"     # Strong passphrase
)

print("Success! Your secret is now protected across two USB drives.")
```

**What happens:**
1. Your secret is encrypted with quantum-resistant algorithms
2. The encryption key is split between the two USB drives
3. An encrypted backup is stored on the second drive
4. Without both drives + your passphrase, the data is inaccessible

### Retrieving Your Data

```python
from pathlib import Path
from pqcdualusb.storage import retrieve_from_dual_usb

# Retrieve your secret later
my_secret = retrieve_from_dual_usb(
    primary_mount=Path("/media/usb1"),
    backup_mount=Path("/media/usb2"),
    passphrase="MyStr0ngP@ssphrase123"
)

print(f"Retrieved: {my_secret}")
```

---

## Key Security Features

- **Dual USB Split**: Your secret is split between two physical drives
- **Post-Quantum Safe**: Uses Kyber1024 and Dilithium3 (NIST-approved)
- **Hybrid Encryption**: Combines classical AES-256 + post-quantum crypto
- **Memory Protection**: Automatically wipes sensitive data from RAM
- **Strong Password Protection**: Uses Argon2id to resist brute-force attacks
- **Cross-Platform**: Works on Windows, Linux, and macOS

---

## Why Post-Quantum Cryptography?

**The Quantum Threat:** Quantum computers (when they become powerful enough) will break today's widely-used encryption methods like RSA and ECC. Organizations are already collecting encrypted data now to decrypt it later when quantum computers become available (known as "harvest now, decrypt later" attacks).

**Future-Proof Protection:** This library uses NIST-approved post-quantum algorithms (Kyber1024 and Dilithium3) that are specifically designed to resist quantum attacks, ensuring your data stays secure for decades to come.

---

## Common Use Cases

**1. Password Manager Offline Backup**
```python
# Store your master password recovery key
password_manager_key = b"master-recovery-key-xyz"
init_dual_usb(password_manager_key, usb1, usb2, passphrase)
```

**2. Cryptocurrency Cold Storage**
```python
# Secure your wallet seed phrase
wallet_seed = b"abandon abandon abandon ... art"
init_dual_usb(wallet_seed, usb1, usb2, passphrase)
```

**3. API Key Management**
```python
# Protect production API keys
api_key = b"sk-prod-1234567890"
init_dual_usb(api_key, usb1, usb2, passphrase)
```

---

## Troubleshooting

**Problem: "USB drive not found"**
- Solution: Verify your USB drives are mounted and paths are correct
- Windows: `Path("D:/")` or `Path("E:/")`
- Linux/Mac: `Path("/media/usb1")` or `Path("/Volumes/USB1")`

**Problem: "Passphrase incorrect"**
- Solution: Passphrases are case-sensitive. Ensure you're using the exact passphrase you set during initialization.

**Problem: "Import error"**
- Solution: Ensure Python 3.8+ is installed: `python --version`
- Reinstall the library: `pip install --upgrade --force-reinstall pqcdualusb`

**Need more help?** Check the [full documentation](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library#readme) or [open an issue](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/issues).

---

## Documentation & Support

- **PyPI Package**: https://pypi.org/project/pqcdualusb/
- **Full Documentation**: [README.md](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library#readme)
- **Report Issues**: [GitHub Issues](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/issues)
- **Security Vulnerabilities**: Email Johnsonajibi@gmail.com (PGP key available on request)

---

## Version History

**v0.1.4** - Professional documentation (removed emojis)  
**v0.1.3** - Fixed PyPI display  
**v0.1.2** - Added architectural diagrams  
**v0.1.1** - Modular package structure  
**v0.1.0** - Initial release

[Full Changelog](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/master/CHANGELOG.md)

---

## License

MIT License - Free to use in your projects!

---

## What's New in v0.1.4

### Documentation Improvements
- **Removed all emojis** for enterprise compatibility and professionalism
- **Improved accessibility** for screen reader users
- **Enhanced clarity** with better explanations and examples
- **Added troubleshooting section** for common issues
- **Better use case examples** showing real-world applications

### Why This Update Matters
This release focuses on making the library more accessible to enterprise users, security professionals, and organizations with strict documentation standards. No code changes were made - all improvements are in documentation and presentation.

### Files Changed
- `README.md` - Removed emojis, improved structure
- `PYPI_README.md` - Professional formatting for PyPI
- All markdown documentation - Consistent professional style

**Full Changelog**: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/master/CHANGELOG.md  
**Compare Changes**: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.3...v0.1.4
