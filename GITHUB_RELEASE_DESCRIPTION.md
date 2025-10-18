# v0.1.4 - Professional Documentation Update

**Making Security Software More Professional** | October 18, 2025

## What is pqcdualusb?

This library helps you keep your secrets safe by storing your authentication token and encrypted backups on two separate USB drives. That way, if someone gets one drive, they still can't get everything!

It uses **post-quantum cryptography** - encryption that even future quantum computers can't break - to protect your data from both today's hackers and tomorrow's threats.

## What Changed in v0.1.4?

We cleaned up the documentation to make it more professional and accessible. All emojis have been removed to meet enterprise documentation standards and improve compatibility with screen readers and corporate environments.

## What Changed in v0.1.4?

We cleaned up the documentation to make it more professional and accessible. All emojis have been removed to meet enterprise documentation standards and improve compatibility with screen readers and corporate environments.

**Why this matters:**
- Better for enterprise adoption (banks, hospitals, government)
- Works better with screen readers for accessibility
- More professional tone for a security library
- Compatible with all documentation systems

---

## How It Works

Think of it like splitting a treasure map in half:
1. **USB Drive #1** stores part of your secret
2. **USB Drive #2** stores the other part + encrypted backup
3. An attacker needs **both drives** to access your data
4. Uses post-quantum encryption that even quantum computers can't crack

---

## Installation

```bash
# Install or upgrade to latest version
pip install --upgrade pqcdualusb
```

---

## Quick Example

```python
from pathlib import Path
from pqcdualusb.storage import init_dual_usb

# Set up your two USB drives
init_dual_usb(
    token=b"your-secret-key",
    primary_mount=Path("/media/usb1"),  # First USB drive
    backup_mount=Path("/media/usb2"),   # Second USB drive  
    passphrase="your-strong-passphrase"
)
```

That's it! Your secret is now protected across two USB drives with quantum-resistant encryption.

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

Quantum computers (when they become powerful enough) will break today's encryption methods. This library uses algorithms specifically designed to resist quantum attacks, protecting your data today and for years to come.

---

## Why Post-Quantum Cryptography?

Quantum computers (when they become powerful enough) will break today's encryption methods. This library uses algorithms specifically designed to resist quantum attacks, protecting your data today and for years to come.

---

## Documentation & Support

- **PyPI Package**: https://pypi.org/project/pqcdualusb/
- **Full Documentation**: [README.md](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library#readme)
- **Report Issues**: [GitHub Issues](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/issues)
- **Security Issues**: Email Johnsonajibi@gmail.com

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

**What's Changed**
- Removed emojis from all documentation
- Improved accessibility for screen readers
- Enhanced professional appearance

**Full Diff**: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.3...v0.1.4
