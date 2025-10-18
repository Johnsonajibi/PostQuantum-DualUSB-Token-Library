# Release Notes - v0.1.4

## Professional Documentation Update

**Release Date:** October 18, 2025

This release focuses on making the documentation production-ready for enterprise environments by removing all emojis and adopting professional formatting standards.

---

## What's Changed

### Documentation Improvements

- **Removed all emojis** from README.md and PYPI_README.md for professional, enterprise-grade appearance
- **Replaced emoji-based markers** with clean, professional text formatting
- **Improved accessibility** for screen readers and assistive technologies
- **Enhanced compatibility** with all text processors and corporate documentation systems

### Why This Matters

As a **security-focused cryptographic library**, professional documentation is essential for:

- ✅ Enterprise security audits and compliance reviews
- ✅ Corporate adoption in regulated industries
- ✅ Accessibility for users with screen readers
- ✅ Universal text encoding compatibility
- ✅ Professional tone appropriate for cryptographic software

---

## Installation

### PyPI (Recommended)

```bash
pip install pqcdualusb==0.1.4
```

Or upgrade from previous versions:

```bash
pip install --upgrade pqcdualusb
```

### From Source

```bash
git clone https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library.git
cd PostQuantum-DualUSB-Token-Library
pip install -e .
```

---

## Quick Start

```python
from pathlib import Path
from pqcdualusb.storage import init_dual_usb, rotate_token, verify_dual_setup

# Initialize dual USB backup
primary_usb = Path("/media/usb1")
backup_usb = Path("/media/usb2")

init_info = init_dual_usb(
    token=b"my-secret-data",
    primary_mount=primary_usb,
    backup_mount=backup_usb,
    passphrase="strong-passphrase"
)

print(f"Initialized: {init_info['primary']}")
```

---

## Full Changelog

See [CHANGELOG.md](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/master/CHANGELOG.md) for complete version history.

---

## Documentation

- **PyPI Package:** https://pypi.org/project/pqcdualusb/0.1.4/
- **Full Documentation:** [GitHub README](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/master/README.md)
- **Architecture Guide:** [ARCHITECTURE.md](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/master/ARCHITECTURE.md)
- **Security Policy:** [SECURITY.md](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/master/SECURITY.md)

---

## Previous Releases

- **v0.1.3** - Fixed PyPI README display (added PyPI-specific README without Mermaid diagrams)
- **v0.1.2** - Added comprehensive architectural diagrams and improved documentation
- **v0.1.1** - Major refactoring to modular package architecture
- **v0.1.0** - Initial monolithic script release

---

## Support

- **Issues:** [GitHub Issues](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/issues)
- **Security:** Email Johnsonajibi@gmail.com for security vulnerabilities
- **Discussions:** [GitHub Discussions](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/discussions)

---

## Contributors

Special thanks to all contributors who helped make this release possible!

---

## License

This project is licensed under the MIT License. See [LICENSE](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/blob/master/LICENSE) for details.
